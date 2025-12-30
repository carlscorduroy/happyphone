"""TEE Attestation verification for Happy Phone

This module provides cryptographic verification of AMD SEV-SNP attestation reports,
ensuring hardware-backed proof that the signaling server runs in a Trusted Execution
Environment.

Verification Flow:
1. Client generates a random nonce (challenge)
2. Server generates SNP report with nonce in report_data field
3. Client verifies:
   - AMD certificate chain (ARK -> ASK -> VCEK)
   - Report signature (proves report came from real AMD hardware)
   - Nonce in report_data (proves freshness, prevents replay)
   - Optionally: measurement (proves specific code is running)
"""

import asyncio
import os
import base64
from dataclasses import dataclass
from typing import Optional, Tuple
from urllib.parse import urljoin

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

from .config import (
    SIGNALING_URL, TEE_ATTESTATION_ENABLED, TEE_REQUIRE_ATTESTATION,
    TEE_EXPECTED_VM_SIZES, TEE_EXPECTED_MEASUREMENT
)

# Import SNP verification components
try:
    from .snp_report import (
        SNPAttestationReport, SNPReportVerifier, 
        CRYPTO_AVAILABLE, check_snp_dependencies
    )
    SNP_AVAILABLE = CRYPTO_AVAILABLE
except ImportError:
    SNP_AVAILABLE = False


@dataclass
class TEEAttestation:
    """TEE attestation status"""
    tee_type: str  # 'sev-snp', 'sev', 'none'
    verified: bool
    vm_id: Optional[str] = None
    vm_size: Optional[str] = None
    location: Optional[str] = None
    secure_boot: bool = False
    vtpm: bool = False
    server_version: Optional[str] = None
    timestamp: Optional[str] = None
    error: Optional[str] = None
    
    # Cryptographic verification results
    crypto_verified: bool = False  # True if SNP signature verified
    cert_chain_valid: bool = False  # True if AMD cert chain verified
    nonce_valid: bool = False  # True if challenge-response passed
    measurement: Optional[str] = None  # Launch measurement (hex)
    chip_id: Optional[str] = None  # Unique chip identifier
    verification_issues: list = None  # List of verification issues

    def __post_init__(self):
        if self.verification_issues is None:
            self.verification_issues = []

    @property
    def is_confidential(self) -> bool:
        """Check if server is running in a confidential VM"""
        return self.tee_type in ('sev-snp', 'sev', 'sev-guest', 'azure-cvm')
    
    @property
    def is_cryptographically_verified(self) -> bool:
        """True if we have hardware-backed cryptographic proof"""
        return self.crypto_verified and self.cert_chain_valid and self.nonce_valid

    def status_line(self) -> str:
        """Get a one-line status summary"""
        if self.error:
            return f"⚠ TEE: Error - {self.error}"
        if not self.is_confidential:
            return "⚠ TEE: Server NOT in Trusted Execution Environment"
        
        status = f"✓ TEE: {self.tee_type.upper()}"
        if self.vm_size:
            status += f" ({self.vm_size})"
        
        # Show cryptographic verification status
        if self.is_cryptographically_verified:
            status += " [Crypto ✓]"
        elif self.crypto_verified:
            status += " [Sig ✓]"
        
        if self.secure_boot and self.vtpm:
            status += " [Secure Boot ✓] [vTPM ✓]"
        return status
    
    def detailed_status(self) -> list:
        """Get detailed verification status for display"""
        lines = []
        lines.append(f"TEE Type: {self.tee_type}")
        if self.vm_id:
            lines.append(f"VM ID: {self.vm_id}")
        if self.vm_size:
            lines.append(f"VM Size: {self.vm_size}")
        if self.location:
            lines.append(f"Location: {self.location}")
        
        lines.append(f"")
        lines.append(f"Cryptographic Verification:")
        lines.append(f"  Certificate Chain: {'✓' if self.cert_chain_valid else '✗'}")
        lines.append(f"  Report Signature: {'✓' if self.crypto_verified else '✗'}")
        lines.append(f"  Challenge-Response: {'✓' if self.nonce_valid else '✗'}")
        
        if self.measurement:
            lines.append(f"  Measurement: {self.measurement[:32]}...")
        if self.chip_id:
            lines.append(f"  Chip ID: {self.chip_id[:32]}...")
        
        if self.verification_issues:
            lines.append(f"")
            lines.append(f"Issues:")
            for issue in self.verification_issues:
                lines.append(f"  - {issue}")
        
        return lines


def generate_attestation_nonce() -> bytes:
    """Generate a random 64-byte nonce for attestation challenge"""
    return os.urandom(64)


async def fetch_attestation(base_url: str = SIGNALING_URL) -> TEEAttestation:
    """
    Fetch and parse attestation from the signaling server (basic version).
    
    Args:
        base_url: Base URL of the signaling server
        
    Returns:
        TEEAttestation object with verification results
    """
    if not AIOHTTP_AVAILABLE:
        return TEEAttestation(
            tee_type='unknown',
            verified=False,
            error='aiohttp not installed'
        )

    # Build attestation URL
    attestation_url = urljoin(base_url.rstrip('/') + '/', 'attestation')
    
    # Handle wss:// URLs - convert to https://
    if attestation_url.startswith('wss://'):
        attestation_url = attestation_url.replace('wss://', 'https://', 1)
    elif attestation_url.startswith('ws://'):
        attestation_url = attestation_url.replace('ws://', 'http://', 1)

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(attestation_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    return TEEAttestation(
                        tee_type='unknown',
                        verified=False,
                        error=f'HTTP {resp.status}'
                    )
                
                data = await resp.json()
                
                # Parse response
                tee_type = data.get('teeType', 'none')
                vm_info = data.get('vm', {})
                security = vm_info.get('securityProfile', {})
                
                return TEEAttestation(
                    tee_type=tee_type,
                    verified=tee_type in ('sev-snp', 'sev', 'sev-guest'),
                    vm_id=vm_info.get('vmId'),
                    vm_size=vm_info.get('vmSize'),
                    location=vm_info.get('location'),
                    secure_boot=security.get('secureBootEnabled') == 'true',
                    vtpm=security.get('virtualTpmEnabled') == 'true',
                    server_version=data.get('serverVersion'),
                    timestamp=data.get('timestamp'),
                )

    except asyncio.TimeoutError:
        return TEEAttestation(
            tee_type='unknown',
            verified=False,
            error='Connection timeout'
        )
    except Exception as e:
        return TEEAttestation(
            tee_type='unknown',
            verified=False,
            error=str(e)
        )


async def fetch_and_verify_attestation(
    base_url: str = SIGNALING_URL,
    processor: str = 'milan',
    expected_measurement: Optional[bytes] = None,
) -> TEEAttestation:
    """
    Fetch attestation with cryptographic verification using challenge-response.
    
    This is the secure verification method that:
    1. Sends a random nonce to the server
    2. Server generates SNP report with nonce in report_data
    3. Fetches AMD certificate chain from KDS
    4. Verifies certificate chain (ARK -> ASK -> VCEK)
    5. Verifies report signature
    6. Verifies nonce in report (prevents replay)
    7. Optionally verifies measurement
    
    Args:
        base_url: Base URL of the signaling server
        processor: AMD processor type ('milan' or 'genoa')
        expected_measurement: Optional expected launch measurement
        
    Returns:
        TEEAttestation with cryptographic verification results
    """
    if not AIOHTTP_AVAILABLE:
        return TEEAttestation(
            tee_type='unknown',
            verified=False,
            error='aiohttp not installed'
        )
    
    if not SNP_AVAILABLE:
        return TEEAttestation(
            tee_type='unknown',
            verified=False,
            error='cryptography library not installed (pip install cryptography)'
        )
    
    # Generate challenge nonce
    nonce = generate_attestation_nonce()
    nonce_b64 = base64.b64encode(nonce).decode('ascii')
    
    # Build attestation URL with challenge
    attestation_url = urljoin(base_url.rstrip('/') + '/', 'attestation')
    
    # Handle wss:// URLs
    if attestation_url.startswith('wss://'):
        attestation_url = attestation_url.replace('wss://', 'https://', 1)
    elif attestation_url.startswith('ws://'):
        attestation_url = attestation_url.replace('ws://', 'http://', 1)
    
    issues = []
    
    try:
        async with aiohttp.ClientSession() as session:
            # Request attestation with challenge nonce
            async with session.post(
                attestation_url,
                json={'nonce': nonce_b64},
                timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                if resp.status != 200:
                    return TEEAttestation(
                        tee_type='unknown',
                        verified=False,
                        error=f'HTTP {resp.status}'
                    )
                
                data = await resp.json()
            
            # Parse basic info
            tee_type = data.get('teeType', 'none')
            vm_info = data.get('vm', {})
            security = vm_info.get('securityProfile', {})
            
            # Check if we have a real SNP report
            report_b64 = data.get('report')
            vcek_pem = data.get('vcek')
            
            if not report_b64:
                return TEEAttestation(
                    tee_type=tee_type,
                    verified=False,
                    vm_id=vm_info.get('vmId'),
                    vm_size=vm_info.get('vmSize'),
                    location=vm_info.get('location'),
                    secure_boot=security.get('secureBootEnabled') == 'true',
                    vtpm=security.get('virtualTpmEnabled') == 'true',
                    server_version=data.get('serverVersion'),
                    timestamp=data.get('timestamp'),
                    error='No SNP report in response (server may not be in TEE)',
                )
            
            # Decode and parse the report
            try:
                report_bytes = base64.b64decode(report_b64)
                report = SNPAttestationReport.from_bytes(report_bytes)
            except Exception as e:
                issues.append(f"Failed to parse SNP report: {e}")
                return TEEAttestation(
                    tee_type=tee_type,
                    verified=False,
                    error=f'Invalid SNP report format: {e}',
                    verification_issues=issues,
                )
            
            # Initialize verifier
            verifier = SNPReportVerifier(processor=processor)
            
            # Fetch AMD certificate chain
            cert_chain_url = f"https://kdsintf.amd.com/vcek/v1/{processor}/cert_chain"
            try:
                async with session.get(cert_chain_url, timeout=aiohttp.ClientTimeout(total=10)) as cert_resp:
                    if cert_resp.status == 200:
                        cert_chain_pem = await cert_resp.read()
                        verifier.load_cert_chain_from_pem(cert_chain_pem)
                    else:
                        issues.append(f"Failed to fetch AMD cert chain: HTTP {cert_resp.status}")
            except Exception as e:
                issues.append(f"Failed to fetch AMD cert chain: {e}")
            
            # Load VCEK if provided by server
            if vcek_pem:
                try:
                    verifier.load_vcek_from_pem(vcek_pem.encode() if isinstance(vcek_pem, str) else vcek_pem)
                except Exception as e:
                    issues.append(f"Failed to load VCEK: {e}")
            
            # Verify certificate chain
            cert_chain_valid = False
            try:
                cert_valid, cert_msg = verifier.verify_cert_chain()
                cert_chain_valid = cert_valid
                if not cert_valid:
                    issues.append(f"Certificate chain: {cert_msg}")
            except Exception as e:
                issues.append(f"Certificate verification failed: {e}")
            
            # Verify report signature
            crypto_verified = False
            try:
                sig_valid, sig_msg = verifier.verify_report_signature(report)
                crypto_verified = sig_valid
                if not sig_valid:
                    issues.append(f"Signature: {sig_msg}")
            except Exception as e:
                issues.append(f"Signature verification failed: {e}")
            
            # Verify nonce
            nonce_valid = report.verify_nonce(nonce)
            if not nonce_valid:
                issues.append("Nonce mismatch - possible replay attack or server error")
            
            # Verify measurement if expected
            if expected_measurement and report.measurement != expected_measurement:
                issues.append(f"Measurement mismatch")
            
            # Check security policy
            policy = report.get_policy_flags()
            if policy['debug_allowed']:
                issues.append("Warning: Debug mode is allowed on VM")
            
            return TEEAttestation(
                tee_type=tee_type,
                verified=crypto_verified and cert_chain_valid,
                vm_id=vm_info.get('vmId'),
                vm_size=vm_info.get('vmSize'),
                location=vm_info.get('location'),
                secure_boot=security.get('secureBootEnabled') == 'true',
                vtpm=security.get('virtualTpmEnabled') == 'true',
                server_version=data.get('serverVersion'),
                timestamp=data.get('timestamp'),
                crypto_verified=crypto_verified,
                cert_chain_valid=cert_chain_valid,
                nonce_valid=nonce_valid,
                measurement=report.measurement_hex(),
                chip_id=report.chip_id_hex(),
                verification_issues=issues,
            )
    
    except asyncio.TimeoutError:
        return TEEAttestation(
            tee_type='unknown',
            verified=False,
            error='Connection timeout'
        )
    except Exception as e:
        return TEEAttestation(
            tee_type='unknown',
            verified=False,
            error=str(e)
        )


def check_tee_dependencies() -> Tuple[bool, list]:
    """Check if TEE verification dependencies are available"""
    missing = []
    if not AIOHTTP_AVAILABLE:
        missing.append('aiohttp')
    if not SNP_AVAILABLE:
        missing.append('cryptography (for crypto verification)')
    return len(missing) == 0, missing


def verify_attestation(attestation: TEEAttestation) -> Tuple[bool, list]:
    """
    Verify attestation against expected values.
    
    Returns:
        (is_valid, list of warnings/errors)
    """
    issues = []
    
    if not TEE_ATTESTATION_ENABLED:
        return True, []  # Verification disabled
    
    # Check if running in TEE
    if not attestation.is_confidential:
        issues.append("Server is NOT running in a Trusted Execution Environment")
        if TEE_REQUIRE_ATTESTATION:
            return False, issues
    
    # Verify VM size is expected
    if attestation.vm_size and attestation.vm_size not in TEE_EXPECTED_VM_SIZES:
        issues.append(f"Unexpected VM size: {attestation.vm_size}")
    
    # Verify secure boot and vTPM
    if attestation.is_confidential:
        if not attestation.secure_boot:
            issues.append("Secure Boot is not enabled")
        if not attestation.vtpm:
            issues.append("Virtual TPM is not enabled")
    
    # Check expected measurement if configured
    # Note: Full SNP report verification would require AMD certificate chain
    # This is a placeholder for measurement comparison
    if TEE_EXPECTED_MEASUREMENT:
        # Future: Compare attestation.report hash against expected
        pass
    
    is_valid = len(issues) == 0 or not TEE_REQUIRE_ATTESTATION
    return is_valid, issues


def verify_snp_report_binary(
    report_bytes: bytes,
    nonce: Optional[bytes] = None,
    expected_measurement: Optional[bytes] = None,
    processor: str = 'milan'
) -> Tuple[bool, str, Optional[SNPAttestationReport]]:
    """
    Verify AMD SEV-SNP attestation report from binary data.
    
    This performs offline verification without fetching certificates.
    Use fetch_and_verify_attestation() for full online verification.
    
    Args:
        report_bytes: Raw binary SNP attestation report
        nonce: Expected nonce in report_data (optional)
        expected_measurement: Expected launch measurement (optional)
        processor: AMD processor type
        
    Returns:
        (is_valid, status_message, parsed_report)
    """
    if not SNP_AVAILABLE:
        return False, "cryptography library not installed", None
    
    try:
        report = SNPAttestationReport.from_bytes(report_bytes)
    except Exception as e:
        return False, f"Failed to parse report: {e}", None
    
    issues = []
    
    # Check nonce if provided
    if nonce and not report.verify_nonce(nonce):
        issues.append("Nonce mismatch")
    
    # Check measurement if provided
    if expected_measurement and report.measurement != expected_measurement:
        issues.append("Measurement mismatch")
    
    # Check policy
    policy = report.get_policy_flags()
    if policy['debug_allowed']:
        issues.append("Debug allowed")
    
    if issues:
        return False, "; ".join(issues), report
    
    return True, "Report parsed successfully (signature verification requires certificates)", report


def get_expected_measurements() -> dict:
    """
    Get expected measurements for known server versions.
    
    Returns:
        Dict mapping server version to expected launch measurement hash
    """
    # These would be populated with actual SHA-384 hashes of the
    # server code when built in a reproducible way
    return {
        "1.0.0": TEE_EXPECTED_MEASUREMENT or None,
    }


def format_verification_summary(attestation: TEEAttestation) -> str:
    """
    Format a human-readable verification summary.
    
    Args:
        attestation: TEEAttestation object
        
    Returns:
        Multi-line summary string
    """
    lines = []
    
    if attestation.is_cryptographically_verified:
        lines.append("🔒 CRYPTOGRAPHICALLY VERIFIED")
        lines.append("   Hardware-backed proof of TEE execution")
    elif attestation.is_confidential:
        lines.append("⚠️  SOFT ATTESTATION ONLY")
        lines.append("   Server claims TEE but not cryptographically verified")
    else:
        lines.append("❌ NOT IN TEE")
        lines.append("   Server is not running in Trusted Execution Environment")
    
    lines.append("")
    for line in attestation.detailed_status():
        lines.append(line)
    
    return "\n".join(lines)
