"""TEE Attestation verification for Happy Phone"""

import asyncio
from dataclasses import dataclass
from typing import Optional
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

    @property
    def is_confidential(self) -> bool:
        """Check if server is running in a confidential VM"""
        return self.tee_type in ('sev-snp', 'sev', 'sev-guest', 'azure-cvm')

    def status_line(self) -> str:
        """Get a one-line status summary"""
        if self.error:
            return f"⚠ TEE: Error - {self.error}"
        if not self.is_confidential:
            return "⚠ TEE: Server NOT in Trusted Execution Environment"
        
        status = f"✓ TEE: {self.tee_type.upper()}"
        if self.vm_size:
            status += f" ({self.vm_size})"
        if self.secure_boot and self.vtpm:
            status += " [Secure Boot ✓] [vTPM ✓]"
        return status


async def fetch_attestation(base_url: str = SIGNALING_URL) -> TEEAttestation:
    """
    Fetch and parse attestation from the signaling server.
    
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


def check_tee_dependencies() -> tuple[bool, list[str]]:
    """Check if TEE verification dependencies are available"""
    missing = []
    if not AIOHTTP_AVAILABLE:
        missing.append('aiohttp')
    return len(missing) == 0, missing


def verify_attestation(attestation: TEEAttestation) -> tuple[bool, list[str]]:
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


def verify_snp_report(report: Optional[str]) -> tuple[bool, str]:
    """
    Verify AMD SEV-SNP attestation report.
    
    Note: Full verification requires:
    1. Parse the SNP report structure
    2. Verify AMD's signature chain (ARK -> ASK -> VCEK)
    3. Verify the report signature
    4. Check measurement against expected value
    
    This is a stub that checks report presence.
    Full implementation would need AMD's certificate chain and crypto libs.
    
    Returns:
        (is_valid, status_message)
    """
    if not report:
        return False, "No SNP report available"
    
    # TODO: Implement full AMD SNP signature verification
    # This would require:
    # - Fetching AMD root certificates (ARK, ASK)
    # - Parsing the SNP report binary structure
    # - Verifying ECDSA signatures
    # - Comparing launch measurement
    
    return True, "SNP report present (signature verification not implemented)"


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
