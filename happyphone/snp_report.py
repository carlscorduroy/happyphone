"""
AMD SEV-SNP Attestation Report Parser and Verifier

This module implements cryptographic verification of AMD SEV-SNP attestation reports.
It provides hardware-backed proof that a server is running in a Trusted Execution Environment.

References:
- AMD SEV-SNP ABI Specification: https://www.amd.com/system/files/TechDocs/56860.pdf
- AMD Key Distribution Service: https://kdsintf.amd.com/
"""

import struct
from dataclasses import dataclass
from typing import Optional, Tuple
from enum import IntFlag
import hashlib

# Try to import cryptography for signature verification
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature
    from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# AMD SEV-SNP Report Structure Constants
REPORT_SIZE = 1184  # Total report size in bytes
SIGNED_DATA_SIZE = 0x2A0  # First 672 bytes are signed
SIGNATURE_OFFSET = 0x2A0
SIGNATURE_SIZE = 512  # ECDSA P-384 signature (r,s each 72 bytes padded to 256)

# Field offsets (from AMD SEV-SNP ABI specification)
VERSION_OFFSET = 0x000
GUEST_SVN_OFFSET = 0x004
POLICY_OFFSET = 0x008
FAMILY_ID_OFFSET = 0x010
IMAGE_ID_OFFSET = 0x020
VMPL_OFFSET = 0x030
SIGNATURE_ALGO_OFFSET = 0x034
CURRENT_TCB_OFFSET = 0x038
PLATFORM_INFO_OFFSET = 0x040
FLAGS_OFFSET = 0x048
RESERVED0_OFFSET = 0x04C
REPORT_DATA_OFFSET = 0x050
MEASUREMENT_OFFSET = 0x090
HOST_DATA_OFFSET = 0x0C0
ID_KEY_DIGEST_OFFSET = 0x0F0
AUTHOR_KEY_DIGEST_OFFSET = 0x120
REPORT_ID_OFFSET = 0x150
REPORT_ID_MA_OFFSET = 0x170
REPORTED_TCB_OFFSET = 0x190
RESERVED1_OFFSET = 0x198
CHIP_ID_OFFSET = 0x1A0
COMMITTED_TCB_OFFSET = 0x1E0
CURRENT_BUILD_OFFSET = 0x1E8
CURRENT_MINOR_OFFSET = 0x1E9
CURRENT_MAJOR_OFFSET = 0x1EA
RESERVED2_OFFSET = 0x1EB
COMMITTED_BUILD_OFFSET = 0x1EC
COMMITTED_MINOR_OFFSET = 0x1ED
COMMITTED_MAJOR_OFFSET = 0x1EE
RESERVED3_OFFSET = 0x1EF
LAUNCH_TCB_OFFSET = 0x1F0
RESERVED4_OFFSET = 0x1F8


class GuestPolicy(IntFlag):
    """SEV-SNP Guest Policy Flags"""
    ABI_MINOR = 0xFF  # Bits 0-7
    ABI_MAJOR = 0xFF00  # Bits 8-15
    SMT_ALLOWED = 1 << 16
    RESERVED_17 = 1 << 17
    MIGRATE_MA_ALLOWED = 1 << 18
    DEBUG_ALLOWED = 1 << 19
    SINGLE_SOCKET = 1 << 20


class PlatformInfo(IntFlag):
    """Platform Info Flags"""
    SMT_ENABLED = 1 << 0
    TSME_ENABLED = 1 << 1
    ECC_EN = 1 << 2
    RAPL_DIS = 1 << 3
    CIPHERTEXT_HIDING = 1 << 4


@dataclass
class TCBVersion:
    """Trusted Computing Base Version"""
    bootloader: int
    tee: int
    reserved: int
    snp: int
    microcode: int
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'TCBVersion':
        """Parse TCB version from 8 bytes"""
        return cls(
            bootloader=data[0],
            tee=data[1],
            reserved=data[2],
            snp=data[3],
            microcode=data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24)
        )
    
    def __str__(self) -> str:
        return f"bl={self.bootloader} tee={self.tee} snp={self.snp} ucode={self.microcode}"


@dataclass
class SNPAttestationReport:
    """Parsed AMD SEV-SNP Attestation Report"""
    # Header
    version: int
    guest_svn: int
    policy: int
    
    # Identification
    family_id: bytes  # 16 bytes
    image_id: bytes   # 16 bytes
    vmpl: int
    signature_algo: int  # 1 = ECDSA P-384
    
    # TCB info
    current_tcb: TCBVersion
    platform_info: int
    
    # Flags and report data
    flags: int
    report_data: bytes  # 64 bytes - client nonce goes here
    
    # Measurements
    measurement: bytes  # 48 bytes (SHA-384 of guest memory at launch)
    host_data: bytes    # 32 bytes
    
    # Key digests
    id_key_digest: bytes      # 48 bytes
    author_key_digest: bytes  # 48 bytes
    
    # Report IDs
    report_id: bytes     # 32 bytes
    report_id_ma: bytes  # 32 bytes
    reported_tcb: TCBVersion
    
    # Chip info
    chip_id: bytes  # 64 bytes - unique chip identifier
    committed_tcb: TCBVersion
    
    # Firmware version
    current_build: int
    current_minor: int
    current_major: int
    committed_build: int
    committed_minor: int
    committed_major: int
    launch_tcb: TCBVersion
    
    # Signature
    signature_r: bytes  # 72 bytes (padded)
    signature_s: bytes  # 72 bytes (padded)
    
    # Raw data for verification
    raw_report: bytes
    signed_data: bytes
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'SNPAttestationReport':
        """Parse attestation report from binary data"""
        if len(data) < REPORT_SIZE:
            raise ValueError(f"Report too short: {len(data)} bytes, expected {REPORT_SIZE}")
        
        # Parse all fields
        version = struct.unpack_from('<I', data, VERSION_OFFSET)[0]
        guest_svn = struct.unpack_from('<I', data, GUEST_SVN_OFFSET)[0]
        policy = struct.unpack_from('<Q', data, POLICY_OFFSET)[0]
        family_id = data[FAMILY_ID_OFFSET:FAMILY_ID_OFFSET + 16]
        image_id = data[IMAGE_ID_OFFSET:IMAGE_ID_OFFSET + 16]
        vmpl = struct.unpack_from('<I', data, VMPL_OFFSET)[0]
        signature_algo = struct.unpack_from('<I', data, SIGNATURE_ALGO_OFFSET)[0]
        current_tcb = TCBVersion.from_bytes(data[CURRENT_TCB_OFFSET:CURRENT_TCB_OFFSET + 8])
        platform_info = struct.unpack_from('<Q', data, PLATFORM_INFO_OFFSET)[0]
        flags = struct.unpack_from('<I', data, FLAGS_OFFSET)[0]
        report_data = data[REPORT_DATA_OFFSET:REPORT_DATA_OFFSET + 64]
        measurement = data[MEASUREMENT_OFFSET:MEASUREMENT_OFFSET + 48]
        host_data = data[HOST_DATA_OFFSET:HOST_DATA_OFFSET + 32]
        id_key_digest = data[ID_KEY_DIGEST_OFFSET:ID_KEY_DIGEST_OFFSET + 48]
        author_key_digest = data[AUTHOR_KEY_DIGEST_OFFSET:AUTHOR_KEY_DIGEST_OFFSET + 48]
        report_id = data[REPORT_ID_OFFSET:REPORT_ID_OFFSET + 32]
        report_id_ma = data[REPORT_ID_MA_OFFSET:REPORT_ID_MA_OFFSET + 32]
        reported_tcb = TCBVersion.from_bytes(data[REPORTED_TCB_OFFSET:REPORTED_TCB_OFFSET + 8])
        chip_id = data[CHIP_ID_OFFSET:CHIP_ID_OFFSET + 64]
        committed_tcb = TCBVersion.from_bytes(data[COMMITTED_TCB_OFFSET:COMMITTED_TCB_OFFSET + 8])
        current_build = data[CURRENT_BUILD_OFFSET]
        current_minor = data[CURRENT_MINOR_OFFSET]
        current_major = data[CURRENT_MAJOR_OFFSET]
        committed_build = data[COMMITTED_BUILD_OFFSET]
        committed_minor = data[COMMITTED_MINOR_OFFSET]
        committed_major = data[COMMITTED_MAJOR_OFFSET]
        launch_tcb = TCBVersion.from_bytes(data[LAUNCH_TCB_OFFSET:LAUNCH_TCB_OFFSET + 8])
        
        # Parse signature (ECDSA P-384: r and s, each 72 bytes in AMD format)
        sig_offset = SIGNATURE_OFFSET
        signature_r = data[sig_offset:sig_offset + 72]
        signature_s = data[sig_offset + 72:sig_offset + 144]
        
        return cls(
            version=version,
            guest_svn=guest_svn,
            policy=policy,
            family_id=family_id,
            image_id=image_id,
            vmpl=vmpl,
            signature_algo=signature_algo,
            current_tcb=current_tcb,
            platform_info=platform_info,
            flags=flags,
            report_data=report_data,
            measurement=measurement,
            host_data=host_data,
            id_key_digest=id_key_digest,
            author_key_digest=author_key_digest,
            report_id=report_id,
            report_id_ma=report_id_ma,
            reported_tcb=reported_tcb,
            chip_id=chip_id,
            committed_tcb=committed_tcb,
            current_build=current_build,
            current_minor=current_minor,
            current_major=current_major,
            committed_build=committed_build,
            committed_minor=committed_minor,
            committed_major=committed_major,
            launch_tcb=launch_tcb,
            signature_r=signature_r,
            signature_s=signature_s,
            raw_report=data[:REPORT_SIZE],
            signed_data=data[:SIGNED_DATA_SIZE],
        )
    
    def get_policy_flags(self) -> dict:
        """Decode policy flags"""
        return {
            'abi_minor': self.policy & 0xFF,
            'abi_major': (self.policy >> 8) & 0xFF,
            'smt_allowed': bool(self.policy & GuestPolicy.SMT_ALLOWED),
            'migrate_ma_allowed': bool(self.policy & GuestPolicy.MIGRATE_MA_ALLOWED),
            'debug_allowed': bool(self.policy & GuestPolicy.DEBUG_ALLOWED),
            'single_socket': bool(self.policy & GuestPolicy.SINGLE_SOCKET),
        }
    
    def get_platform_flags(self) -> dict:
        """Decode platform info flags"""
        return {
            'smt_enabled': bool(self.platform_info & PlatformInfo.SMT_ENABLED),
            'tsme_enabled': bool(self.platform_info & PlatformInfo.TSME_ENABLED),
            'ecc_enabled': bool(self.platform_info & PlatformInfo.ECC_EN),
            'rapl_disabled': bool(self.platform_info & PlatformInfo.RAPL_DIS),
            'ciphertext_hiding': bool(self.platform_info & PlatformInfo.CIPHERTEXT_HIDING),
        }
    
    def get_signature_der(self) -> bytes:
        """Convert AMD signature format to DER-encoded ECDSA signature"""
        # AMD stores r and s as little-endian 72-byte values
        # We need to convert to DER format for cryptography library
        
        # Extract r and s (strip padding, reverse for big-endian)
        r_bytes = self.signature_r[:48]  # P-384 uses 48-byte values
        s_bytes = self.signature_s[:48]
        
        # Convert from little-endian to big-endian
        r_int = int.from_bytes(r_bytes, 'little')
        s_int = int.from_bytes(s_bytes, 'little')
        
        # Encode as DER
        def encode_der_integer(value: int) -> bytes:
            """Encode integer as DER INTEGER"""
            value_bytes = value.to_bytes((value.bit_length() + 7) // 8 or 1, 'big')
            # Add leading zero if high bit set (to avoid negative interpretation)
            if value_bytes[0] & 0x80:
                value_bytes = b'\x00' + value_bytes
            return bytes([0x02, len(value_bytes)]) + value_bytes
        
        r_der = encode_der_integer(r_int)
        s_der = encode_der_integer(s_int)
        sequence = r_der + s_der
        
        return bytes([0x30, len(sequence)]) + sequence
    
    def verify_nonce(self, expected_nonce: bytes) -> bool:
        """Verify that the report contains the expected nonce in report_data"""
        return self.report_data[:len(expected_nonce)] == expected_nonce
    
    def firmware_version_string(self) -> str:
        """Get firmware version as string"""
        return f"{self.current_major}.{self.current_minor}.{self.current_build}"
    
    def measurement_hex(self) -> str:
        """Get measurement as hex string"""
        return self.measurement.hex()
    
    def chip_id_hex(self) -> str:
        """Get chip ID as hex string"""
        return self.chip_id.hex()


class SNPReportVerifier:
    """Verify AMD SEV-SNP attestation reports against AMD certificate chain"""
    
    # AMD Key Distribution Service URLs
    AMD_KDS_VCEK_URL = "https://kdsintf.amd.com/vcek/v1/{processor}/cert_chain"
    AMD_KDS_VLEK_URL = "https://kdsintf.amd.com/vlek/v1/{processor}/cert_chain"
    
    # Known AMD root certificate fingerprints (for extra validation)
    AMD_ROOT_FINGERPRINTS = {
        'milan': 'b35472e90b52c2ed3d3fdbe4919285c2bd5bc8ff6b19d2c29b6c69c3c6f60f6f',
        'genoa': None,  # To be added when available
    }
    
    def __init__(self, processor: str = 'milan'):
        """
        Initialize verifier.
        
        Args:
            processor: AMD processor generation ('milan' for EPYC 7xx3, 'genoa' for 9xx4)
        """
        if not CRYPTO_AVAILABLE:
            raise ImportError("cryptography library required for SNP verification")
        
        self.processor = processor
        self.ark_cert = None  # AMD Root Key
        self.ask_cert = None  # AMD Signing Key  
        self.vcek_cert = None  # Versioned Chip Endorsement Key
    
    def load_cert_chain_from_pem(self, pem_data: bytes):
        """Load certificate chain from PEM data (ARK, ASK, VCEK)"""
        # PEM data typically contains multiple certificates
        certs = []
        pem_str = pem_data.decode('utf-8')
        
        # Split on certificate boundaries
        import re
        cert_matches = re.findall(
            r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
            pem_str, re.DOTALL
        )
        
        for cert_pem in cert_matches:
            cert = load_pem_x509_certificate(cert_pem.encode())
            certs.append(cert)
        
        # AMD cert chain order: ARK, ASK, VCEK (or just ARK, ASK for chain file)
        if len(certs) >= 2:
            self.ark_cert = certs[0]
            self.ask_cert = certs[1]
        if len(certs) >= 3:
            self.vcek_cert = certs[2]
    
    def load_vcek_from_pem(self, vcek_pem: bytes):
        """Load VCEK certificate separately"""
        self.vcek_cert = load_pem_x509_certificate(vcek_pem)
    
    def load_vcek_from_der(self, vcek_der: bytes):
        """Load VCEK certificate from DER format"""
        self.vcek_cert = load_der_x509_certificate(vcek_der)
    
    def verify_cert_chain(self) -> Tuple[bool, str]:
        """
        Verify the certificate chain: ARK -> ASK -> VCEK
        
        Returns:
            (is_valid, message)
        """
        if not self.ark_cert or not self.ask_cert:
            return False, "Certificate chain not loaded"
        
        try:
            # Verify ARK is self-signed
            ark_public_key = self.ark_cert.public_key()
            ark_public_key.verify(
                self.ark_cert.signature,
                self.ark_cert.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA384())
            )
        except InvalidSignature:
            return False, "ARK certificate is not properly self-signed"
        except Exception as e:
            return False, f"ARK verification failed: {e}"
        
        try:
            # Verify ASK is signed by ARK
            ark_public_key.verify(
                self.ask_cert.signature,
                self.ask_cert.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA384())
            )
        except InvalidSignature:
            return False, "ASK certificate not signed by ARK"
        except Exception as e:
            return False, f"ASK verification failed: {e}"
        
        if self.vcek_cert:
            try:
                # Verify VCEK is signed by ASK
                ask_public_key = self.ask_cert.public_key()
                ask_public_key.verify(
                    self.vcek_cert.signature,
                    self.vcek_cert.tbs_certificate_bytes,
                    ec.ECDSA(hashes.SHA384())
                )
            except InvalidSignature:
                return False, "VCEK certificate not signed by ASK"
            except Exception as e:
                return False, f"VCEK verification failed: {e}"
        
        return True, "Certificate chain valid"
    
    def verify_report_signature(self, report: SNPAttestationReport) -> Tuple[bool, str]:
        """
        Verify the attestation report signature against VCEK.
        
        Args:
            report: Parsed SNP attestation report
            
        Returns:
            (is_valid, message)
        """
        if not self.vcek_cert:
            return False, "VCEK certificate not loaded"
        
        if report.signature_algo != 1:
            return False, f"Unsupported signature algorithm: {report.signature_algo}"
        
        try:
            vcek_public_key = self.vcek_cert.public_key()
            signature_der = report.get_signature_der()
            
            # Verify signature over the signed portion of the report
            vcek_public_key.verify(
                signature_der,
                report.signed_data,
                ec.ECDSA(hashes.SHA384())
            )
            
            return True, "Report signature valid"
        
        except InvalidSignature:
            return False, "Report signature invalid - not signed by VCEK"
        except Exception as e:
            return False, f"Signature verification failed: {e}"
    
    def verify_report(
        self,
        report: SNPAttestationReport,
        expected_nonce: Optional[bytes] = None,
        expected_measurement: Optional[bytes] = None,
        require_debug_disabled: bool = True,
    ) -> Tuple[bool, list]:
        """
        Fully verify an attestation report.
        
        Args:
            report: Parsed SNP attestation report
            expected_nonce: Expected value in report_data (for freshness)
            expected_measurement: Expected launch measurement (for code identity)
            require_debug_disabled: Fail if debug mode is allowed
            
        Returns:
            (is_valid, list of issues/warnings)
        """
        issues = []
        
        # Verify certificate chain
        chain_valid, chain_msg = self.verify_cert_chain()
        if not chain_valid:
            issues.append(f"Certificate chain: {chain_msg}")
        
        # Verify report signature
        sig_valid, sig_msg = self.verify_report_signature(report)
        if not sig_valid:
            issues.append(f"Signature: {sig_msg}")
        
        # Verify nonce if provided
        if expected_nonce and not report.verify_nonce(expected_nonce):
            issues.append("Nonce mismatch - possible replay attack")
        
        # Verify measurement if provided
        if expected_measurement and report.measurement != expected_measurement:
            issues.append(f"Measurement mismatch - expected {expected_measurement.hex()}, got {report.measurement_hex()}")
        
        # Check security policy
        policy = report.get_policy_flags()
        if require_debug_disabled and policy['debug_allowed']:
            issues.append("Debug mode is allowed - VM memory may be inspectable")
        
        # Check version
        if report.version < 2:
            issues.append(f"Old report version: {report.version}")
        
        is_valid = len(issues) == 0
        return is_valid, issues


def check_snp_dependencies() -> Tuple[bool, list]:
    """Check if SNP verification dependencies are available"""
    missing = []
    if not CRYPTO_AVAILABLE:
        missing.append('cryptography')
    return len(missing) == 0, missing
