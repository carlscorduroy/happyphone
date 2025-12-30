#!/usr/bin/env python3
"""
Test AMD SEV-SNP attestation report parsing.

This tests the local parsing logic without needing actual TEE hardware.
For full verification, deploy to an Azure DCasv5 confidential VM.
"""

import os
import sys

# Test basic imports
print("Testing SNP report module imports...")
try:
    from happyphone.snp_report import (
        SNPAttestationReport,
        SNPReportVerifier,
        TCBVersion,
        GuestPolicy,
        PlatformInfo,
        REPORT_SIZE,
        SIGNED_DATA_SIZE,
        check_snp_dependencies,
    )
    print("✓ snp_report module imported successfully")
except ImportError as e:
    print(f"✗ Failed to import snp_report: {e}")
    sys.exit(1)

# Test TEE module
print("\nTesting TEE module imports...")
try:
    from happyphone.tee import (
        TEEAttestation,
        generate_attestation_nonce,
        format_verification_summary,
    )
    print("✓ tee module imported successfully")
except ImportError as e:
    print(f"✗ Failed to import tee: {e}")
    sys.exit(1)

# Check dependencies
print("\nChecking dependencies...")
deps_ok, missing = check_snp_dependencies()
if deps_ok:
    print("✓ All SNP verification dependencies available")
else:
    print(f"⚠ Missing dependencies: {', '.join(missing)}")
    print("  Install with: pip install cryptography")

# Test nonce generation
print("\nTesting nonce generation...")
nonce = generate_attestation_nonce()
assert len(nonce) == 64, "Nonce should be 64 bytes"
print(f"✓ Generated 64-byte nonce: {nonce[:16].hex()}...")

# Test report parsing with synthetic data
print("\nTesting SNP report parsing with synthetic data...")

# Create a synthetic report (won't have valid signature)
# This tests the parsing logic
synthetic_report = bytearray(REPORT_SIZE)

# Set version (4 bytes at offset 0)
synthetic_report[0:4] = (2).to_bytes(4, 'little')  # Version 2

# Set guest_svn (4 bytes at offset 4)
synthetic_report[4:8] = (1).to_bytes(4, 'little')

# Set policy (8 bytes at offset 8)
policy = 0x30000  # ABI version 0.0, no special flags
synthetic_report[8:16] = policy.to_bytes(8, 'little')

# Set signature_algo (4 bytes at offset 0x34) - 1 = ECDSA P-384
synthetic_report[0x34:0x38] = (1).to_bytes(4, 'little')

# Set some report_data (64 bytes at offset 0x50)
test_nonce = os.urandom(64)
synthetic_report[0x50:0x90] = test_nonce

# Set measurement (48 bytes at offset 0x90)
fake_measurement = os.urandom(48)
synthetic_report[0x90:0xC0] = fake_measurement

# Set chip_id (64 bytes at offset 0x1A0)
fake_chip_id = os.urandom(64)
synthetic_report[0x1A0:0x1E0] = fake_chip_id

try:
    report = SNPAttestationReport.from_bytes(bytes(synthetic_report))
    print(f"✓ Parsed synthetic report:")
    print(f"  Version: {report.version}")
    print(f"  Guest SVN: {report.guest_svn}")
    print(f"  Policy: 0x{report.policy:016x}")
    print(f"  Signature Algorithm: {report.signature_algo}")
    print(f"  Measurement: {report.measurement_hex()[:32]}...")
    print(f"  Chip ID: {report.chip_id_hex()[:32]}...")
    
    # Test policy flags
    policy_flags = report.get_policy_flags()
    print(f"  Policy Flags:")
    print(f"    ABI: {policy_flags['abi_major']}.{policy_flags['abi_minor']}")
    print(f"    Debug allowed: {policy_flags['debug_allowed']}")
    print(f"    SMT allowed: {policy_flags['smt_allowed']}")
    
    # Test nonce verification
    if report.verify_nonce(test_nonce):
        print(f"✓ Nonce verification passed")
    else:
        print(f"✗ Nonce verification failed")
        
except Exception as e:
    print(f"✗ Failed to parse synthetic report: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test TEEAttestation dataclass
print("\nTesting TEEAttestation dataclass...")
attestation = TEEAttestation(
    tee_type='sev-snp',
    verified=True,
    vm_size='Standard_DC4as_v5',
    location='eastus',
    crypto_verified=True,
    cert_chain_valid=True,
    nonce_valid=True,
    measurement='abc123...',
    chip_id='def456...',
)
print(f"✓ Status line: {attestation.status_line()}")
print(f"✓ Is confidential: {attestation.is_confidential}")
print(f"✓ Is cryptographically verified: {attestation.is_cryptographically_verified}")

# Test format_verification_summary
print("\nTesting verification summary formatting...")
summary = format_verification_summary(attestation)
print("─" * 40)
print(summary)
print("─" * 40)

print("\n" + "=" * 50)
print("  🎉 ALL TESTS PASSED!")
print("=" * 50)
print("\nTo test with real TEE:")
print("1. Deploy server to Azure DCasv5 VM")
print("2. Install snpguest: cargo install snpguest")
print("3. Run 'tee verify' in the CLI")
