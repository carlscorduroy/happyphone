"""Cryptographic operations using PyNaCl (libsodium)"""

import secrets
import hashlib
from dataclasses import dataclass
from typing import Optional

from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import Base64Encoder, RawEncoder
from nacl.pwhash import argon2id
from nacl.hash import blake2b
from nacl.utils import random as nacl_random
from nacl.secret import SecretBox
import nacl.bindings

from .config import ARGON2_OPS_LIMIT, ARGON2_MEM_LIMIT

# Emoji set for fingerprints
FINGERPRINT_EMOJIS = [
    '🔐', '🦊', '🌲', '🎸', '🚀', '🌙', '🎨', '🦋',
    '🌺', '🎭', '🦉', '🌊', '🎪', '🦁', '🌴', '🎯',
    '🦄', '🌈', '🎵', '🦚', '🌻', '🎲', '🦩', '🌸',
    '🎡', '🦔', '🌵', '🎠', '🦜', '🌾', '🎢', '🦝'
]


@dataclass
class Identity:
    """User's cryptographic identity"""
    user_id: str
    public_key: bytes  # 32 bytes
    private_key: bytes  # 32 bytes
    display_name: str

    def public_key_b64(self) -> str:
        return Base64Encoder.encode(self.public_key).decode('ascii')

    def get_fingerprint(self) -> list[str]:
        """Get emoji fingerprint of public key"""
        return get_fingerprint(self.public_key)


@dataclass
class Contact:
    """A verified contact"""
    user_id: str
    public_key: bytes
    display_name: str
    pet_name: str
    trust_tier: str  # 'family', 'business', 'other'
    verified: bool

    def public_key_b64(self) -> str:
        return Base64Encoder.encode(self.public_key).decode('ascii')


@dataclass
class EncryptedPayload:
    """Encrypted message format (supports v1 ephemeral and v2 ratchet)"""
    ciphertext: bytes
    version: int = 1  # 1 = ephemeral, 2 = ratchet
    
    # Version 1 fields (ephemeral)
    ephemeral_public: Optional[bytes] = None
    nonce: Optional[bytes] = None
    
    # Version 2 fields (ratchet)
    dh_public_key: Optional[bytes] = None
    message_number: Optional[int] = None
    previous_chain_length: Optional[int] = None

    def to_dict(self) -> dict:
        result = {
            'version': self.version,
            'ciphertext': Base64Encoder.encode(self.ciphertext).decode('ascii'),
        }
        
        if self.version == 1:
            # Old ephemeral format
            result['ephemeralPublic'] = Base64Encoder.encode(self.ephemeral_public).decode('ascii')
            result['nonce'] = Base64Encoder.encode(self.nonce).decode('ascii')
        elif self.version == 2:
            # New ratchet format
            result['dhPublicKey'] = Base64Encoder.encode(self.dh_public_key).decode('ascii')
            result['messageNumber'] = self.message_number
            result['previousChainLength'] = self.previous_chain_length
        
        return result

    @classmethod
    def from_dict(cls, data: dict) -> 'EncryptedPayload':
        version = data.get('version', 1)  # Default to v1 for backward compat
        ciphertext = Base64Encoder.decode(data['ciphertext'].encode('ascii'))
        
        if version == 1:
            # Old ephemeral format
            return cls(
                version=1,
                ciphertext=ciphertext,
                ephemeral_public=Base64Encoder.decode(data['ephemeralPublic'].encode('ascii')),
                nonce=Base64Encoder.decode(data['nonce'].encode('ascii')),
            )
        elif version == 2:
            # New ratchet format
            return cls(
                version=2,
                ciphertext=ciphertext,
                dh_public_key=Base64Encoder.decode(data['dhPublicKey'].encode('ascii')),
                message_number=data['messageNumber'],
                previous_chain_length=data['previousChainLength'],
            )
        else:
            raise ValueError(f"Unsupported message version: {version}")


def generate_user_id() -> str:
    """Generate a short, memorable user ID"""
    chars = 'abcdefghjkmnpqrstuvwxyz23456789'  # No confusing chars
    return ''.join(secrets.choice(chars) for _ in range(6))


def create_identity(display_name: str) -> Identity:
    """Generate a new identity with keypair"""
    private_key = PrivateKey.generate()
    public_key = private_key.public_key

    return Identity(
        user_id=generate_user_id(),
        public_key=bytes(public_key),
        private_key=bytes(private_key),
        display_name=display_name,
    )


def get_fingerprint(public_key: bytes) -> list[str]:
    """Generate emoji fingerprint from public key"""
    hash_bytes = blake2b(public_key, digest_size=32, encoder=RawEncoder)
    emojis = []
    for i in range(8):
        idx = hash_bytes[i] % len(FINGERPRINT_EMOJIS)
        emojis.append(FINGERPRINT_EMOJIS[idx])
    return emojis


def get_shared_fingerprint(public_key1: bytes, public_key2: bytes) -> list[str]:
    """Generate shared fingerprint for two users (for call verification)"""
    # Sort keys to ensure same result regardless of order
    if public_key1 < public_key2:
        combined = public_key1 + public_key2
    else:
        combined = public_key2 + public_key1

    combined_hash = blake2b(combined, digest_size=32, encoder=RawEncoder)
    return get_fingerprint(combined_hash)


def encrypt_message(plaintext: str, recipient_public_key: bytes) -> EncryptedPayload:
    """Encrypt a message for a recipient using ephemeral keypair"""
    # Generate ephemeral keypair for forward secrecy
    ephemeral_private = PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key

    # Create box for encryption
    recipient_key = PublicKey(recipient_public_key)
    box = Box(ephemeral_private, recipient_key)

    # Encrypt
    plaintext_bytes = plaintext.encode('utf-8')
    encrypted = box.encrypt(plaintext_bytes)

    return EncryptedPayload(
        ephemeral_public=bytes(ephemeral_public),
        nonce=encrypted.nonce,
        ciphertext=encrypted.ciphertext,
    )


def decrypt_message(payload: EncryptedPayload, recipient_private_key: bytes) -> str:
    """Decrypt a message using recipient's private key"""
    private_key = PrivateKey(recipient_private_key)
    ephemeral_public = PublicKey(payload.ephemeral_public)

    box = Box(private_key, ephemeral_public)
    plaintext_bytes = box.decrypt(payload.ciphertext, payload.nonce)

    return plaintext_bytes.decode('utf-8')


def derive_key_from_keyphrase(keyphrase: str, salt: bytes) -> bytes:
    """Derive encryption key from keyphrase using Argon2id"""
    return argon2id.kdf(
        size=32,
        password=keyphrase.lower().strip().encode('utf-8'),
        salt=salt,
        opslimit=ARGON2_OPS_LIMIT,
        memlimit=ARGON2_MEM_LIMIT,
    )


def generate_challenge() -> tuple[bytes, bytes]:
    """Generate challenge and salt for keyphrase verification"""
    challenge = nacl_random(32)
    salt = nacl_random(16)  # Argon2 salt size
    return challenge, salt


def respond_to_challenge(challenge: bytes, salt: bytes, keyphrase: str) -> bytes:
    """Create HMAC response to challenge using derived key"""
    derived_key = derive_key_from_keyphrase(keyphrase, salt)
    # Use BLAKE2b as HMAC
    return blake2b(challenge, key=derived_key, digest_size=32, encoder=RawEncoder)


def verify_challenge(challenge: bytes, salt: bytes, response: bytes, keyphrase: str) -> bool:
    """Verify a challenge response"""
    expected = respond_to_challenge(challenge, salt, keyphrase)
    return secrets.compare_digest(expected, response)


def public_key_from_b64(b64_key: str) -> bytes:
    """Decode base64 public key"""
    return Base64Encoder.decode(b64_key.encode('ascii'))


def public_key_to_b64(public_key: bytes) -> str:
    """Encode public key to base64"""
    return Base64Encoder.encode(public_key).decode('ascii')


# === Double Ratchet Functions ===

def derive_shared_secret(our_private_key: bytes, their_public_key: bytes) -> bytes:
    """Derive initial shared secret from identity keys (for session initialization)"""
    private_key = PrivateKey(our_private_key)
    public_key = PublicKey(their_public_key)
    box = Box(private_key, public_key)
    return bytes(box.shared_key())


def encrypt_message_ratchet(
    plaintext: str,
    session_state: dict
) -> tuple[EncryptedPayload, dict]:
    """
    Encrypt a message using Double Ratchet.
    Returns: (encrypted_payload, updated_session_state)
    """
    from .session import Session
    
    # Load session
    session = Session.from_state_dict(session_state)
    
    # Encrypt and advance ratchet
    dh_public, ciphertext, msg_num, prev_chain_len = session.ratchet_encrypt(
        plaintext.encode('utf-8')
    )
    
    # Create payload
    payload = EncryptedPayload(
        version=2,
        ciphertext=ciphertext,
        dh_public_key=dh_public,
        message_number=msg_num,
        previous_chain_length=prev_chain_len,
    )
    
    # Return payload and updated state
    return payload, session.get_state_dict()


def decrypt_message_ratchet(
    payload: EncryptedPayload,
    session_state: dict
) -> tuple[str, dict]:
    """
    Decrypt a message using Double Ratchet.
    Returns: (plaintext, updated_session_state)
    """
    from .session import Session
    
    if payload.version != 2:
        raise ValueError("Not a ratchet message (wrong version)")
    
    # Load session
    session = Session.from_state_dict(session_state)
    
    # Decrypt and advance ratchet
    plaintext_bytes = session.ratchet_decrypt(
        payload.dh_public_key,
        payload.ciphertext,
        payload.message_number,
        payload.previous_chain_length,
    )
    
    # Return plaintext and updated state
    return plaintext_bytes.decode('utf-8'), session.get_state_dict()
