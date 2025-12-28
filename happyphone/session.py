"""Double Ratchet session management for Perfect Forward Secrecy"""

from dataclasses import dataclass, field
from typing import Optional, Dict
import hashlib
import hmac

from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import RawEncoder
from nacl.utils import random as nacl_random


def hkdf(input_key_material: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF key derivation (RFC 5869) using SHA-256"""
    # Extract
    if not salt:
        salt = b'\x00' * 32
    prk = hmac.new(salt, input_key_material, hashlib.sha256).digest()
    
    # Expand
    okm = b''
    previous = b''
    counter = 1
    
    while len(okm) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        okm += previous
        counter += 1
    
    return okm[:length]


def kdf_rk(root_key: bytes, dh_output: bytes) -> tuple[bytes, bytes]:
    """
    KDF for root key chain.
    Returns: (new_root_key, new_chain_key)
    """
    output = hkdf(dh_output, root_key, b'RootKeyKDF', length=64)
    return output[:32], output[32:64]


def kdf_ck(chain_key: bytes) -> tuple[bytes, bytes]:
    """
    KDF for message key chain.
    Returns: (new_chain_key, message_key)
    """
    # Use HMAC for chain key advancement
    message_key = hmac.new(chain_key, b'\x01', hashlib.sha256).digest()
    new_chain_key = hmac.new(chain_key, b'\x02', hashlib.sha256).digest()
    return new_chain_key, message_key


@dataclass
class SessionState:
    """Double Ratchet session state"""
    # DH Ratchet state
    dh_self: PrivateKey  # Our current ratchet private key
    dh_remote: Optional[PublicKey]  # Their current ratchet public key
    
    # Root key
    root_key: bytes
    
    # Chain keys
    sending_chain_key: Optional[bytes]
    receiving_chain_key: Optional[bytes]
    
    # Message numbers
    sending_msg_num: int = 0
    receiving_msg_num: int = 0
    previous_sending_chain_length: int = 0
    
    # Skipped message keys (for out-of-order messages)
    skipped_message_keys: Dict[tuple[bytes, int], bytes] = field(default_factory=dict)
    
    # Maximum number of skipped message keys to store
    max_skip: int = 1000


class Session:
    """Double Ratchet session manager"""
    
    def __init__(self, state: SessionState):
        self.state = state
    
    @classmethod
    def initialize_alice(cls, shared_secret: bytes, bob_public_key: bytes) -> 'Session':
        """
        Initialize session as Alice (sender).
        Performs the initial DH ratchet step.
        """
        # Generate initial ratchet keypair
        dh_self = PrivateKey.generate()
        dh_remote = PublicKey(bob_public_key)
        
        # Derive root and chain keys from shared secret
        root_key = shared_secret
        
        # Perform initial DH ratchet
        dh_output = bytes(Box(dh_self, dh_remote).shared_key())
        root_key, sending_chain_key = kdf_rk(root_key, dh_output)
        
        state = SessionState(
            dh_self=dh_self,
            dh_remote=dh_remote,
            root_key=root_key,
            sending_chain_key=sending_chain_key,
            receiving_chain_key=None,
        )
        
        return cls(state)
    
    @classmethod
    def initialize_bob(cls, shared_secret: bytes, bob_private_key: bytes) -> 'Session':
        """
        Initialize session as Bob (receiver).
        Waits for Alice's first message to complete initialization.
        """
        # Bob uses his long-term identity key as initial ratchet key
        dh_self = PrivateKey(bob_private_key)
        
        state = SessionState(
            dh_self=dh_self,
            dh_remote=None,
            root_key=shared_secret,
            sending_chain_key=None,
            receiving_chain_key=None,
        )
        
        return cls(state)
    
    def ratchet_encrypt(self, plaintext: bytes) -> tuple[bytes, bytes, int, int]:
        """
        Encrypt a message, advancing the sending chain.
        Returns: (dh_public_key, ciphertext, message_number, previous_chain_length)
        """
        # Advance sending chain
        if self.state.sending_chain_key is None:
            raise RuntimeError("Cannot send: sending chain not initialized")
        
        self.state.sending_chain_key, message_key = kdf_ck(self.state.sending_chain_key)
        
        # Encrypt with message key (AES-256 in the actual implementation, simplified here)
        # For now, we'll use NaCl's SecretBox
        from nacl.secret import SecretBox
        box = SecretBox(message_key)
        ciphertext = box.encrypt(plaintext)
        
        # Get current message number and DH public key
        msg_num = self.state.sending_msg_num
        dh_public = bytes(self.state.dh_self.public_key)
        prev_chain_len = self.state.previous_sending_chain_length
        
        self.state.sending_msg_num += 1
        
        return dh_public, ciphertext, msg_num, prev_chain_len
    
    def ratchet_decrypt(self, dh_public_bytes: bytes, ciphertext: bytes, 
                       message_number: int, previous_chain_length: int) -> bytes:
        """
        Decrypt a message, advancing ratchets as needed.
        """
        dh_public = PublicKey(dh_public_bytes)
        
        # Check if we need to perform a DH ratchet step
        if self.state.dh_remote is None or bytes(self.state.dh_remote) != dh_public_bytes:
            self._dh_ratchet_decrypt(dh_public, previous_chain_length)
        
        # Check for skipped messages
        message_key = self._try_skipped_message_keys(dh_public_bytes, message_number)
        if message_key:
            from nacl.secret import SecretBox
            box = SecretBox(message_key)
            return box.decrypt(ciphertext)
        
        # Skip messages if needed
        if message_number > self.state.receiving_msg_num:
            self._skip_message_keys(message_number)
        
        # Advance receiving chain and decrypt
        if self.state.receiving_chain_key is None:
            raise RuntimeError("Cannot decrypt: receiving chain not initialized")
        
        self.state.receiving_chain_key, message_key = kdf_ck(self.state.receiving_chain_key)
        self.state.receiving_msg_num += 1
        
        from nacl.secret import SecretBox
        box = SecretBox(message_key)
        return box.decrypt(ciphertext)
    
    def _dh_ratchet_decrypt(self, dh_public: PublicKey, previous_chain_length: int):
        """Perform DH ratchet step when receiving a message with a new DH public key"""
        # Store skipped message keys from previous receiving chain
        if self.state.receiving_chain_key is not None:
            self._skip_message_keys(previous_chain_length)
        
        # Update DH remote key
        self.state.dh_remote = dh_public
        
        # Derive new receiving chain
        dh_output = bytes(Box(self.state.dh_self, dh_public).shared_key())
        self.state.root_key, self.state.receiving_chain_key = kdf_rk(
            self.state.root_key, dh_output
        )
        self.state.receiving_msg_num = 0
        
        # Perform DH ratchet to update sending chain
        self.state.previous_sending_chain_length = self.state.sending_msg_num
        self.state.dh_self = PrivateKey.generate()
        dh_output = bytes(Box(self.state.dh_self, dh_public).shared_key())
        self.state.root_key, self.state.sending_chain_key = kdf_rk(
            self.state.root_key, dh_output
        )
        self.state.sending_msg_num = 0
    
    def _skip_message_keys(self, until: int):
        """Store message keys for skipped messages"""
        if self.state.receiving_chain_key is None:
            return
        
        if self.state.receiving_msg_num + self.state.max_skip < until:
            raise RuntimeError("Too many skipped messages")
        
        if self.state.dh_remote is None:
            return
        
        while self.state.receiving_msg_num < until:
            self.state.receiving_chain_key, message_key = kdf_ck(self.state.receiving_chain_key)
            key_tuple = (bytes(self.state.dh_remote), self.state.receiving_msg_num)
            self.state.skipped_message_keys[key_tuple] = message_key
            self.state.receiving_msg_num += 1
    
    def _try_skipped_message_keys(self, dh_public: bytes, message_number: int) -> Optional[bytes]:
        """Try to find message key in skipped keys"""
        key_tuple = (dh_public, message_number)
        if key_tuple in self.state.skipped_message_keys:
            message_key = self.state.skipped_message_keys[key_tuple]
            del self.state.skipped_message_keys[key_tuple]
            return message_key
        return None
    
    def get_state_dict(self) -> dict:
        """Serialize session state for storage"""
        # Serialize skipped message keys
        skipped_keys_serialized = {
            f"{dh_public.hex()}:{msg_num}": key
            for (dh_public, msg_num), key in self.state.skipped_message_keys.items()
        }
        
        return {
            'dh_self_private': bytes(self.state.dh_self),
            'dh_remote_public': bytes(self.state.dh_remote) if self.state.dh_remote else None,
            'root_key': self.state.root_key,
            'sending_chain_key': self.state.sending_chain_key,
            'receiving_chain_key': self.state.receiving_chain_key,
            'sending_msg_num': self.state.sending_msg_num,
            'receiving_msg_num': self.state.receiving_msg_num,
            'previous_sending_chain_length': self.state.previous_sending_chain_length,
            'skipped_message_keys': skipped_keys_serialized,
        }
    
    @classmethod
    def from_state_dict(cls, data: dict) -> 'Session':
        """Deserialize session state from storage"""
        # Deserialize skipped message keys
        skipped_keys = {}
        if 'skipped_message_keys' in data:
            for key_str, message_key in data['skipped_message_keys'].items():
                dh_public_hex, msg_num_str = key_str.split(':', 1)
                dh_public = bytes.fromhex(dh_public_hex)
                msg_num = int(msg_num_str)
                skipped_keys[(dh_public, msg_num)] = message_key
        
        state = SessionState(
            dh_self=PrivateKey(data['dh_self_private']),
            dh_remote=PublicKey(data['dh_remote_public']) if data['dh_remote_public'] else None,
            root_key=data['root_key'],
            sending_chain_key=data['sending_chain_key'],
            receiving_chain_key=data['receiving_chain_key'],
            sending_msg_num=data['sending_msg_num'],
            receiving_msg_num=data['receiving_msg_num'],
            previous_sending_chain_length=data['previous_sending_chain_length'],
            skipped_message_keys=skipped_keys,
        )
        return cls(state)
