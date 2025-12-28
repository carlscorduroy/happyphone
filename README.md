# Happy Phone 📱

End-to-end encrypted communication platform with Perfect Forward Secrecy using Signal's Double Ratchet Algorithm.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Cryptographic Implementation](#cryptographic-implementation)
- [Storage Layer](#storage-layer)
- [Signaling Protocol](#signaling-protocol)
- [Azure Deployment](#azure-deployment)
- [Testing](#testing)
- [Installation](#installation)
- [Usage](#usage)
- [Roadmap](#roadmap)

---

## Overview

Happy Phone is a privacy-focused communication platform that provides:

- **End-to-End Encryption**: All messages encrypted on device, server cannot read content
- **Perfect Forward Secrecy**: Compromising current keys doesn't compromise past messages
- **Double Ratchet Algorithm**: Same protocol used by Signal, WhatsApp, and others
- **Minimal Trust Architecture**: Server only relays encrypted payloads
- **Future TEE Support**: Planned deployment on Azure Confidential Computing with AMD SEV-SNP

### Key Features

- Text messaging with Double Ratchet encryption
- Contact verification with emoji fingerprints
- Keyphrase-based mutual authentication
- Voice calling with WebRTC (planned)
- Out-of-order message handling
- Backward compatibility (v1 ephemeral, v2 ratchet)

---

## Architecture

```
┌─────────────────┐                  ┌──────────────────┐                  ┌─────────────────┐
│   Client A      │                  │  Signaling       │                  │   Client B      │
│                 │                  │  Server          │                  │                 │
│  ┌───────────┐  │   WebSocket     │                  │   WebSocket     │  ┌───────────┐  │
│  │ CLI/UI    │  │◄────────────────►│  Socket.IO       │◄────────────────►│  │ CLI/UI    │  │
│  └─────┬─────┘  │                  │  Relay Only      │                  │  └─────┬─────┘  │
│        │        │                  │                  │                  │        │        │
│  ┌─────▼─────┐  │                  │  - User Registry │                  │  ┌─────▼─────┐  │
│  │ Session   │  │                  │  - Routing       │                  │  │ Session   │  │
│  │ Manager   │  │                  │  - No Decryption │                  │  │ Manager   │  │
│  └─────┬─────┘  │                  └──────────────────┘                  │  └─────┬─────┘  │
│        │        │                                                         │        │        │
│  ┌─────▼─────┐  │                                                         │  ┌─────▼─────┐  │
│  │ Crypto    │  │     Encrypted Payload (Server Cannot Read)             │  │ Crypto    │  │
│  │ Engine    │  │─────────────────────────────────────────────────────────►│  │ Engine    │  │
│  └─────┬─────┘  │                                                         │  └─────┬─────┘  │
│        │        │                                                         │        │        │
│  ┌─────▼─────┐  │                                                         │  ┌─────▼─────┐  │
│  │ Storage   │  │                                                         │  │ Storage   │  │
│  │ (SQLite)  │  │                                                         │  │ (SQLite)  │  │
│  └───────────┘  │                                                         │  └───────────┘  │
└─────────────────┘                                                         └─────────────────┘
```

### Component Overview

#### Client Components

1. **CLI/UI Layer** (`cli.py`)
   - User interface using Rich and prompt_toolkit
   - Command parsing and routing
   - Interactive contact verification flow
   - Message display and history

2. **Session Manager** (`session.py`)
   - Double Ratchet state machine
   - Key derivation and chain management
   - Out-of-order message handling
   - Skipped message key storage

3. **Crypto Engine** (`crypto.py`)
   - Identity and key generation
   - Message encryption/decryption
   - Fingerprint generation
   - Keyphrase-based authentication

4. **Storage Layer** (`storage.py`)
   - Async SQLite database
   - Identity, contacts, messages
   - Session state persistence
   - Transaction management

5. **Signaling Client** (`signaling.py`)
   - Socket.IO WebSocket client
   - Event-driven message routing
   - Automatic reconnection
   - Online status tracking

#### Server Component

The signaling server is a simple relay that:
- Registers users by their user ID
- Routes encrypted payloads between clients
- Tracks online status
- **Cannot decrypt messages** (zero-knowledge server)
- Built with Node.js, Express, and Socket.IO

---

## Cryptographic Implementation

### Core Primitives

Happy Phone uses **libsodium** (via PyNaCl) for all cryptographic operations:

| Operation | Algorithm | Key Size |
|-----------|-----------|----------|
| Key Exchange | X25519 (ECDH) | 32 bytes |
| Symmetric Encryption | XSalsa20-Poly1305 | 32 bytes |
| Key Derivation | HKDF-SHA256 | 32 bytes |
| Hashing | BLAKE2b | 32 bytes |
| Password KDF | Argon2id | 32 bytes |

### Double Ratchet Protocol

Happy Phone implements the **Double Ratchet Algorithm** (Signal Protocol) for Perfect Forward Secrecy.

#### How It Works

The protocol uses two ratchets:

1. **DH Ratchet** (Diffie-Hellman Ratchet)
   - Generates new ephemeral key pairs with each message
   - Provides forward secrecy: past messages safe even if current key compromised
   - Advances on every message exchange direction change

2. **Symmetric Ratchet** (KDF Chain)
   - Derives new message keys from chain keys
   - One chain for sending, one for receiving
   - Advances with every message sent/received

#### Session Initialization

**Alice (Initiator):**
```python
# Step 1: Derive shared secret from identity keys
shared_secret = derive_shared_secret(alice_private, bob_public)

# Step 2: Generate initial ratchet keypair
alice_ratchet_private = PrivateKey.generate()

# Step 3: Perform initial DH ratchet
dh_output = DH(alice_ratchet_private, bob_public)
root_key, sending_chain_key = KDF_RK(shared_secret, dh_output)
```

**Bob (Receiver):**
```python
# Step 1: Wait for Alice's first message with her ratchet public key
# Step 2: Derive shared secret from identity keys
shared_secret = derive_shared_secret(bob_private, alice_public)

# Step 3: On first message, perform DH ratchet with Alice's key
dh_output = DH(bob_private, alice_ratchet_public)
root_key, receiving_chain_key = KDF_RK(shared_secret, dh_output)
```

#### Message Encryption

```python
def ratchet_encrypt(plaintext: bytes, session_state: SessionState):
    # Advance symmetric ratchet
    sending_chain_key, message_key = KDF_CK(sending_chain_key)
    
    # Encrypt with message key
    ciphertext = SecretBox(message_key).encrypt(plaintext)
    
    # Return ciphertext + current DH public key + message number
    return {
        'ciphertext': ciphertext,
        'dhPublicKey': dh_self.public_key,
        'messageNumber': sending_msg_num,
        'previousChainLength': previous_sending_chain_length
    }
```

#### Message Decryption

```python
def ratchet_decrypt(payload: dict, session_state: SessionState):
    # Check if sender's DH key changed (need to perform DH ratchet)
    if payload.dhPublicKey != dh_remote:
        # Store skipped message keys from old chain
        skip_message_keys(previous_chain_length)
        
        # Perform DH ratchet (receive)
        dh_output = DH(dh_self, payload.dhPublicKey)
        root_key, receiving_chain_key = KDF_RK(root_key, dh_output)
        
        # Perform DH ratchet (send)
        dh_self = PrivateKey.generate()
        dh_output = DH(dh_self, payload.dhPublicKey)
        root_key, sending_chain_key = KDF_RK(root_key, dh_output)
    
    # Check for out-of-order messages
    if (payload.dhPublicKey, payload.messageNumber) in skipped_keys:
        message_key = skipped_keys.pop((payload.dhPublicKey, payload.messageNumber))
        return SecretBox(message_key).decrypt(payload.ciphertext)
    
    # Skip messages if needed (store keys for later)
    while receiving_msg_num < payload.messageNumber:
        receiving_chain_key, skipped_key = KDF_CK(receiving_chain_key)
        skipped_keys[(payload.dhPublicKey, receiving_msg_num)] = skipped_key
        receiving_msg_num += 1
    
    # Decrypt current message
    receiving_chain_key, message_key = KDF_CK(receiving_chain_key)
    plaintext = SecretBox(message_key).decrypt(payload.ciphertext)
    
    return plaintext
```

### Key Derivation Functions

#### HKDF (HMAC-based KDF)

Used for root key derivation:
```python
def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    # Extract
    prk = HMAC-SHA256(salt, ikm)
    
    # Expand
    okm = HMAC-SHA256(prk, info || 0x01)
    return okm[:length]
```

#### KDF_RK (Root Key KDF)

Derives new root key and chain key from DH output:
```python
def kdf_rk(root_key: bytes, dh_output: bytes) -> (bytes, bytes):
    output = HKDF(dh_output, salt=root_key, info=b'RootKeyKDF', length=64)
    new_root_key = output[:32]
    new_chain_key = output[32:64]
    return new_root_key, new_chain_key
```

#### KDF_CK (Chain Key KDF)

Derives new chain key and message key:
```python
def kdf_ck(chain_key: bytes) -> (bytes, bytes):
    message_key = HMAC-SHA256(chain_key, 0x01)
    new_chain_key = HMAC-SHA256(chain_key, 0x02)
    return new_chain_key, message_key
```

### Contact Verification

Happy Phone uses **emoji fingerprints** and **keyphrase authentication**:

#### Emoji Fingerprints

```python
def get_fingerprint(public_key: bytes) -> list[str]:
    """Generate 8 emoji fingerprint from public key"""
    hash_bytes = BLAKE2b(public_key, digest_size=32)
    emojis = []
    for i in range(8):
        idx = hash_bytes[i] % 32  # 32 emoji set
        emojis.append(EMOJI_SET[idx])
    return emojis
```

Users verify each other's fingerprints match before trusting the contact.

#### Keyphrase Authentication

Challenge-response protocol to verify shared secret:

1. **Alice generates challenge:**
   ```python
   challenge = random(32)  # 32 random bytes
   salt = random(16)       # Argon2 salt
   ```

2. **Bob responds with HMAC:**
   ```python
   derived_key = Argon2id(keyphrase, salt)
   response = BLAKE2b(challenge, key=derived_key)
   ```

3. **Alice verifies:**
   ```python
   expected = BLAKE2b(challenge, key=Argon2id(keyphrase, salt))
   verified = constant_time_compare(response, expected)
   ```

### Backward Compatibility

The system supports two message formats:

- **Version 1**: Ephemeral encryption (no ratchet, forward secrecy per message)
- **Version 2**: Double Ratchet (full PFS with session state)

Messages include a `version` field that determines decryption method.

---

## Storage Layer

### Database Schema

Happy Phone uses SQLite with async operations (aiosqlite):

#### Identity Table
```sql
CREATE TABLE identity (
    user_id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,      -- Base64-encoded X25519 public key
    private_key TEXT NOT NULL,     -- Base64-encoded X25519 private key
    display_name TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### Contacts Table
```sql
CREATE TABLE contacts (
    user_id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    display_name TEXT NOT NULL,
    pet_name TEXT NOT NULL,        -- User's nickname for contact
    trust_tier TEXT DEFAULT 'other',
    verified INTEGER DEFAULT 0,    -- 0 = unverified, 1 = verified
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### Messages Table
```sql
CREATE TABLE messages (
    id TEXT PRIMARY KEY,
    contact_id TEXT NOT NULL,
    direction TEXT NOT NULL,       -- 'sent' or 'received'
    content TEXT NOT NULL,         -- Plaintext (already decrypted)
    timestamp INTEGER NOT NULL,    -- Unix timestamp in milliseconds
    status TEXT DEFAULT 'sent',    -- 'sent', 'delivered', 'read'
    FOREIGN KEY (contact_id) REFERENCES contacts(user_id)
);

CREATE INDEX idx_messages_contact ON messages(contact_id);
CREATE INDEX idx_messages_timestamp ON messages(timestamp);
```

#### Session State Table
```sql
CREATE TABLE session_state (
    contact_user_id TEXT PRIMARY KEY,
    root_key BLOB NOT NULL,
    sending_chain_key BLOB,
    receiving_chain_key BLOB,
    dh_self_private BLOB NOT NULL,
    dh_remote_public BLOB,
    sending_msg_num INTEGER DEFAULT 0,
    receiving_msg_num INTEGER DEFAULT 0,
    previous_sending_chain_length INTEGER DEFAULT 0,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (contact_user_id) REFERENCES contacts(user_id) ON DELETE CASCADE
);
```

### Data Directory

Default location: `~/.happyphone/`

```
~/.happyphone/
├── data.db          # SQLite database
└── logs/            # (future)
```

Environment variable override:
```bash
export HAPPYPHONE_DATA_DIR=~/.happyphone-alice
```

---

## Signaling Protocol

### Connection Flow

```
Client                              Server
  │                                   │
  ├──── connect() ──────────────────► │
  │                                   │
  │ ◄──── 'connected' event ─────────┤
  │                                   │
  ├──── emit('register', {           │
  │         userId,                   │
  │         publicKey,                │
  │         displayName               │
  │       }) ────────────────────────►│
  │                                   │
  │                                   ├── Store user in registry
  │                                   │
  │ ◄──── emit('registered') ─────────┤
  │                                   │
```

### Message Relay

```
Alice                               Server                               Bob
  │                                   │                                   │
  ├──── emit('message', {             │                                   │
  │         to: bob_user_id,          │                                   │
  │         payload: encrypted_json   │                                   │
  │       }) ────────────────────────►│                                   │
  │                                   │                                   │
  │                                   ├─── Lookup Bob's socket ───────────┤
  │                                   │                                   │
  │                                   ├──── emit('message', {             │
  │                                   │         from: alice_user_id,      │
  │                                   │         payload: encrypted_json   │
  │                                   │       }) ────────────────────────►│
  │                                   │                                   │
  │                                   │                             Decrypt & Display
```

### Server Cannot Decrypt

The server **never has access to**:
- User private keys (stored only on client)
- Message plaintext (encrypted before sending)
- Session state (client-side only)
- Shared secrets (derived locally)

The server **only knows**:
- User IDs (public identifiers)
- Public keys (already public)
- Encrypted payload blobs (opaque)
- Routing information (who to send to)

---

## Azure Deployment

### Current Status

**Production**: Regular Azure VM (NOT TEE)
- **VM Type**: Standard D2s v3 (2 vCPUs, 8GB RAM)
- **Region**: East US
- **IP**: 20.124.90.32
- **Domain**: signal.happy.land
- **SSL**: Let's Encrypt (auto-renewal enabled)
- **Server**: Node.js 20.19.6 with systemd service
- **Nginx**: Reverse proxy with WebSocket support

### Infrastructure

#### Network Security Group (NSG) Rules

| Rule | Port | Protocol | Purpose |
|------|------|----------|---------|
| SSH | 22 | TCP | Remote administration |
| HTTP | 80 | TCP | Let's Encrypt validation |
| HTTPS | 443 | TCP | Signaling server (WSS) |

#### Systemd Service

Location: `/etc/systemd/system/happyphone-signal.service`

```ini
[Unit]
Description=Happy Phone Signaling Server
After=network.target

[Service]
Type=simple
User=happyphone
WorkingDirectory=/home/happyphone/happyphone-signal
ExecStart=/usr/bin/node src/index.js
Restart=always
RestartSec=10
StandardOutput=append:/home/happyphone/happyphone-signal/server.log
StandardError=append:/home/happyphone/happyphone-signal/server.log
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
```

#### Nginx Configuration

Location: `/etc/nginx/sites-available/happyphone`

```nginx
server {
    listen 443 ssl http2;
    server_name signal.happy.land;

    ssl_certificate /etc/letsencrypt/live/signal.happy.land/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/signal.happy.land/privkey.pem;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /socket.io/ {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

### Planned: Azure Confidential Computing with TEE

**Target**: Trusted Execution Environment with hardware attestation

#### VM Specifications (Pending Quota Approval)

- **VM Type**: Standard_DC4as_v5 (DCASv5 Family)
- **TEE**: AMD SEV-SNP (Secure Encrypted Virtualization)
- **vCPUs**: 4
- **Memory**: 16GB RAM
- **Features**:
  - Memory encryption at hardware level
  - CPU-based attestation
  - Protection from cloud provider access
  - Secure boot with measured boot

#### TEE Architecture

```
┌────────────────────────────────────────┐
│  Azure Confidential VM                  │
│  ┌──────────────────────────────────┐  │
│  │  Encrypted Memory (SEV-SNP)      │  │
│  │  ┌────────────────────────────┐  │  │
│  │  │  Happy Phone Server        │  │  │
│  │  │  - Node.js Process         │  │  │
│  │  │  - Signaling Logic         │  │  │
│  │  │  - Attestation Endpoint    │  │  │
│  │  └────────────────────────────┘  │  │
│  │                                  │  │
│  │  Attestation:                    │  │
│  │  - CPU signs report              │  │
│  │  - Proves code + config          │  │
│  │  - Verifiable by clients         │  │
│  └──────────────────────────────────┘  │
│                                         │
│  Hardware: AMD EPYC (Milan/Genoa)      │
└────────────────────────────────────────┘
```

#### Attestation Flow (Planned)

1. **Server generates attestation report**
   - AMD SEV-SNP hardware signs measurement
   - Report includes: code hash, memory state, configuration
   
2. **Client requests attestation**
   ```javascript
   GET /attestation
   
   Response:
   {
     "report": "<hardware-signed attestation>",
     "signature": "<AMD signature>",
     "measurements": {
       "codeHash": "sha256...",
       "configHash": "sha256..."
     }
   }
   ```

3. **Client verifies attestation**
   - Check AMD signature (proves running in TEE)
   - Verify code hash matches expected server
   - Verify configuration is secure
   - Only connect if attestation valid

#### Benefits of TEE Deployment

| Threat | Current Protection | With TEE |
|--------|-------------------|----------|
| Network eavesdropping | ✅ TLS encryption | ✅ TLS encryption |
| Malicious server operator | ❌ Can access memory | ✅ Memory encrypted |
| Cloud provider access | ❌ Can inspect VM | ✅ Cannot access memory |
| Code tampering | ❌ No verification | ✅ Attestation proves code |
| Configuration changes | ❌ No detection | ✅ Measurement includes config |

**Note**: Even without TEE, the server cannot decrypt messages due to end-to-end encryption. TEE adds protection against server-side memory inspection and proves server integrity.

#### Migration Plan

Once quota approved:

1. Provision Standard_DC4as_v5 VM
2. Configure AMD SEV-SNP
3. Deploy server code
4. Add attestation endpoint
5. Update DNS to point to new IP
6. Update clients to verify attestation
7. Decommission old VM

---

## Testing

### Unit Tests

**Double Ratchet Tests** (`test_ratchet.py`):

```bash
python test_ratchet.py
```

Tests:
- Session initialization (Alice and Bob)
- Basic message exchange
- Out-of-order message handling
- Skipped message key management
- Session state persistence

### Integration Testing

#### Two-Client Test (Local)

Terminal 1 (Alice):
```bash
python -m happyphone
```

Terminal 2 (Bob):
```bash
HAPPYPHONE_DATA_DIR=~/.happyphone-bob python -m happyphone
```

**Test Flow:**

1. Both terminals create identities (if first run)
2. Exchange user IDs out-of-band
3. Alice adds Bob: `add bob <bob_user_id> business`
4. Bob adds Alice: `add alice <alice_user_id> family`
5. Both verify fingerprints: `verify <name>`
6. Exchange and confirm keyphrase
7. Send messages: `msg <name> Hello!`
8. Check ratchet state:
   ```bash
   sqlite3 ~/.happyphone/data.db "SELECT contact_user_id, sending_msg_num, receiving_msg_num FROM session_state"
   ```

#### Server Health Check

```bash
curl https://signal.happy.land/health
```

Expected response:
```json
{
  "status": "ok",
  "users": 0,
  "timestamp": "2025-12-28T02:00:00.000Z"
}
```

### Message Counter Verification

Verify the Double Ratchet is advancing:

```bash
# Alice's perspective
sqlite3 ~/.happyphone/data.db "SELECT contact_user_id, sending_msg_num, receiving_msg_num FROM session_state"

# Bob's perspective
sqlite3 ~/.happyphone-bob/data.db "SELECT contact_user_id, sending_msg_num, receiving_msg_num FROM session_state"
```

Expected:
- `sending_msg_num` increments each time you send a message
- `receiving_msg_num` increments each time you receive a message
- Counters are independent per direction

---

## Installation

### Client Installation

#### Requirements

- Python 3.10+
- pip
- SQLite (usually pre-installed)

#### Install Dependencies

```bash
cd happyphone-cli
pip install -r requirements.txt
```

#### Run

```bash
python -m happyphone
```

### Server Installation (Azure VM)

#### Requirements

- Ubuntu 24.04 LTS
- Node.js 20+
- Nginx
- Certbot (Let's Encrypt)

#### Setup Script

```bash
# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Clone server code
git clone <server-repo> ~/happyphone-signal
cd ~/happyphone-signal
npm install

# Install nginx
sudo apt-get install -y nginx

# Install certbot
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot

# Configure nginx (see nginx config above)
sudo nano /etc/nginx/sites-available/happyphone
sudo ln -s /etc/nginx/sites-available/happyphone /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# Get SSL certificate
sudo certbot --nginx -d signal.happy.land

# Create systemd service (see service file above)
sudo nano /etc/systemd/system/happyphone-signal.service
sudo systemctl daemon-reload
sudo systemctl enable happyphone-signal
sudo systemctl start happyphone-signal
```

---

## Usage

### CLI Commands

| Command | Description |
|---------|-------------|
| `whoami` | Show your user ID and fingerprint |
| `add <name> <user_id> <tier>` | Add contact (tier: family/business/other) |
| `list` | List all contacts |
| `verify <name>` | Verify contact with fingerprint + keyphrase |
| `msg <name> <message>` | Send encrypted message |
| `chat <name>` | Enter chat mode with contact |
| `history <name>` | View message history |
| `call <name>` | Start voice call (experimental) |
| `online <name>` | Check if contact is online |
| `remove <name>` | Remove contact |
| `reset` | Delete identity and all data |
| `exit` | Quit application |

### Configuration

Environment variables:

```bash
# Signaling server URL
export HAPPYPHONE_SIGNAL_URL=https://signal.happy.land

# Data directory
export HAPPYPHONE_DATA_DIR=~/.happyphone

# TURN server (for WebRTC calls)
export HAPPYPHONE_TURN_SERVER=turn:turn.happy.land:3478
export HAPPYPHONE_TURN_USER=happyphone
export HAPPYPHONE_TURN_PASS=<password>
```

---

## Roadmap

### Completed ✅

- [x] End-to-end encryption with X25519 + XSalsa20-Poly1305
- [x] Double Ratchet algorithm implementation
- [x] Perfect Forward Secrecy
- [x] Contact verification (fingerprints + keyphrase)
- [x] Out-of-order message handling
- [x] Session state persistence
- [x] Signaling server relay
- [x] Azure VM deployment with SSL
- [x] CLI interface

### In Progress 🚧

- [ ] Azure Confidential Computing migration (quota pending)
- [ ] TEE attestation endpoint
- [ ] Client-side attestation verification

### Planned 🎯

#### Security
- [ ] Post-quantum cryptography (Kyber + Dilithium)
- [ ] Sealed sender (hide metadata)
- [ ] Padding to prevent traffic analysis
- [ ] Automatic key rotation policies
- [ ] Multi-device support with session syncing

#### Features
- [ ] Group messaging (multi-party Double Ratchet)
- [ ] File transfer with progressive encryption
- [ ] Voice calls (WebRTC integration)
- [ ] Video calls
- [ ] Screen sharing
- [ ] Message reactions and editing
- [ ] Read receipts (optional)
- [ ] Push notifications

#### Infrastructure
- [ ] TURN server for NAT traversal
- [ ] Geographic server distribution
- [ ] Load balancing
- [ ] Monitoring and alerting
- [ ] Automatic backups

#### Clients
- [ ] Web client (React)
- [ ] Mobile apps (React Native)
- [ ] Desktop apps (Electron)
- [ ] Browser extension

#### Compliance & Audits
- [ ] Security audit by third party
- [ ] GDPR compliance documentation
- [ ] Formal cryptographic verification
- [ ] Pen testing

---

## Security Considerations

### Threat Model

**What Happy Phone protects against:**
- ✅ Network eavesdropping (TLS + E2EE)
- ✅ Server compromise (messages encrypted)
- ✅ Retrospective decryption (Perfect Forward Secrecy)
- ✅ Man-in-the-middle (fingerprint verification)
- ✅ Message replay attacks (message counters)

**What Happy Phone does NOT protect against (yet):**
- ❌ Client device compromise (malware, keyloggers)
- ❌ Traffic analysis (message timing/size)
- ❌ Metadata leakage (who talks to whom)
- ❌ Social engineering attacks
- ❌ Physical device access

### Known Limitations

1. **Skipped message keys not persisted**: Out-of-order keys stored in memory only. Database restart loses them (low risk, rare scenario).

2. **No sealed sender**: Server knows who sends to whom (metadata), but not message content.

3. **Real-time UI updates**: prompt_toolkit limitations prevent live message display without checking history.

4. **No message deletion**: Old messages remain in SQLite. Future: add expiration policies.

5. **Single device**: Each device has separate identity. Multi-device support requires session syncing protocol.

### Best Practices

- **Verify fingerprints**: Always verify emoji fingerprints with contacts through a separate channel (phone call, in person).
- **Use strong keyphrases**: Keyphrase should be 20+ characters, high entropy.
- **Secure your device**: Full disk encryption, strong password, auto-lock.
- **Update regularly**: Keep client and dependencies up to date.
- **Don't share keys**: Never export or send your private key.

---

## License

MIT License (or specify your license)

---

## Contributing

Contributions welcome! Areas needing help:
- Security audits and reviews
- Post-quantum cryptography integration
- Mobile client development
- Documentation improvements
- Testing and QA

---

## Credits

- **Cryptography**: libsodium (NaCl)
- **Double Ratchet**: Signal Protocol specification
- **Python libraries**: PyNaCl, aiosqlite, socketio, Rich
- **Infrastructure**: Azure, Let's Encrypt, Nginx

---

## Contact

For security issues: security@happy.land (create this)
For general inquiries: hello@happy.land

**Remember: The best security is layered security. Use Happy Phone as part of a comprehensive privacy strategy.**
