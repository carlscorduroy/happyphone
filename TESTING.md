# Testing Double Ratchet Implementation

## Overview
The Happy Phone CLI now implements Signal's Double Ratchet algorithm for Perfect Forward Secrecy. This document explains how to test the implementation.

## What is Double Ratchet?
The Double Ratchet provides:
- **Forward Secrecy**: Past messages remain secure even if current keys are compromised
- **Future Secrecy**: Future messages are secure after key compromise
- **Unique Message Keys**: Each message encrypted with a different key
- **Out-of-Order Support**: Messages can arrive in any order

## Testing Setup

### Prerequisites
```bash
# Install dependencies
pip install aiosqlite websockets python-socketio aiohttp PyNaCl prompt-toolkit rich
```

### Running Two Test Instances

You need two separate terminals with different identities to test messaging.

**Terminal 1 - Alice (Default Instance):**
```bash
cd /Users/mikee/projects/happyphone-cli
python -m happyphone.cli
```
- Uses data directory: `~/.happyphone`
- Creates identity "Alice" with unique user ID

**Terminal 2 - Bob (Separate Instance):**
```bash
cd /Users/mikee/projects/happyphone-cli
HAPPYPHONE_DATA_DIR=~/.happyphone-bob python -m happyphone.cli
```
- Uses data directory: `~/.happyphone-bob`
- Creates identity "Bob" with different user ID

**IMPORTANT:** Both terminals must use different data directories or they'll share the same identity!

## Testing Procedure

### 1. Get User IDs
In each terminal, run:
```
id
```
Note down each user ID (e.g., `7mjftu`, `bvzst4`).

### 2. Add Contacts with Keyphrase Verification

**Terminal 1 (Alice):**
```
add <bob_user_id> christmas Bob
```

**Terminal 2 (Bob) - wait for notification, then:**
```
add <alice_user_id> christmas Alice
```

You should see:
```
✓ Contact verified and added: <name>
```

### 3. Send Messages

**Terminal 1:**
```
msg Bob Hello with Double Ratchet!
```

**Terminal 2:**
```
msg Alice Hi back with PFS!
```

### 4. Verify Double Ratchet is Working

Check message history in either terminal:
```
history <contact_name>
```

Check the ratchet state in the database:

**Alice's database:**
```bash
sqlite3 ~/.happyphone/data.db "SELECT contact_user_id, sending_msg_num, receiving_msg_num FROM session_state"
```

**Bob's database:**
```bash
sqlite3 ~/.happyphone-bob/data.db "SELECT contact_user_id, sending_msg_num, receiving_msg_num FROM session_state"
```

Expected output:
```
alice_contact|3|2
bob_contact|2|3
```

The incrementing message numbers prove:
- Each message uses a unique key
- The ratchet is advancing properly
- Perfect Forward Secrecy is active

## Verifying Security Properties

### 1. Forward Secrecy Test
Send several messages, then check that each has a different message number:
```bash
sqlite3 ~/.happyphone/data.db "SELECT contact_user_id, sending_msg_num FROM session_state"
```
Each sent message increments the counter, proving unique keys.

### 2. Out-of-Order Messages
The implementation handles messages arriving out of order by storing skipped message keys. This is automatic and tested in `test_ratchet.py`.

### 3. Session Persistence
- Send messages
- Quit both CLIs
- Restart both CLIs
- Send more messages

The message numbers should continue incrementing from where they left off, proving session state persists correctly.

## Known Limitations

### Real-Time Message Display
Messages don't appear in real-time in the terminal due to prompt_toolkit limitations. Instead:
- Sent messages show immediately: `→ contact: message`
- Received messages are saved to history
- Use `history <contact>` to view received messages

This is an acceptable limitation for a CLI application.

### Audio Calls
Audio functionality requires additional dependencies:
```bash
pip install pyaudio aiortc
```
Voice calls use WebRTC but do NOT use Double Ratchet (they use DTLS-SRTP instead).

## Troubleshooting

### "Contact not found"
- Check contacts are added: `contacts`
- Verify you're using the correct contact name (case-insensitive)
- Restart CLI to reload contacts from database

### "Cannot send: sending chain not initialized"
- The session isn't ready yet
- Messages will fallback to ephemeral encryption (v1)
- After first exchange, Double Ratchet (v2) will activate

### "Failed to decrypt"
- May occur with old messages sent before session was initialized
- New messages should decrypt correctly
- Check `history` to see if subsequent messages work

### Both terminals have same ID
- Make sure Terminal 2 uses different data directory:
  ```bash
  HAPPYPHONE_DATA_DIR=~/.happyphone-bob python -m happyphone.cli
  ```

## Test Script

Run the automated test suite:
```bash
python test_ratchet.py
```

This tests:
- Basic message exchange
- DH ratchet advancement
- Multiple consecutive messages
- Out-of-order message delivery
- Session serialization

Expected output:
```
=== Testing Double Ratchet Basic Exchange ===
✓ All tests passed!

=== Testing Out-of-Order Message Delivery ===
✓ Out-of-order delivery works!

🎉 All Double Ratchet tests passed!
```

## Architecture

### Key Files
- `happyphone/session.py` - Core Double Ratchet logic
- `happyphone/crypto.py` - High-level encryption/decryption functions
- `happyphone/storage.py` - Session state persistence
- `happyphone/cli.py` - Integration into message flows
- `test_ratchet.py` - Automated test suite

### Message Flow
1. **Contact Added**: Session initialized with shared secret
2. **Send Message**: 
   - Load session state from DB
   - Encrypt with ratchet (advances sending chain)
   - Save updated session state
   - Send encrypted payload over signaling server
3. **Receive Message**:
   - Load session state from DB
   - Decrypt with ratchet (advances receiving chain, may perform DH ratchet)
   - Save updated session state
   - Store message in history

### Backward Compatibility
- v1 messages (ephemeral encryption) still supported
- v2 messages (Double Ratchet) automatically used when session exists
- Graceful fallback if session not ready

## Success Criteria

✅ Messages encrypt and send successfully
✅ Messages decrypt and save to history
✅ Session state persists across restarts
✅ Message counters increment with each message
✅ Both directions work (Alice→Bob and Bob→Alice)
✅ Out-of-order messages handled correctly
✅ Backward compatible with old ephemeral encryption

## Cleanup

To reset and start fresh:
```bash
rm -rf ~/.happyphone ~/.happyphone-bob
```

Then restart both CLIs to create new identities.
