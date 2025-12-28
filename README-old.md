# Happy Phone CLI 📱🔐

End-to-end encrypted voice calls and messaging from the command line.

## Quick Install

```bash
# Clone or download the project
cd happyphone-cli

# Install (creates 'happyphone' command)
pip install -e .

# Or install dependencies manually
pip install pynacl python-socketio[asyncio_client] aiohttp prompt-toolkit rich aiosqlite

# For voice calls (optional, requires system audio libraries)
pip install pyaudio aiortc
```

### System Dependencies (for voice calls)

**macOS:**
```bash
brew install portaudio opus libvpx
```

**Ubuntu/Debian:**
```bash
sudo apt install portaudio19-dev python3-pyaudio libopus-dev libvpx-dev
```

**If you skip voice dependencies**, text messaging still works perfectly.

## Usage

```bash
# Run the CLI
happyphone

# Or run directly
python -m happyphone
```

### First Run

```
📱 Happy Phone
End-to-End Encrypted Communication

No identity found. Let's create one.

Enter your display name: Michael

✓ Identity created!
  Your ID: kx8m2p
  Fingerprint: 🔐 🦊 🌲 🎸 🚀 🌙 🎨 🦋

  Share your ID with contacts to connect.
```

### Commands

```
status                    Show connection status
id                        Show your user ID and fingerprint
contacts                  List all contacts
add <id> <phrase> [name]  Add contact with keyphrase verification
msg <name> <text>         Send encrypted message
history <name>            Show message history
call <name>               Start voice call
answer                    Answer incoming call
decline                   Decline incoming call
hangup                    End current call
delete <name>             Delete a contact
reset                     Delete identity and all data
quit                      Exit
```

## Adding a Contact

You and your friend need to:

1. **Exchange User IDs** (text, call, in person)
2. **Agree on a keyphrase** (any word you both know)
3. **Both run the add command around the same time:**

```bash
# You (ID: kx8m2p)
[kx8m2p]> add jd7h3k pizza Brother

# Your friend (ID: jd7h3k)
[jd7h3k]> add kx8m2p pizza Michael
```

Once both verify, you'll see:
```
✓ Contact verified and added: Brother
```

## Sending Messages

```bash
[kx8m2p]> msg Brother hey, are you there?
→ Brother: hey, are you there?

# When they reply, you'll see:
[Brother] ✓: yeah what's up
```

## Voice Calls

```bash
[kx8m2p]> call Brother
📞 Calling Brother...

# On their end:
📞 Incoming call from Michael ✓
Type 'answer' to accept or 'decline' to reject

[jd7h3k]> answer
📞 Call connected!

# To end:
[kx8m2p]> hangup
📞 Call ended
```

## Configuration

Set environment variables or edit `~/.happyphone/`:

```bash
# Use a different signaling server
export HAPPYPHONE_SIGNAL_URL="https://signal.happy.land"

# Configure TURN for voice calls through NAT
export HAPPYPHONE_TURN_SERVER="turn:turn.happy.land:3478"
export HAPPYPHONE_TURN_USER="happyphone"
export HAPPYPHONE_TURN_PASS="your_password"
```

## Data Storage

All data is stored locally in `~/.happyphone/`:

```
~/.happyphone/
└── data.db          # SQLite database (identity, contacts, messages)
```

Private keys never leave your device.

## Security

- **Encryption**: X25519 key exchange + XSalsa20-Poly1305 (via libsodium/PyNaCl)
- **Voice**: WebRTC with DTLS-SRTP
- **Verification**: Argon2id key derivation + HMAC challenge-response
- **Server sees**: Only encrypted blobs and metadata (who talks to whom, when)
- **Server cannot see**: Message content, voice audio, private keys

## Troubleshooting

### "Not connected to server"
```bash
# Check server is reachable
curl https://signal.happy.land/health
```

### Voice calls not working
```bash
# Check audio dependencies
[kx8m2p]> status
  Audio: Missing: pyaudio, aiortc

# Install them
pip install pyaudio aiortc
```

### Contact verification stuck
- Both users must run `add` within ~30 seconds
- Make sure keyphrases match exactly (case-insensitive)
- Both users must be online

### Reset everything
```bash
[kx8m2p]> reset
This will delete your identity and all contacts!
Type 'yes' to confirm: yes
✓ All data deleted.
```

Or manually:
```bash
rm -rf ~/.happyphone
```

## Project Structure

```
happyphone-cli/
├── happyphone/
│   ├── __init__.py
│   ├── __main__.py     # Entry point
│   ├── cli.py          # Main CLI interface
│   ├── config.py       # Configuration
│   ├── crypto.py       # Encryption (PyNaCl)
│   ├── signaling.py    # Socket.io client
│   ├── storage.py      # SQLite database
│   └── audio.py        # Voice calls (WebRTC)
├── pyproject.toml      # Package config
└── README.md
```

## Future: Local/Mesh Mode

The CLI is designed to easily switch from internet to local mode:

```bash
# Point to a Raspberry Pi running the signaling server
export HAPPYPHONE_SIGNAL_URL="http://192.168.4.1:3000"
```

See the main Happy Phone docs for drone/mesh deployment.

## License

MIT
