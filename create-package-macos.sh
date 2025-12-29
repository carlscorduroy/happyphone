#!/bin/bash
set -e

echo "📦 Creating Happy Phone deployment package for macOS..."
echo ""

VERSION="0.1.0"
PACKAGE_NAME="happyphone-macos-${VERSION}"
PACKAGE_DIR="dist/${PACKAGE_NAME}"

# Clean previous builds
rm -rf dist/
mkdir -p "$PACKAGE_DIR"

# Copy source files
echo "Copying source files..."
cp -r happyphone "$PACKAGE_DIR/"
cp pyproject.toml "$PACKAGE_DIR/"
cp README.md "$PACKAGE_DIR/"
cp TESTING.md "$PACKAGE_DIR/" 2>/dev/null || true
cp TURN-CREDENTIALS.txt "$PACKAGE_DIR/" 2>/dev/null || true

# Create macOS-specific installer
cat > "$PACKAGE_DIR/install-macos.sh" <<'INSTALL_EOF'
#!/bin/bash
set -e

echo "📱 Happy Phone - macOS Installer"
echo "=================================="
echo ""

# Check for Homebrew
if ! command -v brew &> /dev/null; then
    echo "❌ Homebrew is required but not installed."
    echo ""
    echo "Install Homebrew first:"
    echo "  /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
    echo ""
    exit 1
fi
echo "✓ Homebrew found"

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Installing via Homebrew..."
    brew install python@3.11
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "✓ Python $PYTHON_VERSION found"

# Check minimum Python version
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 9 ]); then
    echo "❌ Python 3.9+ required. Current version: $PYTHON_VERSION"
    echo "Install newer Python: brew install python@3.11"
    exit 1
fi

# Install system dependencies for audio
echo ""
echo "Installing system dependencies..."
echo "(This may take a few minutes on first install)"
brew install portaudio opus libvpx libsrtp

# Create virtual environment
echo ""
echo "Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip setuptools wheel

# Install Happy Phone
echo ""
echo "Installing Happy Phone..."
pip install -e .

# Create launch script in user bin
INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

cat > "$INSTALL_DIR/happy" <<'HAPPY_EOF'
#!/bin/bash
# Happy Phone launcher script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$HOME/.happyphone-env"

# Activate virtual environment
source "$VENV_DIR/bin/activate"

# Run Happy Phone
python3 -m happyphone "$@"
HAPPY_EOF

chmod +x "$INSTALL_DIR/happy"

# Move venv to permanent location
VENV_INSTALL_DIR="$HOME/.happyphone-env"
if [ -d "$VENV_INSTALL_DIR" ]; then
    echo "Removing old installation..."
    rm -rf "$VENV_INSTALL_DIR"
fi
mv venv "$VENV_INSTALL_DIR"

echo ""
echo "✅ Installation complete!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "To start Happy Phone, run:"
echo "  happy"
echo ""
echo "Make sure $INSTALL_DIR is in your PATH."
echo "Add this to your ~/.zshrc or ~/.bash_profile:"
echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
echo ""
echo "Then reload your shell:"
echo "  source ~/.zshrc"
echo ""
echo "Server Configuration:"
echo "  Signal server: https://signal.happy.land"
echo "  TURN server: turn:turn.happy.land:3478"
echo "  (See TURN-CREDENTIALS.txt for credentials)"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
INSTALL_EOF

chmod +x "$PACKAGE_DIR/install-macos.sh"

# Create installation instructions
cat > "$PACKAGE_DIR/INSTALL-MACOS.txt" <<'EOF'
HAPPY PHONE - macOS INSTALLATION
=================================

Quick Start:
------------
1. Extract this package
2. Open Terminal and cd to the extracted directory
3. Run: bash install-macos.sh
4. Add to PATH (follow the instructions printed by installer)
5. Start with: happy

Requirements:
-------------
- macOS 10.15 (Catalina) or later
- Homebrew package manager
- Python 3.9+ (installer will handle this)
- ~500MB disk space for dependencies

What the installer does:
------------------------
1. Checks for Homebrew (required)
2. Installs Python 3 (if needed)
3. Installs audio libraries: portaudio, opus, libvpx, libsrtp
4. Creates isolated Python virtual environment
5. Installs Happy Phone and all dependencies
6. Creates 'happy' command in ~/.local/bin/

First Run:
----------
When you first run 'happy', you'll:
1. Create your cryptographic identity
2. Get your User ID (share this with contacts to add you)
3. See the main interface

Adding Contacts:
----------------
1. Get their User ID (out-of-band, e.g., text message, email)
2. Run: add <nickname> <their_user_id> <tier>
   - tier can be: family, business, or other
3. Verify their fingerprint: verify <nickname>
4. Exchange and confirm keyphrase (optional but recommended)
5. Send messages: msg <nickname> Hello!

Server Configuration:
---------------------
Happy Phone connects to Azure-hosted servers:

Signal Server (for messaging):
  https://signal.happy.land
  
TURN Server (for voice calls through NAT):
  turn:turn.happy.land:3478
  Username: happyphone
  Password: (see TURN-CREDENTIALS.txt)

To configure TURN in your shell (~/.zshrc or ~/.bash_profile):
  export HAPPYPHONE_TURN_SERVER=turn:turn.happy.land:3478
  export HAPPYPHONE_TURN_USER=happyphone
  export HAPPYPHONE_TURN_PASS=<password from TURN-CREDENTIALS.txt>

Troubleshooting:
----------------
If 'happy' command not found:
  - Make sure ~/.local/bin is in your PATH
  - Add to ~/.zshrc: export PATH="$HOME/.local/bin:$PATH"
  - Reload: source ~/.zshrc

If audio libraries fail to install:
  - Make sure Homebrew is updated: brew update
  - Try installing manually: brew install portaudio opus libvpx

If Python errors:
  - Check Python version: python3 --version
  - Should be 3.9 or higher
  - Update if needed: brew upgrade python@3.11

Data Storage:
-------------
Your identity, contacts, and messages are stored in:
  ~/.happyphone/data.db

To run multiple accounts (e.g., for testing):
  export HAPPYPHONE_DATA_DIR=~/.happyphone-alt
  happy

Security Notes:
---------------
- Your private keys never leave your device
- Messages are end-to-end encrypted
- Server cannot read your messages (zero-knowledge relay)
- Always verify fingerprints with contacts via separate channel
- Use strong keyphrases (20+ characters)
- Enable FileVault (full disk encryption) on macOS

Commands Reference:
-------------------
  whoami              Show your user ID and fingerprint
  add <name> <id> <tier>  Add contact (tier: family/business/other)
  list                List all contacts
  verify <name>       Verify contact with fingerprint + keyphrase
  msg <name> <text>   Send encrypted message
  chat <name>         Enter chat mode with contact
  history <name>      View message history
  online <name>       Check if contact is online
  remove <name>       Remove contact
  reset               Delete identity and all data (careful!)
  exit                Quit application

For More Info:
--------------
- README.md: Full architecture and cryptographic details
- TESTING.md: Testing procedures
- Security questions: security@happy.land

Version: 0.1.0
EOF

# Create quick reference card
cat > "$PACKAGE_DIR/QUICK-START.txt" <<'EOF'
╔══════════════════════════════════════════════════════════╗
║          HAPPY PHONE - QUICK START GUIDE                 ║
╚══════════════════════════════════════════════════════════╝

INSTALLATION:
  bash install-macos.sh
  export PATH="$HOME/.local/bin:$PATH"  # Add to ~/.zshrc
  source ~/.zshrc

FIRST RUN:
  happy
  → Creates your identity and User ID

SHARE YOUR USER ID:
  You: whoami  → Copy your User ID
  Send to friend via text/email

ADD A CONTACT:
  add alice <alice_user_id> family
  verify alice  → Compare fingerprints, set keyphrase

SEND MESSAGE:
  msg alice Hello, this is encrypted!

CHAT MODE:
  chat alice  → Enter interactive chat

COMMON COMMANDS:
  whoami          Your ID and fingerprint
  list            Show all contacts
  verify <name>   Verify contact
  msg <name>      Send message
  chat <name>     Chat mode
  history <name>  View messages
  exit            Quit

SERVER INFO:
  Signal: https://signal.happy.land
  TURN: turn:turn.happy.land:3478

SECURITY:
  ✓ End-to-end encrypted
  ✓ Perfect forward secrecy
  ✓ Double Ratchet (Signal protocol)
  ✓ Server cannot read messages
  → Always verify fingerprints!
EOF

# Create tarball
echo "Creating tarball..."
cd dist
tar -czf "${PACKAGE_NAME}.tar.gz" "${PACKAGE_NAME}"
cd ..

# Create checksum
echo "Generating checksum..."
cd dist
shasum -a 256 "${PACKAGE_NAME}.tar.gz" > "${PACKAGE_NAME}.tar.gz.sha256"
cd ..

# Create DMG instructions (for future)
cat > "dist/CREATE-DMG.txt" <<'EOF'
To create a macOS DMG (optional, for easier distribution):

1. Install create-dmg:
   brew install create-dmg

2. Run:
   create-dmg \
     --volname "Happy Phone" \
     --window-pos 200 120 \
     --window-size 800 400 \
     --icon-size 100 \
     --app-drop-link 600 185 \
     happyphone-macos-0.1.0.dmg \
     happyphone-macos-0.1.0/

This creates a drag-and-drop installer.
EOF

echo ""
echo "✅ macOS package created successfully!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Package: dist/${PACKAGE_NAME}.tar.gz"
echo "Size: $(du -h "dist/${PACKAGE_NAME}.tar.gz" | cut -f1)"
echo "SHA256: dist/${PACKAGE_NAME}.tar.gz.sha256"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📤 TO SHARE WITH ANOTHER MAC USER:"
echo ""
echo "Option 1 - File Sharing:"
echo "  1. Send them: dist/${PACKAGE_NAME}.tar.gz"
echo "  2. They extract: tar -xzf ${PACKAGE_NAME}.tar.gz"
echo "  3. They install: cd ${PACKAGE_NAME} && bash install-macos.sh"
echo ""
echo "Option 2 - AirDrop:"
echo "  1. Right-click dist/${PACKAGE_NAME}.tar.gz"
echo "  2. Share → AirDrop"
echo "  3. Select their Mac"
echo ""
echo "Option 3 - Cloud:"
echo "  Upload to Dropbox/Google Drive/iCloud and share link"
echo ""
echo "Option 4 - Direct SSH:"
echo "  scp dist/${PACKAGE_NAME}.tar.gz user@theirhost:~/"
echo ""
echo "They'll need:"
echo "  ✓ macOS 10.15+"
echo "  ✓ Homebrew installed"
echo "  ✓ ~150MB free space (less if Homebrew already installed)"
echo "  ✓ Internet connection (for dependencies)"
echo ""
