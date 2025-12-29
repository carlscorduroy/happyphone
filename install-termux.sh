#!/data/data/com.termux/files/usr/bin/bash
set -e

echo "📱 Happy Phone - Termux Installation"
echo "====================================="
echo ""

# Update Termux packages
echo "Updating Termux packages..."
pkg update -y
pkg upgrade -y

# Install Python and dependencies
echo ""
echo "Installing Python and build tools..."
pkg install -y \
    python \
    python-pip \
    clang \
    make \
    pkg-config \
    libportaudio \
    openssl \
    libsodium \
    opus \
    libvpx \
    libsrtp

echo "✓ System packages installed"
echo ""

# Check Python version
PYTHON_VERSION=$(python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "✓ Python $PYTHON_VERSION found"
echo ""

# Install directory
INSTALL_DIR="$HOME/.local/happyphone"
BIN_DIR="$PREFIX/bin"

echo "Installing Happy Phone to: $INSTALL_DIR"
echo ""

# Create directories
mkdir -p "$INSTALL_DIR"

# Copy source files (these will be pushed via ADB)
if [ -d "happyphone" ]; then
    echo "Copying files..."
    cp -r happyphone "$INSTALL_DIR/"
    cp pyproject.toml "$INSTALL_DIR/"
    cp README.md "$INSTALL_DIR/" 2>/dev/null || true
else
    echo "⚠ Source files not found in current directory"
    echo "Make sure you're in the happyphone package directory"
    exit 1
fi

# Create virtual environment
echo "Creating Python virtual environment..."
cd "$INSTALL_DIR"
python -m venv venv

# Activate and install
echo "Installing Python dependencies..."
source venv/bin/activate
pip install --upgrade pip setuptools wheel

# Install the package
pip install -e .

echo "✓ Happy Phone installed"
echo ""

# Create wrapper script
echo "Creating 'happy' command..."
cat > "$BIN_DIR/happy" <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
# Happy Phone CLI wrapper for Termux
INSTALL_DIR="$HOME/.local/happyphone"
source "$INSTALL_DIR/venv/bin/activate"
python -m happyphone "$@"
EOF

chmod +x "$BIN_DIR/happy"

# Configure TURN server
echo ""
echo "Configuring TURN server..."
cat >> "$HOME/.bashrc" <<'EOF'

# Happy Phone configuration
export HAPPYPHONE_TURN_SERVER=turn:signal.happy.land:3478
export HAPPYPHONE_TURN_USER=happyphone
export HAPPYPHONE_TURN_PASS=4f775f64fce29c38c8659d87542845b6715ac1bee4706407f58cb9a921a4c6d8
EOF

echo ""
echo "✅ Installation complete!"
echo ""
echo "Usage:"
echo "  happy              Start Happy Phone CLI"
echo ""
echo "Configuration:"
echo "  Data directory: ~/.happyphone/"
echo "  Server: https://signal.happy.land"
echo "  TURN configured: Yes"
echo ""
echo "First run:"
echo "  source ~/.bashrc    # Load TURN configuration"
echo "  happy               # Start Happy Phone"
echo ""
echo "Note: For audio calls to work on Android, you may need to:"
echo "  - Grant microphone permissions to Termux"
echo "  - Use a headset or external mic"
echo ""
