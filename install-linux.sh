#!/bin/bash
set -e

echo "📱 Happy Phone - Linux Installation"
echo "===================================="
echo ""

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "❌ This script is for Linux only"
    echo "For macOS, use: install.sh"
    exit 1
fi

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Installing..."
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip python3-venv
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "✓ Python $PYTHON_VERSION found"
echo ""

# Install system dependencies for audio
echo "Installing system dependencies..."
sudo apt-get update
sudo apt-get install -y \
    portaudio19-dev \
    python3-pyaudio \
    libopus-dev \
    libvpx-dev \
    libsrtp2-dev \
    pkg-config \
    build-essential

echo "✓ System dependencies installed"
echo ""

# Determine installation directory
INSTALL_DIR="$HOME/.local/happyphone"
BIN_DIR="$HOME/.local/bin"

echo "Installing Happy Phone to: $INSTALL_DIR"
echo ""

# Create directories
mkdir -p "$INSTALL_DIR"
mkdir -p "$BIN_DIR"

# Copy source files
echo "Copying files..."
cp -r happyphone "$INSTALL_DIR/"
cp pyproject.toml "$INSTALL_DIR/"
cp README.md "$INSTALL_DIR/" 2>/dev/null || true

# Create virtual environment
echo "Creating Python virtual environment..."
cd "$INSTALL_DIR"
python3 -m venv venv

# Activate and install
echo "Installing Python dependencies..."
source venv/bin/activate
pip install --upgrade pip setuptools wheel

# Install the package in editable mode
pip install -e .

echo "✓ Happy Phone installed"
echo ""

# Create wrapper script
echo "Creating 'happy' command..."
cat > "$BIN_DIR/happy" <<'EOF'
#!/bin/bash
# Happy Phone CLI wrapper
INSTALL_DIR="$HOME/.local/happyphone"
source "$INSTALL_DIR/venv/bin/activate"
python3 -m happyphone "$@"
EOF

chmod +x "$BIN_DIR/happy"

# Add to PATH if not already there
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo ""
    echo "Adding $BIN_DIR to PATH..."
    
    # Detect shell
    if [ -n "$BASH_VERSION" ]; then
        SHELL_RC="$HOME/.bashrc"
    elif [ -n "$ZSH_VERSION" ]; then
        SHELL_RC="$HOME/.zshrc"
    else
        SHELL_RC="$HOME/.profile"
    fi
    
    echo "" >> "$SHELL_RC"
    echo "# Happy Phone CLI" >> "$SHELL_RC"
    echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$SHELL_RC"
    
    echo "✓ Added to $SHELL_RC"
    echo ""
    echo "Run: source $SHELL_RC"
    echo "Or open a new terminal for PATH to take effect"
fi

echo ""
echo "✅ Installation complete!"
echo ""
echo "Usage:"
echo "  happy              Start Happy Phone CLI"
echo "  happy --help       Show help"
echo ""
echo "Configuration:"
echo "  Data directory: ~/.happyphone/"
echo "  Server: https://signal.happy.land"
echo ""
echo "Environment variables (optional):"
echo "  HAPPYPHONE_SIGNAL_URL     Custom signaling server"
echo "  HAPPYPHONE_DATA_DIR       Custom data directory"
echo "  HAPPYPHONE_TURN_SERVER    TURN server for calls"
echo "  HAPPYPHONE_TURN_USER      TURN username"
echo "  HAPPYPHONE_TURN_PASS      TURN password"
echo ""
echo "Try it now:"
echo "  $BIN_DIR/happy"
echo ""
