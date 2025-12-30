#!/bin/bash
#
# Happy Phone - One-Line Installer for macOS/Linux
# Usage: curl -fsSL https://raw.githubusercontent.com/carlscorduroy/happyphone/main/install.sh | bash
#

set -e

echo ""
echo "📱 Installing Happy Phone..."
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found."
    echo "   macOS: It should be pre-installed. Try: xcode-select --install"
    echo "   Linux: sudo apt install python3 python3-pip python3-venv"
    exit 1
fi

INSTALL_DIR="$HOME/.happyphone-cli"
BIN_DIR="$HOME/.local/bin"

# Download
echo "⬇️  Downloading..."
rm -rf "$INSTALL_DIR"
if command -v git &> /dev/null; then
    git clone --quiet --depth 1 https://github.com/carlscorduroy/happyphone.git "$INSTALL_DIR"
else
    # Fallback: download zip
    curl -fsSL https://github.com/carlscorduroy/happyphone/archive/refs/heads/main.zip -o /tmp/happyphone.zip
    unzip -q /tmp/happyphone.zip -d /tmp
    mv /tmp/happyphone-main "$INSTALL_DIR"
    rm /tmp/happyphone.zip
fi

# Create venv and install
echo "📦 Installing..."
cd "$INSTALL_DIR"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip -q
pip install -e . -q
deactivate

# Create launcher
mkdir -p "$BIN_DIR"
cat > "$BIN_DIR/happy" << 'EOF'
#!/bin/bash
source "$HOME/.happyphone-cli/venv/bin/activate"
python3 -m happyphone "$@"
EOF
chmod +x "$BIN_DIR/happy"

# Add to PATH if needed
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    SHELL_RC="$HOME/.zshrc"
    [[ -f "$HOME/.bashrc" ]] && [[ ! -f "$HOME/.zshrc" ]] && SHELL_RC="$HOME/.bashrc"
    echo "" >> "$SHELL_RC"
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_RC"
    echo ""
    echo "✅ Installed! Run this to start:"
    echo ""
    echo "   source $SHELL_RC && happy"
    echo ""
else
    echo ""
    echo "✅ Installed! Run this to start:"
    echo ""
    echo "   happy"
    echo ""
fi
