#!/bin/bash
set -e

echo "📱 Setting up 'happy' command for macOS..."
echo ""

BIN_DIR="$HOME/.local/bin"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Create bin directory
mkdir -p "$BIN_DIR"

# Create wrapper script
echo "Creating 'happy' command..."
cat > "$BIN_DIR/happy" <<EOF
#!/bin/bash
# Happy Phone CLI wrapper for macOS
cd "$REPO_DIR"
python3 -m happyphone "\$@"
EOF

chmod +x "$BIN_DIR/happy"

# Add to PATH if not already there
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo ""
    echo "Adding $BIN_DIR to PATH..."
    
    # For zsh (default on macOS)
    if [ -f "$HOME/.zshrc" ]; then
        echo "" >> "$HOME/.zshrc"
        echo "# Happy Phone CLI" >> "$HOME/.zshrc"
        echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$HOME/.zshrc"
        echo "✓ Added to ~/.zshrc"
        echo ""
        echo "Run: source ~/.zshrc"
        echo "Or open a new terminal"
    fi
fi

echo ""
echo "✅ 'happy' command installed!"
echo ""
echo "Usage:"
echo "  happy              Start Happy Phone CLI"
echo ""
echo "Location: $BIN_DIR/happy"
echo "Points to: $REPO_DIR"
echo ""
echo "Try it now:"
echo "  $BIN_DIR/happy"
echo ""
