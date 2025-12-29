#!/bin/bash
set -e

echo "📦 Creating Happy Phone deployment package..."
echo ""

VERSION="0.1.0"
PACKAGE_NAME="happyphone-${VERSION}"
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

# Copy installation scripts
cp install-linux.sh "$PACKAGE_DIR/"
chmod +x "$PACKAGE_DIR/install-linux.sh"

# Create a quick start guide
cat > "$PACKAGE_DIR/INSTALL.txt" <<'EOF'
HAPPY PHONE - INSTALLATION INSTRUCTIONS
========================================

For Linux (Ubuntu/Debian):
--------------------------
1. Extract this package
2. cd into the directory
3. Run: bash install-linux.sh
4. Follow the prompts
5. Start with: happy

The installer will:
- Install system dependencies (portaudio, opus, vpx, srtp)
- Create a Python virtual environment
- Install Happy Phone and all Python dependencies
- Create a 'happy' command in ~/.local/bin/

First Run:
----------
When you first run 'happy', you'll create your identity.
Your User ID will be generated - share this with contacts.

Server Configuration:
--------------------
The client connects to: https://signal.happy.land

TURN Server (for voice calls through NAT):
- Server: turn:signal.happy.land:3478
- See TURN-CREDENTIALS.txt for username/password

To configure TURN, add to ~/.bashrc or ~/.zshrc:
  export HAPPYPHONE_TURN_SERVER=turn:signal.happy.land:3478
  export HAPPYPHONE_TURN_USER=happyphone
  export HAPPYPHONE_TURN_PASS=<see TURN-CREDENTIALS.txt>

Support:
--------
For issues, check:
- README.md for architecture and usage
- TESTING.md for testing procedures

Requirements:
-------------
- Linux (Ubuntu 20.04+, Debian 10+, or similar)
- Python 3.9+
- sudo access (for installing system packages)
- Internet connection
EOF

# Create tarball
echo "Creating tarball..."
cd dist
tar -czf "${PACKAGE_NAME}.tar.gz" "${PACKAGE_NAME}"
cd ..

# Create checksum
echo "Generating checksum..."
cd dist
sha256sum "${PACKAGE_NAME}.tar.gz" > "${PACKAGE_NAME}.tar.gz.sha256"
cd ..

echo ""
echo "✅ Package created successfully!"
echo ""
echo "Package: dist/${PACKAGE_NAME}.tar.gz"
echo "Size: $(du -h "dist/${PACKAGE_NAME}.tar.gz" | cut -f1)"
echo "SHA256: dist/${PACKAGE_NAME}.tar.gz.sha256"
echo ""
echo "To deploy to another Linux machine:"
echo "  1. Copy dist/${PACKAGE_NAME}.tar.gz to the target machine"
echo "  2. tar -xzf ${PACKAGE_NAME}.tar.gz"
echo "  3. cd ${PACKAGE_NAME}"
echo "  4. bash install-linux.sh"
echo ""
echo "Quick one-liner for deployment:"
echo "  scp dist/${PACKAGE_NAME}.tar.gz user@host:~ && \\"
echo "  ssh user@host 'tar -xzf ${PACKAGE_NAME}.tar.gz && cd ${PACKAGE_NAME} && bash install-linux.sh'"
echo ""
