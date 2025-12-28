#!/bin/bash
# Happy Phone CLI - Install Helper

set -e

echo "📱 Happy Phone CLI Installer"
echo "============================"
echo

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
else
    OS="unknown"
fi

echo "Detected OS: $OS"
echo

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.9+"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "✓ Python $PYTHON_VERSION found"

# Install system dependencies for voice (optional)
echo
read -p "Install voice call dependencies? (requires sudo) [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if [[ "$OS" == "macos" ]]; then
        echo "Installing macOS dependencies via Homebrew..."
        if ! command -v brew &> /dev/null; then
            echo "❌ Homebrew not found. Install from https://brew.sh"
            exit 1
        fi
        brew install portaudio opus libvpx
    elif [[ "$OS" == "linux" ]]; then
        echo "Installing Linux dependencies..."
        sudo apt update
        sudo apt install -y portaudio19-dev python3-pyaudio libopus-dev libvpx-dev
    fi
    echo "✓ System dependencies installed"
fi

# Create virtual environment (optional but recommended)
echo
read -p "Create virtual environment? (recommended) [Y/n] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    python3 -m venv venv
    source venv/bin/activate
    echo "✓ Virtual environment created and activated"
fi

# Install Python package
echo
echo "Installing Happy Phone CLI..."
pip install -e .

# Install voice dependencies if system deps were installed
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Installing voice call packages..."
    pip install pyaudio aiortc || echo "⚠️ Voice packages failed (text messaging will still work)"
fi

echo
echo "✅ Installation complete!"
echo
echo "Run with: happyphone"
echo
echo "Or if using virtual environment:"
echo "  source venv/bin/activate"
echo "  happyphone"
