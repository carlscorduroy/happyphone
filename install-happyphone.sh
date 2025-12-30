#!/bin/bash
#
# Happy Phone CLI - Universal Installer
# Works on: macOS, Linux (Debian/Ubuntu/Fedora), Termux (Android)
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${BLUE}"
    echo "  _    _                         ______ _                      "
    echo " | |  | |                       |  ____| |                     "
    echo " | |__| | __ _ _ __  _ __  _   _| |__  | |__   ___  _ __   ___ "
    echo " |  __  |/ _\` | '_ \| '_ \| | | |  __| | '_ \ / _ \| '_ \ / _ \\"
    echo " | |  | | (_| | |_) | |_) | |_| | |    | | | | (_) | | | |  __/"
    echo " |_|  |_|\__,_| .__/| .__/ \__, |_|    |_| |_|\___/|_| |_|\___|"
    echo "              | |   | |     __/ |                              "
    echo "              |_|   |_|    |___/   CLI Installer               "
    echo -e "${NC}"
}

info() { echo -e "${BLUE}ℹ${NC}  $1"; }
success() { echo -e "${GREEN}✓${NC}  $1"; }
warn() { echo -e "${YELLOW}⚠${NC}  $1"; }
error() { echo -e "${RED}✗${NC}  $1"; }

detect_os() {
    if [[ "$PREFIX" == *"com.termux"* ]]; then
        echo "termux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    elif [[ -f /etc/fedora-release ]]; then
        echo "fedora"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    else
        echo "unknown"
    fi
}

check_python() {
    if ! command -v python3 &> /dev/null; then
        error "Python 3 not found"
        return 1
    fi
    
    local version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    local major=$(echo $version | cut -d. -f1)
    local minor=$(echo $version | cut -d. -f2)
    
    if [[ $major -lt 3 ]] || [[ $major -eq 3 && $minor -lt 9 ]]; then
        error "Python 3.9+ required (found $version)"
        return 1
    fi
    
    success "Python $version"
    return 0
}

install_system_deps_macos() {
    if ! command -v brew &> /dev/null; then
        warn "Homebrew not found"
        echo "    Install from: https://brew.sh"
        echo "    Then re-run this script"
        return 1
    fi
    
    info "Installing system dependencies via Homebrew..."
    brew install portaudio opus libvpx 2>/dev/null || true
    success "System dependencies installed"
}

install_system_deps_debian() {
    info "Installing system dependencies (requires sudo)..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq \
        python3-pip python3-venv \
        portaudio19-dev \
        libopus-dev \
        libvpx-dev \
        libsrtp2-dev \
        pkg-config \
        build-essential
    success "System dependencies installed"
}

install_system_deps_fedora() {
    info "Installing system dependencies (requires sudo)..."
    sudo dnf install -y \
        python3-pip python3-virtualenv \
        portaudio-devel \
        opus-devel \
        libvpx-devel \
        libsrtp-devel \
        gcc gcc-c++
    success "System dependencies installed"
}

install_system_deps_termux() {
    info "Installing Termux dependencies..."
    pkg update -y
    pkg install -y python portaudio opus libvpx
    success "Termux dependencies installed"
}

install_happyphone() {
    local install_dir="$1"
    local with_voice="$2"
    
    info "Creating installation directory..."
    mkdir -p "$install_dir"
    
    # Copy source
    cp -r happyphone "$install_dir/"
    cp pyproject.toml "$install_dir/"
    cp README.md "$install_dir/" 2>/dev/null || true
    
    # Create venv
    info "Creating Python virtual environment..."
    python3 -m venv "$install_dir/venv"
    
    # Install
    info "Installing Happy Phone..."
    source "$install_dir/venv/bin/activate"
    pip install --upgrade pip setuptools wheel -q
    
    if [[ "$with_voice" == "yes" ]]; then
        # Install with voice support
        pip install -e "$install_dir" -q
        pip install pyaudio aiortc -q 2>/dev/null || warn "Voice packages failed (text will still work)"
    else
        # Install without voice (skip pyaudio/aiortc)
        pip install pynacl python-socketio[asyncio_client] aiohttp prompt-toolkit rich aiosqlite -q
        pip install -e "$install_dir" --no-deps -q
    fi
    
    deactivate
    success "Happy Phone installed"
}

create_launcher() {
    local install_dir="$1"
    local bin_dir="$2"
    
    mkdir -p "$bin_dir"
    
    cat > "$bin_dir/happy" << EOF
#!/bin/bash
# Happy Phone CLI launcher
source "$install_dir/venv/bin/activate"
python3 -m happyphone "\$@"
EOF
    
    chmod +x "$bin_dir/happy"
    success "Created 'happy' command"
}

add_to_path() {
    local bin_dir="$1"
    
    if [[ ":$PATH:" == *":$bin_dir:"* ]]; then
        return 0
    fi
    
    local shell_rc=""
    if [[ -n "$ZSH_VERSION" ]] || [[ "$SHELL" == *"zsh"* ]]; then
        shell_rc="$HOME/.zshrc"
    elif [[ -n "$BASH_VERSION" ]] || [[ "$SHELL" == *"bash"* ]]; then
        shell_rc="$HOME/.bashrc"
    else
        shell_rc="$HOME/.profile"
    fi
    
    echo "" >> "$shell_rc"
    echo "# Happy Phone CLI" >> "$shell_rc"
    echo "export PATH=\"$bin_dir:\$PATH\"" >> "$shell_rc"
    
    info "Added to $shell_rc"
    warn "Run: source $shell_rc (or open new terminal)"
}

# ============ Main ============

print_banner

OS=$(detect_os)
info "Detected: $OS"
echo ""

# Check Python
if ! check_python; then
    echo ""
    error "Please install Python 3.9+ and try again"
    exit 1
fi
echo ""

# Ask about voice support
echo -e "${YELLOW}Voice calls require additional system libraries (portaudio, opus).${NC}"
echo -e "${YELLOW}Text messaging works without them.${NC}"
echo ""
read -p "Install voice call support? [y/N] " -n 1 -r
echo ""
INSTALL_VOICE="no"
if [[ $REPLY =~ ^[Yy]$ ]]; then
    INSTALL_VOICE="yes"
fi
echo ""

# Install system dependencies for voice
if [[ "$INSTALL_VOICE" == "yes" ]]; then
    case "$OS" in
        macos)
            install_system_deps_macos || exit 1
            ;;
        debian)
            install_system_deps_debian || exit 1
            ;;
        fedora)
            install_system_deps_fedora || exit 1
            ;;
        termux)
            install_system_deps_termux || exit 1
            ;;
        *)
            warn "Unknown OS - skipping system deps"
            warn "You may need to install portaudio manually"
            ;;
    esac
    echo ""
fi

# Set install locations
if [[ "$OS" == "termux" ]]; then
    INSTALL_DIR="$HOME/.happyphone-cli"
    BIN_DIR="$HOME/.local/bin"
else
    INSTALL_DIR="$HOME/.local/happyphone"
    BIN_DIR="$HOME/.local/bin"
fi

# Install
install_happyphone "$INSTALL_DIR" "$INSTALL_VOICE"
echo ""

# Create launcher
create_launcher "$INSTALL_DIR" "$BIN_DIR"
echo ""

# Add to PATH
add_to_path "$BIN_DIR"
echo ""

# Done!
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  Installation complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo "  Start Happy Phone:"
echo -e "    ${BLUE}$BIN_DIR/happy${NC}"
echo ""
echo "  Or after restarting terminal:"
echo -e "    ${BLUE}happy${NC}"
echo ""
echo "  Data stored in: ~/.happyphone/"
echo ""
if [[ "$INSTALL_VOICE" == "no" ]]; then
    echo -e "  ${YELLOW}Note: Voice calls disabled (text-only mode)${NC}"
    echo "  Re-run installer with voice support to enable calls."
    echo ""
fi
