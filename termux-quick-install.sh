#!/data/data/com.termux/files/usr/bin/bash
# Quick install script for Happy Phone on Termux
# Usage: Just paste this entire file into Termux

set -e
cd ~
cp -r /sdcard/happyphone-deploy . 2>/dev/null || { echo "Run: termux-setup-storage first"; exit 1; }
cd happyphone-deploy
chmod +x install-termux.sh
bash install-termux.sh
