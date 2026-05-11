#!/bin/bash
#===============================================================================
# Headless Debian Builder Installer (Linux host)
#
# Downloads Build-Headless-Debian.sh + helper scripts from the PhoneHomeWeb
# server. Designed to be invoked via:
#   curl -fsSL https://<server>:3500/headless-debian-installer -H 'X-Auth-Key: <key>' | sudo bash
#===============================================================================

set -e

SERVER_URL="${SERVER_URL:-<<SERVERURL>>}"
AUTH_KEY="${AUTH_KEY:-<<AUTHKEY>>}"

cd / 2>/dev/null || true

if [[ -n "$SUDO_USER" ]]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    INSTALL_DIR="$USER_HOME/HeadlessDebianBuilder"
else
    INSTALL_DIR="${HOME:-/opt}/HeadlessDebianBuilder"
fi

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

echo
echo -e "${CYAN}==============================${NC}"
echo -e "${YELLOW} HEADLESS DEBIAN BUILDER INSTALLER${NC}"
echo -e "${CYAN}==============================${NC}"
echo

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR: run as root (sudo)${NC}"; exit 1
fi
command -v curl >/dev/null 2>&1 || { echo -e "${RED}ERROR: curl required${NC}"; exit 1; }

echo -e "${CYAN}Installing to:${NC} $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
[[ -n "$SUDO_USER" ]] && chown "$SUDO_USER:$SUDO_USER" "$INSTALL_DIR"

fetch() {
    local f="$1" required="${2:-0}"
    local url="${SERVER_URL%/}/payloads/LinuxCollector/download/$f"
    local dest="$INSTALL_DIR/$f"
    echo -ne "  ${f} ... "
    if curl -fsSL -H "X-Auth-Key: $AUTH_KEY" -o "$dest" "$url"; then
        chmod +x "$dest" 2>/dev/null || true
        [[ -n "$SUDO_USER" ]] && chown "$SUDO_USER:$SUDO_USER" "$dest"
        echo -e "${GREEN}OK${NC}"
    else
        if [[ "$required" == "1" ]]; then
            echo -e "${RED}FAIL${NC}"
            exit 1
        fi
        echo -e "${YELLOW}skip${NC}"
    fi
}

fetch Build-Headless-Debian.sh 1

# Inject creds so user doesn't need to pass --server-url / --auth-key
if [[ -f "$INSTALL_DIR/Build-Headless-Debian.sh" ]]; then
    sed -i "s|<<SERVERURL>>|${SERVER_URL%/}|g; s|<<AUTHKEY>>|$AUTH_KEY|g" "$INSTALL_DIR/Build-Headless-Debian.sh"
fi

echo
echo -e "${GREEN}==============================${NC}"
echo -e "${GREEN} INSTALLATION COMPLETE${NC}"
echo -e "${GREEN}==============================${NC}"
echo
echo -e "${CYAN}Quick start:${NC}"
echo "  sudo $INSTALL_DIR/Build-Headless-Debian.sh --ssh-key ~/.ssh/id_ed25519.pub --output ./phw-headless.iso"
echo
echo "Add --device /dev/sdX to write directly to USB."
echo "Run with --help for all options."
echo
