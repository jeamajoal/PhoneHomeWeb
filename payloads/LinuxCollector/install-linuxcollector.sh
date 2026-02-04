#!/bin/bash
#===============================================================================
# Linux Collector Installer - One-liner deployment
#===============================================================================
#
# SYNOPSIS
#     Downloads and installs the Linux Collector for offline Windows diagnostics
#
# DESCRIPTION
#     Designed for quick deployment in Debian Live environment via:
#     curl -fsSL https://<server>/linuxcollector-installer -H 'X-Auth-Key: <key>' | sudo bash
#
# AUTHOR
#     jeamajoal
#
# LICENSE
#     MIT
#
#===============================================================================

# Configuration (placeholders replaced at download time)
SERVER_URL="${SERVER_URL:-<<SERVERURL>>}"
AUTH_KEY="${AUTH_KEY:-<<AUTHKEY>>}"

# Installation directory
INSTALL_DIR="/opt/LinuxCollector"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

DIVIDER="=============================="

echo ""
echo -e "${CYAN}${DIVIDER}${NC}"
echo -e "${YELLOW} LINUX COLLECTOR INSTALLER${NC}"
echo -e "${CYAN}${DIVIDER}${NC}"
echo ""

# Check for root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR: This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Check for required tools
for tool in curl; do
    if ! command -v "$tool" &>/dev/null; then
        echo -e "${RED}ERROR: Required tool '$tool' not found${NC}"
        exit 1
    fi
done

echo -e "${CYAN}Checking Linux environment...${NC}"

# Verify we're on a Linux system
if [[ "$(uname -s)" != "Linux" ]]; then
    echo -e "${YELLOW}WARNING: This script is designed for Linux systems${NC}"
fi

echo -e "${GREEN}Linux environment detected${NC}"
echo ""
echo -e "${CYAN}Installation directory: ${NC}$INSTALL_DIR"

# Create installation directory
if [[ -d "$INSTALL_DIR" ]]; then
    echo -e "${GRAY}  Removing existing installation...${NC}"
    rm -rf "$INSTALL_DIR"
fi

mkdir -p "$INSTALL_DIR"
echo -e "${GREEN}  Installation directory created${NC}"

echo ""
echo -e "${CYAN}Downloading Linux Collector...${NC}"

# Download main collector script
COLLECTOR_URL="$SERVER_URL/payloads/LinuxCollector/download/Linux-Collector.sh"
COLLECTOR_PATH="$INSTALL_DIR/Linux-Collector.sh"

echo -e "${GRAY}  Downloading Linux-Collector.sh...${NC}"

if curl -fsSL -o "$COLLECTOR_PATH" \
    -H "X-Auth-Key: $AUTH_KEY" \
    --connect-timeout 30 \
    --max-time 120 \
    "$COLLECTOR_URL"; then
    
    chmod +x "$COLLECTOR_PATH"
    echo -e "${GREEN}  Linux-Collector.sh downloaded${NC}"
else
    echo -e "${RED}  Error downloading collector script${NC}"
    echo -e "${RED}  URL: $COLLECTOR_URL${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}Installation completed successfully!${NC}"
echo ""
echo -e "${CYAN}$(printf '=%.0s' {1..80})${NC}"
echo -e "${YELLOW} NEXT STEPS${NC}"
echo -e "${CYAN}$(printf '=%.0s' {1..80})${NC}"
echo ""
echo -e "${NC}1. Navigate to installation directory:${NC}"
echo -e "${CYAN}   cd $INSTALL_DIR${NC}"
echo ""
echo -e "${NC}2. Run the collector:${NC}"
echo -e "${CYAN}   sudo ./Linux-Collector.sh${NC}"
echo ""
echo -e "${NC}3. Follow the on-screen prompts to:${NC}"
echo -e "${GRAY}   - Select the Windows partition to diagnose${NC}"
echo -e "${GRAY}   - Enter BitLocker recovery key if needed${NC}"
echo -e "${GRAY}   - Upload diagnostics to server${NC}"
echo ""
echo -e "${CYAN}$(printf '=%.0s' {1..80})${NC}"
echo ""

echo ""
echo -e "${CYAN}Starting Linux Collector...${NC}"
echo ""

# Change to install directory and run
cd "$INSTALL_DIR" || exit 1
exec "$INSTALL_DIR/Linux-Collector.sh"
