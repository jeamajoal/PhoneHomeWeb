#!/bin/bash
#===============================================================================
# Linux USB Builder Installer - Downloads the USB creation tool
#===============================================================================
#
# SYNOPSIS
#     Downloads the Linux Diagnostic USB Builder to the current machine
#
# DESCRIPTION
#     This installer downloads Build-Linux-USB.sh which creates bootable
#     Debian Live USB drives with recovery and diagnostic tools.
#     
#     Designed for deployment via:
#     curl -fsSL https://<server>/linux-usb-installer -H 'X-Auth-Key: <key>' | sudo bash
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

# Installation directory (user's home or /opt)
if [[ -n "$SUDO_USER" ]]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    INSTALL_DIR="$USER_HOME/LinuxUSBBuilder"
else
    INSTALL_DIR="${HOME:-/opt}/LinuxUSBBuilder"
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
NC='\033[0m'

DIVIDER="=============================="

echo ""
echo -e "${CYAN}${DIVIDER}${NC}"
echo -e "${YELLOW} LINUX USB BUILDER INSTALLER${NC}"
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

echo -e "${CYAN}Verifying environment...${NC}"

# Verify we're on a Linux system
if [[ "$(uname -s)" != "Linux" ]]; then
    echo -e "${RED}ERROR: This script requires Linux${NC}"
    echo -e "${YELLOW}The USB builder must run on Debian/Ubuntu Linux or WSL2${NC}"
    exit 1
fi

# Check for Debian/Ubuntu
if ! command -v apt-get &>/dev/null; then
    echo -e "${YELLOW}WARNING: apt-get not found. This tool is designed for Debian/Ubuntu.${NC}"
    echo -e "${YELLOW}Some dependencies may need to be installed manually.${NC}"
fi

echo -e "${GREEN}Linux environment verified${NC}"
echo ""
echo -e "${CYAN}Installation directory: ${NC}$INSTALL_DIR"

# Create installation directory
mkdir -p "$INSTALL_DIR"

# Fix ownership if running under sudo
if [[ -n "$SUDO_USER" ]]; then
    chown "$SUDO_USER:$SUDO_USER" "$INSTALL_DIR"
fi

echo -e "${GREEN}  Installation directory created${NC}"

echo ""
echo -e "${CYAN}Downloading USB Builder...${NC}"

# Download Build-Linux-USB.sh
BUILDER_URL="$SERVER_URL/payloads/LinuxCollector/download/Build-Linux-USB.sh"
BUILDER_PATH="$INSTALL_DIR/Build-Linux-USB.sh"

echo -e "${GRAY}  Downloading Build-Linux-USB.sh...${NC}"

if curl -fsSL -o "$BUILDER_PATH" \
    -H "X-Auth-Key: $AUTH_KEY" \
    --connect-timeout 30 \
    --max-time 120 \
    "$BUILDER_URL"; then
    
    chmod +x "$BUILDER_PATH"
    
    # Fix ownership
    if [[ -n "$SUDO_USER" ]]; then
        chown "$SUDO_USER:$SUDO_USER" "$BUILDER_PATH"
    fi
    
    echo -e "${GREEN}  Build-Linux-USB.sh downloaded${NC}"
else
    echo -e "${RED}  Error downloading USB builder script${NC}"
    echo -e "${RED}  URL: $BUILDER_URL${NC}"
    exit 1
fi

# Download README.md for documentation
README_URL="$SERVER_URL/payloads/LinuxCollector/download/README.md"
README_PATH="$INSTALL_DIR/README.md"

echo -e "${GRAY}  Downloading README.md...${NC}"
if curl -fsSL -o "$README_PATH" \
    -H "X-Auth-Key: $AUTH_KEY" \
    --connect-timeout 30 \
    --max-time 60 \
    "$README_URL" 2>/dev/null; then
    
    if [[ -n "$SUDO_USER" ]]; then
        chown "$SUDO_USER:$SUDO_USER" "$README_PATH"
    fi
    echo -e "${GREEN}  README.md downloaded${NC}"
else
    echo -e "${YELLOW}  README.md not available (optional)${NC}"
fi

# Create a launcher script with sudo
LAUNCHER_PATH="$INSTALL_DIR/create-usb.sh"
cat > "$LAUNCHER_PATH" << 'LAUNCHER_EOF'
#!/bin/bash
# Launcher script for Linux USB Builder
cd "$(dirname "$0")" || exit 1
if [[ $EUID -ne 0 ]]; then
    echo "This script requires root privileges. Running with sudo..."
    exec sudo ./Build-Linux-USB.sh "$@"
else
    exec ./Build-Linux-USB.sh "$@"
fi
LAUNCHER_EOF
chmod +x "$LAUNCHER_PATH"
if [[ -n "$SUDO_USER" ]]; then
    chown "$SUDO_USER:$SUDO_USER" "$LAUNCHER_PATH"
fi
echo -e "${GREEN}  Launcher script created${NC}"

echo ""
echo -e "${GREEN}Installation completed successfully!${NC}"
echo ""
echo -e "${CYAN}$(printf '=%.0s' {1..80})${NC}"
echo -e "${YELLOW} WHAT'S NEXT${NC}"
echo -e "${CYAN}$(printf '=%.0s' {1..80})${NC}"
echo ""
echo -e "${NC}The Linux USB Builder has been installed to:${NC}"
echo -e "${CYAN}   $INSTALL_DIR${NC}"
echo ""
echo -e "${NC}To create a bootable USB:${NC}"
echo ""
echo -e "${NC}1. Insert a USB drive (8GB+ recommended)${NC}"
echo ""
echo -e "${NC}2. Run the builder:${NC}"
echo -e "${CYAN}   cd $INSTALL_DIR${NC}"
echo -e "${CYAN}   sudo ./Build-Linux-USB.sh${NC}"
echo ""
echo -e "${NC}3. Follow the interactive prompts to:${NC}"
echo -e "${GRAY}   - Select a Debian Live ISO from the mirror${NC}"
echo -e "${GRAY}   - Choose your USB device${NC}"
echo -e "${GRAY}   - Optionally enable persistence${NC}"
echo ""
echo -e "${YELLOW}REQUIREMENTS:${NC}"
echo -e "${GRAY}   - Debian/Ubuntu Linux host (or WSL2 with USB passthrough)${NC}"
echo -e "${GRAY}   - Root privileges${NC}"
echo -e "${GRAY}   - Internet connection for ISO download${NC}"
echo -e "${GRAY}   - 8GB+ USB drive${NC}"
echo ""
echo -e "${CYAN}$(printf '=%.0s' {1..80})${NC}"
echo ""

# List required packages
echo -e "${YELLOW}Installing required dependencies...${NC}"
apt-get update -qq
apt-get install -y -qq \
    parted gdisk dosfstools e2fsprogs \
    xorriso isolinux syslinux-common \
    squashfs-tools debootstrap \
    curl wget rsync coreutils \
    2>/dev/null

echo ""
echo -e "${GREEN}Setup complete! Ready to create bootable USB drives.${NC}"
echo ""
