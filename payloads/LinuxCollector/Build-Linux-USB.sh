#!/usr/bin/env bash
# =============================================================================
# Build-Linux-USB.sh
# Linux companion builder script for PhoneHomeWeb
#
# Creates a bootable Debian Live USB with recovery/diagnostic tools:
#   - dislocker        : Unlock BitLocker-encrypted Windows drives
#   - gdisk/sgdisk     : GPT partition table management and recovery
#   - testdisk         : Partition recovery and file undelete
#   - ntfs-3g          : NTFS read/write support
#   - parted           : Partition management
#   - ddrescue         : Data recovery from damaged drives
#   - smartmontools    : Disk health diagnostics (SMART)
#   - lvm2             : Logical Volume Manager support
#   - mdadm            : Software RAID support
#   - cryptsetup       : LUKS/encrypted volume support
#
# Digital Forensics Tools (for offline investigation):
#   - sleuthkit        : Filesystem forensics (fls, icat, mmls, etc.)
#   - foremost         : File carving and recovery from raw data
#   - binwalk          : Firmware analysis and extraction
#   - exiftool         : Metadata extraction from files
#   - chntpw           : Windows password reset and registry editor
#   - reglookup        : Windows registry file parser
#   - hivex            : Windows registry hive extraction library
#   - libesedb-utils   : Windows ESE database tools (for SRUM, etc.)
#
# Usage:
#   sudo ./Build-Linux-USB.sh [options]
#
# Options:
#   --device PATH       Target USB device (e.g. /dev/sdb). Will be detected if omitted.
#   --debian-iso PATH   Path to Debian Live ISO. Downloaded if not provided.
#   --iso-url URL       URL to download Debian Live ISO (uses official mirror if omitted).
#   --skip-write        Build customization only; do not write to USB.
#   --work-dir PATH     Working directory for build files (default: /tmp/linux-usb-build).
#   --keep-work         Do not delete working directory after build.
#   --non-interactive   Do not prompt; exit if required options are missing.
#   -h, --help          Show this help message.
#
# Requirements:
#   - Debian/Ubuntu host (or WSL2 with USB passthrough)
#   - Root privileges
#   - Internet connection (to download ISO if not provided)
#   - USB drive (8GB+ recommended)
#
# Author: jeamajoal
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

# Server configuration (placeholders replaced at download time)
# When downloaded from PhoneHomeWeb, these get the actual server URL and auth key
PHW_SERVER_URL="${PHW_SERVER_URL:-<<SERVERURL>>}"
PHW_AUTH_KEY="${PHW_AUTH_KEY:-<<AUTHKEY>>}"

# Default ISO base URL (directory listing)
DEFAULT_ISO_BASE_URL="https://cdimage.debian.org/debian-cd/current-live/amd64/iso-hybrid/"
DEFAULT_ISO_URL=""

# Tool packages to install in the live environment
LIVE_PACKAGES=(
    # Core recovery tools
    dislocker
    gdisk
    testdisk
    parted
    ntfs-3g
    dosfstools
    gddrescue
    smartmontools
    lvm2
    mdadm
    cryptsetup
    e2fsprogs
    xfsprogs
    btrfs-progs
    hdparm
    nvme-cli
    pciutils
    usbutils
    lshw
    dmidecode
    # Network and transfer
    curl
    wget
    rsync
    # Archiving
    zip
    unzip
    p7zip-full
    # Editors and utilities
    less
    vim-tiny
    nano
    tmux
    htop
    iotop
    sysstat
    # Digital forensics tools
    sleuthkit
    foremost
    binwalk
    libimage-exiftool-perl
    chntpw
    reglookup
    hivex
    libesedb-utils
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# -----------------------------------------------------------------------------
# Logging helpers
# -----------------------------------------------------------------------------

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

die() {
    log_error "$*"
    exit 1
}

# -----------------------------------------------------------------------------
# Usage
# -----------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: sudo $SCRIPT_NAME [options]

Creates a bootable Debian Live USB with recovery/diagnostic tools.

Options:
  --device PATH       Target USB device (e.g. /dev/sdb). Detected interactively if omitted.
  --debian-iso PATH   Path to Debian Live ISO. Downloaded if not provided.
  --iso-url URL       Direct URL to download a specific Debian Live ISO.
  --iso-base-url URL  Base URL for ISO directory listing (for interactive selection).
  --persist-size SIZE Size of persistence partition in MB (default: 10240 / 10GB).
  --no-persistence    Disable persistence partition (not recommended).
  --skip-write        Build customization only; do not write to USB.
  --work-dir PATH     Working directory for build files (default: /tmp/linux-usb-build).
  --keep-work         Do not delete working directory after build.
  --non-interactive   Do not prompt; exit if required options are missing.
  --server-url URL    PhoneHomeWeb server URL (for downloading scripts with embedded credentials).
  --auth-key KEY      Authentication key for PhoneHomeWeb server.
  -h, --help          Show this help message.

Examples:
  # Interactive mode - select ISO and USB device interactively
  sudo $SCRIPT_NAME

  # Specify device directly (still prompts for ISO selection)
  sudo $SCRIPT_NAME --device /dev/sdb

  # Use a pre-downloaded ISO
  sudo $SCRIPT_NAME --device /dev/sdb --debian-iso ~/Downloads/debian-live.iso

  # Specify smaller persistence partition (2GB instead of default 10GB)
  sudo $SCRIPT_NAME --device /dev/sdb --persist-size 2048

  # Disable persistence (not recommended - changes won't be saved)
  sudo $SCRIPT_NAME --device /dev/sdb --no-persistence

  # Build without writing (for testing)
  sudo $SCRIPT_NAME --skip-write

USB Partition Layout:
  Partition 1: Main boot partition (FAT32, LINUXDIAG) - Debian Live system
  Partition 2: Scripts partition (FAT32, LINUX-TOOLS) - Helper scripts
  Partition 3: Persistence (ext4, persistence) - Saves changes between reboots

Tools Included:
  - dislocker        : Unlock BitLocker-encrypted Windows drives
  - gdisk/sgdisk     : GPT partition table management and recovery
  - testdisk         : Partition recovery and file undelete
  - parted           : Partition management
  - ntfs-3g          : NTFS read/write support
  - ddrescue         : Data recovery from damaged drives
  - smartmontools    : Disk health diagnostics (SMART)
  - lvm2             : Logical Volume Manager support
  - mdadm            : Software RAID support
  - cryptsetup       : LUKS/encrypted volume support

Requirements:
  - Debian/Ubuntu host with root privileges
  - Internet connection (if ISO download needed)
  - USB drive (8GB+ recommended)

EOF
}

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

check_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        die "This script must be run as root (use sudo)."
    fi
}

check_dependencies() {
    local missing=()
    local deps=(lsblk parted mkfs.vfat mount umount rsync curl xorriso mksquashfs unsquashfs chroot syslinux)

    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_warn "Missing required tools: ${missing[*]}"
        log_info "Attempting to install missing dependencies..."

        apt-get update -y
        apt-get install -y --no-install-recommends \
            parted dosfstools mount rsync curl xorriso squashfs-tools debootstrap syslinux syslinux-common

        # Re-check
        for cmd in "${deps[@]}"; do
            command -v "$cmd" >/dev/null 2>&1 || die "Still missing required command: $cmd"
        done
    fi

    log_success "All dependencies satisfied."
}

list_usb_devices() {
    # List removable/USB block devices
    # Check RM=1 (removable) attribute
    lsblk -d -o NAME,SIZE,RM,TYPE -n 2>/dev/null | awk '
        $3=="1" && $4=="disk" {print "/dev/"$1, $2, "(removable)"}
    '
}

list_all_disks() {
    # List all block devices (fallback for WSL where RM attribute may not work)
    # Use separate lsblk call for model info to avoid column shifting
    lsblk -d -o NAME,SIZE,TYPE -n 2>/dev/null | while read name size dtype; do
        if [[ "$dtype" == "disk" ]] && [[ "$name" != loop* ]] && [[ "$name" != sr* ]]; then
            model=$(lsblk -d -o MODEL -n "/dev/$name" 2>/dev/null | xargs)
            echo "/dev/$name $size $model"
        fi
    done
}

select_iso_from_mirror() {
    local base_url="$1"

    log_info "Fetching available ISOs from Debian mirror..."
    echo ""

    # Fetch the directory listing and parse ISO links
    local page_content
    page_content=$(curl -sL "$base_url" 2>/dev/null)

    if [[ -z "$page_content" ]]; then
        die "Failed to fetch ISO listing from $base_url"
    fi

    # Extract .iso filenames from href attributes
    local iso_list
    iso_list=$(echo "$page_content" | grep -oP 'href="\K[^"]+\.iso(?=")' | sort -u)

    if [[ -z "$iso_list" ]]; then
        die "No ISO files found at $base_url"
    fi

    echo "Available Debian Live ISOs:"
    echo "----------------------------"

    local i=1
    local iso_array=()
    while IFS= read -r iso_name; do
        # Extract flavor from filename
        local flavor="unknown"
        if [[ "$iso_name" =~ debian-live-[0-9.]+-amd64-([a-z-]+)\.iso ]]; then
            flavor="${BASH_REMATCH[1]}"
        fi
        echo "  [$i] $iso_name"
        echo "      Flavor: $flavor"
        iso_array+=("$iso_name")
        ((i++))
    done <<< "$iso_list"

    echo ""
    echo "  [0] Cancel"
    echo ""
    echo "Tip: 'standard' is minimal CLI-only (smallest)."
    echo "     Desktop flavors (xfce, gnome, kde) include a GUI."
    echo ""

    local selection
    read -r -p "Select ISO number [1-$((i-1))]: " selection

    if [[ "$selection" == "0" ]] || [[ -z "$selection" ]]; then
        die "Aborted by user."
    fi

    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [[ "$selection" -lt 1 ]] || [[ "$selection" -ge "$i" ]]; then
        die "Invalid selection: $selection"
    fi

    local selected_iso="${iso_array[$((selection-1))]}"
    SELECTED_ISO_URL="${base_url%/}/${selected_iso}"

    log_info "Selected: $selected_iso"
}

select_usb_device() {
    log_info "Scanning for USB devices..."
    echo ""

    local devices
    devices=$(list_usb_devices)

    # Fallback for WSL where USB attributes may not be detected
    if [[ -z "$devices" ]]; then
        log_warn "No USB devices detected via standard method."
        log_info "Showing all available disks (WSL/usbipd mode)..."
        echo ""
        devices=$(list_all_disks)
    fi

    if [[ -z "$devices" ]]; then
        die "No disk devices found. Insert a USB drive and try again."
    fi

    echo "Available devices:"
    echo "------------------"
    local i=1
    local dev_array=()
    while IFS= read -r line; do
        echo "  [$i] $line"
        dev_array+=("$(echo "$line" | awk '{print $1}')")
        ((i++))
    done <<< "$devices"
    echo ""
    echo "  [0] Cancel"
    echo ""
    log_warn "CAUTION: Make sure you select the correct USB device!"
    log_warn "Selecting the wrong device will DESTROY all data on it."
    echo ""

    local selection
    read -r -p "Select device number [1-$((i-1))]: " selection

    if [[ "$selection" == "0" ]] || [[ -z "$selection" ]]; then
        die "Aborted by user."
    fi

    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [[ "$selection" -lt 1 ]] || [[ "$selection" -ge "$i" ]]; then
        die "Invalid selection: $selection"
    fi

    DEVICE="${dev_array[$((selection-1))]}"
    log_info "Selected device: $DEVICE"
}

confirm_destructive() {
    local device="$1"

    echo ""
    log_warn "========================================"
    log_warn "WARNING: ALL DATA ON $device WILL BE DESTROYED!"
    log_warn "========================================"
    echo ""

    lsblk "$device" -o NAME,SIZE,FSTYPE,MOUNTPOINT,LABEL 2>/dev/null || true
    echo ""

    local confirm
    read -r -p "Type 'YES' (uppercase) to continue: " confirm

    if [[ "$confirm" != "YES" ]]; then
        die "Aborted by user."
    fi
}

download_iso() {
    local url="$1"
    local dest="$2"

    log_info "Downloading Debian Live ISO..."
    log_info "URL: $url"
    log_info "Destination: $dest"

    curl -L --progress-bar -o "$dest" "$url" || die "Failed to download ISO."

    log_success "ISO downloaded successfully."
}

prepare_usb() {
    local device="$1"
    local with_persistence="$2"
    local persist_size="$3"

    log_info "Preparing USB device $device..."

    # Unmount any mounted partitions
    for part in "${device}"*; do
        if mount | grep -q "$part"; then
            log_info "Unmounting $part..."
            umount "$part" || true
        fi
    done

    # Get device size in MB
    local device_size_mb
    device_size_mb=$(( $(blockdev --getsize64 "$device") / 1024 / 1024 ))
    log_info "Device size: ${device_size_mb} MB"

    # Calculate partition sizes
    # Layout: [ESP/Boot: main] [Scripts: 128MB] [Persistence: optional]
    local scripts_size=128
    local main_end
    local scripts_end

    if [[ "$with_persistence" == "1" ]]; then
        # Reserve space for persistence at the end
        main_end=$(( device_size_mb - persist_size - scripts_size - 2 ))
        scripts_end=$(( main_end + scripts_size ))
        log_info "Creating partitions: Main (${main_end}MB), Scripts (${scripts_size}MB), Persistence (${persist_size}MB)"
    else
        main_end=$(( device_size_mb - scripts_size - 2 ))
        scripts_end=$(( main_end + scripts_size ))
        log_info "Creating partitions: Main (${main_end}MB), Scripts (${scripts_size}MB)"
    fi

    # Create GPT partition table
    log_info "Creating partition table..."
    parted -s "$device" mklabel gpt

    # Partition 1: Main boot partition (ESP)
    parted -s "$device" mkpart primary fat32 1MiB "${main_end}MiB"
    parted -s "$device" set 1 boot on
    parted -s "$device" set 1 esp on

    # Partition 2: Scripts partition (FAT32 for cross-platform access)
    parted -s "$device" mkpart primary fat32 "${main_end}MiB" "${scripts_end}MiB"

    # Partition 3: Persistence partition (ext4) - optional
    if [[ "$with_persistence" == "1" ]]; then
        parted -s "$device" mkpart primary ext4 "${scripts_end}MiB" 100%
    fi

    # Wait for partitions to appear
    sleep 2
    partprobe "$device" 2>/dev/null || true
    sleep 2

    # Determine partition naming style
    local part_prefix="$device"
    if [[ "$device" == *"nvme"* ]] || [[ "$device" == *"mmcblk"* ]]; then
        part_prefix="${device}p"
    fi

    local part1="${part_prefix}1"
    local part2="${part_prefix}2"
    local part3="${part_prefix}3"

    if [[ ! -b "$part1" ]]; then
        die "Partition $part1 not found after partitioning."
    fi

    # Format partitions
    log_info "Formatting main partition as FAT32..."
    mkfs.vfat -F 32 -n "LINUXDIAG" "$part1"

    log_info "Formatting scripts partition as FAT32..."
    mkfs.vfat -F 32 -n "LINUX-TOOLS" "$part2"

    if [[ "$with_persistence" == "1" ]] && [[ -b "$part3" ]]; then
        log_info "Formatting persistence partition as ext4..."
        mkfs.ext4 -L "persistence" "$part3"

        # Configure persistence
        log_info "Configuring persistence partition..."
        local persist_mount="/mnt/persistence-$$"
        mkdir -p "$persist_mount"
        mount "$part3" "$persist_mount"
        echo "/ union" > "$persist_mount/persistence.conf"
        
        # Create autorun structure
        mkdir -p "$persist_mount/etc/rc.local.d"
        mkdir -p "$persist_mount/usr/local/bin"
        
        sync
        umount "$persist_mount"
        rmdir "$persist_mount"
        log_success "Persistence partition configured."
    fi

    log_success "USB device prepared."
    
    # Return partition info
    USB_PART_MAIN="$part1"
    USB_PART_SCRIPTS="$part2"
    USB_PART_PERSIST="$part3"
}

extract_iso() {
    local iso_path="$1"
    local mount_point="$2"
    local extract_dir="$3"

    log_info "Extracting ISO contents..."

    mkdir -p "$mount_point"
    mount -o loop,ro "$iso_path" "$mount_point"

    mkdir -p "$extract_dir"
    rsync -a --info=progress2 "$mount_point/" "$extract_dir/"

    umount "$mount_point"
    rmdir "$mount_point"

    log_success "ISO extracted."
}

copy_scripts_to_partition() {
    local scripts_partition="$1"

    log_info "Copying helper scripts to scripts partition..."

    local scripts_mount="/mnt/scripts-$$"
    mkdir -p "$scripts_mount"
    mount "$scripts_partition" "$scripts_mount"

    local scripts_dir="$scripts_mount/scripts"
    mkdir -p "$scripts_dir"

    #---------------------------------------------------------------------------
    # 1. detect-bitlocker.sh - Scan for BitLocker partitions
    #---------------------------------------------------------------------------
    cat > "$scripts_dir/detect-bitlocker.sh" << 'SCRIPT_EOF'
#!/bin/bash
#===============================================================================
# BitLocker Detection Script
# Scans all partitions to identify BitLocker-encrypted volumes
#===============================================================================

echo "========================================"
echo " BitLocker Volume Detection"
echo " $(date)"
echo "========================================"
echo ""

found=0

echo "Scanning partitions..."
echo ""

for part in /dev/sd?? /dev/nvme?n?p?; do
    [ -b "$part" ] || continue
    
    # Check for BitLocker signature using blkid
    fstype=$(blkid -o value -s TYPE "$part" 2>/dev/null)
    label=$(blkid -o value -s LABEL "$part" 2>/dev/null)
    size=$(lsblk -bno SIZE "$part" 2>/dev/null | numfmt --to=iec 2>/dev/null || echo "?")
    
    if [ "$fstype" = "BitLocker" ]; then
        echo "[BITLOCKER] $part"
        echo "    Size:  $size"
        echo "    Label: ${label:-<none>}"
        echo ""
        found=$((found + 1))
    fi
    
    # Also check for -FVE-FS- signature in first sector (BitLocker marker)
    if dd if="$part" bs=512 count=1 2>/dev/null | grep -q "\-FVE-FS-"; then
        if [ "$fstype" != "BitLocker" ]; then
            echo "[BITLOCKER?] $part (signature detected but blkid shows: $fstype)"
            echo "    Size:  $size"
            echo "    Label: ${label:-<none>}"
            echo ""
            found=$((found + 1))
        fi
    fi
done

echo "----------------------------------------"
if [ $found -eq 0 ]; then
    echo "No BitLocker volumes detected."
else
    echo "Found $found BitLocker volume(s)."
    echo ""
    echo "To unlock, use:"
    echo "  ./unlock-bitlocker.sh /dev/sdXN YOUR-RECOVERY-KEY"
fi
SCRIPT_EOF

    #---------------------------------------------------------------------------
    # 2. unlock-bitlocker.sh - Unlock BitLocker drives (improved)
    #---------------------------------------------------------------------------
    cat > "$scripts_dir/unlock-bitlocker.sh" << 'SCRIPT_EOF'
#!/bin/bash
#===============================================================================
# BitLocker Unlock Helper
# Usage: ./unlock-bitlocker.sh /dev/sdX1 "YOUR-RECOVERY-KEY"
#===============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

MOUNT_BL="/mnt/bitlocker"
MOUNT_WIN="/mnt/windows"

show_usage() {
    echo "BitLocker Unlock Helper"
    echo ""
    echo "Usage: $0 <device> <recovery-key>"
    echo "       $0 --detect"
    echo "       $0 --unmount"
    echo ""
    echo "Arguments:"
    echo "  device        Partition to unlock (e.g., /dev/sda3)"
    echo "  recovery-key  48-digit BitLocker recovery key"
    echo ""
    echo "Options:"
    echo "  --detect      Scan for BitLocker partitions"
    echo "  --unmount     Unmount previously unlocked volume"
    echo ""
    echo "Example:"
    echo "  $0 /dev/sda3 123456-789012-345678-901234-567890-123456-789012-345678"
    echo ""
    echo "To get recovery key:"
    echo "  - Azure AD: portal.azure.com > Devices > BitLocker keys"
    echo "  - Active Directory: Check with IT admin"
    echo "  - Microsoft Account: account.microsoft.com/devices"
}

detect_bitlocker() {
    echo "Scanning for BitLocker volumes..."
    ./detect-bitlocker.sh
}

unmount_volume() {
    echo "[*] Unmounting BitLocker volume..."
    
    if mountpoint -q "$MOUNT_WIN" 2>/dev/null; then
        umount "$MOUNT_WIN" && echo -e "${GREEN}[+] Unmounted $MOUNT_WIN${NC}"
    fi
    
    if mountpoint -q "$MOUNT_BL" 2>/dev/null; then
        umount "$MOUNT_BL" && echo -e "${GREEN}[+] Unmounted $MOUNT_BL${NC}"
    elif [ -d "$MOUNT_BL" ] && [ -f "$MOUNT_BL/dislocker-file" ]; then
        fusermount -u "$MOUNT_BL" 2>/dev/null && echo -e "${GREEN}[+] Unmounted $MOUNT_BL${NC}"
    fi
    
    echo "[+] Cleanup complete."
}

if [ $# -eq 0 ]; then
    show_usage
    exit 1
fi

case "$1" in
    --detect|-d)
        detect_bitlocker
        exit 0
        ;;
    --unmount|-u)
        unmount_volume
        exit 0
        ;;
    --help|-h)
        show_usage
        exit 0
        ;;
esac

if [ $# -lt 2 ]; then
    echo -e "${RED}Error: Missing arguments${NC}"
    show_usage
    exit 1
fi

DEVICE=$1
KEY=$2

# Validate device exists
if [ ! -b "$DEVICE" ]; then
    echo -e "${RED}Error: Device $DEVICE not found${NC}"
    exit 1
fi

# Validate key format (basic check)
clean_key=$(echo "$KEY" | tr -d '- ')
if [ ${#clean_key} -ne 48 ]; then
    echo -e "${YELLOW}Warning: Key should be 48 digits (got ${#clean_key})${NC}"
fi

echo "[*] Creating mount points..."
mkdir -p "$MOUNT_BL" "$MOUNT_WIN"

# Unmount if already mounted
if mountpoint -q "$MOUNT_WIN" 2>/dev/null; then
    echo "[*] Unmounting existing $MOUNT_WIN..."
    umount "$MOUNT_WIN"
fi

echo "[*] Unlocking BitLocker volume on $DEVICE..."
echo "    (This may take a moment...)"

if dislocker -V "$DEVICE" -p"$KEY" -- "$MOUNT_BL"; then
    if [ -f "$MOUNT_BL/dislocker-file" ]; then
        echo "[*] Mounting Windows filesystem..."
        if mount -o loop,ro "$MOUNT_BL/dislocker-file" "$MOUNT_WIN"; then
            echo ""
            echo -e "${GREEN}[+] SUCCESS! Windows drive mounted at: $MOUNT_WIN${NC}"
            echo ""
            echo "Contents:"
            ls -la "$MOUNT_WIN" | head -20
            echo ""
            echo "To unmount later: $0 --unmount"
        else
            echo -e "${RED}[-] Failed to mount filesystem${NC}"
            echo "    The volume is unlocked but filesystem mount failed."
            echo "    Try: mount -t ntfs-3g -o loop $MOUNT_BL/dislocker-file $MOUNT_WIN"
            exit 1
        fi
    else
        echo -e "${RED}[-] dislocker-file not created${NC}"
        exit 1
    fi
else
    echo -e "${RED}[-] Failed to unlock BitLocker volume${NC}"
    echo ""
    echo "Possible causes:"
    echo "  - Incorrect recovery key"
    echo "  - Partition is not BitLocker encrypted"
    echo "  - Corrupted BitLocker metadata"
    echo ""
    echo "Run: ./detect-bitlocker.sh to verify the partition"
    exit 1
fi
SCRIPT_EOF

    #---------------------------------------------------------------------------
    # 3. mount-windows.sh - Mount Windows/NTFS partitions (hardened)
    #---------------------------------------------------------------------------
    cat > "$scripts_dir/mount-windows.sh" << 'SCRIPT_EOF'
#!/bin/bash
#===============================================================================
# Windows/NTFS Mount Helper
# Easily mount NTFS partitions with proper options
#===============================================================================

set -o pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

MOUNT_POINT="/mnt/windows"

show_usage() {
    echo "Windows/NTFS Mount Helper"
    echo ""
    echo "Usage: $0 [options] <device>"
    echo "       $0 --list"
    echo "       $0 --unmount [mount-point]"
    echo ""
    echo "Options:"
    echo "  -r, --readonly    Mount read-only (default, safer)"
    echo "  -w, --readwrite   Mount read-write (use with caution)"
    echo "  -m, --mount PATH  Custom mount point (default: /mnt/windows)"
    echo "  --list            List all mountable partitions"
    echo "  --unmount [PATH]  Unmount specified or default mount point"
    echo "  --fix             Attempt to fix NTFS dirty flag before mounting"
    echo ""
    echo "Examples:"
    echo "  $0 /dev/sda3              # Mount read-only"
    echo "  $0 -w /dev/sda3           # Mount read-write"
    echo "  $0 -m /mnt/c /dev/sda3    # Mount to custom location"
    echo "  $0 --list                 # Show available partitions"
}

list_partitions() {
    echo -e "${CYAN}Available Partitions:${NC}"
    echo "====================="
    echo ""
    printf "  %-15s %-10s %-10s %-12s %s\n" "DEVICE" "SIZE" "FSTYPE" "LABEL" "STATUS"
    printf "  %-15s %-10s %-10s %-12s %s\n" "------" "----" "------" "-----" "------"
    
    for part in /dev/sd?? /dev/nvme?n?p? /dev/mmcblk?p?; do
        [ -b "$part" ] || continue
        
        local fstype=$(blkid -o value -s TYPE "$part" 2>/dev/null)
        [ -z "$fstype" ] && continue
        
        local label=$(blkid -o value -s LABEL "$part" 2>/dev/null)
        local size=$(lsblk -bno SIZE "$part" 2>/dev/null | numfmt --to=iec 2>/dev/null || echo "?")
        local status=""
        
        # Check mount status
        if mount | grep -q "^$part "; then
            local mp=$(mount | grep "^$part " | awk '{print $3}')
            status="${GREEN}mounted at $mp${NC}"
        elif [ "$fstype" = "BitLocker" ]; then
            status="${YELLOW}BitLocker encrypted${NC}"
        else
            status="available"
        fi
        
        printf "  %-15s %-10s %-10s %-12s %b\n" "$part" "$size" "$fstype" "${label:-<none>}" "$status"
    done
    
    echo ""
    echo "To mount NTFS:    $0 /dev/sdXN"
    echo "For BitLocker:    ./unlock-bitlocker.sh /dev/sdXN <recovery-key>"
}

do_unmount() {
    local mp="${1:-$MOUNT_POINT}"
    
    if ! mountpoint -q "$mp" 2>/dev/null; then
        # Check if path exists but isn't a mountpoint
        if [ -d "$mp" ]; then
            echo -e "${YELLOW}$mp exists but is not a mount point${NC}"
        else
            echo -e "${YELLOW}Nothing mounted at $mp${NC}"
        fi
        return 1
    fi
    
    echo "[*] Unmounting $mp..."
    if umount "$mp" 2>/dev/null; then
        echo -e "${GREEN}[+] Unmounted successfully${NC}"
        rmdir "$mp" 2>/dev/null || true
        return 0
    else
        echo -e "${YELLOW}[!] Normal unmount failed, trying lazy unmount...${NC}"
        if umount -l "$mp" 2>/dev/null; then
            echo -e "${GREEN}[+] Lazy unmount successful${NC}"
            return 0
        else
            echo -e "${RED}[-] Failed to unmount $mp${NC}"
            echo "    Processes using mount point:"
            lsof "$mp" 2>/dev/null | head -10 || fuser -v "$mp" 2>/dev/null || echo "    (unknown)"
            return 1
        fi
    fi
}

fix_ntfs() {
    local dev="$1"
    echo "[*] Attempting to fix NTFS filesystem on $dev..."
    
    if ! command -v ntfsfix >/dev/null 2>&1; then
        echo -e "${RED}[-] ntfsfix not available${NC}"
        return 1
    fi
    
    if ntfsfix "$dev" 2>&1; then
        echo -e "${GREEN}[+] NTFS fix completed${NC}"
        return 0
    else
        echo -e "${YELLOW}[!] NTFS fix may have encountered issues${NC}"
        return 1
    fi
}

# Parse arguments
READONLY=1
DEVICE=""
DO_FIX=0

while [ $# -gt 0 ]; do
    case "$1" in
        -r|--readonly) READONLY=1; shift ;;
        -w|--readwrite) READONLY=0; shift ;;
        -m|--mount) 
            [ -z "$2" ] && { echo -e "${RED}Error: --mount requires a path${NC}"; exit 1; }
            MOUNT_POINT="$2"; shift 2 
            ;;
        --list|-l) list_partitions; exit 0 ;;
        --unmount|-u)
            if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
                do_unmount "$2"
            else
                do_unmount "$MOUNT_POINT"
            fi
            exit $?
            ;;
        --fix|-f) DO_FIX=1; shift ;;
        --help|-h) show_usage; exit 0 ;;
        -*) echo -e "${RED}Unknown option: $1${NC}"; show_usage; exit 1 ;;
        *) DEVICE="$1"; shift ;;
    esac
done

# Validate device
if [ -z "$DEVICE" ]; then
    echo -e "${RED}Error: No device specified${NC}"
    echo ""
    show_usage
    exit 1
fi

if [ ! -b "$DEVICE" ]; then
    echo -e "${RED}Error: Device $DEVICE not found${NC}"
    echo ""
    echo "Available block devices:"
    lsblk -o NAME,SIZE,TYPE,FSTYPE -n | grep -E "part|disk" | head -10
    exit 1
fi

# Check filesystem type
FSTYPE=$(blkid -o value -s TYPE "$DEVICE" 2>/dev/null)

if [ -z "$FSTYPE" ]; then
    echo -e "${RED}Error: Could not determine filesystem type for $DEVICE${NC}"
    echo "The partition may be unformatted or use an unknown filesystem."
    exit 1
fi

if [ "$FSTYPE" = "BitLocker" ]; then
    echo -e "${YELLOW}Error: $DEVICE is BitLocker encrypted${NC}"
    echo ""
    echo "Use the BitLocker unlock script instead:"
    echo "  ./unlock-bitlocker.sh $DEVICE <recovery-key>"
    exit 1
fi

if [ "$FSTYPE" != "ntfs" ]; then
    echo -e "${YELLOW}Warning: $DEVICE is $FSTYPE, not NTFS${NC}"
    echo "This script is optimized for NTFS. Proceeding anyway..."
fi

# Check if already mounted
if mount | grep -q "^$DEVICE "; then
    existing_mp=$(mount | grep "^$DEVICE " | awk '{print $3}')
    echo -e "${YELLOW}Warning: $DEVICE is already mounted at $existing_mp${NC}"
    echo ""
    read -p "Unmount and remount at $MOUNT_POINT? [y/N]: " response
    if [ "$response" = "y" ] || [ "$response" = "Y" ]; then
        do_unmount "$existing_mp" || exit 1
    else
        echo "Aborted."
        exit 0
    fi
fi

# Check if mount point is in use
if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
    echo -e "${YELLOW}Warning: $MOUNT_POINT is already in use${NC}"
    current_dev=$(mount | grep " $MOUNT_POINT " | awk '{print $1}')
    echo "  Currently mounted: $current_dev"
    echo ""
    read -p "Unmount existing mount? [y/N]: " response
    if [ "$response" = "y" ] || [ "$response" = "Y" ]; then
        do_unmount "$MOUNT_POINT" || exit 1
    else
        echo "Aborted."
        exit 0
    fi
fi

# Fix NTFS if requested
if [ $DO_FIX -eq 1 ]; then
    fix_ntfs "$DEVICE"
fi

# Create mount point
mkdir -p "$MOUNT_POINT" || {
    echo -e "${RED}Error: Failed to create mount point $MOUNT_POINT${NC}"
    exit 1
}

# Build mount options
if [ $READONLY -eq 1 ]; then
    echo "[*] Mounting $DEVICE read-only at $MOUNT_POINT..."
    OPTS="ro,noexec,nodev,nosuid,show_sys_files,streams_interface=windows"
else
    echo -e "${YELLOW}[*] Mounting $DEVICE read-write at $MOUNT_POINT...${NC}"
    echo -e "${YELLOW}    WARNING: Writing to NTFS while Windows is hibernated may corrupt data!${NC}"
    OPTS="rw,noexec,nodev,nosuid,show_sys_files,streams_interface=windows"
fi

# Attempt mount
if mount -t ntfs-3g -o "$OPTS" "$DEVICE" "$MOUNT_POINT" 2>&1; then
    echo -e "${GREEN}[+] Mounted successfully!${NC}"
    echo ""
    df -h "$MOUNT_POINT"
    echo ""
    echo "Contents:"
    ls -la "$MOUNT_POINT" 2>/dev/null | head -15
    echo ""
    echo "To unmount: $0 --unmount"
else
    echo -e "${RED}[-] Mount failed${NC}"
    echo ""
    echo "Troubleshooting:"
    echo "  1. Windows hibernation/fast boot may lock the drive"
    echo "     Try: ntfsfix $DEVICE"
    echo "  2. Filesystem may need repair"
    echo "     Boot to Windows and run: chkdsk /f"
    echo "  3. Try mounting read-only: $0 -r $DEVICE"
    rmdir "$MOUNT_POINT" 2>/dev/null
    exit 1
fi
SCRIPT_EOF

    #---------------------------------------------------------------------------
    # 4. disk-diagnostics.sh - Comprehensive disk health (improved)
    #---------------------------------------------------------------------------
    cat > "$scripts_dir/disk-diagnostics.sh" << 'SCRIPT_EOF'
#!/bin/bash
#===============================================================================
# Comprehensive Disk Diagnostics
# Generates detailed disk health report
#===============================================================================

REPORT_DIR="/tmp/disk-report-$(date +%Y%m%d-%H%M%S)"
REPORT_FILE="$REPORT_DIR/disk-health-report.txt"

mkdir -p "$REPORT_DIR"

# Function to add to report
report() {
    echo "$@" | tee -a "$REPORT_FILE"
}

report "================================================================================"
report " DISK HEALTH DIAGNOSTIC REPORT"
report " Generated: $(date)"
report " Hostname:  $(hostname)"
report "================================================================================"
report ""

# System overview
report "=== SYSTEM OVERVIEW ==="
report ""
report "--- DMI/BIOS Information ---"
dmidecode -t system 2>/dev/null | grep -E "Manufacturer|Product|Serial|UUID" >> "$REPORT_FILE"
report ""

# Block devices
report "=== BLOCK DEVICES ==="
report ""
lsblk -o NAME,SIZE,TYPE,FSTYPE,LABEL,MOUNTPOINT,MODEL,SERIAL 2>/dev/null | tee -a "$REPORT_FILE"
report ""

# Partition tables
report "=== PARTITION TABLES ==="
report ""
for disk in /dev/sd? /dev/nvme?n?; do
    [ -b "$disk" ] || continue
    report "--- $disk ---"
    fdisk -l "$disk" 2>/dev/null >> "$REPORT_FILE"
    report ""
done

# SMART Health for each disk
report "=== SMART HEALTH DATA ==="
report ""

for disk in /dev/sd? /dev/nvme?n?; do
    [ -b "$disk" ] || continue
    
    report "--- $disk ---"
    
    # Get basic info
    model=$(smartctl -i "$disk" 2>/dev/null | grep -E "Device Model|Model Number" | head -1)
    serial=$(smartctl -i "$disk" 2>/dev/null | grep -i "Serial" | head -1)
    
    report "$model"
    report "$serial"
    report ""
    
    # Health status
    health=$(smartctl -H "$disk" 2>/dev/null | grep -E "PASSED|FAILED|result")
    if echo "$health" | grep -qi "PASSED"; then
        report "Health: PASSED ✓"
    elif echo "$health" | grep -qi "FAILED"; then
        report "Health: FAILED ✗ *** DRIVE MAY BE FAILING ***"
    else
        report "Health: Unable to determine"
    fi
    report ""
    
    # Key SMART attributes (SATA)
    if [[ "$disk" == /dev/sd* ]]; then
        report "Key SMART Attributes:"
        smartctl -A "$disk" 2>/dev/null | grep -E "Reallocated|Pending|Uncorrectable|Power_On|Temperature|Wear" >> "$REPORT_FILE"
    fi
    
    # NVMe specific
    if [[ "$disk" == /dev/nvme* ]]; then
        report "NVMe SMART Log:"
        nvme smart-log "$disk" 2>/dev/null >> "$REPORT_FILE" || smartctl -A "$disk" 2>/dev/null >> "$REPORT_FILE"
    fi
    
    report ""
done

# Filesystem checks
report "=== FILESYSTEM STATUS ==="
report ""
for part in /dev/sd?? /dev/nvme?n?p?; do
    [ -b "$part" ] || continue
    fstype=$(blkid -o value -s TYPE "$part" 2>/dev/null)
    [ -n "$fstype" ] || continue
    
    report "--- $part ($fstype) ---"
    
    case "$fstype" in
        ntfs)
            ntfsinfo -m "$part" 2>/dev/null | grep -E "Volume|Cluster|Free" >> "$REPORT_FILE" || echo "  (ntfsinfo not available)" >> "$REPORT_FILE"
            ;;
        ext*)
            dumpe2fs -h "$part" 2>/dev/null | grep -E "state|count|Check|Free" >> "$REPORT_FILE" || echo "  (dumpe2fs not available)" >> "$REPORT_FILE"
            ;;
        *)
            echo "  Filesystem: $fstype" >> "$REPORT_FILE"
            ;;
    esac
    report ""
done

# Summary
report "=== SUMMARY ==="
report ""

failing=0
for disk in /dev/sd? /dev/nvme?n?; do
    [ -b "$disk" ] || continue
    if smartctl -H "$disk" 2>/dev/null | grep -qi "FAILED"; then
        report "*** WARNING: $disk reports SMART FAILURE ***"
        failing=$((failing + 1))
    fi
done

if [ $failing -eq 0 ]; then
    report "All drives report healthy SMART status."
fi

report ""
report "================================================================================"
report "Report saved to: $REPORT_FILE"
report "================================================================================"

echo ""
echo "Full report: $REPORT_FILE"
echo "View with: less $REPORT_FILE"
SCRIPT_EOF

    #---------------------------------------------------------------------------
    # 5. collect-windows-logs.sh - Collect logs from Windows partition
    #---------------------------------------------------------------------------
    cat > "$scripts_dir/collect-windows-logs.sh" << 'SCRIPT_EOF'
#!/bin/bash
#===============================================================================
# Windows Log Collector
# Collects diagnostic logs from offline Windows installation
#===============================================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

show_usage() {
    echo "Windows Log Collector"
    echo ""
    echo "Usage: $0 <windows-mount-point> [output-dir]"
    echo ""
    echo "Arguments:"
    echo "  windows-mount-point   Path where Windows is mounted (e.g., /mnt/windows)"
    echo "  output-dir            Output directory (default: /tmp/windows-logs-TIMESTAMP)"
    echo ""
    echo "Example:"
    echo "  # First mount the Windows partition:"
    echo "  ./mount-windows.sh /dev/sda3"
    echo ""
    echo "  # Then collect logs:"
    echo "  $0 /mnt/windows"
}

if [ $# -lt 1 ]; then
    show_usage
    exit 1
fi

WIN_MOUNT="$1"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_DIR="${2:-/tmp/windows-logs-$TIMESTAMP}"

# Validate mount point
if [ ! -d "$WIN_MOUNT/Windows/System32" ]; then
    echo -e "${RED}Error: $WIN_MOUNT does not appear to be a Windows installation${NC}"
    echo "Expected to find: $WIN_MOUNT/Windows/System32"
    exit 1
fi

echo -e "${CYAN}Windows Log Collector${NC}"
echo "====================="
echo "Source: $WIN_MOUNT"
echo "Output: $OUTPUT_DIR"
echo ""

mkdir -p "$OUTPUT_DIR"/{EvtxLogs,RegistryHives,Logs,CrashDumps,SystemInfo}

# Collect Event Logs
echo -e "${CYAN}[*] Collecting Event Logs...${NC}"
evtx_src="$WIN_MOUNT/Windows/System32/winevt/Logs"
if [ -d "$evtx_src" ]; then
    cp -r "$evtx_src"/* "$OUTPUT_DIR/EvtxLogs/" 2>/dev/null || true
    count=$(find "$OUTPUT_DIR/EvtxLogs" -name "*.evtx" 2>/dev/null | wc -l)
    echo -e "${GREEN}    Collected $count .evtx files${NC}"
else
    echo -e "${YELLOW}    Event logs not found${NC}"
fi

# Collect Registry Hives (excluding sensitive ones)
echo -e "${CYAN}[*] Collecting Registry Hives...${NC}"
reg_src="$WIN_MOUNT/Windows/System32/config"
if [ -d "$reg_src" ]; then
    for hive in SYSTEM SOFTWARE DEFAULT; do
        if [ -f "$reg_src/$hive" ]; then
            cp "$reg_src/$hive" "$OUTPUT_DIR/RegistryHives/" 2>/dev/null && echo "    $hive"
        fi
    done
    echo -e "${GREEN}    Registry hives collected (SAM/SECURITY excluded)${NC}"
else
    echo -e "${YELLOW}    Registry hives not found${NC}"
fi

# Collect Windows Update Logs
echo -e "${CYAN}[*] Collecting Windows Update Logs...${NC}"
for logdir in "Windows/Logs/WindowsUpdate" "Windows/Logs/CBS" "Windows/Logs/DISM"; do
    if [ -d "$WIN_MOUNT/$logdir" ]; then
        dirname=$(basename "$logdir")
        cp -r "$WIN_MOUNT/$logdir" "$OUTPUT_DIR/Logs/$dirname" 2>/dev/null
        echo "    $dirname"
    fi
done

# Collect Setup Logs
echo -e "${CYAN}[*] Collecting Setup Logs...${NC}"
if [ -d "$WIN_MOUNT/Windows/Panther" ]; then
    cp -r "$WIN_MOUNT/Windows/Panther" "$OUTPUT_DIR/Logs/Panther" 2>/dev/null
    echo "    Panther"
fi

# Collect Minidumps
echo -e "${CYAN}[*] Collecting Crash Dumps...${NC}"
if [ -d "$WIN_MOUNT/Windows/Minidump" ]; then
    cp -r "$WIN_MOUNT/Windows/Minidump" "$OUTPUT_DIR/CrashDumps/Minidump" 2>/dev/null
    count=$(find "$OUTPUT_DIR/CrashDumps/Minidump" -name "*.dmp" 2>/dev/null | wc -l)
    echo "    $count minidump files"
fi

# Check for MEMORY.DMP (only copy if < 500MB)
if [ -f "$WIN_MOUNT/Windows/MEMORY.DMP" ]; then
    size=$(stat -c%s "$WIN_MOUNT/Windows/MEMORY.DMP" 2>/dev/null || echo 0)
    if [ "$size" -lt 524288000 ]; then
        cp "$WIN_MOUNT/Windows/MEMORY.DMP" "$OUTPUT_DIR/CrashDumps/" 2>/dev/null
        echo "    MEMORY.DMP ($(numfmt --to=iec $size))"
    else
        echo -e "${YELLOW}    MEMORY.DMP skipped ($(numfmt --to=iec $size) > 500MB)${NC}"
    fi
fi

# Create summary
echo -e "${CYAN}[*] Creating collection summary...${NC}"
cat > "$OUTPUT_DIR/COLLECTION_SUMMARY.txt" << EOF
Windows Log Collection Summary
==============================
Collection Date: $(date)
Source: $WIN_MOUNT
Collector: Linux Diagnostic USB

Collected Data:
$(find "$OUTPUT_DIR" -type f | wc -l) files total
$(du -sh "$OUTPUT_DIR" | cut -f1) total size

Contents:
$(ls -la "$OUTPUT_DIR")
EOF

# Create ZIP archive
echo -e "${CYAN}[*] Creating ZIP archive...${NC}"
zip_name="windows-logs-$TIMESTAMP.zip"
(cd "$OUTPUT_DIR" && zip -r "../$zip_name" . -x "*.zip") >/dev/null
zip_path="$(dirname "$OUTPUT_DIR")/$zip_name"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} Collection Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Output directory: $OUTPUT_DIR"
echo "ZIP archive:      $zip_path"
echo "Size:             $(du -sh "$zip_path" | cut -f1)"
echo ""
echo "To upload: ./upload-file.sh $zip_path"
SCRIPT_EOF

    #---------------------------------------------------------------------------
    # 6. upload-file.sh - Upload files to PhoneHomeWeb server
    #---------------------------------------------------------------------------
    cat > "$scripts_dir/upload-file.sh" << 'SCRIPT_EOF'
#!/bin/bash
#===============================================================================
# File Upload Helper
# Uploads files to PhoneHomeWeb server
#===============================================================================

# Default values (can be overridden by environment or arguments)
SERVER_URL="${SERVER_URL:-<<SERVERURL>>}"
AUTH_KEY="${AUTH_KEY:-<<AUTHKEY>>}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

show_usage() {
    echo "File Upload Helper"
    echo ""
    echo "Usage: $0 <file> [options]"
    echo ""
    echo "Arguments:"
    echo "  file              File to upload"
    echo ""
    echo "Options:"
    echo "  -s, --server URL  Server URL (default: $SERVER_URL)"
    echo "  -k, --key KEY     Authentication key"
    echo "  -h, --help        Show this help"
    echo ""
    echo "Environment variables:"
    echo "  SERVER_URL        Upload server URL"
    echo "  AUTH_KEY          Authentication key"
    echo ""
    echo "Example:"
    echo "  $0 /tmp/windows-logs.zip"
    echo "  $0 /tmp/report.txt --server https://myserver:3500/upload"
}

FILE=""

while [ $# -gt 0 ]; do
    case "$1" in
        -s|--server) SERVER_URL="$2"; shift 2 ;;
        -k|--key) AUTH_KEY="$2"; shift 2 ;;
        -h|--help) show_usage; exit 0 ;;
        -*) echo "Unknown option: $1"; show_usage; exit 1 ;;
        *) FILE="$1"; shift ;;
    esac
done

if [ -z "$FILE" ]; then
    show_usage
    exit 1
fi

if [ ! -f "$FILE" ]; then
    echo -e "${RED}Error: File not found: $FILE${NC}"
    exit 1
fi

# Check if server URL is still placeholder (use single angle brackets so server doesn't replace these)
if [[ "$SERVER_URL" == *"<SERVERURL>"* ]] || [[ "$SERVER_URL" == "<<SERVERURL>>" ]]; then
    echo -e "${YELLOW}Server URL not configured.${NC}"
    read -p "Enter server URL (e.g., https://server:3500/upload): " SERVER_URL
fi

if [[ "$AUTH_KEY" == *"<AUTHKEY>"* ]] || [[ "$AUTH_KEY" == "<<AUTHKEY>>" ]] || [ -z "$AUTH_KEY" ]; then
    echo -e "${YELLOW}Auth key not configured.${NC}"
    read -p "Enter authentication key: " AUTH_KEY
fi

filename=$(basename "$FILE")
filesize=$(stat -c%s "$FILE" | numfmt --to=iec)

echo -e "${CYAN}Uploading: $filename ($filesize)${NC}"
echo "Target: $SERVER_URL"
echo ""

# Upload using curl
response=$(curl -s -w "\n%{http_code}" \
    -X POST \
    -H "X-Auth-Key: $AUTH_KEY" \
    -F "file=@$FILE;filename=$filename" \
    "$SERVER_URL" 2>&1)

http_code=$(echo "$response" | tail -1)
body=$(echo "$response" | head -n -1)

if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
    echo -e "${GREEN}[+] Upload successful! (HTTP $http_code)${NC}"
    echo "$body"
else
    echo -e "${RED}[-] Upload failed (HTTP $http_code)${NC}"
    echo "$body"
    exit 1
fi
SCRIPT_EOF

    #---------------------------------------------------------------------------
    # 7. system-info.sh - Collect hardware/system information
    #---------------------------------------------------------------------------
    cat > "$scripts_dir/system-info.sh" << 'SCRIPT_EOF'
#!/bin/bash
#===============================================================================
# System Information Collector
# Gathers comprehensive hardware and system details
#===============================================================================

OUTPUT_DIR="/tmp/sysinfo-$(date +%Y%m%d-%H%M%S)"
REPORT="$OUTPUT_DIR/system-info.txt"

mkdir -p "$OUTPUT_DIR"

echo "Collecting system information..."
echo ""

{
    echo "================================================================================"
    echo " SYSTEM INFORMATION REPORT"
    echo " Generated: $(date)"
    echo "================================================================================"
    echo ""
    
    echo "=== SYSTEM ==="
    dmidecode -t system 2>/dev/null || echo "(dmidecode not available)"
    echo ""
    
    echo "=== BIOS ==="
    dmidecode -t bios 2>/dev/null | head -20
    echo ""
    
    echo "=== CPU ==="
    lscpu 2>/dev/null || cat /proc/cpuinfo
    echo ""
    
    echo "=== MEMORY ==="
    free -h
    echo ""
    dmidecode -t memory 2>/dev/null | grep -E "Size|Type|Speed|Manufacturer" | head -20
    echo ""
    
    echo "=== STORAGE ==="
    lsblk -o NAME,SIZE,TYPE,MODEL,SERIAL,ROTA
    echo ""
    
    echo "=== PCI DEVICES ==="
    lspci 2>/dev/null || echo "(lspci not available)"
    echo ""
    
    echo "=== USB DEVICES ==="
    lsusb 2>/dev/null || echo "(lsusb not available)"
    echo ""
    
    echo "=== NETWORK INTERFACES ==="
    ip addr 2>/dev/null || ifconfig 2>/dev/null
    echo ""
    
    echo "=== LSHW SUMMARY ==="
    lshw -short 2>/dev/null || echo "(lshw not available)"
    
} > "$REPORT" 2>&1

echo "Report saved to: $REPORT"
echo ""
echo "Quick summary:"
echo "--------------"
grep -E "Product Name|Serial Number" "$REPORT" | head -4
echo ""
cat "$REPORT" | grep -A1 "=== CPU ===" | tail -1 | head -1
free -h | grep Mem
echo ""
echo "Full report: less $REPORT"
SCRIPT_EOF

    #---------------------------------------------------------------------------
    # 8. gpt-backup.sh - Backup and restore GPT partition tables
    #---------------------------------------------------------------------------
    cat > "$scripts_dir/gpt-backup.sh" << 'SCRIPT_EOF'
#!/bin/bash
#===============================================================================
# GPT Partition Table Backup/Restore
# Critical tool for partition table recovery
#===============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

show_usage() {
    echo "GPT Partition Table Backup/Restore"
    echo ""
    echo "Usage: $0 <action> <device> [backup-file]"
    echo ""
    echo "Actions:"
    echo "  backup     Save GPT to file"
    echo "  restore    Restore GPT from file"
    echo "  verify     Verify GPT integrity"
    echo "  show       Display current GPT"
    echo ""
    echo "Examples:"
    echo "  $0 backup /dev/sda /tmp/sda-gpt.bak"
    echo "  $0 restore /dev/sda /tmp/sda-gpt.bak"
    echo "  $0 verify /dev/sda"
    echo "  $0 show /dev/sda"
}

if [ $# -lt 2 ]; then
    show_usage
    exit 1
fi

ACTION="$1"
DEVICE="$2"
BACKUP_FILE="${3:-/tmp/$(basename $DEVICE)-gpt-$(date +%Y%m%d-%H%M%S).bak}"

if [ ! -b "$DEVICE" ]; then
    echo -e "${RED}Error: Device $DEVICE not found${NC}"
    exit 1
fi

case "$ACTION" in
    backup)
        echo "Backing up GPT from $DEVICE to $BACKUP_FILE..."
        if sgdisk -b "$BACKUP_FILE" "$DEVICE"; then
            echo -e "${GREEN}[+] GPT backup saved to: $BACKUP_FILE${NC}"
            echo ""
            echo "Partition table backed up:"
            sgdisk -p "$DEVICE"
        else
            echo -e "${RED}[-] Backup failed${NC}"
            exit 1
        fi
        ;;
    
    restore)
        if [ ! -f "$BACKUP_FILE" ]; then
            echo -e "${RED}Error: Backup file not found: $BACKUP_FILE${NC}"
            exit 1
        fi
        
        echo -e "${YELLOW}WARNING: This will overwrite the partition table on $DEVICE${NC}"
        echo "Current partition table:"
        sgdisk -p "$DEVICE"
        echo ""
        read -p "Are you sure? Type 'YES' to confirm: " confirm
        
        if [ "$confirm" = "YES" ]; then
            echo "Restoring GPT from $BACKUP_FILE to $DEVICE..."
            if sgdisk -l "$BACKUP_FILE" "$DEVICE"; then
                echo -e "${GREEN}[+] GPT restored successfully${NC}"
                partprobe "$DEVICE"
            else
                echo -e "${RED}[-] Restore failed${NC}"
                exit 1
            fi
        else
            echo "Cancelled."
        fi
        ;;
    
    verify)
        echo "Verifying GPT on $DEVICE..."
        if sgdisk -v "$DEVICE"; then
            echo -e "${GREEN}[+] GPT appears valid${NC}"
        else
            echo -e "${YELLOW}[!] GPT may have issues${NC}"
            echo ""
            echo "To attempt repair: sgdisk -e $DEVICE"
        fi
        ;;
    
    show)
        echo "Partition table for $DEVICE:"
        echo ""
        sgdisk -p "$DEVICE"
        ;;
    
    *)
        echo -e "${RED}Unknown action: $ACTION${NC}"
        show_usage
        exit 1
        ;;
esac
SCRIPT_EOF

    #---------------------------------------------------------------------------
    # 9. recover-data.sh - Improved data recovery helper
    #---------------------------------------------------------------------------
    cat > "$scripts_dir/recover-data.sh" << 'SCRIPT_EOF'
#!/bin/bash
#===============================================================================
# Data Recovery Helper
# Guided data recovery using ddrescue and other tools
#===============================================================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

show_usage() {
    echo "Data Recovery Helper"
    echo ""
    echo "Usage: $0 <action> [options]"
    echo ""
    echo "Actions:"
    echo "  clone       Clone disk/partition with error recovery (ddrescue)"
    echo "  resume      Resume interrupted clone operation"
    echo "  partitions  Recover lost partitions (testdisk)"
    echo "  files       Recover deleted files (photorec)"
    echo ""
    echo "Clone options:"
    echo "  $0 clone <source> <destination> [logfile]"
    echo ""
    echo "Examples:"
    echo "  $0 clone /dev/sda /dev/sdb                  # Clone disk to disk"
    echo "  $0 clone /dev/sda1 /mnt/external/disk.img   # Clone to image file"
    echo "  $0 resume /mnt/external/disk.img            # Resume with existing log"
    echo "  $0 partitions /dev/sda                      # Launch testdisk"
    echo "  $0 files /dev/sda1                          # Launch photorec"
}

clone_disk() {
    local source="$1"
    local dest="$2"
    local logfile="${3:-${dest}.log}"
    
    if [ ! -b "$source" ] && [ ! -f "$source" ]; then
        echo -e "${RED}Error: Source not found: $source${NC}"
        exit 1
    fi
    
    echo -e "${CYAN}Data Recovery Clone${NC}"
    echo "==================="
    echo "Source:      $source"
    echo "Destination: $dest"
    echo "Log file:    $logfile"
    echo ""
    
    # Create destination directory if needed
    if [[ "$dest" == */* ]]; then
        mkdir -p "$(dirname "$dest")"
    fi
    
    echo -e "${YELLOW}This will clone data from $source to $dest${NC}"
    echo "ddrescue will:"
    echo "  - Skip bad sectors on first pass"
    echo "  - Retry bad sectors up to 3 times"
    echo "  - Log progress for resume capability"
    echo ""
    read -p "Continue? (y/n): " confirm
    
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo "Cancelled."
        exit 0
    fi
    
    echo ""
    echo -e "${CYAN}Starting first pass (skip bad sectors)...${NC}"
    ddrescue -n "$source" "$dest" "$logfile"
    
    echo ""
    echo -e "${CYAN}Starting recovery pass (retry bad sectors 3 times)...${NC}"
    ddrescue -d -r3 "$source" "$dest" "$logfile"
    
    echo ""
    echo -e "${GREEN}Clone complete!${NC}"
    echo ""
    echo "Results saved to: $dest"
    echo "Log file: $logfile"
    echo ""
    echo "If destination is an image file, mount with:"
    echo "  mount -o loop $dest /mnt/recovered"
}

resume_clone() {
    local dest="$1"
    local logfile="${dest}.log"
    
    if [ ! -f "$logfile" ]; then
        echo -e "${RED}Error: Log file not found: $logfile${NC}"
        echo "Cannot resume without the original log file."
        exit 1
    fi
    
    # Extract source from log file
    source=$(head -5 "$logfile" | grep "^#" | grep -oP '/dev/\S+' | head -1)
    
    if [ -z "$source" ]; then
        echo "Could not determine source from log file."
        read -p "Enter source device: " source
    fi
    
    echo -e "${CYAN}Resuming clone operation${NC}"
    echo "Source: $source"
    echo "Dest:   $dest"
    echo "Log:    $logfile"
    echo ""
    
    ddrescue -d -r3 "$source" "$dest" "$logfile"
}

if [ $# -lt 1 ]; then
    show_usage
    exit 1
fi

case "$1" in
    clone)
        if [ $# -lt 3 ]; then
            echo "Usage: $0 clone <source> <destination> [logfile]"
            exit 1
        fi
        clone_disk "$2" "$3" "$4"
        ;;
    
    resume)
        if [ $# -lt 2 ]; then
            echo "Usage: $0 resume <destination-file>"
            exit 1
        fi
        resume_clone "$2"
        ;;
    
    partitions)
        device="${2:-}"
        if [ -n "$device" ]; then
            echo "Launching testdisk on $device..."
            testdisk "$device"
        else
            echo "Launching testdisk..."
            testdisk
        fi
        ;;
    
    files)
        device="${2:-}"
        if [ -n "$device" ]; then
            echo "Launching photorec on $device..."
            photorec "$device"
        else
            echo "Launching photorec..."
            photorec
        fi
        ;;
    
    -h|--help)
        show_usage
        ;;
    
    *)
        echo -e "${RED}Unknown action: $1${NC}"
        show_usage
        exit 1
        ;;
esac
SCRIPT_EOF

    #---------------------------------------------------------------------------
    # 10. network-setup.sh - Network configuration helper
    #---------------------------------------------------------------------------
    cat > "$scripts_dir/network-setup.sh" << 'SCRIPT_EOF'
#!/bin/bash
#===============================================================================
# Network Setup Helper
# Configure network for diagnostics and uploads
#===============================================================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

show_status() {
    echo -e "${CYAN}Current Network Status${NC}"
    echo "======================"
    echo ""
    
    # Show interfaces
    echo "Interfaces:"
    ip -br addr 2>/dev/null || ifconfig 2>/dev/null
    echo ""
    
    # Show default route
    echo "Default Gateway:"
    ip route | grep default || route -n | grep "^0.0.0.0"
    echo ""
    
    # Show DNS
    echo "DNS Servers:"
    cat /etc/resolv.conf 2>/dev/null | grep nameserver
    echo ""
    
    # Test connectivity
    echo "Connectivity Test:"
    if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
        echo -e "  Internet: ${GREEN}OK${NC}"
    else
        echo -e "  Internet: ${RED}No connection${NC}"
    fi
    
    if ping -c 1 -W 2 google.com >/dev/null 2>&1; then
        echo -e "  DNS:      ${GREEN}OK${NC}"
    else
        echo -e "  DNS:      ${RED}Not resolving${NC}"
    fi
}

setup_dhcp() {
    local iface="$1"
    
    if [ -z "$iface" ]; then
        # Find first ethernet interface
        iface=$(ip -br link | grep -E "^(eth|en)" | head -1 | awk '{print $1}')
    fi
    
    if [ -z "$iface" ]; then
        echo -e "${RED}No network interface found${NC}"
        exit 1
    fi
    
    echo "Configuring DHCP on $iface..."
    
    # Bring up interface
    ip link set "$iface" up
    
    # Release any existing lease
    dhclient -r "$iface" 2>/dev/null
    
    # Get new lease
    if dhclient -v "$iface" 2>&1; then
        echo -e "${GREEN}DHCP configured successfully${NC}"
        show_status
    else
        echo -e "${RED}DHCP configuration failed${NC}"
        echo "Try: dhclient -v $iface"
    fi
}

setup_static() {
    local iface="$1"
    
    if [ -z "$iface" ]; then
        iface=$(ip -br link | grep -E "^(eth|en)" | head -1 | awk '{print $1}')
    fi
    
    echo "Static IP Configuration for $iface"
    echo ""
    
    read -p "IP Address (e.g., 192.168.1.100): " ipaddr
    read -p "Netmask (e.g., 255.255.255.0 or /24): " netmask
    read -p "Gateway (e.g., 192.168.1.1): " gateway
    read -p "DNS Server (e.g., 8.8.8.8): " dns
    
    # Convert netmask if needed
    if [[ "$netmask" == "255.255.255.0" ]]; then
        netmask="/24"
    elif [[ "$netmask" != /* ]]; then
        netmask="/$netmask"
    fi
    
    echo ""
    echo "Applying configuration..."
    
    ip addr flush dev "$iface"
    ip addr add "${ipaddr}${netmask}" dev "$iface"
    ip link set "$iface" up
    ip route add default via "$gateway"
    
    echo "nameserver $dns" > /etc/resolv.conf
    
    echo -e "${GREEN}Static IP configured${NC}"
    show_status
}

echo "Network Setup Helper"
echo "===================="
echo ""
echo "Options:"
echo "  [1] Show current network status"
echo "  [2] Configure DHCP (automatic)"
echo "  [3] Configure static IP"
echo "  [4] Test connectivity"
echo "  [5] Exit"
echo ""

read -p "Select option: " choice

case "$choice" in
    1) show_status ;;
    2) setup_dhcp ;;
    3) setup_static ;;
    4) 
        echo "Testing connectivity..."
        ping -c 3 8.8.8.8
        ;;
    5) exit 0 ;;
    *) echo "Invalid option" ;;
esac
SCRIPT_EOF

    #---------------------------------------------------------------------------
    # 11. Create comprehensive README.txt
    #---------------------------------------------------------------------------
    cat > "$scripts_mount/README.txt" << 'README_EOF'
===============================================================================
 LINUX DIAGNOSTIC USB - TECHNICIAN GUIDE
===============================================================================

ALL TOOLS ARE PRE-INSTALLED - No internet required for basic operations!

QUICK START
-----------
1. Mount this partition:    mount /dev/sdX2 /mnt/tools
2. Go to scripts:           cd /mnt/tools/scripts
3. Run script:              ./script-name.sh

AVAILABLE SCRIPTS
-----------------
  detect-bitlocker.sh     - Scan for BitLocker-encrypted partitions
  unlock-bitlocker.sh     - Unlock BitLocker drives with recovery key
  mount-windows.sh        - Mount Windows/NTFS partitions easily
  collect-windows-logs.sh - Collect logs from offline Windows
  upload-file.sh          - Upload files to PhoneHomeWeb server
  disk-diagnostics.sh     - Comprehensive disk health report
  system-info.sh          - Collect hardware/system information
  gpt-backup.sh           - Backup/restore GPT partition tables
  recover-data.sh         - Data recovery with ddrescue/testdisk
  network-setup.sh        - Configure network (DHCP/static)

COMMON WORKFLOWS
================

1. UNLOCK BITLOCKER AND COLLECT LOGS
------------------------------------
   # Find BitLocker partitions
   ./detect-bitlocker.sh
   
   # Unlock (get key from Azure AD or IT)
   ./unlock-bitlocker.sh /dev/sda3 "123456-789012-345678-901234-567890-123456-789012-345678"
   
   # Collect Windows logs
   ./collect-windows-logs.sh /mnt/windows
   
   # Upload to server
   ./upload-file.sh /tmp/windows-logs-*.zip

2. DIAGNOSE FAILING DISK
------------------------
   # Check SMART health
   ./disk-diagnostics.sh
   
   # Backup partition table FIRST
   ./gpt-backup.sh backup /dev/sda /tmp/sda-gpt.bak
   
   # Clone failing disk
   ./recover-data.sh clone /dev/sda /mnt/external/disk.img

3. RECOVER DELETED PARTITIONS
-----------------------------
   # Launch interactive partition recovery
   ./recover-data.sh partitions /dev/sda
   
   # Or use testdisk directly
   testdisk /dev/sda

4. MOUNT WINDOWS WITHOUT BITLOCKER
----------------------------------
   # List NTFS partitions
   ./mount-windows.sh --list
   
   # Mount read-only (safe)
   ./mount-windows.sh /dev/sda3
   
   # Mount read-write (for repairs)
   ./mount-windows.sh -w /dev/sda3

COMMAND QUICK REFERENCE
=======================

DISK INFORMATION
  lsblk                         List block devices
  lsblk -o +MODEL,SERIAL        Include model and serial
  blkid                         Show filesystem types and UUIDs
  fdisk -l /dev/sda             Show partition table
  smartctl -a /dev/sda          Full SMART data

MOUNTING
  mount -t ntfs-3g /dev/sda1 /mnt/win    Mount NTFS read-write
  mount -o ro /dev/sda1 /mnt/win         Mount read-only
  umount /mnt/win                         Unmount

BITLOCKER
  dislocker -V /dev/sda3 -p"KEY" -- /mnt/bl    Unlock to /mnt/bl
  mount -o loop /mnt/bl/dislocker-file /mnt/w  Mount decrypted volume

PARTITION RECOVERY
  testdisk /dev/sda              Interactive partition recovery
  gdisk /dev/sda                 GPT partition editor
  sgdisk -p /dev/sda             Print GPT partition table
  sgdisk -v /dev/sda             Verify GPT

DATA RECOVERY
  ddrescue -n /dev/sda /tmp/d.img /tmp/d.log   First pass (skip errors)
  ddrescue -r3 /dev/sda /tmp/d.img /tmp/d.log  Retry bad sectors
  photorec /dev/sda                             File recovery

NETWORK
  ip addr                        Show IP addresses
  dhclient eth0                  Get DHCP address
  ping 8.8.8.8                   Test connectivity

WHERE TO GET BITLOCKER KEYS
===========================
  Azure AD:          portal.azure.com > Devices > BitLocker keys
  Active Directory:  Check with domain admin
  Microsoft Account: account.microsoft.com/devices
  Local backup:      Look for saved key files

TIPS
====
  - Always work READ-ONLY when possible
  - Backup partition tables BEFORE making changes
  - For failing disks, clone first, then work on the copy
  - Check disk health (SMART) before trusting a drive
  - Document everything (take photos of screens)

TROUBLESHOOTING
===============
  NTFS mount fails:     Run 'ntfsfix /dev/sdX1' first
  BitLocker fails:      Verify key format (8 groups of 6 digits)
  No network:           Run 'dhclient eth0' or ./network-setup.sh
  Script permission:    Run 'chmod +x script.sh'

===============================================================================
README_EOF

    #---------------------------------------------------------------------------
    # 12. Create cheat-sheet.txt for quick reference
    #---------------------------------------------------------------------------
    cat > "$scripts_mount/cheat-sheet.txt" << 'CHEAT_EOF'
╔══════════════════════════════════════════════════════════════════════════════╗
║                    LINUX DIAGNOSTIC USB - CHEAT SHEET                        ║
╚══════════════════════════════════════════════════════════════════════════════╝

┌─ DISK INFO ──────────────────────────────────────────────────────────────────┐
│ lsblk                    │ List all block devices                            │
│ lsblk -f                 │ Show filesystems                                  │
│ blkid                    │ Show UUIDs and types                              │
│ fdisk -l                 │ Show all partition tables                         │
│ smartctl -H /dev/sda     │ Quick SMART health check                          │
│ smartctl -a /dev/sda     │ Full SMART report                                 │
└──────────────────────────┴───────────────────────────────────────────────────┘

┌─ MOUNTING ───────────────────────────────────────────────────────────────────┐
│ mount /dev/sda1 /mnt              │ Basic mount                              │
│ mount -t ntfs-3g /dev/sda1 /mnt   │ Mount NTFS (read-write)                  │
│ mount -o ro /dev/sda1 /mnt        │ Mount read-only                          │
│ umount /mnt                       │ Unmount                                  │
└───────────────────────────────────┴──────────────────────────────────────────┘

┌─ BITLOCKER ──────────────────────────────────────────────────────────────────┐
│ Step 1: Unlock                                                               │
│   dislocker -V /dev/sda3 -p"KEY" -- /mnt/bitlocker                          │
│                                                                              │
│ Step 2: Mount decrypted volume                                               │
│   mount -o loop /mnt/bitlocker/dislocker-file /mnt/windows                  │
│                                                                              │
│ Key format: 123456-789012-345678-901234-567890-123456-789012-345678         │
└──────────────────────────────────────────────────────────────────────────────┘

┌─ PARTITION RECOVERY ─────────────────────────────────────────────────────────┐
│ testdisk /dev/sda        │ Interactive partition recovery                    │
│ gdisk /dev/sda           │ GPT editor (p=print, v=verify, w=write)          │
│ sgdisk -b file /dev/sda  │ Backup GPT                                        │
│ sgdisk -l file /dev/sda  │ Restore GPT                                       │
└──────────────────────────┴───────────────────────────────────────────────────┘

┌─ DATA RECOVERY ──────────────────────────────────────────────────────────────┐
│ # Clone failing disk (safe method):                                         │
│ ddrescue -n /dev/sda /tmp/disk.img /tmp/disk.log    # Pass 1: skip errors   │
│ ddrescue -r3 /dev/sda /tmp/disk.img /tmp/disk.log   # Pass 2: retry errors  │
│                                                                              │
│ # Recover deleted files:                                                     │
│ photorec /dev/sda                                                            │
└──────────────────────────────────────────────────────────────────────────────┘

┌─ NETWORK ────────────────────────────────────────────────────────────────────┐
│ ip addr                  │ Show IP addresses                                 │
│ dhclient eth0            │ Get DHCP address                                  │
│ ip route                 │ Show routing table                                │
│ ping 8.8.8.8             │ Test internet                                     │
│ curl -I https://url      │ Test HTTPS                                        │
└──────────────────────────┴───────────────────────────────────────────────────┘

┌─ FILESYSTEM REPAIR ──────────────────────────────────────────────────────────┐
│ ntfsfix /dev/sda1        │ Fix NTFS dirty flag (before mounting)             │
│ fsck.ext4 /dev/sda1      │ Check/repair ext4                                 │
│ xfs_repair /dev/sda1     │ Repair XFS                                        │
└──────────────────────────┴───────────────────────────────────────────────────┘

CHEAT_EOF

    #---------------------------------------------------------------------------
    # 12. boot-repair.sh - Windows boot repair helper
    #---------------------------------------------------------------------------
    cat > "$scripts_dir/boot-repair.sh" << 'SCRIPT_EOF'
#!/bin/bash
#===============================================================================
# Windows Boot Repair Helper
# Helps diagnose and repair Windows boot issues from Linux
#===============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

show_usage() {
    echo "Windows Boot Repair Helper"
    echo ""
    echo "This tool helps diagnose Windows boot issues from Linux."
    echo "For actual repair, you may need Windows Recovery Environment."
    echo ""
    echo "Usage: $0 <action>"
    echo ""
    echo "Actions:"
    echo "  diagnose      Analyze boot configuration"
    echo "  check-bcd     Check BCD store"
    echo "  backup-bcd    Backup BCD files"
    echo "  info          Show system/boot partition info"
    echo ""
    echo "Common Windows boot repair commands (run from WinRE):"
    echo "  bootrec /fixmbr         - Repair Master Boot Record"
    echo "  bootrec /fixboot        - Repair boot sector"
    echo "  bootrec /rebuildbcd     - Rebuild BCD store"
    echo "  bcdboot C:\\Windows      - Reinstall bootloader"
}

find_efi_partition() {
    for part in /dev/sd?? /dev/nvme?n?p?; do
        [ -b "$part" ] || continue
        fstype=$(blkid -o value -s TYPE "$part" 2>/dev/null)
        if [ "$fstype" = "vfat" ]; then
            # Check if it's an EFI partition by looking for EFI directory
            mount -t vfat -o ro "$part" /mnt/efi-check 2>/dev/null || continue
            if [ -d "/mnt/efi-check/EFI" ]; then
                echo "$part"
                umount /mnt/efi-check 2>/dev/null
                return 0
            fi
            umount /mnt/efi-check 2>/dev/null
        fi
    done
    return 1
}

find_windows_partition() {
    for part in /dev/sd?? /dev/nvme?n?p?; do
        [ -b "$part" ] || continue
        fstype=$(blkid -o value -s TYPE "$part" 2>/dev/null)
        if [ "$fstype" = "ntfs" ] || [ "$fstype" = "BitLocker" ]; then
            # Quick check for Windows directory
            if [ "$fstype" = "ntfs" ]; then
                mount -t ntfs-3g -o ro "$part" /mnt/win-check 2>/dev/null || continue
                if [ -d "/mnt/win-check/Windows/System32" ]; then
                    echo "$part"
                    umount /mnt/win-check 2>/dev/null
                    return 0
                fi
                umount /mnt/win-check 2>/dev/null
            fi
        fi
    done
    return 1
}

diagnose_boot() {
    echo -e "${CYAN}=== Windows Boot Diagnostics ===${NC}"
    echo ""
    
    # Check for UEFI vs Legacy
    if [ -d /sys/firmware/efi ]; then
        echo -e "Boot Mode: ${GREEN}UEFI${NC}"
        boot_mode="uefi"
    else
        echo -e "Boot Mode: ${YELLOW}Legacy/BIOS${NC}"
        boot_mode="bios"
    fi
    echo ""
    
    # Find EFI partition
    if [ "$boot_mode" = "uefi" ]; then
        echo "Searching for EFI System Partition..."
        mkdir -p /mnt/efi-check 2>/dev/null
        efi_part=$(find_efi_partition)
        if [ -n "$efi_part" ]; then
            echo -e "  EFI Partition: ${GREEN}$efi_part${NC}"
            
            # Mount and check
            mount -t vfat -o ro "$efi_part" /mnt/efi-check 2>/dev/null
            if [ -d "/mnt/efi-check/EFI/Microsoft/Boot" ]; then
                echo -e "  Microsoft Boot Folder: ${GREEN}Found${NC}"
                if [ -f "/mnt/efi-check/EFI/Microsoft/Boot/bootmgfw.efi" ]; then
                    echo -e "  Windows Boot Manager: ${GREEN}Found${NC}"
                else
                    echo -e "  Windows Boot Manager: ${RED}MISSING${NC}"
                fi
                if [ -f "/mnt/efi-check/EFI/Microsoft/Boot/BCD" ]; then
                    echo -e "  BCD Store: ${GREEN}Found${NC}"
                else
                    echo -e "  BCD Store: ${RED}MISSING${NC}"
                fi
            else
                echo -e "  Microsoft Boot Folder: ${RED}MISSING${NC}"
            fi
            umount /mnt/efi-check 2>/dev/null
        else
            echo -e "  EFI Partition: ${RED}Not found${NC}"
        fi
        rmdir /mnt/efi-check 2>/dev/null
    fi
    echo ""
    
    # Find Windows partition
    echo "Searching for Windows partition..."
    mkdir -p /mnt/win-check 2>/dev/null
    win_part=$(find_windows_partition)
    if [ -n "$win_part" ]; then
        echo -e "  Windows Partition: ${GREEN}$win_part${NC}"
    else
        echo -e "  Windows Partition: ${YELLOW}Not found (may be BitLocker encrypted)${NC}"
        echo "  Run ./detect-bitlocker.sh to check for encrypted volumes"
    fi
    rmdir /mnt/win-check 2>/dev/null
    echo ""
    
    # Partition table info
    echo "Partition Table Information:"
    echo "----------------------------"
    for disk in /dev/sd? /dev/nvme?n?; do
        [ -b "$disk" ] || continue
        pttype=$(blkid -o value -s PTTYPE "$disk" 2>/dev/null)
        echo "  $disk: ${pttype:-unknown} partition table"
    done
    echo ""
    
    echo "Recommendations:"
    echo "----------------"
    if [ "$boot_mode" = "uefi" ]; then
        echo "1. Boot from Windows Recovery USB/DVD"
        echo "2. Select 'Repair your computer' > Troubleshoot > Command Prompt"
        echo "3. Run: bcdboot C:\\Windows /s S: /f UEFI"
        echo "   (Replace S: with your EFI partition letter)"
    else
        echo "1. Boot from Windows Recovery USB/DVD"
        echo "2. Select 'Repair your computer' > Troubleshoot > Command Prompt"
        echo "3. Run: bootrec /fixmbr"
        echo "4. Run: bootrec /fixboot"
        echo "5. Run: bootrec /rebuildbcd"
    fi
}

check_bcd() {
    echo -e "${CYAN}=== BCD Store Check ===${NC}"
    echo ""
    
    # Try to find BCD on EFI partition or Windows system partition
    bcd_found=0
    
    for part in /dev/sd?? /dev/nvme?n?p?; do
        [ -b "$part" ] || continue
        fstype=$(blkid -o value -s TYPE "$part" 2>/dev/null)
        
        tmpdir="/mnt/bcd-check-$$"
        mkdir -p "$tmpdir"
        
        case "$fstype" in
            vfat)
                mount -t vfat -o ro "$part" "$tmpdir" 2>/dev/null || continue
                bcd_path="$tmpdir/EFI/Microsoft/Boot/BCD"
                ;;
            ntfs)
                mount -t ntfs-3g -o ro "$part" "$tmpdir" 2>/dev/null || continue
                bcd_path="$tmpdir/Boot/BCD"
                ;;
            *)
                rmdir "$tmpdir" 2>/dev/null
                continue
                ;;
        esac
        
        if [ -f "$bcd_path" ]; then
            echo -e "${GREEN}Found BCD on $part${NC}"
            echo "  Path: $bcd_path"
            echo "  Size: $(stat -c%s "$bcd_path") bytes"
            echo "  Modified: $(stat -c%y "$bcd_path")"
            bcd_found=1
            
            # Try to read BCD with hivexsh if available
            if command -v hivexsh &>/dev/null; then
                echo ""
                echo "BCD Registry Entries (partial):"
                hivexsh -f "$bcd_path" -c "ls" 2>/dev/null | head -20
            fi
        fi
        
        umount "$tmpdir" 2>/dev/null
        rmdir "$tmpdir" 2>/dev/null
    done
    
    if [ $bcd_found -eq 0 ]; then
        echo -e "${RED}No BCD store found${NC}"
        echo "The boot configuration may be corrupted or partition is encrypted."
    fi
}

backup_bcd() {
    backup_dir="/tmp/bcd-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$backup_dir"
    
    echo -e "${CYAN}=== Backing Up BCD Files ===${NC}"
    echo ""
    
    for part in /dev/sd?? /dev/nvme?n?p?; do
        [ -b "$part" ] || continue
        fstype=$(blkid -o value -s TYPE "$part" 2>/dev/null)
        
        tmpdir="/mnt/bcd-backup-$$"
        mkdir -p "$tmpdir"
        
        case "$fstype" in
            vfat)
                mount -t vfat -o ro "$part" "$tmpdir" 2>/dev/null || continue
                if [ -d "$tmpdir/EFI/Microsoft/Boot" ]; then
                    echo "Backing up from $part (EFI)..."
                    cp -r "$tmpdir/EFI/Microsoft/Boot" "$backup_dir/EFI-Boot-$(basename $part)"
                fi
                ;;
            ntfs)
                mount -t ntfs-3g -o ro "$part" "$tmpdir" 2>/dev/null || continue
                if [ -d "$tmpdir/Boot" ]; then
                    echo "Backing up from $part..."
                    cp -r "$tmpdir/Boot" "$backup_dir/Boot-$(basename $part)"
                fi
                ;;
        esac
        
        umount "$tmpdir" 2>/dev/null
        rmdir "$tmpdir" 2>/dev/null
    done
    
    if [ -n "$(ls -A "$backup_dir" 2>/dev/null)" ]; then
        echo ""
        echo -e "${GREEN}Backup saved to: $backup_dir${NC}"
        ls -la "$backup_dir"
    else
        echo -e "${YELLOW}No BCD files found to backup${NC}"
        rmdir "$backup_dir"
    fi
}

if [ $# -lt 1 ]; then
    show_usage
    exit 1
fi

case "$1" in
    diagnose)
        diagnose_boot
        ;;
    check-bcd|check)
        check_bcd
        ;;
    backup-bcd|backup)
        backup_bcd
        ;;
    info)
        diagnose_boot
        ;;
    -h|--help)
        show_usage
        ;;
    *)
        echo -e "${RED}Unknown action: $1${NC}"
        show_usage
        exit 1
        ;;
esac
SCRIPT_EOF

    #---------------------------------------------------------------------------
    # 13. Get Linux-Collector.sh (download from server or copy local)
    #---------------------------------------------------------------------------
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local collector_obtained=false
    
    # If server URL is configured, download from server (credentials get injected)
    # Use single angle brackets in check so server replacement doesn't break validation
    if [[ "$PHW_SERVER_URL" != *"<SERVERURL>"* && -n "$PHW_SERVER_URL" ]]; then
        log_info "Downloading Linux-Collector.sh from server (with credentials)..."
        local download_url="${PHW_SERVER_URL%/}/payloads/LinuxCollector/download/Linux-Collector.sh"
        if curl -sf -H "X-Auth-Key: $PHW_AUTH_KEY" -o "$scripts_dir/Linux-Collector.sh" "$download_url"; then
            chmod +x "$scripts_dir/Linux-Collector.sh"
            echo "  Added: Linux-Collector.sh (downloaded with embedded credentials)"
            collector_obtained=true
        else
            log_warn "Failed to download from server, falling back to local copy"
        fi
    fi
    
    # Fallback: copy local file and inject credentials via sed
    if [[ "$collector_obtained" == "false" ]] && [ -f "$script_dir/Linux-Collector.sh" ]; then
        log_info "Copying Linux-Collector.sh to scripts partition..."
        cp "$script_dir/Linux-Collector.sh" "$scripts_dir/Linux-Collector.sh"
        chmod +x "$scripts_dir/Linux-Collector.sh"
        
        # Inject credentials if we have them
        if [[ "$PHW_SERVER_URL" != *"<SERVERURL>"* && -n "$PHW_SERVER_URL" ]]; then
            sed -i "s|<<SERVERURL>>|${PHW_SERVER_URL%/}|g" "$scripts_dir/Linux-Collector.sh"
            echo "  Added: Linux-Collector.sh (local copy with server URL injected)"
        else
            echo "  Added: Linux-Collector.sh (local copy - configure server manually)"
        fi
        if [[ "$PHW_AUTH_KEY" != *"<AUTHKEY>"* && -n "$PHW_AUTH_KEY" ]]; then
            sed -i "s|<<AUTHKEY>>|$PHW_AUTH_KEY|g" "$scripts_dir/Linux-Collector.sh"
        fi
        collector_obtained=true
    fi
    
    # Warn if Linux-Collector.sh was not obtained
    if [[ "$collector_obtained" == "false" ]]; then
        log_warn "Linux-Collector.sh not available - use collect-windows-logs.sh instead"
        log_warn "Or deploy collector after boot: curl -fsSL https://server/linuxcollector-installer | sudo bash"
    fi
    
    #---------------------------------------------------------------------------
    # 14. Inject credentials into upload-file.sh
    #---------------------------------------------------------------------------
    if [ -f "$scripts_dir/upload-file.sh" ]; then
        if [[ "$PHW_SERVER_URL" != *"<SERVERURL>"* && -n "$PHW_SERVER_URL" ]]; then
            sed -i "s|<<SERVERURL>>|${PHW_SERVER_URL%/}|g" "$scripts_dir/upload-file.sh"
        fi
        if [[ "$PHW_AUTH_KEY" != *"<AUTHKEY>"* && -n "$PHW_AUTH_KEY" ]]; then
            sed -i "s|<<AUTHKEY>>|$PHW_AUTH_KEY|g" "$scripts_dir/upload-file.sh"
        fi
    fi

    # Make all scripts executable
    chmod +x "$scripts_dir"/*.sh

    sync
    umount "$scripts_mount"
    rmdir "$scripts_mount"

    log_success "Helper scripts copied to scripts partition."
}

customize_live_system() {
    local squashfs_path="$1"
    local work_dir="$2"

    log_info "Customizing live system with recovery tools..."

    local squashfs_mount="$work_dir/squashfs-mount"
    local squashfs_edit="$work_dir/squashfs-edit"

    mkdir -p "$squashfs_mount" "$squashfs_edit"

    # Extract squashfs
    log_info "Extracting squashfs filesystem (this may take a while)..."
    unsquashfs -d "$squashfs_edit" "$squashfs_path"

    # Prepare chroot
    log_info "Preparing chroot environment..."
    mount --bind /dev "$squashfs_edit/dev"
    mount --bind /dev/pts "$squashfs_edit/dev/pts"
    mount -t proc proc "$squashfs_edit/proc"
    mount -t sysfs sysfs "$squashfs_edit/sys"
    
    # Mount /run for systemd-resolved DNS (if available on host)
    if [ -d /run/systemd/resolve ]; then
        mkdir -p "$squashfs_edit/run/systemd/resolve"
        mount --bind /run/systemd/resolve "$squashfs_edit/run/systemd/resolve" 2>/dev/null || true
    fi
    
    # Copy DNS configuration - try multiple methods for compatibility
    # Method 1: Direct resolv.conf copy (works on most systems)
    if [ -f /etc/resolv.conf ]; then
        # If resolv.conf is a symlink, copy the actual file content
        cat /etc/resolv.conf > "$squashfs_edit/etc/resolv.conf" 2>/dev/null || true
    fi
    
    # Method 2: If still empty or missing, add fallback DNS
    if [ ! -s "$squashfs_edit/etc/resolv.conf" ]; then
        log_warn "No DNS configuration found, adding fallback DNS servers..."
        cat > "$squashfs_edit/etc/resolv.conf" <<DNS
# Fallback DNS configuration for chroot
nameserver 8.8.8.8
nameserver 1.1.1.1
nameserver 9.9.9.9
DNS
    fi

    # Install packages
    log_info "Installing recovery tools in live environment..."
    cat > "$squashfs_edit/tmp/install-tools.sh" <<'INSTALL_SCRIPT'
#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive

echo "========================================"
echo " PhoneHomeWeb Live System Customization"
echo "========================================"
echo ""

# Check network connectivity
echo "Checking network connectivity..."
if ping -c 1 -W 5 deb.debian.org >/dev/null 2>&1; then
    echo "  Network: OK (deb.debian.org reachable)"
elif ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
    echo "  Network: Partial (IP works, DNS may have issues)"
else
    echo "  Network: FAILED"
    echo "  WARNING: No network connectivity detected in chroot"
    echo "  Package installation will likely fail"
    echo "  Check that /etc/resolv.conf is properly copied"
fi
echo ""

# Detect distribution and codename
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "${VERSION_CODENAME:-${ID:-debian}}"
    elif command -v lsb_release >/dev/null 2>&1; then
        lsb_release -cs 2>/dev/null || echo "bookworm"
    else
        echo "bookworm"
    fi
}

CODENAME=$(detect_distro)
echo "Detected distribution codename: $CODENAME"

# Remove live media sources that break apt in chroot
echo "Removing live media sources..."

# Handle traditional sources.list
if [ -f /etc/apt/sources.list ]; then
    # Remove lines referencing live media
    sed -i '/file:\/\/\/run\/live\/medium/d' /etc/apt/sources.list
    sed -i '/file:\/\/\/cdrom/d' /etc/apt/sources.list
    # Remove empty file if it only had live sources
    [ -s /etc/apt/sources.list ] || rm -f /etc/apt/sources.list
fi

# Handle sources.list.d directory
if [ -d /etc/apt/sources.list.d ]; then
    # Process .list files
    for f in /etc/apt/sources.list.d/*.list; do
        [ -f "$f" ] || continue
        sed -i '/file:\/\/\/run\/live\/medium/d' "$f" 2>/dev/null || true
        sed -i '/file:\/\/\/cdrom/d' "$f" 2>/dev/null || true
        # Remove empty files
        [ -s "$f" ] || rm -f "$f"
    done
    
    # Handle DEB822 .sources files (Debian 12+/Trixie)
    for f in /etc/apt/sources.list.d/*.sources; do
        [ -f "$f" ] || continue
        if grep -qE 'file:///run/live/medium|file:///cdrom|URIs:.*file:' "$f" 2>/dev/null; then
            echo "Disabling live media source: $f"
            mv "$f" "${f}.disabled" 2>/dev/null || true
        fi
    done
fi

# Ensure we have working network sources
echo "Checking for network apt sources..."

has_network_sources() {
    grep -rqE 'https?://.*(debian|ubuntu)' /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources 2>/dev/null
}

if ! has_network_sources; then
    echo "No network sources found - adding Debian mirrors..."
    
    # Determine correct sources based on codename
    # Trixie is testing/unstable, so it doesn't have -security yet
    case "$CODENAME" in
        trixie|sid|unstable|testing)
            # Trixie/testing: no -security or -updates repos
            cat > /etc/apt/sources.list.d/debian-network.list <<SOURCES
deb http://deb.debian.org/debian ${CODENAME} main contrib non-free non-free-firmware
SOURCES
            ;;
        *)
            # Stable releases (bookworm, bullseye, etc.)
            cat > /etc/apt/sources.list.d/debian-network.list <<SOURCES
deb http://deb.debian.org/debian ${CODENAME} main contrib non-free non-free-firmware
deb http://deb.debian.org/debian ${CODENAME}-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security ${CODENAME}-security main contrib non-free non-free-firmware
SOURCES
            ;;
    esac
    echo "Created /etc/apt/sources.list.d/debian-network.list"
fi

# Show active sources
echo "Active apt sources:"
cat /etc/apt/sources.list 2>/dev/null || true
cat /etc/apt/sources.list.d/*.list 2>/dev/null || true
cat /etc/apt/sources.list.d/*.sources 2>/dev/null | grep -E '^(Types|URIs|Suites|Components):' || true
echo ""

# Update package lists with retry
echo "Updating package lists..."
apt_update_success=0
for attempt in 1 2 3; do
    if apt-get update 2>&1; then
        apt_update_success=1
        break
    else
        echo "apt-get update failed (attempt $attempt/3), retrying in 5s..."
        sleep 5
    fi
done

if [ "$apt_update_success" -eq 0 ]; then
    echo "WARNING: apt-get update failed after 3 attempts"
    echo "Attempting to continue with existing package cache..."
fi

# Install packages with better error handling
echo "Installing recovery/diagnostic tools..."

# Essential packages first (includes coreutils for numfmt)
ESSENTIAL_PKGS="coreutils parted gdisk ntfs-3g dosfstools rsync curl wget zip unzip"

# Recovery and diagnostic packages
RECOVERY_PKGS="dislocker testdisk gddrescue smartmontools cryptsetup lvm2 mdadm"

# Filesystem packages (fuse/fuse3 for fusermount, ntfsprogs for ntfsinfo)
FS_PKGS="e2fsprogs xfsprogs btrfs-progs fuse3"

# Hardware diagnostic packages
HW_PKGS="hdparm nvme-cli pciutils usbutils lshw dmidecode"

# Utility packages
UTIL_PKGS="p7zip-full less vim-tiny nano tmux htop iotop sysstat file"

install_packages() {
    local pkg_list="$1"
    local pkg_desc="$2"
    echo ""
    echo "Installing $pkg_desc..."
    
    # Try to install all at once first
    if apt-get install -y --no-install-recommends $pkg_list 2>&1; then
        echo "$pkg_desc installed successfully."
        return 0
    fi
    
    # If batch fails, try one by one
    echo "Batch install failed, trying individual packages..."
    local failed=""
    for pkg in $pkg_list; do
        if ! apt-get install -y --no-install-recommends "$pkg" 2>&1; then
            echo "  FAILED: $pkg"
            failed="$failed $pkg"
        fi
    done
    
    if [ -n "$failed" ]; then
        echo "WARNING: Some packages failed to install:$failed"
        return 1
    fi
    return 0
}

# Install each category
install_packages "$ESSENTIAL_PKGS" "essential tools" || true
install_packages "$RECOVERY_PKGS" "recovery tools" || true
install_packages "$FS_PKGS" "filesystem tools" || true
install_packages "$HW_PKGS" "hardware diagnostics" || true
install_packages "$UTIL_PKGS" "utilities" || true

# Verify critical tools are installed
echo ""
echo "Verifying critical tools..."

# Critical tools needed by tech scripts
critical_tools="parted gdisk ntfs-3g rsync dislocker smartctl curl zip"
missing=""
for tool in $critical_tools; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "  OK: $tool"
    else
        echo "  MISSING: $tool"
        missing="$missing $tool"
    fi
done

# Also verify packages that provide tools with different names
for pkg in "fuse3:fusermount3" "lshw:lshw" "dmidecode:dmidecode"; do
    pkgname="${pkg%%:*}"
    cmdname="${pkg##*:}"
    if command -v "$cmdname" >/dev/null 2>&1 || dpkg -l "$pkgname" 2>/dev/null | grep -q '^ii'; then
        echo "  OK: $pkgname ($cmdname)"
    else
        echo "  MISSING: $pkgname"
        missing="$missing $pkgname"
    fi
done

if [ -n "$missing" ]; then
    echo ""
    echo "WARNING: Critical tools missing:$missing"
    echo "The USB may have limited functionality."
else
    echo "All critical tools verified."
fi

# Clean up
apt-get clean
rm -rf /var/lib/apt/lists/*

echo ""
echo "Package installation complete."
INSTALL_SCRIPT

    chmod +x "$squashfs_edit/tmp/install-tools.sh"
    chroot "$squashfs_edit" /tmp/install-tools.sh || log_warn "Some packages may have failed to install"
    rm -f "$squashfs_edit/tmp/install-tools.sh"

    # Add welcome message / MOTD
    cat > "$squashfs_edit/etc/motd" <<'MOTD'

================================================================================
  PhoneHomeWeb Linux Diagnostic Environment
================================================================================

  Recovery & Diagnostic Tools Available:

  BitLocker / Encrypted Drives:
    dislocker           - Unlock BitLocker-encrypted Windows drives

  Partition Management:
    parted              - Partition editor
    gdisk / sgdisk      - GPT partition table management
    fdisk               - MBR partition table management

  Data Recovery:
    testdisk            - Partition recovery and file undelete
    ddrescue            - Data recovery from failing drives

  Filesystem Tools:
    ntfs-3g             - NTFS read/write support
    e2fsck              - ext2/3/4 filesystem check
    xfs_repair          - XFS filesystem repair
    btrfs check         - Btrfs filesystem check

  Disk Diagnostics:
    smartctl            - SMART disk health monitoring
    hdparm              - Disk parameters and benchmarks
    nvme                - NVMe drive management

  Quick Start:
    # Unlock a BitLocker drive:
    dislocker -V /dev/sdX1 -p<password> -- /mnt/bitlocker
    mount -o loop /mnt/bitlocker/dislocker-file /mnt/windows

    # Scan for lost partitions:
    testdisk /dev/sdX

    # Check disk health:
    smartctl -a /dev/sdX

================================================================================

MOTD

    # Cleanup chroot mounts
    log_info "Cleaning up chroot..."
    umount "$squashfs_edit/run/systemd/resolve" 2>/dev/null || true
    umount "$squashfs_edit/sys" 2>/dev/null || true
    umount "$squashfs_edit/proc" 2>/dev/null || true
    umount "$squashfs_edit/dev/pts" 2>/dev/null || true
    umount "$squashfs_edit/dev" 2>/dev/null || true
    rm -f "$squashfs_edit/etc/resolv.conf"

    # Configure desktop environment (if present)
    configure_desktop_automount "$squashfs_edit"

    # Repack squashfs
    log_info "Repacking squashfs filesystem (this may take a while)..."
    rm -f "$squashfs_path"
    mksquashfs "$squashfs_edit" "$squashfs_path" -comp xz -Xbcj x86 -b 1M

    # Cleanup
    rm -rf "$squashfs_edit" "$squashfs_mount"

    log_success "Live system customized with recovery tools."
}

configure_grub_persistence() {
    local usb_mount="$1"
    local with_persistence="$2"
    
    log_info "Configuring GRUB boot menu..."
    
    # Find GRUB config file (location varies by Debian version)
    local grub_cfg=""
    local grub_locations=(
        "$usb_mount/boot/grub/grub.cfg"
        "$usb_mount/EFI/boot/grub.cfg"
        "$usb_mount/boot/grub/loopback.cfg"
    )
    
    for cfg in "${grub_locations[@]}"; do
        if [[ -f "$cfg" ]]; then
            grub_cfg="$cfg"
            log_info "Found GRUB config: $grub_cfg"
            break
        fi
    done
    
    if [[ -z "$grub_cfg" ]]; then
        log_warn "GRUB config not found - persistence boot option not added"
        log_warn "You may need to add 'persistence' to boot parameters manually"
        return 1
    fi
    
    # Backup original
    cp "$grub_cfg" "${grub_cfg}.orig"
    
    # For Debian Live, we need to add persistence parameter to boot entries
    # The default entries boot without persistence; we modify them
    
    if [[ "$with_persistence" == "1" ]]; then
        # Add persistence parameter to existing linux/boot lines
        # Debian Live uses 'boot=live' parameter - add 'persistence' after it
        if grep -q "boot=live" "$grub_cfg"; then
            # Add persistence to all boot=live lines that don't have it
            sed -i 's/boot=live\([^p]\|$\)/boot=live persistence\1/g' "$grub_cfg"
            log_success "Added persistence parameter to GRUB boot entries"
        else
            log_warn "Could not find 'boot=live' in GRUB config - manual configuration may be needed"
        fi
        
        # Also create a custom menu entry for persistence (as backup)
        if ! grep -q "PhoneHomeWeb Persistence" "$grub_cfg"; then
            cat >> "$grub_cfg" << 'GRUB_ENTRY'

# PhoneHomeWeb custom entries
menuentry "PhoneHomeWeb Linux (Persistence Enabled)" {
    linux /live/vmlinuz boot=live persistence quiet splash
    initrd /live/initrd.img
}

menuentry "PhoneHomeWeb Linux (No Persistence - RAM only)" {
    linux /live/vmlinuz boot=live quiet splash
    initrd /live/initrd.img
}

menuentry "PhoneHomeWeb Linux (Recovery Mode)" {
    linux /live/vmlinuz boot=live persistence single
    initrd /live/initrd.img
}
GRUB_ENTRY
            log_success "Added custom PhoneHomeWeb boot menu entries"
        fi
    fi
    
    return 0
}

configure_desktop_automount() {
    local squashfs_edit="$1"
    
    log_info "Configuring desktop automount settings..."
    
    # Check if this is a desktop environment (has a display manager)
    local has_desktop=false
    if [[ -d "$squashfs_edit/usr/share/xsessions" ]] || \
       [[ -f "$squashfs_edit/usr/bin/startxfce4" ]] || \
       [[ -f "$squashfs_edit/usr/bin/gnome-session" ]] || \
       [[ -f "$squashfs_edit/usr/bin/startlxde" ]]; then
        has_desktop=true
    fi
    
    if [[ "$has_desktop" == "false" ]]; then
        log_info "No desktop environment detected - skipping desktop configuration"
        return 0
    fi
    
    # Create autostart directory for all users
    mkdir -p "$squashfs_edit/etc/xdg/autostart"
    mkdir -p "$squashfs_edit/etc/skel/.config/autostart"
    mkdir -p "$squashfs_edit/etc/skel/Desktop"
    
    # Create polkit rule to allow mounting without password
    mkdir -p "$squashfs_edit/etc/polkit-1/rules.d"
    cat > "$squashfs_edit/etc/polkit-1/rules.d/90-phonehomeweb-mount.rules" << 'POLKIT_RULE'
// Allow users in sudo group to mount/unmount without password
polkit.addRule(function(action, subject) {
    if ((action.id == "org.freedesktop.udisks2.filesystem-mount" ||
         action.id == "org.freedesktop.udisks2.filesystem-mount-system" ||
         action.id == "org.freedesktop.udisks2.filesystem-unmount-others" ||
         action.id == "org.freedesktop.udisks2.encrypted-unlock" ||
         action.id == "org.freedesktop.udisks2.encrypted-unlock-system") &&
        subject.isInGroup("sudo")) {
        return polkit.Result.YES;
    }
});
POLKIT_RULE
    
    # Create udev rule to auto-mount removable drives
    mkdir -p "$squashfs_edit/etc/udev/rules.d"
    cat > "$squashfs_edit/etc/udev/rules.d/99-phonehomeweb-automount.rules" << 'UDEV_RULE'
# Auto-create desktop shortcuts for block devices
ACTION=="add", SUBSYSTEM=="block", ENV{ID_FS_TYPE}!="", RUN+="/usr/local/bin/phw-desktop-mount.sh add %k"
ACTION=="remove", SUBSYSTEM=="block", RUN+="/usr/local/bin/phw-desktop-mount.sh remove %k"
UDEV_RULE
    
    # Create helper script for desktop icons
    mkdir -p "$squashfs_edit/usr/local/bin"
    cat > "$squashfs_edit/usr/local/bin/phw-desktop-mount.sh" << 'MOUNT_SCRIPT'
#!/bin/bash
# PhoneHomeWeb - Create desktop icons for detected partitions

ACTION="$1"
DEVICE="$2"

DESKTOP_DIR="/home/user/Desktop"
[ -d "$DESKTOP_DIR" ] || DESKTOP_DIR="/etc/skel/Desktop"

# Get device info
LABEL=$(blkid -o value -s LABEL "/dev/$DEVICE" 2>/dev/null)
FSTYPE=$(blkid -o value -s TYPE "/dev/$DEVICE" 2>/dev/null)
SIZE=$(lsblk -bno SIZE "/dev/$DEVICE" 2>/dev/null | numfmt --to=iec 2>/dev/null || echo "?")

# Skip if not a recognized filesystem
case "$FSTYPE" in
    ntfs|ext4|ext3|ext2|vfat|exfat|xfs|btrfs) ;;
    *) exit 0 ;;
esac

ICON_NAME="${LABEL:-$DEVICE}"
DESKTOP_FILE="$DESKTOP_DIR/mount-$DEVICE.desktop"

case "$ACTION" in
    add)
        [ -d "$DESKTOP_DIR" ] || exit 0
        
        cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=$ICON_NAME ($SIZE)
Comment=Mount /dev/$DEVICE ($FSTYPE)
Icon=drive-harddisk
Exec=sh -c 'udisksctl mount -b /dev/$DEVICE && xdg-open /run/media/\$(whoami)/$ICON_NAME || (mkdir -p /mnt/$DEVICE && mount /dev/$DEVICE /mnt/$DEVICE && xdg-open /mnt/$DEVICE)'
Terminal=false
Categories=System;FileTools;
EOF
        chmod +x "$DESKTOP_FILE"
        ;;
    remove)
        rm -f "$DESKTOP_FILE"
        ;;
esac
MOUNT_SCRIPT
    chmod +x "$squashfs_edit/usr/local/bin/phw-desktop-mount.sh"
    
    # Create initial desktop icons for common mount points
    cat > "$squashfs_edit/etc/skel/Desktop/Mount-Partitions.desktop" << 'DESKTOP_FILE'
[Desktop Entry]
Version=1.0
Type=Application
Name=Scan & Mount Partitions
Comment=Detect and show available partitions
Icon=drive-harddisk
Exec=sh -c 'for dev in /dev/sd?? /dev/nvme?n?p?; do [ -b "$dev" ] && /usr/local/bin/phw-desktop-mount.sh add $(basename $dev); done; notify-send "Partitions scanned" "Desktop icons created for detected partitions"'
Terminal=false
Categories=System;FileTools;
DESKTOP_FILE
    
    # Create link to tools partition on desktop
    cat > "$squashfs_edit/etc/skel/Desktop/Linux-Tools.desktop" << 'DESKTOP_FILE'
[Desktop Entry]
Version=1.0
Type=Application
Name=Linux Recovery Tools
Comment=Mount the tools partition and open scripts folder
Icon=folder-documents
Exec=sh -c 'mkdir -p /mnt/tools; for dev in /dev/sd?? /dev/nvme?n?p?; do [ -b "$dev" ] && blkid "$dev" 2>/dev/null | grep -q "LINUX-TOOLS" && mount "$dev" /mnt/tools && xdg-open /mnt/tools/scripts && exit 0; done; notify-send "Tools partition not found" "Insert the Linux USB and try again"'
Terminal=false
Categories=System;FileTools;
DESKTOP_FILE

    # Create terminal launcher
    cat > "$squashfs_edit/etc/skel/Desktop/Terminal.desktop" << 'DESKTOP_FILE'
[Desktop Entry]
Version=1.0
Type=Application
Name=Root Terminal
Comment=Open a root terminal for diagnostics
Icon=utilities-terminal
Exec=sudo -i
Terminal=true
Categories=System;TerminalEmulator;
DESKTOP_FILE

    chmod +x "$squashfs_edit/etc/skel/Desktop"/*.desktop
    
    log_success "Desktop automount and icons configured"
    return 0
}

install_syslinux_bootloader() {
    local usb_partition="$1"
    local usb_mount="$2"
    
    log_info "Installing syslinux bootloader for legacy BIOS boot..."
    
    # Get the device from partition (e.g., /dev/sdi1 -> /dev/sdi)
    local device="${usb_partition%[0-9]}"
    # Handle nvme/mmcblk naming (e.g., /dev/nvme0n1p1 -> /dev/nvme0n1)
    if [[ "$usb_partition" == *"p"[0-9]* ]]; then
        device="${usb_partition%p[0-9]*}"
    fi
    
    # Check if syslinux is available
    if ! command -v syslinux &>/dev/null; then
        log_warn "syslinux not found - legacy BIOS boot may not work"
        log_info "Install with: apt-get install syslinux syslinux-common"
        return 1
    fi
    
    # Debian Live ISOs use isolinux - we need to convert to syslinux for USB
    # Check for isolinux directory and copy config
    if [[ -d "$usb_mount/isolinux" ]]; then
        log_info "Converting isolinux to syslinux..."
        
        # Create syslinux directory if needed
        mkdir -p "$usb_mount/syslinux"
        
        # Copy isolinux files to syslinux
        cp -r "$usb_mount/isolinux/"* "$usb_mount/syslinux/" 2>/dev/null || true
        
        # Rename isolinux.cfg to syslinux.cfg
        if [[ -f "$usb_mount/syslinux/isolinux.cfg" ]]; then
            mv "$usb_mount/syslinux/isolinux.cfg" "$usb_mount/syslinux/syslinux.cfg"
        fi
        
        # Update any references from isolinux to syslinux in config files
        find "$usb_mount/syslinux" -name "*.cfg" -exec sed -i 's/isolinux/syslinux/g' {} \; 2>/dev/null || true
        
        log_success "Converted isolinux to syslinux"
    fi
    
    # Install syslinux to partition
    if command -v syslinux &>/dev/null; then
        log_info "Installing syslinux to partition..."
        syslinux --install "$usb_partition" 2>/dev/null || {
            log_warn "syslinux installation to partition failed (may need extlinux for ext4)"
        }
    fi
    
    # Install MBR
    local mbr_file=""
    local mbr_locations=(
        "/usr/lib/syslinux/mbr/mbr.bin"
        "/usr/lib/syslinux/bios/mbr.bin"
        "/usr/share/syslinux/mbr.bin"
        "/usr/lib/SYSLINUX/mbr.bin"
    )
    
    for mbr in "${mbr_locations[@]}"; do
        if [[ -f "$mbr" ]]; then
            mbr_file="$mbr"
            break
        fi
    done
    
    if [[ -n "$mbr_file" ]]; then
        log_info "Installing MBR from $mbr_file to $device..."
        dd if="$mbr_file" of="$device" bs=440 count=1 conv=notrunc 2>/dev/null
        log_success "MBR installed for legacy BIOS boot"
    else
        log_warn "MBR binary not found - legacy BIOS boot may not work"
        log_info "The USB should still boot on UEFI systems via EFI/boot/bootx64.efi"
    fi
    
    return 0
}

write_to_usb() {
    local extract_dir="$1"
    local usb_partition="$2"
    local with_persistence="${3:-1}"

    log_info "Writing files to USB..."

    local usb_mount="/mnt/linux-usb-$$"
    mkdir -p "$usb_mount"
    mount "$usb_partition" "$usb_mount"

    # Note: rsync may return code 23 when symlinks fail on FAT32 - this is expected
    # We use --no-links to skip symlinks entirely on FAT32 (they can't be created)
    # Use || true to prevent set -e from exiting on partial transfer warnings
    rsync -a --no-links --info=progress2 "$extract_dir/" "$usb_mount/" || {
        local rsync_code=$?
        if [[ $rsync_code -eq 23 ]]; then
            # Code 23 = "Partial transfer due to error" - symlinks fail on FAT32, which is expected
            log_warn "Some files were skipped (symlinks cannot be created on FAT32 - this is normal)"
        else
            log_error "rsync failed with exit code $rsync_code"
            umount "$usb_mount" 2>/dev/null || true
            rmdir "$usb_mount" 2>/dev/null || true
            return 1
        fi
    }

    # Configure GRUB for persistence boot
    configure_grub_persistence "$usb_mount" "$with_persistence"

    # Ensure boot files are in place for UEFI
    if [[ -d "$usb_mount/EFI" ]]; then
        log_success "UEFI boot files present."
    else
        log_warn "EFI directory not found - USB may not boot on UEFI systems."
    fi
    
    # Install syslinux for legacy BIOS boot
    install_syslinux_bootloader "$usb_partition" "$usb_mount"

    # Sync and unmount
    sync
    umount "$usb_mount"
    rmdir "$usb_mount"

    log_success "Files written to USB."
}

cleanup() {
    local work_dir="$1"
    local keep_work="$2"

    if [[ "$keep_work" == "1" ]]; then
        log_info "Keeping work directory: $work_dir"
    else
        log_info "Cleaning up work directory..."
        rm -rf "$work_dir"
    fi
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

main() {
    local device=""
    local debian_iso=""
    local iso_url=""
    local iso_base_url="$DEFAULT_ISO_BASE_URL"
    local with_persistence=1
    local persist_size=10240
    local skip_write=0
    local work_dir="/tmp/linux-usb-build"
    local keep_work=0
    local non_interactive=0

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --device)
                device="$2"; shift 2 ;;
            --debian-iso)
                debian_iso="$2"; shift 2 ;;
            --iso-url)
                iso_url="$2"; shift 2 ;;
            --iso-base-url)
                iso_base_url="$2"; shift 2 ;;
            --no-persistence)
                with_persistence=0; shift ;;
            --persist-size)
                persist_size="$2"; shift 2 ;;
            --skip-write)
                skip_write=1; shift ;;
            --work-dir)
                work_dir="$2"; shift 2 ;;
            --keep-work)
                keep_work=1; shift ;;
            --non-interactive)
                non_interactive=1; shift ;;
            --server-url)
                PHW_SERVER_URL="$2"; shift 2 ;;
            --auth-key)
                PHW_AUTH_KEY="$2"; shift 2 ;;
            -h|--help)
                usage; exit 0 ;;
            *)
                die "Unknown option: $1. Use --help for usage." ;;
        esac
    done

    echo ""
    echo "================================================================================"
    echo "  PhoneHomeWeb Linux USB Builder"
    echo "================================================================================"
    echo ""

    # Pre-flight checks
    check_root
    check_dependencies

    # Device selection
    if [[ "$skip_write" == "0" ]]; then
        if [[ -z "$device" ]]; then
            if [[ "$non_interactive" == "1" ]]; then
                die "No device specified. Use --device or remove --non-interactive."
            fi
            select_usb_device
        else
            DEVICE="$device"
        fi

        if [[ ! -b "$DEVICE" ]]; then
            die "Device not found: $DEVICE"
        fi

        if [[ "$non_interactive" == "0" ]]; then
            confirm_destructive "$DEVICE"
        fi
    fi

    # Setup work directory
    mkdir -p "$work_dir"
    log_info "Working directory: $work_dir"

    # ISO selection - interactive if no URL provided
    if [[ -z "$debian_iso" ]] && [[ -z "$iso_url" ]]; then
        if [[ "$non_interactive" == "1" ]]; then
            die "No ISO specified. Use --debian-iso or --iso-url, or remove --non-interactive."
        fi
        select_iso_from_mirror "$iso_base_url"
        iso_url="$SELECTED_ISO_URL"
    fi

    # Get or download ISO
    local iso_path="$debian_iso"
    if [[ -z "$iso_path" ]]; then
        local iso_filename
        iso_filename=$(basename "$iso_url")

        # Check common locations before downloading
        local candidates=(
            "$work_dir/$iso_filename"
            "./$iso_filename"
            "$SCRIPT_DIR/$iso_filename"
        )

        for candidate in "${candidates[@]}"; do
            if [[ -f "$candidate" ]]; then
                iso_path="$candidate"
                log_info "Using existing ISO: $iso_path"
                break
            fi
        done

        if [[ -z "$iso_path" ]]; then
            iso_path="$work_dir/$iso_filename"
            download_iso "$iso_url" "$iso_path"
        fi
    else
        if [[ ! -f "$iso_path" ]]; then
            die "ISO file not found: $iso_path"
        fi
        log_info "Using provided ISO: $iso_path"
    fi

    # Extract ISO
    local iso_mount="$work_dir/iso-mount"
    local extract_dir="$work_dir/iso-extract"
    extract_iso "$iso_path" "$iso_mount" "$extract_dir"

    # Find and customize squashfs
    local squashfs_path
    squashfs_path=$(find "$extract_dir" -name "filesystem.squashfs" -o -name "*.squashfs" 2>/dev/null | head -n1)

    if [[ -n "$squashfs_path" && -f "$squashfs_path" ]]; then
        customize_live_system "$squashfs_path" "$work_dir"
    else
        log_warn "No squashfs found - skipping customization."
        log_warn "The USB will boot with default packages only."
    fi

    # Write to USB
    if [[ "$skip_write" == "0" ]]; then
        # Prepare USB with multiple partitions
        prepare_usb "$DEVICE" "$with_persistence" "$persist_size"

        # Write ISO contents to main partition (with persistence config)
        write_to_usb "$extract_dir" "$USB_PART_MAIN" "$with_persistence"

        # Copy scripts to scripts partition
        copy_scripts_to_partition "$USB_PART_SCRIPTS"

        echo ""
        log_success "================================================================================"
        log_success "  USB creation complete!"
        log_success "================================================================================"
        echo ""
        log_info "Device: $DEVICE"
        log_info "  Main partition:    $USB_PART_MAIN (LINUXDIAG)"
        log_info "  Scripts partition: $USB_PART_SCRIPTS (LINUX-TOOLS)"
        if [[ "$with_persistence" == "1" ]]; then
            log_info "  Persistence:       $USB_PART_PERSIST (persistence)"
        else
            log_warn "  Persistence:       DISABLED (changes will not be saved)"
        fi
        echo ""
        log_info "Select 'persistence' in GRUB boot menu to save changes between reboots."
        echo ""
        log_info "All diagnostic tools are PRE-INSTALLED. No internet required!"
        echo ""
        log_info "Quick reference after booting:"
        echo "  - Mount scripts:     mount /dev/sdX2 /mnt/tools"
        echo "  - Unlock BitLocker:  dislocker -V /dev/sdX1 -p<password> -- /mnt/bitlocker"
        echo "  - Partition recovery: testdisk /dev/sdX"
        echo "  - GPT repair:         gdisk /dev/sdX"
        echo "  - Disk health:        smartctl -a /dev/sdX"
        echo ""
    else
        log_success "Build complete (--skip-write mode)."
        log_info "Extracted files are in: $extract_dir"
    fi

    # Cleanup
    cleanup "$work_dir" "$keep_work"
}

main "$@"
