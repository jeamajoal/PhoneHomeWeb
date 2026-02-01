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

# Default ISO URL (Debian 12 Live GNOME amd64)
DEFAULT_ISO_URL="https://cdimage.debian.org/debian-cd/current-live/amd64/iso-hybrid/debian-live-12.9.0-amd64-standard.iso"

# Tool packages to install in the live environment
LIVE_PACKAGES=(
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
    curl
    wget
    rsync
    zip
    unzip
    p7zip-full
    less
    vim-tiny
    nano
    tmux
    htop
    iotop
    sysstat
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
  --iso-url URL       URL to download Debian Live ISO.
  --skip-write        Build customization only; do not write to USB.
  --work-dir PATH     Working directory for build files (default: /tmp/linux-usb-build).
  --keep-work         Do not delete working directory after build.
  --non-interactive   Do not prompt; exit if required options are missing.
  -h, --help          Show this help message.

Examples:
  # Interactive mode - lists USB devices and prompts for selection
  sudo $SCRIPT_NAME

  # Specify device directly
  sudo $SCRIPT_NAME --device /dev/sdb

  # Use a pre-downloaded ISO
  sudo $SCRIPT_NAME --device /dev/sdb --debian-iso ~/Downloads/debian-live.iso

  # Build without writing (for testing)
  sudo $SCRIPT_NAME --skip-write

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
    local deps=(lsblk parted mkfs.vfat mount umount rsync curl xorriso mksquashfs unsquashfs chroot)

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
            parted dosfstools mount rsync curl xorriso squashfs-tools debootstrap

        # Re-check
        for cmd in "${deps[@]}"; do
            command -v "$cmd" >/dev/null 2>&1 || die "Still missing required command: $cmd"
        done
    fi

    log_success "All dependencies satisfied."
}

list_usb_devices() {
    # List removable USB block devices
    lsblk -d -o NAME,SIZE,MODEL,TRAN,RM -n | awk '$4=="usb" || $5=="1" {print "/dev/"$1, $2, $3}'
}

select_usb_device() {
    log_info "Scanning for USB devices..."
    echo ""

    local devices
    devices=$(list_usb_devices)

    if [[ -z "$devices" ]]; then
        die "No USB devices found. Insert a USB drive and try again."
    fi

    echo "Available USB devices:"
    echo "----------------------"
    local i=1
    local dev_array=()
    while IFS= read -r line; do
        echo "  [$i] $line"
        dev_array+=("$(echo "$line" | awk '{print $1}')")
        ((i++))
    done <<< "$devices"
    echo ""

    local selection
    read -r -p "Select device number [1-$((i-1))]: " selection

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

    log_info "Preparing USB device $device..."

    # Unmount any mounted partitions
    for part in "${device}"*; do
        if mount | grep -q "$part"; then
            log_info "Unmounting $part..."
            umount "$part" || true
        fi
    done

    # Create GPT partition table with single FAT32 partition (for UEFI boot)
    # and set boot flag
    log_info "Creating partition table..."

    parted -s "$device" mklabel gpt
    parted -s "$device" mkpart primary fat32 1MiB 100%
    parted -s "$device" set 1 boot on
    parted -s "$device" set 1 esp on

    # Wait for partition to appear
    sleep 2
    partprobe "$device" 2>/dev/null || true
    sleep 1

    local part1="${device}1"
    if [[ ! -b "$part1" ]]; then
        # Try alternate naming (nvme style)
        part1="${device}p1"
    fi

    if [[ ! -b "$part1" ]]; then
        die "Partition $part1 not found after partitioning."
    fi

    log_info "Formatting partition as FAT32..."
    mkfs.vfat -F 32 -n "LINUXDIAG" "$part1"

    log_success "USB device prepared."
    echo "$part1"
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
    cp /etc/resolv.conf "$squashfs_edit/etc/resolv.conf" 2>/dev/null || true

    # Install packages
    log_info "Installing recovery tools in live environment..."
    cat > "$squashfs_edit/tmp/install-tools.sh" <<'INSTALL_SCRIPT'
#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive

# Update package lists
apt-get update

# Install recovery/diagnostic tools
apt-get install -y --no-install-recommends \
    dislocker \
    gdisk \
    testdisk \
    parted \
    ntfs-3g \
    dosfstools \
    gddrescue \
    smartmontools \
    lvm2 \
    mdadm \
    cryptsetup \
    e2fsprogs \
    xfsprogs \
    btrfs-progs \
    hdparm \
    nvme-cli \
    pciutils \
    usbutils \
    lshw \
    dmidecode \
    curl \
    wget \
    rsync \
    zip \
    unzip \
    less \
    vim-tiny \
    nano \
    tmux \
    htop \
    sysstat

# Clean up
apt-get clean
rm -rf /var/lib/apt/lists/*

echo "Recovery tools installed successfully."
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
    umount "$squashfs_edit/sys" 2>/dev/null || true
    umount "$squashfs_edit/proc" 2>/dev/null || true
    umount "$squashfs_edit/dev/pts" 2>/dev/null || true
    umount "$squashfs_edit/dev" 2>/dev/null || true
    rm -f "$squashfs_edit/etc/resolv.conf"

    # Repack squashfs
    log_info "Repacking squashfs filesystem (this may take a while)..."
    rm -f "$squashfs_path"
    mksquashfs "$squashfs_edit" "$squashfs_path" -comp xz -Xbcj x86 -b 1M

    # Cleanup
    rm -rf "$squashfs_edit" "$squashfs_mount"

    log_success "Live system customized with recovery tools."
}

write_to_usb() {
    local extract_dir="$1"
    local usb_partition="$2"

    log_info "Writing files to USB..."

    local usb_mount="/mnt/linux-usb-$$"
    mkdir -p "$usb_mount"
    mount "$usb_partition" "$usb_mount"

    rsync -a --info=progress2 "$extract_dir/" "$usb_mount/"

    # Ensure boot files are in place for UEFI
    if [[ -d "$usb_mount/EFI" ]]; then
        log_success "UEFI boot files present."
    else
        log_warn "EFI directory not found - USB may not boot on UEFI systems."
    fi

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
    local iso_url="$DEFAULT_ISO_URL"
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
            --skip-write)
                skip_write=1; shift ;;
            --work-dir)
                work_dir="$2"; shift 2 ;;
            --keep-work)
                keep_work=1; shift ;;
            --non-interactive)
                non_interactive=1; shift ;;
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

    # Get or download ISO
    local iso_path="$debian_iso"
    if [[ -z "$iso_path" ]]; then
        iso_path="$work_dir/debian-live.iso"
        if [[ -f "$iso_path" ]]; then
            log_info "Using cached ISO: $iso_path"
        else
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
        local usb_partition
        usb_partition=$(prepare_usb "$DEVICE")
        write_to_usb "$extract_dir" "$usb_partition"

        echo ""
        log_success "================================================================================"
        log_success "  USB creation complete!"
        log_success "================================================================================"
        echo ""
        log_info "Device: $DEVICE"
        log_info "You can now boot from this USB to access Linux recovery tools."
        echo ""
        log_info "Quick reference after booting:"
        echo "  - Unlock BitLocker: dislocker -V /dev/sdX1 -p<password> -- /mnt/bitlocker"
        echo "  - Partition recovery: testdisk /dev/sdX"
        echo "  - GPT repair: gdisk /dev/sdX"
        echo "  - Disk health: smartctl -a /dev/sdX"
        echo ""
    else
        log_success "Build complete (--skip-write mode)."
        log_info "Extracted files are in: $extract_dir"
    fi

    # Cleanup
    cleanup "$work_dir" "$keep_work"
}

main "$@"
