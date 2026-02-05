#!/bin/bash
#===============================================================================
# Linux Collector - Offline Windows Diagnostic Collection from Linux Live USB
#===============================================================================
#
# SYNOPSIS
#     Collects diagnostic data from offline Windows installations using a
#     Linux Live environment (Debian Live USB with recovery tools)
#
# DESCRIPTION
#     This script detects and mounts Windows partitions (including BitLocker-
#     encrypted drives via dislocker), collects diagnostic data such as:
#       - Event logs (.evtx files)
#       - Registry hives
#       - Windows Update/CBS/DISM logs
#       - Setup/upgrade logs
#       - Crash dumps
#     Then packages the data into a ZIP archive and uploads to the diagnostic server.
#
# USAGE
#     sudo ./Linux-Collector.sh [OPTIONS]
#
# OPTIONS
#     --upload-url URL    Upload server URL (default: <<SERVERURL>>/upload)
#     --auth-key KEY      Authentication key for upload
#     --no-upload         Skip upload, only create local archive
#     --help              Show this help message
#
# REQUIREMENTS
#     - Root privileges
#     - dislocker (for BitLocker drives)
#     - ntfs-3g (for NTFS support)
#     - curl (for uploads)
#     - zip (for archiving)
#
# AUTHOR
#     jeamajoal
#
# LICENSE
#     MIT
#
#===============================================================================

set -o pipefail

# Default configuration (placeholders replaced at download time)
UPLOAD_URL="${UPLOAD_URL:-<<SERVERURL>>/upload}"
AUTH_KEY="${AUTH_KEY:-<<AUTHKEY>>}"
VERSION="1.0.0"

# Working directories
WORK_DIR="/tmp/linux-collector"
OUTPUT_DIR="$WORK_DIR/output"
MOUNT_DIR="/mnt/windows"
DISLOCKER_DIR="/mnt/bitlocker"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Divider
DIVIDER="$(printf '=%.0s' {1..80})"

# Session log
LOG_FILE=""
SKIP_UPLOAD=false
COMPUTER_NAME="UNKNOWN"
SERIAL_NUMBER="UNKNOWN"
SELECTED_PARTITION=""
IS_BITLOCKER=false

#===============================================================================
# Logging Functions
#===============================================================================

log_message() {
    local message="$1"
    local color="${2:-$WHITE}"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Print to console with color (stderr so it doesn't interfere with function return values)
    echo -e "${color}${message}${NC}" >&2
    
    # Log to file without color codes
    if [[ -n "$LOG_FILE" && -d "$(dirname "$LOG_FILE")" ]]; then
        echo "[$timestamp] $message" >> "$LOG_FILE"
    fi
}

log_error() {
    log_message "ERROR: $1" "$RED"
}

log_warning() {
    log_message "WARNING: $1" "$YELLOW"
}

log_success() {
    log_message "$1" "$GREEN"
}

log_info() {
    log_message "$1" "$CYAN"
}

log_detail() {
    log_message "  $1" "$GRAY"
}

#===============================================================================
# Banner and Help
#===============================================================================

show_banner() {
    clear
    echo -e "${CYAN}${DIVIDER}${NC}"
    echo -e "${YELLOW}  LINUX COLLECTOR - Offline Windows Diagnostic Tool${NC}"
    echo -e "${CYAN}${DIVIDER}${NC}"
    echo -e "${GRAY}  Version: $VERSION${NC}"
    echo -e "${GRAY}  Server:  $UPLOAD_URL${NC}"
    echo ""
}

show_help() {
    cat << EOF
Linux Collector - Offline Windows Diagnostic Collection

USAGE:
    sudo $0 [OPTIONS]

OPTIONS:
    --upload-url URL    Upload server URL (default: $UPLOAD_URL)
    --auth-key KEY      Authentication key for upload
    --no-upload         Skip upload, only create local archive
    --help              Show this help message

DESCRIPTION:
    This script collects diagnostic data from offline Windows installations:
    
    1. Detects Windows partitions (including BitLocker-encrypted drives)
    2. Prompts for BitLocker recovery key if needed
    3. Mounts the Windows partition read-only
    4. Collects diagnostic data:
       - Event logs (.evtx)
       - Registry hives (SYSTEM, SOFTWARE, DEFAULT)
       - Windows Update/CBS/DISM logs
       - Setup/Upgrade logs (Panther/MoSetup)
       - Crash dumps (minidumps, MEMORY.DMP)
       - BitLocker and BCD status
    5. Creates a ZIP archive
    6. Uploads to the diagnostic server

EXAMPLES:
    # Run with default settings
    sudo ./Linux-Collector.sh

    # Run without upload
    sudo ./Linux-Collector.sh --no-upload

    # Specify custom server
    sudo ./Linux-Collector.sh --upload-url https://myserver:3500/upload

EOF
}

#===============================================================================
# Utility Functions
#===============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (sudo)"
        exit 1
    fi
}

check_dependencies() {
    local missing=()
    local deps=("lsblk" "blkid" "mount" "umount" "zip" "curl" "dmidecode")
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done
    
    # Check for dislocker (optional but important for BitLocker)
    if ! command -v dislocker &>/dev/null; then
        log_warning "dislocker not found - BitLocker drives cannot be unlocked"
    fi
    
    # Check for ntfs-3g
    if ! command -v ntfs-3g &>/dev/null; then
        log_warning "ntfs-3g not found - NTFS support may be limited"
    fi
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing[*]}"
        log_info "Install with: apt-get install ${missing[*]}"
        exit 1
    fi
}

cleanup() {
    log_info "Cleaning up..."
    
    # Unmount Windows partition
    if mountpoint -q "$MOUNT_DIR" 2>/dev/null; then
        log_detail "Unmounting $MOUNT_DIR"
        umount "$MOUNT_DIR" 2>/dev/null || umount -l "$MOUNT_DIR" 2>/dev/null
    fi
    
    # Unmount dislocker
    if mountpoint -q "$DISLOCKER_DIR" 2>/dev/null; then
        log_detail "Unmounting $DISLOCKER_DIR"
        umount "$DISLOCKER_DIR" 2>/dev/null || umount -l "$DISLOCKER_DIR" 2>/dev/null
    fi
    
    # Clean up dislocker file
    if [[ -f "$DISLOCKER_DIR/dislocker-file" ]]; then
        rm -f "$DISLOCKER_DIR/dislocker-file"
    fi
    
    log_success "Cleanup complete"
}

# Trap for cleanup on exit
trap cleanup EXIT INT TERM

setup_directories() {
    log_info "Setting up working directories..."
    
    # Create work directories
    mkdir -p "$WORK_DIR" "$OUTPUT_DIR" "$MOUNT_DIR" "$DISLOCKER_DIR"
    
    # Initialize log file
    LOG_FILE="$WORK_DIR/collector-$(date '+%Y%m%d-%H%M%S').log"
    touch "$LOG_FILE"
    
    log_success "Working directories created"
}

get_system_info() {
    log_info "Getting system identification..."
    
    # Try to get computer name from DMI
    COMPUTER_NAME=$(dmidecode -s system-product-name 2>/dev/null | head -1 | tr -d '[:space:]' || echo "UNKNOWN")
    [[ -z "$COMPUTER_NAME" || "$COMPUTER_NAME" == "ToBeFilledByO.E.M." ]] && COMPUTER_NAME="LINUX-HOST"
    
    # Try to get serial number
    SERIAL_NUMBER=$(dmidecode -s system-serial-number 2>/dev/null | head -1 | tr -d '[:space:]' || echo "UNKNOWN")
    [[ -z "$SERIAL_NUMBER" || "$SERIAL_NUMBER" == "ToBeFilledByO.E.M." ]] && SERIAL_NUMBER="UNKNOWN"
    
    log_detail "Computer: $COMPUTER_NAME"
    log_detail "Serial:   $SERIAL_NUMBER"
}

#===============================================================================
# Partition Detection and BitLocker Handling
#===============================================================================

detect_windows_partitions() {
    log_info "Scanning for Windows partitions..."
    echo ""
    
    local partitions=()
    local index=0
    
    # Get all partitions with NTFS or BitLocker
    while IFS= read -r line; do
        local dev=$(echo "$line" | awk '{print $1}')
        local fstype=$(echo "$line" | awk '{print $2}')
        local size=$(echo "$line" | awk '{print $3}')
        local label=$(echo "$line" | awk '{print $4}')
        
        # Skip empty lines
        [[ -z "$dev" ]] && continue
        
        # Check for BitLocker signature
        local is_bitlocker=false
        if [[ "$fstype" == "BitLocker" ]] || blkid "$dev" 2>/dev/null | grep -qi "bitlocker"; then
            is_bitlocker=true
            fstype="BitLocker"
        fi
        
        # Check if it's a Windows partition (NTFS or BitLocker)
        if [[ "$fstype" == "ntfs" || "$fstype" == "BitLocker" ]]; then
            index=$((index + 1))
            partitions+=("$dev|$fstype|$size|$label|$is_bitlocker")
            
            local bl_marker=""
            [[ "$is_bitlocker" == "true" ]] && bl_marker="${YELLOW}[BitLocker]${NC}"
            
            printf "  ${GREEN}[%d]${NC} %-15s %-12s %-10s %s %s\n" \
                "$index" "$dev" "$fstype" "$size" "$label" "$bl_marker"
        fi
    done < <(lsblk -rno NAME,FSTYPE,SIZE,LABEL 2>/dev/null | while read name fstype size label; do
        [[ -n "$name" ]] && echo "/dev/$name $fstype $size $label"
    done)
    
    echo ""
    
    if [[ ${#partitions[@]} -eq 0 ]]; then
        log_error "No Windows partitions found"
        exit 1
    fi
    
    # Prompt for selection
    while true; do
        read -p "Select Windows partition to diagnose (1-$index): " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le "$index" ]]; then
            local selected="${partitions[$((choice - 1))]}"
            SELECTED_PARTITION=$(echo "$selected" | cut -d'|' -f1)
            IS_BITLOCKER=$(echo "$selected" | cut -d'|' -f5)
            break
        else
            log_error "Invalid selection. Please enter a number between 1 and $index"
        fi
    done
    
    log_success "Selected: $SELECTED_PARTITION (BitLocker: $IS_BITLOCKER)"
}

unlock_bitlocker() {
    local partition="$1"
    
    if ! command -v dislocker &>/dev/null; then
        log_error "dislocker is required to unlock BitLocker drives"
        log_info "Install with: apt-get install dislocker"
        exit 1
    fi
    
    log_info "BitLocker encrypted drive detected"
    echo "" >&2
    echo -e "${YELLOW}Enter the 48-digit BitLocker recovery key${NC}" >&2
    echo -e "${GRAY}(Format: 123456-123456-123456-123456-123456-123456-123456-123456)${NC}" >&2
    echo "" >&2
    
    local recovery_key
    read -p "Recovery Key: " recovery_key
    
    # Validate format (basic check)
    if ! echo "$recovery_key" | grep -qE '^[0-9]{6}(-[0-9]{6}){7}$'; then
        log_error "Invalid recovery key format"
        log_info "Expected format: XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX"
        exit 1
    fi
    
    log_info "Unlocking BitLocker drive..."
    
    # Create dislocker mount point and ensure it's empty
    mkdir -p "$DISLOCKER_DIR"
    
    # Unmount if already mounted from a previous attempt
    if mountpoint -q "$DISLOCKER_DIR" 2>/dev/null; then
        log_warning "Dislocker mount point already in use, unmounting..."
        umount "$DISLOCKER_DIR" 2>/dev/null || fusermount -u "$DISLOCKER_DIR" 2>/dev/null || true
        sleep 1
    fi
    
    # Run dislocker to create decrypted file (FUSE-based)
    # Capture output for debugging
    local dislocker_output
    dislocker_output=$(dislocker "$partition" -p"$recovery_key" -- "$DISLOCKER_DIR" 2>&1)
    local dislocker_exit=$?
    
    if [[ $dislocker_exit -ne 0 ]]; then
        log_error "dislocker failed with exit code $dislocker_exit"
        log_error "Output: $dislocker_output"
        log_info "Please verify the recovery key is correct"
        exit 1
    fi
    
    # Give dislocker a moment to create the FUSE mount
    sleep 2
    
    # Verify the dislocker-file was created (critical check)
    if [[ ! -e "$DISLOCKER_DIR/dislocker-file" ]]; then
        log_error "dislocker reported success but dislocker-file was not created"
        log_detail "Expected file: $DISLOCKER_DIR/dislocker-file"
        log_detail "Contents of $DISLOCKER_DIR:"
        ls -la "$DISLOCKER_DIR" 2>&1 | while read line; do log_detail "  $line"; done
        
        # Check if it's a FUSE mount issue
        if ! mountpoint -q "$DISLOCKER_DIR" 2>/dev/null; then
            log_error "dislocker FUSE mount failed - $DISLOCKER_DIR is not a mount point"
            log_info "Possible causes:"
            log_info "  - FUSE not installed or not working (try: modprobe fuse)"
            log_info "  - Wrong recovery key (try re-entering)"
            log_info "  - BitLocker metadata corrupted on disk"
        fi
        
        exit 1
    fi
    
    log_success "BitLocker drive unlocked"
    log_detail "Decrypted partition available at: $DISLOCKER_DIR/dislocker-file"
    
    # The decrypted partition is now at $DISLOCKER_DIR/dislocker-file
    echo "$DISLOCKER_DIR/dislocker-file"
}

mount_windows_partition() {
    local partition="$1"
    local mount_source="$partition"
    
    # If BitLocker, unlock first
    if [[ "$IS_BITLOCKER" == "true" ]]; then
        mount_source=$(unlock_bitlocker "$partition")
    fi
    
    log_info "Mounting Windows partition..."
    
    # Try to mount read-only with ntfs-3g
    if ! mount -t ntfs-3g -o ro,noexec "$mount_source" "$MOUNT_DIR" >&2 2>&1; then
        # Fallback to kernel NTFS driver
        if ! mount -t ntfs -o ro "$mount_source" "$MOUNT_DIR" >&2 2>&1; then
            log_error "Failed to mount Windows partition"
            exit 1
        fi
    fi
    
    # Verify it's a Windows installation
    if [[ ! -d "$MOUNT_DIR/Windows/System32" ]]; then
        log_error "This doesn't appear to be a Windows installation"
        log_info "Missing: Windows/System32 directory"
        exit 1
    fi
    
    log_success "Windows partition mounted at $MOUNT_DIR"
    
    # Try to get Windows version
    detect_windows_version
}

detect_windows_version() {
    log_info "Detecting Windows version..."
    
    local product_name="Unknown Windows"
    local current_build="Unknown"
    
    # Try to read SOFTWARE hive (requires offline registry tools)
    # For now, just check for version markers
    if [[ -f "$MOUNT_DIR/Windows/System32/ntoskrnl.exe" ]]; then
        # Use file command to get some version info
        local file_info
        file_info=$(file "$MOUNT_DIR/Windows/System32/ntoskrnl.exe" 2>/dev/null)
        
        # Check for Windows version indicators
        if [[ -f "$MOUNT_DIR/Windows/System32/config/SOFTWARE" ]]; then
            log_detail "SOFTWARE registry hive found"
        fi
        
        # Check for common Windows 10/11 markers
        if [[ -d "$MOUNT_DIR/Windows/SystemApps" ]]; then
            product_name="Windows 10/11"
        elif [[ -d "$MOUNT_DIR/Windows/winsxs" ]]; then
            product_name="Windows Vista/7/8/10"
        fi
    fi
    
    log_detail "Detected: $product_name"
}

#===============================================================================
# Diagnostic Collection Functions
#===============================================================================

collect_environment_info() {
    log_info "Collecting Linux environment information..."
    
    local env_file="$OUTPUT_DIR/SystemInfo/Linux_Environment.txt"
    mkdir -p "$(dirname "$env_file")"
    
    {
        echo "$DIVIDER"
        echo "LINUX COLLECTOR ENVIRONMENT INFORMATION"
        echo "$DIVIDER"
        echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Hostname: $(hostname)"
        echo "Kernel: $(uname -r)"
        echo "Distribution: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
        echo ""
        echo "=== Network Configuration ==="
        ip addr 2>&1 || ifconfig 2>&1
        echo ""
        echo "=== Routing Table ==="
        ip route 2>&1 || route -n 2>&1
        echo ""
        echo "=== Storage Devices ==="
        lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT 2>&1
        echo ""
        echo "=== Block Device Info ==="
        blkid 2>&1
        echo ""
        echo "=== Mount Points ==="
        mount | grep -E "^/dev" 2>&1
        echo ""
        echo "=== Memory Info ==="
        free -h 2>&1
    } > "$env_file"
    
    log_success "Linux environment info collected"
}

collect_event_logs() {
    log_info "Collecting Windows event logs (.evtx)..."
    
    local evtx_src="$MOUNT_DIR/Windows/System32/winevt/Logs"
    local evtx_dest="$OUTPUT_DIR/EvtxLogs"
    
    if [[ -d "$evtx_src" ]]; then
        mkdir -p "$evtx_dest"
        
        # Copy all .evtx files
        local count=0
        find "$evtx_src" -name "*.evtx" -type f 2>/dev/null | while read -r evtx; do
            cp "$evtx" "$evtx_dest/" 2>/dev/null && ((count++))
        done
        
        local copied_count
        copied_count=$(find "$evtx_dest" -name "*.evtx" 2>/dev/null | wc -l)
        log_success "Collected $copied_count event log files"
    else
        log_warning "Event logs directory not found"
    fi
}

collect_registry_hives() {
    log_info "Collecting registry hives..."
    
    local reg_src="$MOUNT_DIR/Windows/System32/config"
    local reg_dest="$OUTPUT_DIR/RegistryHives"
    
    if [[ -d "$reg_src" ]]; then
        mkdir -p "$reg_dest"
        
        # Collect non-sensitive hives (exclude SAM/SECURITY)
        local hives=("SYSTEM" "SOFTWARE" "DEFAULT")
        local collected=0
        
        for hive in "${hives[@]}"; do
            if [[ -f "$reg_src/$hive" ]]; then
                cp "$reg_src/$hive" "$reg_dest/" 2>/dev/null && ((collected++))
                log_detail "Collected $hive hive"
            fi
        done
        
        log_success "Collected $collected registry hives (SAM/SECURITY excluded for privacy)"
    else
        log_warning "Registry hives directory not found"
    fi
}

collect_windows_logs() {
    log_info "Collecting Windows logs..."
    
    local logs_dest="$OUTPUT_DIR/Logs"
    mkdir -p "$logs_dest"
    
    # Windows Update logs
    local wu_src="$MOUNT_DIR/Windows/Logs/WindowsUpdate"
    if [[ -d "$wu_src" ]]; then
        cp -r "$wu_src" "$logs_dest/WindowsUpdate" 2>/dev/null
        log_detail "Windows Update logs collected"
    fi
    
    # CBS logs
    local cbs_src="$MOUNT_DIR/Windows/Logs/CBS"
    if [[ -d "$cbs_src" ]]; then
        cp -r "$cbs_src" "$logs_dest/CBS" 2>/dev/null
        log_detail "CBS logs collected"
    fi
    
    # DISM logs
    local dism_src="$MOUNT_DIR/Windows/Logs/DISM"
    if [[ -d "$dism_src" ]]; then
        cp -r "$dism_src" "$logs_dest/DISM" 2>/dev/null
        log_detail "DISM logs collected"
    fi
    
    # Panther logs (Setup/Upgrade)
    local panther_src="$MOUNT_DIR/Windows/Panther"
    if [[ -d "$panther_src" ]]; then
        cp -r "$panther_src" "$logs_dest/Panther" 2>/dev/null
        log_detail "Panther (Setup) logs collected"
    fi
    
    # MoSetup logs
    local mosetup_src="$MOUNT_DIR/Windows/Logs/MoSetup"
    if [[ -d "$mosetup_src" ]]; then
        cp -r "$mosetup_src" "$logs_dest/MoSetup" 2>/dev/null
        log_detail "MoSetup logs collected"
    fi
    
    # SetupAPI logs
    local setupapi_src="$MOUNT_DIR/Windows/INF"
    if [[ -d "$setupapi_src" ]]; then
        mkdir -p "$logs_dest/SetupAPI"
        find "$setupapi_src" -name "setupapi*.log" -exec cp {} "$logs_dest/SetupAPI/" \; 2>/dev/null
        log_detail "SetupAPI logs collected"
    fi
    
    # Startup Repair logs (SrtTrail)
    local srt_src="$MOUNT_DIR/Windows/System32/LogFiles/Srt"
    if [[ -d "$srt_src" ]]; then
        cp -r "$srt_src" "$logs_dest/Srt" 2>/dev/null
        log_detail "Startup Repair logs collected"
    fi
    
    # NetSetup logs
    local netsetup_paths=(
        "$MOUNT_DIR/Windows/debug/NetSetup"
        "$MOUNT_DIR/Windows/debug/NetSetup.log"
        "$MOUNT_DIR/Windows/System32/LogFiles/NetSetup"
    )
    for nspath in "${netsetup_paths[@]}"; do
        if [[ -e "$nspath" ]]; then
            mkdir -p "$logs_dest/NetSetup"
            cp -r "$nspath" "$logs_dest/NetSetup/" 2>/dev/null
            log_detail "NetSetup logs collected"
            break
        fi
    done
    
    log_success "Windows logs collection complete"
}

collect_crash_dumps() {
    log_info "Collecting crash dumps..."
    
    local dumps_dest="$OUTPUT_DIR/CrashDumps"
    mkdir -p "$dumps_dest"
    local collected=0
    
    # Minidumps
    local minidump_src="$MOUNT_DIR/Windows/Minidump"
    if [[ -d "$minidump_src" ]]; then
        cp -r "$minidump_src" "$dumps_dest/Minidump" 2>/dev/null
        local count
        count=$(find "$dumps_dest/Minidump" -name "*.dmp" 2>/dev/null | wc -l)
        log_detail "Collected $count minidump files"
        ((collected += count))
    fi
    
    # MEMORY.DMP (only if < 500MB)
    local memory_dmp="$MOUNT_DIR/Windows/MEMORY.DMP"
    if [[ -f "$memory_dmp" ]]; then
        local size
        size=$(stat -c%s "$memory_dmp" 2>/dev/null || echo 0)
        if [[ $size -lt 524288000 ]]; then  # 500MB
            cp "$memory_dmp" "$dumps_dest/" 2>/dev/null
            log_detail "MEMORY.DMP collected ($(numfmt --to=iec $size))"
            ((collected++))
        else
            log_detail "MEMORY.DMP skipped ($(numfmt --to=iec $size) > 500MB)"
        fi
    fi
    
    # LiveKernelReports
    local lkr_src="$MOUNT_DIR/Windows/LiveKernelReports"
    if [[ -d "$lkr_src" ]]; then
        mkdir -p "$dumps_dest/LiveKernelReports"
        find "$lkr_src" -name "*.dmp" -size -500M -exec cp {} "$dumps_dest/LiveKernelReports/" \; 2>/dev/null
        log_detail "LiveKernelReports collected"
    fi
    
    log_success "Crash dumps collection complete ($collected files)"
}

collect_wer_reports() {
    log_info "Collecting Windows Error Reports..."
    
    local wer_dest="$OUTPUT_DIR/WERReports"
    mkdir -p "$wer_dest"
    local collected=0
    
    # WER Report Archive
    local wer_archive="$MOUNT_DIR/ProgramData/Microsoft/Windows/WER/ReportArchive"
    if [[ -d "$wer_archive" ]]; then
        cp -r "$wer_archive" "$wer_dest/ReportArchive" 2>/dev/null
        log_detail "WER ReportArchive collected"
        ((collected++))
    fi
    
    # WER Report Queue
    local wer_queue="$MOUNT_DIR/ProgramData/Microsoft/Windows/WER/ReportQueue"
    if [[ -d "$wer_queue" ]]; then
        cp -r "$wer_queue" "$wer_dest/ReportQueue" 2>/dev/null
        log_detail "WER ReportQueue collected"
        ((collected++))
    fi
    
    # Check for user profile WER locations
    local users_dir="$MOUNT_DIR/Users"
    if [[ -d "$users_dir" ]]; then
        for user_dir in "$users_dir"/*; do
            [[ -d "$user_dir" ]] || continue
            local user_wer="$user_dir/AppData/Local/Microsoft/Windows/WER/ReportArchive"
            if [[ -d "$user_wer" ]]; then
                local username=$(basename "$user_dir")
                mkdir -p "$wer_dest/Users/$username"
                cp -r "$user_wer" "$wer_dest/Users/$username/ReportArchive" 2>/dev/null
                log_detail "WER for user $username collected"
                ((collected++))
            fi
        done
    fi
    
    if [[ $collected -eq 0 ]]; then
        log_warning "No WER reports found"
    else
        log_success "WER reports collection complete ($collected locations)"
    fi
}

collect_boot_config() {
    log_info "Collecting boot configuration..."
    
    local boot_dest="$OUTPUT_DIR/BootConfig"
    mkdir -p "$boot_dest"
    local collected=0
    
    # BCD stores (may be on different partitions)
    local bcd_locations=(
        "$MOUNT_DIR/Boot/BCD"
        "$MOUNT_DIR/EFI/Microsoft/Boot/BCD"
    )
    
    for bcd_path in "${bcd_locations[@]}"; do
        if [[ -f "$bcd_path" ]]; then
            local bcd_name
            bcd_name=$(dirname "$bcd_path" | sed 's|/|-|g' | sed "s|$MOUNT_DIR-||")
            cp "$bcd_path" "$boot_dest/BCD-$bcd_name" 2>/dev/null
            log_detail "BCD copied from $(dirname "$bcd_path")"
            ((collected++))
        fi
    done
    
    # Also check for EFI partition (might be separate - look for mounted EFI)
    for efi_mount in /mnt/efi /boot/efi; do
        if mountpoint -q "$efi_mount" 2>/dev/null; then
            local efi_bcd="$efi_mount/EFI/Microsoft/Boot/BCD"
            if [[ -f "$efi_bcd" ]]; then
                cp "$efi_bcd" "$boot_dest/BCD-EFI" 2>/dev/null
                log_detail "BCD copied from EFI partition"
                ((collected++))
            fi
        fi
    done
    
    # bootstat.dat
    local bootstat="$MOUNT_DIR/Windows/bootstat.dat"
    if [[ -f "$bootstat" ]]; then
        cp "$bootstat" "$boot_dest/bootstat.dat" 2>/dev/null
        log_detail "bootstat.dat collected"
        ((collected++))
    fi
    
    # Boot log
    local ntbtlog="$MOUNT_DIR/Windows/ntbtlog.txt"
    if [[ -f "$ntbtlog" ]]; then
        cp "$ntbtlog" "$boot_dest/ntbtlog.txt" 2>/dev/null
        log_detail "ntbtlog.txt collected"
        ((collected++))
    fi
    
    if [[ $collected -gt 0 ]]; then
        log_success "Boot configuration collected ($collected files)"
    else
        log_warning "No boot configuration files found"
    fi
}

collect_servicing_packages() {
    log_info "Collecting Windows Servicing information..."
    
    local svc_dest="$OUTPUT_DIR/Servicing"
    mkdir -p "$svc_dest"
    local collected=0
    
    # Servicing packages directory
    local packages_dir="$MOUNT_DIR/Windows/servicing/Packages"
    if [[ -d "$packages_dir" ]]; then
        # Just list the installed packages (too many files to copy)
        ls -la "$packages_dir" > "$svc_dest/Packages-listing.txt" 2>/dev/null
        log_detail "Package listing created"
        ((collected++))
    fi
    
    # Component store info
    local cbs_dir="$MOUNT_DIR/Windows/WinSxS"
    if [[ -d "$cbs_dir" ]]; then
        # Size summary
        du -sh "$cbs_dir" > "$svc_dest/WinSxS-size.txt" 2>/dev/null
        log_detail "WinSxS size recorded"
        ((collected++))
    fi
    
    # Pending.xml (pending package operations)
    local pending="$MOUNT_DIR/Windows/WinSxS/pending.xml"
    if [[ -f "$pending" ]]; then
        cp "$pending" "$svc_dest/pending.xml" 2>/dev/null
        log_detail "pending.xml collected"
        ((collected++))
    fi
    
    # Sessions.xml (transaction history)
    local sessions="$MOUNT_DIR/Windows/servicing/Sessions/Sessions.xml"
    if [[ -f "$sessions" ]]; then
        cp "$sessions" "$svc_dest/Sessions.xml" 2>/dev/null
        log_detail "Sessions.xml collected"
        ((collected++))
    fi
    
    # Component detection files
    local component_detect="$MOUNT_DIR/Windows/servicing/ComponentDetect"
    if [[ -d "$component_detect" ]]; then
        ls -la "$component_detect" > "$svc_dest/ComponentDetect-listing.txt" 2>/dev/null
        ((collected++))
    fi
    
    if [[ $collected -gt 0 ]]; then
        log_success "Servicing information collected ($collected items)"
    else
        log_warning "No servicing information found"
    fi
}

collect_network_config() {
    log_info "Collecting network configuration..."
    
    local net_dest="$OUTPUT_DIR/NetworkConfig"
    mkdir -p "$net_dest"
    local collected=0
    
    # hosts file
    local hosts_file="$MOUNT_DIR/Windows/System32/drivers/etc/hosts"
    if [[ -f "$hosts_file" ]]; then
        cp "$hosts_file" "$net_dest/hosts" 2>/dev/null
        log_detail "hosts file collected"
        ((collected++))
    fi
    
    # lmhosts (if exists)
    local lmhosts_file="$MOUNT_DIR/Windows/System32/drivers/etc/lmhosts"
    if [[ -f "$lmhosts_file" ]]; then
        cp "$lmhosts_file" "$net_dest/lmhosts" 2>/dev/null
        ((collected++))
    fi
    
    # networks file
    local networks_file="$MOUNT_DIR/Windows/System32/drivers/etc/networks"
    if [[ -f "$networks_file" ]]; then
        cp "$networks_file" "$net_dest/networks" 2>/dev/null
        ((collected++))
    fi
    
    # protocol file
    local protocol_file="$MOUNT_DIR/Windows/System32/drivers/etc/protocol"
    if [[ -f "$protocol_file" ]]; then
        cp "$protocol_file" "$net_dest/protocol" 2>/dev/null
        ((collected++))
    fi
    
    # services file
    local services_file="$MOUNT_DIR/Windows/System32/drivers/etc/services"
    if [[ -f "$services_file" ]]; then
        cp "$services_file" "$net_dest/services" 2>/dev/null
        ((collected++))
    fi
    
    # WLAN profiles (if accessible - usually encrypted but structure is useful)
    local wlan_profiles="$MOUNT_DIR/ProgramData/Microsoft/Wlansvc/Profiles"
    if [[ -d "$wlan_profiles" ]]; then
        cp -r "$wlan_profiles" "$net_dest/WlanProfiles" 2>/dev/null
        log_detail "WLAN profiles collected"
        ((collected++))
    fi
    
    if [[ $collected -gt 0 ]]; then
        log_success "Network configuration collected ($collected items)"
    else
        log_warning "No network configuration found"
    fi
}

collect_bitlocker_info() {
    log_info "Documenting BitLocker status..."
    
    local bl_file="$OUTPUT_DIR/SystemInfo/BitLocker_Status.txt"
    mkdir -p "$(dirname "$bl_file")"
    
    {
        echo "$DIVIDER"
        echo "BITLOCKER STATUS (LINUX COLLECTOR)"
        echo "$DIVIDER"
        echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Selected Partition: $SELECTED_PARTITION"
        echo "Was BitLocker Encrypted: $IS_BITLOCKER"
        echo ""
        
        if [[ "$IS_BITLOCKER" == "true" ]]; then
            echo "Drive was successfully unlocked using recovery key"
            echo "(Recovery key has been redacted from this log)"
        else
            echo "Drive was not BitLocker encrypted"
        fi
        echo ""
        
        echo "=== Partition Information ==="
        blkid "$SELECTED_PARTITION" 2>&1
        echo ""
        
        echo "=== All Detected BitLocker Volumes ==="
        lsblk -o NAME,SIZE,TYPE,FSTYPE | grep -i "bitlocker" 2>&1 || echo "None detected"
    } > "$bl_file"
    
    log_success "BitLocker status documented"
}

collect_disk_health() {
    log_info "Collecting disk health information..."
    
    local disk_file="$OUTPUT_DIR/SystemInfo/Disk_Health.txt"
    mkdir -p "$(dirname "$disk_file")"
    
    {
        echo "$DIVIDER"
        echo "DISK HEALTH DIAGNOSTICS"
        echo "$DIVIDER"
        echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        
        # List all disks
        echo "=== Block Devices ==="
        lsblk -o NAME,SIZE,TYPE,MODEL,SERIAL,ROTA,DISC-MAX 2>&1
        echo ""
        
        # SMART data for each disk (if smartctl available)
        if command -v smartctl &>/dev/null; then
            echo "=== SMART Health Data ==="
            shopt -s nullglob
            for disk in /dev/sd? /dev/nvme?n?; do
                if [[ -b "$disk" ]]; then
                    echo ""
                    echo "--- $disk ---"
                    smartctl -H "$disk" 2>&1 || echo "SMART not available for $disk"
                    smartctl -A "$disk" 2>&1 | head -30 || true
                fi
            done
            shopt -u nullglob
        else
            echo "smartctl not available - install smartmontools for SMART data"
        fi
        echo ""
        
        # NVMe health (if nvme-cli available)
        if command -v nvme &>/dev/null; then
            echo "=== NVMe Health ==="
            shopt -s nullglob
            for nvme in /dev/nvme?n?; do
                if [[ -b "$nvme" ]]; then
                    echo ""
                    echo "--- $nvme ---"
                    nvme smart-log "$nvme" 2>&1 || echo "Could not read NVMe health for $nvme"
                fi
            done
            shopt -u nullglob
        fi
    } > "$disk_file"
    
    log_success "Disk health information collected"
}

collect_file_inventory() {
    log_info "Collecting file inventory for all mounted partitions..."
    
    local inventory_dir="$OUTPUT_DIR/FileInventory"
    mkdir -p "$inventory_dir"
    
    # Collect inventory for the mounted Windows partition
    if [[ -d "$MOUNT_DIR" && -d "$MOUNT_DIR/Windows" ]]; then
        log_detail "Scanning Windows partition at $MOUNT_DIR..."
        local win_inventory="$inventory_dir/Inventory_Windows.txt"
        
        # Use find for full recursive listing
        find "$MOUNT_DIR" -type f 2>/dev/null > "$win_inventory" || true
        
        local file_count
        file_count=$(wc -l < "$win_inventory" 2>/dev/null || echo "0")
        log_detail "  Windows partition: $file_count files"
    fi
    
    # Also collect inventory for any other mounted NTFS partitions
    local mount_point
    while IFS= read -r mount_point; do
        # Skip the main Windows mount we already did
        [[ "$mount_point" == "$MOUNT_DIR" ]] && continue
        
        # Only process NTFS mounts that aren't system mounts
        if [[ "$mount_point" =~ ^/mnt/ || "$mount_point" =~ ^/media/ ]]; then
            local safe_name
            safe_name=$(echo "$mount_point" | tr '/' '_' | sed 's/^_//')
            local output_file="$inventory_dir/Inventory_${safe_name}.txt"
            
            log_detail "Scanning $mount_point..."
            find "$mount_point" -type f 2>/dev/null > "$output_file" || true
            
            local file_count
            file_count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
            log_detail "  $mount_point: $file_count files"
        fi
    done < <(mount | grep -E 'ntfs|fuseblk' | awk '{print $3}')
    
    log_success "File inventory collected"
}

#===============================================================================
# Digital Forensics Collection (Optional)
#===============================================================================

collect_forensic_artifacts() {
    log_info "Collecting forensic artifacts..."
    
    local forensic_dest="$OUTPUT_DIR/Forensics"
    mkdir -p "$forensic_dest"/{MFT,Prefetch,USNJournal,SRUM,Timeline,RecycleBin,Amcache}
    local collected=0
    
    # $MFT (Master File Table) - critical forensic artifact
    local mft_file="$MOUNT_DIR/\$MFT"
    if [[ -f "$mft_file" ]]; then
        # MFT is usually huge, copy first 100MB for analysis
        dd if="$mft_file" of="$forensic_dest/MFT/\$MFT-sample" bs=1M count=100 2>/dev/null
        log_detail "\$MFT sample (first 100MB) collected"
        ((collected++))
    fi
    
    # Prefetch files (application execution evidence)
    local prefetch_src="$MOUNT_DIR/Windows/Prefetch"
    if [[ -d "$prefetch_src" ]]; then
        cp -r "$prefetch_src" "$forensic_dest/Prefetch/" 2>/dev/null
        local pf_count
        pf_count=$(find "$forensic_dest/Prefetch" -name "*.pf" 2>/dev/null | wc -l)
        log_detail "Prefetch files collected ($pf_count files)"
        ((collected++))
    fi
    
    # $UsnJrnl ($Extend/$UsnJrnl:$J) - filesystem change journal
    local usn_file="$MOUNT_DIR/\$Extend/\$UsnJrnl:\$J"
    if [[ -f "$usn_file" ]]; then
        # USN Journal can be very large, get last 50MB
        tail -c 52428800 "$usn_file" > "$forensic_dest/USNJournal/UsnJrnl-tail.bin" 2>/dev/null
        log_detail "USN Journal (last 50MB) collected"
        ((collected++))
    fi
    
    # SRUM (System Resource Usage Monitor) - application usage database
    local srum_db="$MOUNT_DIR/Windows/System32/sru/SRUDB.dat"
    if [[ -f "$srum_db" ]]; then
        cp "$srum_db" "$forensic_dest/SRUM/SRUDB.dat" 2>/dev/null
        log_detail "SRUM database collected"
        ((collected++))
    fi
    
    # Amcache.hve - application compatibility cache
    local amcache="$MOUNT_DIR/Windows/AppCompat/Programs/Amcache.hve"
    if [[ -f "$amcache" ]]; then
        cp "$amcache" "$forensic_dest/Amcache/Amcache.hve" 2>/dev/null
        log_detail "Amcache.hve collected"
        ((collected++))
    fi
    
    # ShimCache/AppCompatCache is in SYSTEM registry (already collected)
    
    # Recent files (LNK files)
    local recent_src="$MOUNT_DIR/Users"
    if [[ -d "$recent_src" ]]; then
        for user_dir in "$recent_src"/*; do
            [[ -d "$user_dir" ]] || continue
            local username=$(basename "$user_dir")
            
            # Recent folder
            local recent="$user_dir/AppData/Roaming/Microsoft/Windows/Recent"
            if [[ -d "$recent" ]]; then
                mkdir -p "$forensic_dest/Timeline/$username"
                cp -r "$recent" "$forensic_dest/Timeline/$username/Recent" 2>/dev/null
            fi
            
            # Jump lists
            local jumplists="$user_dir/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations"
            if [[ -d "$jumplists" ]]; then
                cp -r "$jumplists" "$forensic_dest/Timeline/$username/JumpLists" 2>/dev/null
            fi
        done
        log_detail "User timeline artifacts collected"
        ((collected++))
    fi
    
    # $Recycle.Bin content listing
    local recycle_bin="$MOUNT_DIR/\$Recycle.Bin"
    if [[ -d "$recycle_bin" ]]; then
        find "$recycle_bin" -type f 2>/dev/null > "$forensic_dest/RecycleBin/listing.txt"
        log_detail "Recycle Bin listing collected"
        ((collected++))
    fi
    
    # Browser history databases (SQLite)
    for user_dir in "$MOUNT_DIR/Users"/*; do
        [[ -d "$user_dir" ]] || continue
        local username=$(basename "$user_dir")
        local browser_dest="$forensic_dest/Timeline/$username/Browsers"
        
        # Chrome History
        local chrome_hist="$user_dir/AppData/Local/Google/Chrome/User Data/Default/History"
        if [[ -f "$chrome_hist" ]]; then
            mkdir -p "$browser_dest/Chrome"
            cp "$chrome_hist" "$browser_dest/Chrome/History" 2>/dev/null
        fi
        
        # Edge History
        local edge_hist="$user_dir/AppData/Local/Microsoft/Edge/User Data/Default/History"
        if [[ -f "$edge_hist" ]]; then
            mkdir -p "$browser_dest/Edge"
            cp "$edge_hist" "$browser_dest/Edge/History" 2>/dev/null
        fi
        
        # Firefox places.sqlite
        local ff_profiles="$user_dir/AppData/Roaming/Mozilla/Firefox/Profiles"
        if [[ -d "$ff_profiles" ]]; then
            for ff_profile in "$ff_profiles"/*; do
                [[ -f "$ff_profile/places.sqlite" ]] && {
                    mkdir -p "$browser_dest/Firefox"
                    cp "$ff_profile/places.sqlite" "$browser_dest/Firefox/places.sqlite" 2>/dev/null
                    break
                }
            done
        fi
    done
    
    if [[ $collected -gt 0 ]]; then
        log_success "Forensic artifacts collected ($collected categories)"
    else
        log_warning "No forensic artifacts found"
    fi
}

run_forensic_tools() {
    log_info "Running forensic analysis tools..."
    
    local forensic_dest="$OUTPUT_DIR/Forensics"
    mkdir -p "$forensic_dest/Analysis"
    local tools_run=0
    
    # fls - list files from filesystem image (from sleuthkit)
    if command -v fls &>/dev/null; then
        log_detail "Running fls for deleted file recovery list..."
        # This would need raw device access - for mounted we just note the tool is available
        echo "fls available - use on raw device for deleted file listing" > "$forensic_dest/Analysis/fls-note.txt"
        ((tools_run++))
    fi
    
    # strings - extract ASCII/Unicode strings from binary files
    if command -v strings &>/dev/null; then
        log_detail "Running strings on key files..."
        
        # Extract strings from hiberfil.sys (hibernation file may contain passwords)
        local hiberfil="$MOUNT_DIR/hiberfil.sys"
        if [[ -f "$hiberfil" ]]; then
            strings -n 10 "$hiberfil" 2>/dev/null | head -5000 > "$forensic_dest/Analysis/hiberfil-strings.txt"
            log_detail "Hibernation file strings extracted"
        fi
        
        # Extract strings from pagefile.sys
        local pagefile="$MOUNT_DIR/pagefile.sys"
        if [[ -f "$pagefile" ]]; then
            strings -n 10 "$pagefile" 2>/dev/null | head -5000 > "$forensic_dest/Analysis/pagefile-strings.txt"
            log_detail "Pagefile strings extracted"
        fi
        
        ((tools_run++))
    fi
    
    # exiftool - extract metadata from files
    if command -v exiftool &>/dev/null; then
        log_detail "ExifTool available for metadata extraction"
        # Don't run by default as it would take too long on full filesystem
        echo "exiftool available - run manually on specific files" > "$forensic_dest/Analysis/exiftool-note.txt"
        ((tools_run++))
    fi
    
    # foremost - file carving (recover deleted files)
    if command -v foremost &>/dev/null; then
        log_detail "Foremost available for file carving"
        echo "foremost available - run on raw device for file recovery" > "$forensic_dest/Analysis/foremost-note.txt"
        echo "Example: foremost -t doc,pdf,jpg -i /dev/sda1 -o /output/dir" >> "$forensic_dest/Analysis/foremost-note.txt"
        ((tools_run++))
    fi
    
    # photorec - file recovery
    if command -v photorec &>/dev/null; then
        log_detail "PhotoRec available for file recovery"
        echo "photorec available - run interactively for file recovery" > "$forensic_dest/Analysis/photorec-note.txt"
        ((tools_run++))
    fi
    
    # Create forensic tools summary
    {
        echo "=== FORENSIC TOOLS STATUS ==="
        echo "Date: $(date)"
        echo ""
        echo "Available tools:"
        for tool in fls mmls img_stat icat blkcat strings foremost photorec testdisk scalpel; do
            if command -v "$tool" &>/dev/null; then
                echo "  [+] $tool: $(which $tool)"
            else
                echo "  [-] $tool: NOT INSTALLED"
            fi
        done
        echo ""
        echo "To install forensic tools:"
        echo "  apt install sleuthkit foremost testdisk exiftool"
    } > "$forensic_dest/Analysis/tools-status.txt"
    
    if [[ $tools_run -gt 0 ]]; then
        log_success "Forensic tool analysis complete ($tools_run tools available)"
    else
        log_warning "No forensic tools available - install sleuthkit, foremost, etc."
    fi
}

create_collection_summary() {
    log_info "Creating collection summary..."
    
    local summary_file="$OUTPUT_DIR/COLLECTION_SUMMARY.txt"
    
    {
        echo "$DIVIDER"
        echo "LINUX COLLECTOR - OFFLINE WINDOWS DIAGNOSTIC COLLECTION"
        echo "$DIVIDER"
        echo ""
        echo "Collection Date:    $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Collector Version:  $VERSION"
        echo "Collection Host:    $(hostname)"
        echo "Computer Name:      $COMPUTER_NAME"
        echo "Serial Number:      $SERIAL_NUMBER"
        echo "Source Partition:   $SELECTED_PARTITION"
        echo "BitLocker:          $IS_BITLOCKER"
        echo ""
        echo "$DIVIDER"
        echo "COLLECTED DATA"
        echo "$DIVIDER"
        echo ""
        
        # List what was collected
        if [[ -d "$OUTPUT_DIR/EvtxLogs" ]]; then
            local evtx_count
            evtx_count=$(find "$OUTPUT_DIR/EvtxLogs" -name "*.evtx" 2>/dev/null | wc -l)
            echo "Event Logs:         $evtx_count .evtx files"
        fi
        
        if [[ -d "$OUTPUT_DIR/RegistryHives" ]]; then
            local reg_count
            reg_count=$(ls "$OUTPUT_DIR/RegistryHives" 2>/dev/null | wc -l)
            echo "Registry Hives:     $reg_count hives"
        fi
        
        if [[ -d "$OUTPUT_DIR/Logs" ]]; then
            echo "Windows Logs:       $(du -sh "$OUTPUT_DIR/Logs" 2>/dev/null | cut -f1)"
        fi
        
        if [[ -d "$OUTPUT_DIR/CrashDumps" ]]; then
            echo "Crash Dumps:        $(du -sh "$OUTPUT_DIR/CrashDumps" 2>/dev/null | cut -f1)"
        fi
        
        echo ""
        echo "$DIVIDER"
        echo ""
        echo "Files included in this archive:"
        find "$OUTPUT_DIR" -type f | sed "s|$OUTPUT_DIR/||" | sort
    } > "$summary_file"
    
    log_success "Collection summary created"
}

#===============================================================================
# Archive and Upload Functions
#===============================================================================

create_archive() {
    log_info "Creating ZIP archive..."
    
    local timestamp
    timestamp=$(date '+%Y%m%d-%H%M%S')
    local zip_name="Linux-Diag-${COMPUTER_NAME}-${SERIAL_NUMBER}-${timestamp}.zip"
    local zip_path="$WORK_DIR/$zip_name"
    
    # Create zip archive
    cd "$OUTPUT_DIR" || exit 1
    if ! zip -r "$zip_path" . -x "*.tmp" >&2; then
        log_error "Failed to create ZIP archive"
        exit 1
    fi
    cd - >/dev/null || exit 1
    
    local zip_size
    zip_size=$(du -h "$zip_path" | cut -f1)
    log_success "Archive created: $zip_name ($zip_size)"
    
    echo "$zip_path"
}

upload_archive() {
    local zip_path="$1"
    local zip_name
    zip_name=$(basename "$zip_path")
    
    log_info "Uploading diagnostics to server..."
    log_detail "Target: $UPLOAD_URL"
    log_detail "File: $zip_name"
    
    # Upload using curl with multipart form
    local response
    local http_code
    
    rm -f /tmp/upload_curl_stderr.txt
    http_code=$(curl -s -o /tmp/upload_response.txt -w "%{http_code}" \
        -X POST \
        -H "X-Auth-Key: $AUTH_KEY" \
        -F "file=@$zip_path;filename=$zip_name" \
        "$UPLOAD_URL" 2>/tmp/upload_curl_stderr.txt)
    
    response=$(cat /tmp/upload_response.txt 2>/dev/null)
    rm -f /tmp/upload_response.txt
    local curl_stderr
    curl_stderr=$(cat /tmp/upload_curl_stderr.txt 2>/dev/null)
    rm -f /tmp/upload_curl_stderr.txt
    
    if [[ "$http_code" == "200" || "$http_code" == "201" ]]; then
        log_success "Upload successful! (HTTP $http_code)"
        log_detail "Server response: $response"
        return 0
    else
        log_error "Upload failed (HTTP $http_code)"
        log_detail "Response: $response"
        if [[ -n "$curl_stderr" ]]; then
            log_detail "curl stderr: $curl_stderr"
        fi
        return 1
    fi
}

show_upload_menu() {
    local zip_path="$1"
    local zip_name
    zip_name=$(basename "$zip_path")
    local zip_size
    zip_size=$(du -h "$zip_path" | cut -f1)
    
    echo ""
    echo -e "${CYAN}${DIVIDER}${NC}"
    echo -e "${YELLOW}  UPLOAD METHOD SELECTION${NC}"
    echo -e "${CYAN}${DIVIDER}${NC}"
    echo ""
    echo -e "  File: ${WHITE}$zip_name${NC} ($zip_size)"
    echo ""
    echo -e "${YELLOW}  Available upload methods:${NC}"
    echo -e "${GRAY}  [1] HTTPS Upload (to PhoneHomeWeb server)${NC}"
    echo -e "${GRAY}  [2] SCP Upload (via SSH)${NC}"
    echo -e "${GRAY}  [3] Copy to USB/mounted drive${NC}"
    echo -e "${GRAY}  [4] Skip upload (keep local file only)${NC}"
    echo ""
    
    while true; do
        read -p "Select upload method (1-4): " choice
        
        case "$choice" in
            1)
                # Check if URL is still a placeholder (not a valid URL)
                if [[ ! "$UPLOAD_URL" =~ ^https?:// ]]; then
                    read -p "Enter server URL (e.g., https://server:3500/upload): " UPLOAD_URL
                fi
                # Check if auth key is still a placeholder (contains angle brackets)
                if [[ "$AUTH_KEY" =~ [\<\>] ]]; then
                    read -p "Enter authentication key: " AUTH_KEY
                fi
                
                if upload_archive "$zip_path"; then
                    return 0
                fi
                log_warning "HTTPS upload failed. Try another method?"
                ;;
            2)
                read -p "Enter SSH destination (user@host:/path): " scp_dest
                if scp "$zip_path" "$scp_dest" 2>&1; then
                    log_success "SCP upload successful!"
                    return 0
                fi
                log_warning "SCP upload failed. Try another method?"
                ;;
            3)
                read -p "Enter destination path: " dest_path
                if [[ -d "$dest_path" || -d "$(dirname "$dest_path")" ]]; then
                    if cp "$zip_path" "$dest_path/" 2>&1; then
                        log_success "File copied to $dest_path/"
                        return 0
                    fi
                fi
                log_warning "Copy failed. Try another method?"
                ;;
            4)
                log_warning "Upload skipped. File saved at: $zip_path"
                return 0
                ;;
            *)
                log_error "Invalid selection. Please enter 1-4"
                ;;
        esac
    done
}

#===============================================================================
# Main Execution
#===============================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --upload-url)
                UPLOAD_URL="$2"
                shift 2
                ;;
            --auth-key)
                AUTH_KEY="$2"
                shift 2
                ;;
            --no-upload)
                SKIP_UPLOAD=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Show banner
    show_banner
    
    # Pre-flight checks
    check_root
    check_dependencies
    setup_directories
    get_system_info
    
    echo ""
    echo -e "${CYAN}${DIVIDER}${NC}"
    echo -e "${YELLOW}  WINDOWS PARTITION SELECTION${NC}"
    echo -e "${CYAN}${DIVIDER}${NC}"
    echo ""
    
    # Detect and select Windows partition
    detect_windows_partitions
    
    # Mount the selected partition
    mount_windows_partition "$SELECTED_PARTITION"
    
    echo ""
    echo -e "${CYAN}${DIVIDER}${NC}"
    echo -e "${YELLOW}  COLLECTING DIAGNOSTIC DATA${NC}"
    echo -e "${CYAN}${DIVIDER}${NC}"
    echo ""
    
    # Collect diagnostics
    collect_environment_info
    collect_event_logs
    collect_registry_hives
    collect_windows_logs
    collect_crash_dumps
    collect_wer_reports
    collect_boot_config
    collect_servicing_packages
    collect_network_config
    collect_bitlocker_info
    collect_disk_health
    collect_file_inventory
    
    # Forensic collection (optional artifacts)
    collect_forensic_artifacts
    run_forensic_tools
    
    create_collection_summary
    
    echo ""
    echo -e "${CYAN}${DIVIDER}${NC}"
    echo -e "${YELLOW}  CREATING ARCHIVE${NC}"
    echo -e "${CYAN}${DIVIDER}${NC}"
    echo ""
    
    # Create archive
    zip_path=$(create_archive)
    
    # Upload or save locally
    if [[ "$SKIP_UPLOAD" != "true" ]]; then
        echo ""
        # Check if credentials are configured (URL starts with http and auth key has no angle brackets)
        if [[ "$UPLOAD_URL" =~ ^https?:// && ! "$AUTH_KEY" =~ [\<\>] ]]; then
            # Try automatic upload first
            if ! upload_archive "$zip_path"; then
                show_upload_menu "$zip_path"
            fi
        else
            show_upload_menu "$zip_path"
        fi
    else
        log_warning "Upload skipped (--no-upload flag)"
        log_info "Archive saved at: $zip_path"
    fi
    
    echo ""
    echo -e "${CYAN}${DIVIDER}${NC}"
    echo -e "${GREEN}  COLLECTION COMPLETE${NC}"
    echo -e "${CYAN}${DIVIDER}${NC}"
    echo ""
    echo -e "  Archive: ${WHITE}$zip_path${NC}"
    echo -e "  Log:     ${WHITE}$LOG_FILE${NC}"
    echo ""
}

# Run main
main "$@"
