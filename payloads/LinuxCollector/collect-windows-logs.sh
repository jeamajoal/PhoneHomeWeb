#!/bin/bash
#===============================================================================
# Windows Log Collector - PhoneHomeWeb
# Collects diagnostic logs from offline Windows installation
#
# This script is downloaded live from the server with credentials injected.
# Usage: curl -sH "X-Auth-Key: KEY" https://server:3500/linux-collect-logs | bash
#===============================================================================

set -o pipefail

# Server configuration (injected by server at download time)
SERVER_URL="<<SERVERURL>>"
AUTH_KEY="<<AUTHKEY>>"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

show_usage() {
    echo "Windows Log Collector - PhoneHomeWeb"
    echo ""
    echo "Usage: $0 <windows-mount-point> [options]"
    echo ""
    echo "Arguments:"
    echo "  windows-mount-point   Path where Windows is mounted (e.g., /mnt/windows)"
    echo ""
    echo "Options:"
    echo "  -o, --output DIR      Output directory (default: /tmp/windows-logs-TIMESTAMP)"
    echo "  --no-upload           Only collect, do not upload"
    echo "  --server URL          Override server URL"
    echo "  --key KEY             Override auth key"
    echo "  -h, --help            Show this help"
    echo ""
    echo "Example:"
    echo "  # First mount the Windows partition:"
    echo "  ./mount-windows.sh /dev/sda3"
    echo ""
    echo "  # Then collect and upload logs:"
    echo "  $0 /mnt/windows"
}

log_info() { echo -e "${CYAN}[*]${NC} $*"; }
log_success() { echo -e "${GREEN}[+]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[-]${NC} $*" >&2; }

# Parse arguments
WIN_MOUNT=""
OUTPUT_DIR=""
NO_UPLOAD=0

while [ $# -gt 0 ]; do
    case "$1" in
        -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
        --no-upload) NO_UPLOAD=1; shift ;;
        --server) SERVER_URL="$2"; shift 2 ;;
        --key) AUTH_KEY="$2"; shift 2 ;;
        -h|--help) show_usage; exit 0 ;;
        -*) log_error "Unknown option: $1"; show_usage; exit 1 ;;
        *) WIN_MOUNT="$1"; shift ;;
    esac
done

# Validate arguments
if [ -z "$WIN_MOUNT" ]; then
    log_error "No Windows mount point specified"
    show_usage
    exit 1
fi

# Validate mount point
if [ ! -d "$WIN_MOUNT/Windows/System32" ]; then
    log_error "$WIN_MOUNT does not appear to be a Windows installation"
    echo "Expected to find: $WIN_MOUNT/Windows/System32"
    echo ""
    echo "Available directories in $WIN_MOUNT:"
    ls -la "$WIN_MOUNT" 2>/dev/null | head -10 || echo "  (cannot list)"
    exit 1
fi

# Setup output directory
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/windows-logs-$TIMESTAMP}"

# Try to get Windows computer name from registry (if hivexget available)
COMPUTER_NAME="UNKNOWN"
if command -v hivexget >/dev/null 2>&1; then
    reg_file="$WIN_MOUNT/Windows/System32/config/SYSTEM"
    if [ -f "$reg_file" ]; then
        COMPUTER_NAME=$(hivexget "$reg_file" 'ControlSet001\Control\ComputerName\ComputerName' ComputerName 2>/dev/null | tr -d '\0' || echo "UNKNOWN")
    fi
fi

# Try to get serial from system-product-name
SERIAL_NUMBER=$(dmidecode -s system-serial-number 2>/dev/null | tr -d '[:space:]' || echo "UNKNOWN")
[[ "$SERIAL_NUMBER" == "ToBeFilledByO.E.M." ]] && SERIAL_NUMBER="UNKNOWN"

echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN} Windows Log Collector${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""
echo "Source:    $WIN_MOUNT"
echo "Output:    $OUTPUT_DIR"
echo "Computer:  $COMPUTER_NAME"
echo "Serial:    $SERIAL_NUMBER"
echo ""

mkdir -p "$OUTPUT_DIR"/{EventLogs,RegistryHives,WindowsLogs,SetupLogs,CrashDumps,SystemInfo,BootConfig,WERReports}

#===============================================================================
# Collection Functions
#===============================================================================

collect_event_logs() {
    log_info "Collecting Event Logs..."
    local evtx_src="$WIN_MOUNT/Windows/System32/winevt/Logs"
    if [ -d "$evtx_src" ]; then
        cp -r "$evtx_src"/* "$OUTPUT_DIR/EventLogs/" 2>/dev/null || true
        local count=$(find "$OUTPUT_DIR/EventLogs" -name "*.evtx" 2>/dev/null | wc -l)
        log_success "Collected $count .evtx files"
    else
        log_warn "Event logs not found"
    fi
}

collect_registry_hives() {
    log_info "Collecting Registry Hives..."
    local reg_src="$WIN_MOUNT/Windows/System32/config"
    if [ -d "$reg_src" ]; then
        for hive in SYSTEM SOFTWARE DEFAULT; do
            if [ -f "$reg_src/$hive" ]; then
                cp "$reg_src/$hive" "$OUTPUT_DIR/RegistryHives/" 2>/dev/null && echo "    $hive"
            fi
        done
        log_success "Registry hives collected (SAM/SECURITY excluded for security)"
    else
        log_warn "Registry hives not found"
    fi
}

collect_windows_logs() {
    log_info "Collecting Windows Logs..."
    
    # CBS, DISM, WindowsUpdate logs
    for logdir in "Windows/Logs/WindowsUpdate" "Windows/Logs/CBS" "Windows/Logs/DISM"; do
        if [ -d "$WIN_MOUNT/$logdir" ]; then
            dirname=$(basename "$logdir")
            cp -r "$WIN_MOUNT/$logdir" "$OUTPUT_DIR/WindowsLogs/$dirname" 2>/dev/null
            echo "    $dirname"
        fi
    done
    
    # SoftwareDistribution logs
    local sd_log="$WIN_MOUNT/Windows/SoftwareDistribution/ReportingEvents.log"
    if [ -f "$sd_log" ]; then
        cp "$sd_log" "$OUTPUT_DIR/WindowsLogs/" 2>/dev/null
        echo "    SoftwareDistribution/ReportingEvents.log"
    fi
}

collect_setup_logs() {
    log_info "Collecting Setup Logs..."
    
    # Panther (Windows Setup)
    if [ -d "$WIN_MOUNT/Windows/Panther" ]; then
        cp -r "$WIN_MOUNT/Windows/Panther" "$OUTPUT_DIR/SetupLogs/Panther" 2>/dev/null
        echo "    Panther"
    fi
    
    # MoSetup (Feature Update)
    if [ -d "$WIN_MOUNT/Windows/Logs/MoSetup" ]; then
        cp -r "$WIN_MOUNT/Windows/Logs/MoSetup" "$OUTPUT_DIR/SetupLogs/MoSetup" 2>/dev/null
        echo "    MoSetup"
    fi
    
    # SetupAPI (driver installation)
    if [ -d "$WIN_MOUNT/Windows/INF" ]; then
        mkdir -p "$OUTPUT_DIR/SetupLogs/SetupAPI"
        cp "$WIN_MOUNT/Windows/INF"/setupapi*.log "$OUTPUT_DIR/SetupLogs/SetupAPI/" 2>/dev/null
        echo "    SetupAPI"
    fi
    
    # NetSetup (network setup)
    for dir in "Windows/debug/NetSetup" "Windows/System32/LogFiles/NetSetup"; do
        if [ -d "$WIN_MOUNT/$dir" ]; then
            cp -r "$WIN_MOUNT/$dir" "$OUTPUT_DIR/SetupLogs/NetSetup" 2>/dev/null
            echo "    NetSetup"
            break
        fi
    done
    
    # Startup repair logs
    if [ -d "$WIN_MOUNT/Windows/System32/LogFiles/Srt" ]; then
        cp -r "$WIN_MOUNT/Windows/System32/LogFiles/Srt" "$OUTPUT_DIR/SetupLogs/StartupRepair" 2>/dev/null
        echo "    StartupRepair"
    fi
}

collect_crash_dumps() {
    log_info "Collecting Crash Dumps..."
    
    # Minidumps
    if [ -d "$WIN_MOUNT/Windows/Minidump" ]; then
        cp -r "$WIN_MOUNT/Windows/Minidump" "$OUTPUT_DIR/CrashDumps/Minidump" 2>/dev/null
        local count=$(find "$OUTPUT_DIR/CrashDumps/Minidump" -name "*.dmp" 2>/dev/null | wc -l)
        echo "    $count minidump files"
    fi
    
    # MEMORY.DMP (only if < 500MB)
    if [ -f "$WIN_MOUNT/Windows/MEMORY.DMP" ]; then
        local size=$(stat -c%s "$WIN_MOUNT/Windows/MEMORY.DMP" 2>/dev/null || echo 0)
        if [ "$size" -lt 524288000 ]; then
            cp "$WIN_MOUNT/Windows/MEMORY.DMP" "$OUTPUT_DIR/CrashDumps/" 2>/dev/null
            echo "    MEMORY.DMP ($(numfmt --to=iec $size 2>/dev/null || echo $size))"
        else
            echo "    MEMORY.DMP skipped ($(numfmt --to=iec $size 2>/dev/null) > 500MB)"
        fi
    fi
    
    # LiveKernelReports
    if [ -d "$WIN_MOUNT/Windows/LiveKernelReports" ]; then
        cp -r "$WIN_MOUNT/Windows/LiveKernelReports" "$OUTPUT_DIR/CrashDumps/LiveKernelReports" 2>/dev/null
        echo "    LiveKernelReports"
    fi
}

collect_wer_reports() {
    log_info "Collecting Windows Error Reporting..."
    
    local wer_paths=(
        "ProgramData/Microsoft/Windows/WER/ReportArchive"
        "ProgramData/Microsoft/Windows/WER/ReportQueue"
    )
    
    for wer_path in "${wer_paths[@]}"; do
        if [ -d "$WIN_MOUNT/$wer_path" ]; then
            local dirname=$(basename "$wer_path")
            cp -r "$WIN_MOUNT/$wer_path" "$OUTPUT_DIR/WERReports/$dirname" 2>/dev/null
            echo "    $dirname"
        fi
    done
}

collect_boot_config() {
    log_info "Collecting Boot Configuration..."
    
    # Copy BCD stores
    local bcd_paths=(
        "Boot/BCD"
        "EFI/Microsoft/Boot/BCD"
    )
    
    for bcd_path in "${bcd_paths[@]}"; do
        if [ -f "$WIN_MOUNT/$bcd_path" ]; then
            local dirname=$(dirname "$bcd_path" | tr '/' '-')
            cp "$WIN_MOUNT/$bcd_path" "$OUTPUT_DIR/BootConfig/BCD-$dirname" 2>/dev/null
            echo "    $bcd_path"
        fi
    done
    
    # Hosts file
    local hosts_file="$WIN_MOUNT/Windows/System32/drivers/etc/hosts"
    if [ -f "$hosts_file" ]; then
        cp "$hosts_file" "$OUTPUT_DIR/BootConfig/hosts" 2>/dev/null
        echo "    hosts file"
    fi
}

collect_system_info() {
    log_info "Collecting System Information..."
    
    # Create system info summary
    cat > "$OUTPUT_DIR/SystemInfo/collection-info.txt" << EOF
PhoneHomeWeb Linux Collector - Collection Summary
==================================================
Collection Date: $(date)
Collector Host:  $(hostname)
Source Path:     $WIN_MOUNT
Computer Name:   $COMPUTER_NAME
Serial Number:   $SERIAL_NUMBER

Linux Environment:
  Kernel:        $(uname -r)
  Distribution:  $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || echo "Unknown")

Disk Information:
$(lsblk -o NAME,SIZE,TYPE,FSTYPE,LABEL,MOUNTPOINT 2>/dev/null || echo "lsblk not available")

SMART Health Summary:
EOF
    
    # Add SMART data if available
    if command -v smartctl >/dev/null 2>&1; then
        for disk in /dev/sd? /dev/nvme?n?; do
            [ -b "$disk" ] || continue
            echo "--- $disk ---" >> "$OUTPUT_DIR/SystemInfo/collection-info.txt"
            smartctl -H "$disk" 2>/dev/null >> "$OUTPUT_DIR/SystemInfo/collection-info.txt" || echo "SMART not available" >> "$OUTPUT_DIR/SystemInfo/collection-info.txt"
        done
    fi
    
    log_success "System info collected"
}

#===============================================================================
# Main Collection
#===============================================================================

collect_event_logs
collect_registry_hives
collect_windows_logs
collect_setup_logs
collect_crash_dumps
collect_wer_reports
collect_boot_config
collect_system_info

# Create file manifest
log_info "Creating file manifest..."
find "$OUTPUT_DIR" -type f > "$OUTPUT_DIR/file-manifest.txt"
file_count=$(wc -l < "$OUTPUT_DIR/file-manifest.txt")
total_size=$(du -sh "$OUTPUT_DIR" | cut -f1)

# Create ZIP archive
log_info "Creating ZIP archive..."
ZIP_NAME="${COMPUTER_NAME}_${SERIAL_NUMBER}_${TIMESTAMP}_LinuxLogs.zip"
ZIP_PATH="/tmp/$ZIP_NAME"

if zip -rq "$ZIP_PATH" "$OUTPUT_DIR" 2>/dev/null; then
    ZIP_SIZE=$(du -sh "$ZIP_PATH" | cut -f1)
    log_success "Archive created: $ZIP_PATH ($ZIP_SIZE)"
else
    log_error "Failed to create ZIP archive"
    exit 1
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} Collection Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Files collected: $file_count"
echo "Total size:      $total_size"
echo "Archive:         $ZIP_PATH"
echo ""

# Upload if enabled
if [ $NO_UPLOAD -eq 0 ]; then
    if [[ "$SERVER_URL" == *"<<SERVERURL>>"* ]]; then
        log_warn "Server URL not configured - skipping upload"
        log_info "To upload manually: curl -X POST -H 'X-Auth-Key: KEY' -F 'file=@$ZIP_PATH' URL/upload"
    else
        log_info "Uploading to $SERVER_URL..."
        
        UPLOAD_URL="${SERVER_URL}/upload"
        response=$(curl -s -w "\n%{http_code}" \
            --connect-timeout 30 \
            --max-time 3600 \
            -X POST \
            -H "X-Auth-Key: $AUTH_KEY" \
            -F "file=@$ZIP_PATH;filename=$ZIP_NAME" \
            "$UPLOAD_URL" 2>&1)
        
        http_code=$(echo "$response" | tail -1)
        body=$(echo "$response" | head -n -1)
        
        if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
            log_success "Upload successful! (HTTP $http_code)"
        else
            log_error "Upload failed (HTTP $http_code)"
            echo "$body" | head -5
        fi
    fi
else
    log_info "Upload skipped (--no-upload)"
fi

echo ""
echo "Local files available at:"
echo "  Directory: $OUTPUT_DIR"
echo "  Archive:   $ZIP_PATH"
