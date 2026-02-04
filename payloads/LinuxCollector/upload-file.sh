#!/bin/bash
#===============================================================================
# File Upload Helper - PhoneHomeWeb
# Uploads files to PhoneHomeWeb server with authentication
#
# This script is downloaded live from the server with credentials injected.
# Usage: curl -sH "X-Auth-Key: KEY" https://server:3500/linux-upload-script | bash -s /path/to/file
#===============================================================================

set -o pipefail

# Server configuration (injected by server at download time)
SERVER_URL="<<SERVERURL>>/upload"
AUTH_KEY="<<AUTHKEY>>"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

show_usage() {
    echo "PhoneHomeWeb File Upload Helper"
    echo ""
    echo "Usage: $0 <file> [options]"
    echo ""
    echo "Arguments:"
    echo "  file              File or directory to upload"
    echo ""
    echo "Options:"
    echo "  -s, --server URL  Override server URL"
    echo "  -k, --key KEY     Override authentication key"
    echo "  -z, --zip         Compress directory before upload"
    echo "  -h, --help        Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 /tmp/windows-logs.zip"
    echo "  $0 /tmp/report-dir --zip"
    echo "  $0 /tmp/file.txt --server https://myserver:3500/upload"
}

log_info() { echo -e "${CYAN}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Parse arguments
FILE=""
DO_ZIP=0

while [ $# -gt 0 ]; do
    case "$1" in
        -s|--server) SERVER_URL="$2"; shift 2 ;;
        -k|--key) AUTH_KEY="$2"; shift 2 ;;
        -z|--zip) DO_ZIP=1; shift ;;
        -h|--help) show_usage; exit 0 ;;
        -*) log_error "Unknown option: $1"; show_usage; exit 1 ;;
        *) FILE="$1"; shift ;;
    esac
done

# Validate input
if [ -z "$FILE" ]; then
    log_error "No file specified"
    show_usage
    exit 1
fi

if [ ! -e "$FILE" ]; then
    log_error "File not found: $FILE"
    exit 1
fi

# Check for placeholder values (use single angle brackets so server doesn't replace these)
if [[ "$SERVER_URL" == *"<SERVERURL>"* ]] || [[ "$SERVER_URL" == "<<SERVERURL>>" ]]; then
    log_warn "Server URL not configured in script"
    read -rp "Enter server URL (e.g., https://server:3500/upload): " SERVER_URL
    if [ -z "$SERVER_URL" ]; then
        log_error "Server URL is required"
        exit 1
    fi
fi

if [[ "$AUTH_KEY" == *"<AUTHKEY>"* ]] || [[ "$AUTH_KEY" == "<<AUTHKEY>>" ]] || [ -z "$AUTH_KEY" ]; then
    log_warn "Authentication key not configured in script"
    read -rp "Enter authentication key: " AUTH_KEY
    if [ -z "$AUTH_KEY" ]; then
        log_error "Authentication key is required"
        exit 1
    fi
fi

# Handle directory uploads
UPLOAD_FILE="$FILE"
CLEANUP_FILE=""

if [ -d "$FILE" ]; then
    if [ $DO_ZIP -eq 1 ]; then
        log_info "Compressing directory..."
        UPLOAD_FILE="/tmp/upload-$(basename "$FILE")-$(date +%Y%m%d-%H%M%S).zip"
        if ! zip -rq "$UPLOAD_FILE" "$FILE" 2>/dev/null; then
            log_error "Failed to compress directory"
            exit 1
        fi
        CLEANUP_FILE="$UPLOAD_FILE"
        log_success "Compressed to: $UPLOAD_FILE"
    else
        log_error "$FILE is a directory. Use --zip to compress before upload."
        exit 1
    fi
fi

# Get file info
filename=$(basename "$UPLOAD_FILE")
filesize=$(stat -c%s "$UPLOAD_FILE" 2>/dev/null || stat -f%z "$UPLOAD_FILE" 2>/dev/null || echo "0")
filesize_human=$(numfmt --to=iec "$filesize" 2>/dev/null || echo "${filesize} bytes")

log_info "Uploading: $filename ($filesize_human)"
log_info "Target: $SERVER_URL"

# Check if curl is available
if ! command -v curl >/dev/null 2>&1; then
    log_error "curl is required but not installed"
    exit 1
fi

# Perform upload
echo ""
response=$(curl -s -w "\n%{http_code}" \
    --connect-timeout 30 \
    --max-time 3600 \
    -X POST \
    -H "X-Auth-Key: $AUTH_KEY" \
    -F "file=@$UPLOAD_FILE;filename=$filename" \
    "$SERVER_URL" 2>&1)

http_code=$(echo "$response" | tail -1)
body=$(echo "$response" | head -n -1)

# Cleanup temp file if created
if [ -n "$CLEANUP_FILE" ] && [ -f "$CLEANUP_FILE" ]; then
    rm -f "$CLEANUP_FILE"
fi

# Check result
if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
    echo ""
    log_success "Upload successful! (HTTP $http_code)"
    echo "$body" | head -5
    exit 0
else
    echo ""
    log_error "Upload failed (HTTP $http_code)"
    echo "$body" | head -10
    exit 1
fi
