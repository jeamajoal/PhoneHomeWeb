#!/bin/bash
# FileUpload-Curl.sh
# Cross-platform file upload script using curl (Linux/macOS/WSL)
#
# Usage:
#   ./FileUpload-Curl.sh -s "http://localhost:3500" -f "/path/to/file.zip" -k "your-auth-key"
#
# Requirements:
#   - curl installed
#   - Network connectivity to server

set -e

# Default values (can be overridden by placeholders or command-line args)
SERVER_URL="${SERVER_URL:-<<SERVERURL>>}"
FILE_PATH="${FILE_PATH:-<<FILEPATH>>}"
AUTH_KEY="${AUTH_KEY:-<<AUTHKEY>>}"

# Parse command line arguments
while getopts "s:f:k:h" opt; do
    case $opt in
        s) SERVER_URL="$OPTARG" ;;
        f) FILE_PATH="$OPTARG" ;;
        k) AUTH_KEY="$OPTARG" ;;
        h)
            echo "Usage: $0 -s <server_url> -f <file_path> -k <auth_key>"
            echo ""
            echo "Options:"
            echo "  -s    Server URL (e.g., http://localhost:3500)"
            echo "  -f    Path to file to upload"
            echo "  -k    Authentication key"
            echo "  -h    Show this help message"
            exit 0
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            exit 1
            ;;
    esac
done

# Validate required parameters
if [[ "$SERVER_URL" == "<<SERVERURL>>" ]] || [[ -z "$SERVER_URL" ]]; then
    echo "Error: Server URL is required. Use -s option or set SERVER_URL environment variable."
    exit 1
fi

if [[ "$FILE_PATH" == "<<FILEPATH>>" ]] || [[ -z "$FILE_PATH" ]]; then
    echo "Error: File path is required. Use -f option or set FILE_PATH environment variable."
    exit 1
fi

if [[ "$AUTH_KEY" == "<<AUTHKEY>>" ]] || [[ -z "$AUTH_KEY" ]]; then
    echo "Error: Auth key is required. Use -k option or set AUTH_KEY environment variable."
    exit 1
fi

# Check if file exists
if [[ ! -f "$FILE_PATH" ]]; then
    echo "Error: File not found: $FILE_PATH"
    exit 1
fi

# Check if curl is available
if ! command -v curl &> /dev/null; then
    echo "Error: curl is not installed. Please install curl and try again."
    exit 1
fi

# Get system info for filename prefix
HOSTNAME=$(hostname 2>/dev/null || echo "unknown")
# Try to get serial number (Linux-specific, fallback to empty)
SERIAL_NUMBER=$(sudo dmidecode -s system-serial-number 2>/dev/null || cat /sys/class/dmi/id/product_serial 2>/dev/null || echo "")

# Build upload URL
UPLOAD_URL="${SERVER_URL}/upload"

# Get original filename
FILENAME=$(basename "$FILE_PATH")

# Build final filename with system info prefix
if [[ -n "$SERIAL_NUMBER" ]]; then
    FINAL_FILENAME="${HOSTNAME}_${SERIAL_NUMBER}_${FILENAME}"
else
    FINAL_FILENAME="${HOSTNAME}_${FILENAME}"
fi

echo "========================================"
echo "PhoneHomeWeb File Upload (curl)"
echo "========================================"
echo "Server:   $SERVER_URL"
echo "File:     $FILE_PATH"
echo "Filename: $FINAL_FILENAME"
echo "========================================"

# Perform upload using curl
echo "Uploading..."

RESPONSE=$(curl -s -w "\n%{http_code}" \
    -X POST \
    -H "X-Auth-Key: $AUTH_KEY" \
    -F "file=@${FILE_PATH};filename=${FINAL_FILENAME}" \
    "$UPLOAD_URL")

# Extract HTTP status code (last line)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
# Extract response body (everything except last line)
BODY=$(echo "$RESPONSE" | sed '$d')

if [[ "$HTTP_CODE" -ge 200 ]] && [[ "$HTTP_CODE" -lt 300 ]]; then
    echo "========================================"
    echo "Upload successful!"
    echo "========================================"
    echo "$BODY"
    exit 0
else
    echo "========================================"
    echo "Upload failed! HTTP Status: $HTTP_CODE"
    echo "========================================"
    echo "$BODY"
    exit 1
fi
