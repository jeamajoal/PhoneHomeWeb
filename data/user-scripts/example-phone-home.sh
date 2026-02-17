#!/bin/bash
# Example public script for phone home functionality
# This script can be accessed without authentication via:
# curl http://your-server:3500/user-scripts/example-phone-home.sh | bash

# Configuration - these would typically be set by your environment
SERVER_URL="${PHONEHOME_SERVER:-http://localhost:3500}"
AUTH_KEY="${PHONEHOME_AUTH_KEY:-your-auth-key-here}"

echo "PhoneHome Example Script"
echo "======================="
echo "Server: $SERVER_URL"
echo ""

# Example: Collect basic system info
HOSTNAME=$(hostname)
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_FILE="/tmp/system-info-${HOSTNAME}-${TIMESTAMP}.txt"

echo "Collecting system information..."
{
  echo "=== System Information ==="
  echo "Hostname: $(hostname)"
  echo "Date: $(date)"
  echo "Uptime: $(uptime)"
  echo ""
  echo "=== Disk Usage ==="
  df -h
  echo ""
  echo "=== Memory Usage ==="
  free -h
  echo ""
  echo "=== Network Interfaces ==="
  ip addr
} > "$OUTPUT_FILE"

echo "Information collected: $OUTPUT_FILE"

# Upload to server
echo "Uploading to server..."
curl -X POST "$SERVER_URL/upload" \
  -H "X-Auth-Key: $AUTH_KEY" \
  -F "file=@$OUTPUT_FILE"

if [ $? -eq 0 ]; then
  echo "Upload successful!"
  rm -f "$OUTPUT_FILE"
else
  echo "Upload failed. File saved at: $OUTPUT_FILE"
  exit 1
fi
