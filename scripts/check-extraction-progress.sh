#!/usr/bin/env bash
# Monitor archive extraction progress on SIFT VM

set -euo pipefail

VM_IP="${1:-192.168.122.76}"
SSH_USER="sansforensics"
SSH_PASS="forensics"
USB_MOUNT="/mnt/usb-evidence/sift_evidence"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "========================================"
echo "  Archive Extraction Monitor"
echo "========================================"
echo ""

# Check if extraction is running
if sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "${SSH_USER}@${VM_IP}" "pgrep -f 'extract-usb-archives.sh' >/dev/null" 2>&1 | grep -v "Warning:"; then
    echo -e "${GREEN}Extraction is RUNNING${NC}"
else
    echo -e "${YELLOW}Extraction is NOT running${NC}"
fi

echo ""

# Check for extracted files
echo "=== Extracted Evidence ==="
echo ""

for scenario in blue_team_challenge ransomware_2021 national_gallery_2012; do
    echo "--- $scenario ---"
    sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        "${SSH_USER}@${VM_IP}" "
        find $USB_MOUNT/$scenario/evidence -type f \( -name '*.E01' -o -name '*.dd' -o -name '*.raw' \) 2>/dev/null | wc -l
    " 2>&1 | grep -v "Warning:" | sed "s/^/  E01\/DD\/raw files: /"
    echo ""
done

echo "========================================"
echo ""
echo "To watch live: watch -n 5 $0"
