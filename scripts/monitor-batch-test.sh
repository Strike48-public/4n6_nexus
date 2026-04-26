#!/usr/bin/env bash
# Monitor batch test progress on SIFT VM

set -euo pipefail

VM_IP="${1:-192.168.122.76}"
SSH_USER="sansforensics"
SSH_PASS="forensics"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "========================================"
echo "  Batch Test Monitor"
echo "========================================"
echo ""

# Check if batch test is running
if ! sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "${SSH_USER}@${VM_IP}" "pgrep -f 'batch-test-usb.sh' >/dev/null" 2>&1 | grep -v "Warning:"; then
    echo -e "${YELLOW}Batch test is NOT running${NC}"
    echo ""
    echo "Recent results:"
    sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        "${SSH_USER}@${VM_IP}" "ls -lt ~/batch-test-results/ 2>/dev/null | head -5" 2>&1 | grep -v "Warning:" || echo "No results yet"
    exit 0
fi

echo -e "${GREEN}Batch test is RUNNING${NC}"
echo ""

# Get latest results directory
LATEST_DIR=$(sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "${SSH_USER}@${VM_IP}" "ls -td ~/batch-test-results/*/ 2>/dev/null | head -1" 2>&1 | grep -v "Warning:" | tr -d '/')

if [ -z "$LATEST_DIR" ]; then
    echo "No results directory found yet"
    exit 0
fi

echo -e "${BLUE}Results directory:${NC} $LATEST_DIR"
echo ""

# Count scenarios tested
LOG_COUNT=$(sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "${SSH_USER}@${VM_IP}" "ls $LATEST_DIR/*.log 2>/dev/null | wc -l" 2>&1 | grep -v "Warning:")

echo "Scenarios tested so far: $LOG_COUNT"
echo ""

# Show recent logs
echo "Recent activity:"
sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "${SSH_USER}@${VM_IP}" "ls -lt $LATEST_DIR/*.log 2>/dev/null | head -5 | awk '{print \$9}' | xargs -I {} basename {} .log" 2>&1 | grep -v "Warning:" | sed 's/^/  - /'

echo ""

# Check current status of each
echo "Status summary:"
for log in $(sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "${SSH_USER}@${VM_IP}" "ls $LATEST_DIR/*.log 2>/dev/null" 2>&1 | grep -v "Warning:"); do

    scenario=$(basename "$log" .log)
    status=$(sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        "${SSH_USER}@${VM_IP}" "grep 'Status:' $log 2>/dev/null | tail -1" 2>&1 | grep -v "Warning:" | sed 's/.*Status: *//')

    if [ -n "$status" ]; then
        echo "  $scenario: $status"
    fi
done

echo ""
echo "========================================"
echo ""
echo "To watch live: watch -n 5 $0"
echo "To see full output: ssh ${SSH_USER}@${VM_IP} 'tail -f ${LATEST_DIR}/*.log'"
