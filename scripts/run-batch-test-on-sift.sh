#!/usr/bin/env bash
# Run batch testing on SIFT VM from host machine
# This script copies the batch test script to SIFT and executes it

set -euo pipefail

# Configuration
VM_NAME="${SIFT_VM_NAME:-sift-workstation}"
SSH_USER="sansforensics"
SSH_PASS="forensics"

# Get VM IP
get_vm_ip() {
    sudo virsh domifaddr "$VM_NAME" 2>/dev/null | awk '/ipv4/ {print $4}' | cut -d'/' -f1
}

# Check if VM is running
if ! sudo virsh list | grep -q "$VM_NAME.*running"; then
    echo "ERROR: VM '$VM_NAME' is not running"
    echo "Start it with: ./scripts/sift-commands.sh start"
    exit 1
fi

VM_IP=$(get_vm_ip)
if [ -z "$VM_IP" ]; then
    echo "ERROR: Could not get VM IP"
    exit 1
fi

echo "=========================================="
echo "  USB Evidence Batch Testing"
echo "=========================================="
echo ""
echo "VM: $VM_NAME"
echo "IP: $VM_IP"
echo ""

# Copy batch test script to VM
echo "[1/4] Copying batch test script to VM..."
sshpass -p "$SSH_PASS" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    scripts/batch-test-usb.sh "${SSH_USER}@${VM_IP}:/tmp/" 2>&1 | grep -v "Warning:" || true

# Make it executable
echo "[2/4] Setting permissions..."
sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "${SSH_USER}@${VM_IP}" "chmod +x /tmp/batch-test-usb.sh" 2>&1 | grep -v "Warning:" || true

# Run batch test
echo "[3/4] Running batch test (this may take a while)..."
echo ""

sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "${SSH_USER}@${VM_IP}" "bash /tmp/batch-test-usb.sh" 2>&1 | grep -v "Warning:" || true

# Copy results back to host
echo ""
echo "[4/4] Copying results back to host..."

TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
RESULTS_DIR="test-results/usb-batch/$TIMESTAMP"
mkdir -p "$RESULTS_DIR"

# Get the latest batch-test-results directory
LATEST_RUN=$(sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "${SSH_USER}@${VM_IP}" "ls -td ~/batch-test-results/*/ 2>/dev/null | head -1" 2>&1 | grep -v "Warning:" | tr -d '/' || echo "")

if [ -n "$LATEST_RUN" ]; then
    echo "Copying from: $LATEST_RUN"

    # Copy summary and logs
    sshpass -p "$SSH_PASS" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -r \
        "${SSH_USER}@${VM_IP}:$LATEST_RUN/*" "$RESULTS_DIR/" 2>&1 | grep -v "Warning:" || true

    echo ""
    echo "=========================================="
    echo "  Results Summary"
    echo "=========================================="
    echo ""

    if [ -f "$RESULTS_DIR/SUMMARY.md" ]; then
        cat "$RESULTS_DIR/SUMMARY.md"
    fi

    echo ""
    echo "Results saved to: $RESULTS_DIR/"
else
    echo "WARNING: Could not find batch test results on VM"
fi

echo ""
echo "=========================================="
echo "  Batch Test Complete"
echo "=========================================="
echo ""
echo "View detailed findings:"
echo "  find test-results/ -name 'findings.json'"
echo ""
echo "Review logs:"
echo "  ls $RESULTS_DIR/*.log"
echo ""
