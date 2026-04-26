#!/usr/bin/env bash
# Run archive extraction on SIFT VM from host machine

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
echo "  USB Archive Extraction"
echo "=========================================="
echo ""
echo "VM: $VM_NAME"
echo "IP: $VM_IP"
echo ""

# Copy extraction script to VM
echo "[1/2] Copying extraction script to VM..."
sshpass -p "$SSH_PASS" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    scripts/extract-usb-archives.sh "${SSH_USER}@${VM_IP}:/tmp/" 2>&1 | grep -v "Warning:" || true

# Run extraction
echo "[2/2] Running extraction (this will take several minutes)..."
echo ""

sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "${SSH_USER}@${VM_IP}" "bash /tmp/extract-usb-archives.sh" 2>&1 | grep -v "Warning:" || true

echo ""
echo "=========================================="
echo "  Extraction Complete"
echo "=========================================="
echo ""
echo "Next step: Run batch testing"
echo "  ./scripts/run-batch-test-on-sift.sh"
echo ""
