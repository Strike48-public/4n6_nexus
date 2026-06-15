#!/usr/bin/env bash
# SIFT VM Automation - Setup and Test Workflow
# This script automates: VM start → SSH → MCP check → Software test

set -euo pipefail

# Configuration
VM_NAME="${SIFT_VM_NAME:-sift-2026}"
OVA_FILE="${SIFT_OVA:-sift-2026.03.24.ova}"
DISK_PATH="/var/lib/libvirt/images/${VM_NAME}.qcow2"
SSH_USER="sansforensics"
SSH_PASS="forensics"
SSH_PORT="22"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# Check prerequisites
check_prereqs() {
    info "Checking prerequisites..."

    command -v virsh >/dev/null 2>&1 || error "virsh not found. Install: sudo apt install libvirt-clients"
    command -v virt-install >/dev/null 2>&1 || error "virt-install not found. Install: sudo apt install virtinst"
    command -v qemu-img >/dev/null 2>&1 || error "qemu-img not found. Install: sudo apt install qemu-utils"
    command -v sshpass >/dev/null 2>&1 || warn "sshpass not found. Install for automated SSH: sudo apt install sshpass"

    info "Prerequisites OK"
}

# Check if VM exists
vm_exists() {
    virsh dominfo "$VM_NAME" &>/dev/null
}

# Check if VM is running
vm_running() {
    virsh list --name | grep -q "^${VM_NAME}$"
}

# Get VM IP address
get_vm_ip() {
    local ip
    ip=$(virsh domifaddr "$VM_NAME" | awk '/ipv4/ {print $4}' | cut -d'/' -f1)
    echo "$ip"
}

# Wait for SSH to be available
wait_for_ssh() {
    local ip="$1"
    local max_attempts=30
    local attempt=1

    info "Waiting for SSH on $ip..."

    while [ $attempt -le $max_attempts ]; do
        if timeout 2 bash -c "cat < /dev/null > /dev/tcp/$ip/22" 2>/dev/null; then
            info "SSH is available"
            return 0
        fi
        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done

    error "SSH not available after $max_attempts attempts"
}

# Import and create VM
setup_vm() {
    if vm_exists; then
        info "VM '$VM_NAME' already exists"
        return 0
    fi

    info "Setting up VM '$VM_NAME'..."

    # Check OVA file exists
    if [ ! -f "$OVA_FILE" ]; then
        error "OVA file not found: $OVA_FILE"
    fi

    # Extract OVA
    info "Extracting OVA..."
    tar -xf "$OVA_FILE"

    # Find VMDK file
    VMDK_FILE=$(ls *.vmdk 2>/dev/null | head -1)
    if [ -z "$VMDK_FILE" ]; then
        error "No VMDK file found after extracting OVA"
    fi

    # Convert to qcow2
    info "Converting disk to qcow2..."
    sudo qemu-img convert -f vmdk -O qcow2 "$VMDK_FILE" "$DISK_PATH"

    # Create VM
    info "Creating VM..."
    virt-install \
        --name "$VM_NAME" \
        --memory 8192 \
        --vcpus 4 \
        --disk "$DISK_PATH",bus=virtio \
        --import \
        --os-variant ubuntu20.04 \
        --network network=default \
        --graphics vnc,listen=0.0.0.0 \
        --noautoconsole

    # Clean up extracted files
    rm -f *.vmdk *.ovf *.mf

    info "VM created successfully"
}

# Start VM
start_vm() {
    if vm_running; then
        info "VM '$VM_NAME' is already running"
        return 0
    fi

    info "Starting VM '$VM_NAME'..."
    virsh start "$VM_NAME"

    # Wait for boot
    sleep 10

    info "VM started"
}

# SSH execute command
ssh_exec() {
    local ip="$1"
    shift
    local cmd="$*"

    if command -v sshpass >/dev/null 2>&1; then
        sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            "${SSH_USER}@${ip}" "$cmd" 2>/dev/null
    else
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            "${SSH_USER}@${ip}" "$cmd"
    fi
}

# Check MCP status
check_mcp() {
    local ip="$1"

    info "Checking MCP status..."

    # Check if MCP server is running
    if ssh_exec "$ip" "pgrep -f mcp" >/dev/null 2>&1; then
        info "MCP server is running"

        # Get MCP process info
        ssh_exec "$ip" "ps aux | grep mcp | grep -v grep" || true

        # Check MCP config
        if ssh_exec "$ip" "test -f ~/.config/claude/mcp_settings.json"; then
            info "MCP config found"
            ssh_exec "$ip" "cat ~/.config/claude/mcp_settings.json" 2>/dev/null || true
        else
            warn "MCP config not found at ~/.config/claude/mcp_settings.json"
        fi

        return 0
    else
        warn "MCP server is not running"
        return 1
    fi
}

# Install sift_find_evil
install_software() {
    local ip="$1"

    info "Installing sift_find_evil..."

    # Check if already installed
    if ssh_exec "$ip" "test -d ~/sift_find_evil"; then
        info "sift_find_evil already cloned, updating..."
        ssh_exec "$ip" "cd ~/sift_find_evil && git pull"
    else
        info "Cloning sift_find_evil..."
        ssh_exec "$ip" "git clone https://github.com/Strike48-public/sift_find_evil.git"
    fi

    # Install dependencies
    info "Installing Python dependencies..."
    ssh_exec "$ip" "cd ~/sift_find_evil && pip3 install --user -r requirements.txt"
    ssh_exec "$ip" "cd ~/sift_find_evil && pip3 install --user -e ."

    info "Installation complete"
}

# Test software
test_software() {
    local ip="$1"

    info "Testing sift_find_evil..."

    # Run demo
    info "Running demo test..."
    if ssh_exec "$ip" "cd ~/sift_find_evil && python3 -m sift_find_evil.cli demo"; then
        info "Demo test PASSED"
    else
        error "Demo test FAILED"
    fi

    # Run scenario harness
    info "Running scenario harness..."
    if ssh_exec "$ip" "cd ~/sift_find_evil && PYTHONPATH=. python3 tests/scenario_harness.py"; then
        info "Scenario harness PASSED"
    else
        error "Scenario harness FAILED"
    fi
}

# Check USB devices
check_usb() {
    local ip="$1"

    info "Checking for USB devices..."
    ssh_exec "$ip" "lsblk" || true
    ssh_exec "$ip" "ls -la /mnt/ 2>/dev/null" || true
}

# Main workflow
main() {
    info "=== SIFT Automation Workflow ==="
    echo ""

    # 1. Prerequisites
    check_prereqs

    # 2. Setup VM
    setup_vm

    # 3. Start VM
    start_vm

    # 4. Get IP and wait for SSH
    VM_IP=$(get_vm_ip)
    if [ -z "$VM_IP" ]; then
        error "Could not get VM IP address"
    fi
    info "VM IP: $VM_IP"

    wait_for_ssh "$VM_IP"

    # 5. Check MCP
    check_mcp "$VM_IP" || warn "MCP not running, continuing anyway..."

    # 6. Install software
    install_software "$VM_IP"

    # 7. Test software
    test_software "$VM_IP"

    # 8. Check USB
    check_usb "$VM_IP"

    echo ""
    info "=== Workflow Complete ==="
    echo ""
    info "SSH access: ssh ${SSH_USER}@${VM_IP}"
    info "Password: ${SSH_PASS}"
    echo ""
    info "Next steps:"
    echo "  1. Mount USB evidence: sudo mount /dev/sdb1 /mnt/usb-evidence"
    echo "  2. Run analysis: python3 -m sift_find_evil.cli analyze --image /mnt/usb-evidence/suspect.E01"
    echo ""
}

# Run main workflow
main "$@"
