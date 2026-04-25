#!/usr/bin/env bash
# SIFT VM Quick Commands

VM_NAME="${SIFT_VM_NAME:-sift-workstation}"
SSH_USER="sansforensics"
SSH_PASS="forensics"

# Get VM IP
get_ip() {
    sudo virsh domifaddr "$VM_NAME" 2>/dev/null | awk '/ipv4/ {print $4}' | cut -d'/' -f1
}

# Execute command in SIFT
sift_exec() {
    local ip=$(get_ip)
    if [ -z "$ip" ]; then
        echo "ERROR: Could not get VM IP"
        return 1
    fi

    if command -v sshpass >/dev/null 2>&1; then
        sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            "${SSH_USER}@${ip}" "$@"
    else
        echo "Connecting to ${SSH_USER}@${ip} (password: ${SSH_PASS})"
        ssh -o StrictHostKeyChecking=no "${SSH_USER}@${ip}" "$@"
    fi
}

case "${1:-}" in
    start)
        echo "Starting SIFT VM..."

        # Ensure libvirt network is running
        if ! sudo virsh net-list | grep -q "default.*active"; then
            echo "Starting libvirt default network..."
            sudo virsh net-destroy default 2>/dev/null || true
            sudo virsh net-start default
        fi

        # Start VM
        sudo virsh start "$VM_NAME" 2>/dev/null || echo "VM already running"

        # Wait for IP
        echo "Waiting for VM to boot..."
        sleep 10

        local ip
        for i in {1..30}; do
            ip=$(get_ip)
            if [ -n "$ip" ]; then
                echo "VM started at $ip"
                return 0
            fi
            sleep 2
        done

        echo "WARNING: VM started but no IP address found"
        ;;

    stop)
        echo "Stopping SIFT VM..."
        virsh shutdown "$VM_NAME"
        ;;

    status)
        virsh dominfo "$VM_NAME" | grep -E "(State|CPU|Memory)"
        ;;

    ip)
        get_ip
        ;;

    ssh)
        shift
        sift_exec "$@"
        ;;

    console)
        virsh console "$VM_NAME"
        ;;

    viewer)
        virt-viewer "$VM_NAME" &
        ;;

    mcp-status)
        echo "Checking MCP status..."
        sift_exec "ps aux | grep mcp | grep -v grep"
        ;;

    install)
        echo "Installing sift_find_evil..."
        local ip=$(get_ip)

        # Package locally
        echo "Creating package..."
        cd "$(dirname "$0")/.." || exit 1
        tar -czf /tmp/sift_install.tar.gz \
            --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
            --exclude='.beads' --exclude='test-results' --exclude='scenarios' \
            sift_find_evil/ requirements.txt pyproject.toml README.md tests/

        # Copy to VM
        echo "Copying to VM..."
        sshpass -p "$SSH_PASS" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            /tmp/sift_install.tar.gz "${SSH_USER}@${ip}:/tmp/"

        # Install on VM
        echo "Installing on VM..."
        sift_exec "mkdir -p ~/sift_project && \
            cd ~/sift_project && \
            tar -xzf /tmp/sift_install.tar.gz && \
            python3 -m venv ~/sift_find_evil_env 2>/dev/null || true && \
            source ~/sift_find_evil_env/bin/activate && \
            pip install -q -r requirements.txt && \
            pip install -q -e ."

        echo "Installation complete!"
        ;;

    test)
        echo "Testing sift_find_evil..."
        sift_exec "source ~/sift_find_evil_env/bin/activate && cd ~/sift_project && python3 -m sift_find_evil.cli demo"
        ;;

    usb)
        echo "USB devices:"
        sift_exec "lsblk"
        ;;

    mount-usb)
        echo "Mounting USB device..."
        sift_exec "sudo mkdir -p /mnt/usb-evidence && sudo mount /dev/sdb1 /mnt/usb-evidence && ls -la /mnt/usb-evidence"
        ;;

    *)
        echo "SIFT VM Commands"
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  start         - Start SIFT VM"
        echo "  stop          - Stop SIFT VM"
        echo "  status        - Show VM status"
        echo "  ip            - Get VM IP address"
        echo "  ssh [cmd]     - SSH into VM (or run command)"
        echo "  console       - Open VM console"
        echo "  viewer        - Open VNC viewer"
        echo "  mcp-status    - Check MCP server status"
        echo "  install       - Install sift_find_evil"
        echo "  test          - Run demo test"
        echo "  usb           - List USB devices"
        echo "  mount-usb     - Mount USB evidence"
        echo ""
        echo "Examples:"
        echo "  $0 start"
        echo "  $0 ip"
        echo "  $0 ssh 'ps aux | grep mcp'"
        echo "  $0 install"
        echo "  $0 test"
        ;;
esac
