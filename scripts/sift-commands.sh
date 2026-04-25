#!/usr/bin/env bash
# SIFT VM Quick Commands

VM_NAME="${SIFT_VM_NAME:-sift-2026}"
SSH_USER="sansforensics"
SSH_PASS="forensics"

# Get VM IP
get_ip() {
    virsh domifaddr "$VM_NAME" | awk '/ipv4/ {print $4}' | cut -d'/' -f1
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
        virsh start "$VM_NAME"
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
        sift_exec "cd ~ && git clone https://github.com/Strike48/sift_find_evil.git || (cd sift_find_evil && git pull)"
        sift_exec "cd ~/sift_find_evil && pip3 install --user -r requirements.txt && pip3 install --user -e ."
        ;;

    test)
        echo "Testing sift_find_evil..."
        sift_exec "cd ~/sift_find_evil && python3 -m sift_find_evil.cli demo"
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
