# SIFT VM Automation Guide

Automated workflow for starting SIFT OVA, checking MCP, and testing sift_find_evil.

---

## Quick Start

```bash
# Start existing SIFT VM (requires sudo for libvirt network)
cd ~/Code/sift_find_evil
sudo virsh start sift-workstation

# Get VM IP
VM_IP=$(sudo virsh domifaddr sift-workstation | awk '/ipv4/ {print $4}' | cut -d'/' -f1)

# Install and test software
./scripts/sift-commands.sh install
./scripts/sift-commands.sh test
```

This will:
1. Start SIFT VM
2. Wait for SSH
3. Install sift_find_evil in venv
4. Run demo test

---

## Manual Step-by-Step

### Prerequisites

```bash
# Install required tools
sudo apt install libvirt-clients virtinst qemu-utils sshpass
```

### Setup

```bash
# Place OVA file in project root
cp ~/Downloads/sift-2026.03.24.ova ~/Code/sift_find_evil/

# Set environment variables (optional)
export SIFT_VM_NAME="sift-2026"
export SIFT_OVA="sift-2026.03.24.ova"
```

### Run Automation

```bash
cd ~/Code/sift_find_evil
./scripts/sift-automation.sh
```

---

## Quick Commands

Use the helper script for common operations:

```bash
# Start VM
./scripts/sift-commands.sh start

# Get VM IP
./scripts/sift-commands.sh ip

# Check MCP status
./scripts/sift-commands.sh mcp-status

# Install software
./scripts/sift-commands.sh install

# Run tests
./scripts/sift-commands.sh test

# SSH into VM
./scripts/sift-commands.sh ssh

# Execute command in VM
./scripts/sift-commands.sh ssh "ps aux | grep mcp"

# Check USB devices
./scripts/sift-commands.sh usb

# Mount USB evidence
./scripts/sift-commands.sh mount-usb

# Stop VM
./scripts/sift-commands.sh stop
```

---

## Workflow Details

### 1. VM Import (First Time Only)

```bash
# Extract OVA
tar -xf sift-2026.03.24.ova

# Convert VMDK to qcow2
sudo qemu-img convert -f vmdk -O qcow2 \
    sift-2026-disk001.vmdk \
    /var/lib/libvirt/images/sift-2026.qcow2

# Create VM
virt-install \
    --name sift-2026 \
    --memory 8192 \
    --vcpus 4 \
    --disk /var/lib/libvirt/images/sift-2026.qcow2,bus=virtio \
    --import \
    --os-variant ubuntu20.04 \
    --network network=default \
    --graphics vnc \
    --noautoconsole
```

### 2. Start VM

```bash
# Start
virsh start sift-2026

# Check status
virsh list --all

# Get IP
virsh domifaddr sift-2026
```

### 3. SSH Access

```bash
# Wait for SSH (automated)
VM_IP=$(virsh domifaddr sift-2026 | awk '/ipv4/ {print $4}' | cut -d'/' -f1)

# Test SSH
ssh sansforensics@$VM_IP
# Password: forensics
```

### 4. Check MCP

```bash
# Check if MCP server is running
ssh sansforensics@$VM_IP "ps aux | grep mcp"

# Check MCP config
ssh sansforensics@$VM_IP "cat ~/.config/claude/mcp_settings.json"

# Expected: MCP server process visible
```

### 5. Install Software

```bash
# Package on host
tar -czf /tmp/sift_install.tar.gz \
    --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
    --exclude='.beads' --exclude='test-results' --exclude='scenarios' \
    sift_find_evil/ requirements.txt pyproject.toml README.md tests/

# Copy to VM
sshpass -p "forensics" scp -o StrictHostKeyChecking=no /tmp/sift_install.tar.gz sansforensics@$VM_IP:/tmp/

# Install on VM
ssh sansforensics@$VM_IP "
    mkdir -p ~/sift_project && \
    cd ~/sift_project && \
    tar -xzf /tmp/sift_install.tar.gz && \
    python3 -m venv ~/sift_find_evil_env && \
    source ~/sift_find_evil_env/bin/activate && \
    pip install -r requirements.txt && \
    pip install -e .
"
```

### 6. Test Software

```bash
# Run demo
ssh sansforensics@$VM_IP "
    source ~/sift_find_evil_env/bin/activate && \
    cd ~/sift_project && \
    python3 -m sift_find_evil.cli demo
"

# Expected output: Demo completed successfully with self-correction demonstration
```

### 7. Mount USB Evidence

```bash
# Check USB devices
ssh sansforensics@$VM_IP "lsblk"

# Mount USB
ssh sansforensics@$VM_IP "sudo mkdir -p /mnt/usb-evidence && sudo mount /dev/sdb1 /mnt/usb-evidence"

# Verify
ssh sansforensics@$VM_IP "ls -la /mnt/usb-evidence"
```

---

## USB Device Passthrough

### Option 1: Attach USB to Running VM

```bash
# Find USB device on host
lsusb
# Example: Bus 002 Device 005: ID 0781:5583 SanDisk Corp.

# Create XML file
cat > usb-passthrough.xml <<EOF
<hostdev mode='subsystem' type='usb'>
  <source>
    <vendor id='0x0781'/>
    <product id='0x5583'/>
  </source>
</hostdev>
EOF

# Attach to VM
virsh attach-device sift-2026 usb-passthrough.xml --persistent
```

### Option 2: Add USB to VM Definition

```bash
# Edit VM XML
virsh edit sift-2026

# Add this section inside <devices>:
<hostdev mode='subsystem' type='usb' managed='yes'>
  <source>
    <vendor id='0x0781'/>
    <product id='0x5583'/>
  </source>
</hostdev>

# Restart VM
virsh shutdown sift-2026
virsh start sift-2026
```

---

## Troubleshooting

### VM Won't Start

```bash
# Check libvirt daemon
sudo systemctl status libvirtd

# Check VM definition
virsh dumpxml sift-2026

# Check logs
sudo journalctl -u libvirtd -f
```

### Can't Get VM IP

```bash
# Check if DHCP is working
virsh net-list
virsh net-dhcp-leases default

# Try console access
virsh console sift-2026
# Login manually and run: ip addr show
```

### SSH Connection Refused

```bash
# Check SSH is running in VM
virsh console sift-2026
# Login and run: sudo systemctl status ssh

# Check network connectivity
ping $VM_IP
```

### MCP Not Running

```bash
# Check if MCP was installed
ssh sansforensics@$VM_IP "which mcp-server"

# Check systemd service
ssh sansforensics@$VM_IP "systemctl --user status mcp-server"

# Check for config files
ssh sansforensics@$VM_IP "find ~ -name '*mcp*' -type f"
```

### Software Installation Fails

```bash
# Check Python version
ssh sansforensics@$VM_IP "python3 --version"

# Check pip
ssh sansforensics@$VM_IP "pip3 --version"

# Check disk space
ssh sansforensics@$VM_IP "df -h"

# Try manual install
virsh console sift-2026
# Login and manually run commands
```

---

## Environment Variables

Configure behavior with environment variables:

```bash
# VM name (default: sift-2026)
export SIFT_VM_NAME="my-sift-vm"

# OVA file path (default: sift-2026.03.24.ova)
export SIFT_OVA="/path/to/sift.ova"

# SSH credentials (defaults shown)
export SIFT_SSH_USER="sansforensics"
export SIFT_SSH_PASS="forensics"

# Then run automation
./scripts/sift-automation.sh
```

---

## Integration with Development Workflow

```bash
# 1. Start SIFT VM
./scripts/sift-commands.sh start

# 2. Deploy latest code
./scripts/sift-commands.sh ssh "cd sift_find_evil && git pull"
./scripts/sift-commands.sh ssh "cd sift_find_evil && pip3 install --user -e ."

# 3. Run tests
./scripts/sift-commands.sh test

# 4. Analyze evidence
./scripts/sift-commands.sh mount-usb
./scripts/sift-commands.sh ssh "cd sift_find_evil && python3 -m sift_find_evil.cli analyze --image /mnt/usb-evidence/suspect.E01 --output ~/findings.json"

# 5. Retrieve results
VM_IP=$(./scripts/sift-commands.sh ip)
scp sansforensics@$VM_IP:~/findings.json ./results/

# 6. Stop VM when done
./scripts/sift-commands.sh stop
```

---

## Automated Testing Pipeline

```bash
#!/bin/bash
# Automated test pipeline

# Start VM
./scripts/sift-commands.sh start
sleep 30  # Wait for boot

# Install/update software
./scripts/sift-commands.sh install

# Run tests
./scripts/sift-commands.sh test

# Retrieve results
VM_IP=$(./scripts/sift-commands.sh ip)
scp sansforensics@$VM_IP:~/sift_find_evil/test-results/*.json ./test-results/

# Stop VM
./scripts/sift-commands.sh stop
```

---

## Next Steps

After automation completes:

1. **Verify MCP**: Check that MCP server is running and configured
2. **Test with Evidence**: Mount USB and run analysis on real evidence
3. **Validate Results**: Compare findings against known ground truth
4. **Document Issues**: File any issues found during testing

---

**Last Updated:** 2026-04-25
