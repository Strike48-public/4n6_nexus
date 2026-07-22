# SIFT Workstation - Working Setup

**Status:** VERIFIED WORKING  
**Date:** 2026-04-25  
**VM:** sift-workstation (SIFT 2026.03.24)

---

## Current Working Configuration

### VM Details

- **Name:** sift-workstation
- **Platform:** KVM/libvirt (managed via virsh)
- **Disk:** ~/VMs/sift/sift-disk.qcow2
- **CPU:** 4 cores
- **RAM:** 4GB
- **Network:** NAT via libvirt default network (virbr0)
- **OS:** Ubuntu 24.04 LTS (SIFT Workstation)
- **Python:** 3.12.3

### Network Configuration

- **Network:** libvirt default network (192.168.122.0/24)
- **Bridge:** virbr0
- **VM IP:** 192.168.122.76 (DHCP assigned)
- **SSH:** sansforensics@192.168.122.76 (password: forensics)

---

## Quick Start

### 1. Start VM

```bash
cd ~/Code/sift_find_evil
./scripts/sift-commands.sh start
```

This will:
- Start libvirt default network (with sudo)
- Start sift-workstation VM (with sudo)
- Wait for boot and DHCP
- Report VM IP address

### 2. Install Software

```bash
./scripts/sift-commands.sh install
```

This will:
- Package sift_find_evil from local repo
- Copy to VM via SCP
- Create Python venv
- Install dependencies
- Install package in development mode

### 3. Test Software

```bash
./scripts/sift-commands.sh test
```

This will:
- Activate venv
- Run demo test
- Display self-correction demonstration

### 4. Stop VM

```bash
./scripts/sift-commands.sh stop
```

---

## Manual Workflow

### Start VM with Networking

```bash
# Start libvirt network (if not running)
sudo virsh net-destroy default 2>/dev/null || true
sudo virsh net-start default

# Start VM
sudo virsh start sift-workstation

# Wait for boot
sleep 10

# Get IP
VM_IP=$(sudo virsh domifaddr sift-workstation | awk '/ipv4/ {print $4}' | cut -d'/' -f1)
echo "VM IP: $VM_IP"
```

### Install Software Manually

```bash
# On host: Create package
cd ~/Code/sift_find_evil
tar -czf /tmp/sift_install.tar.gz \
    --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
    --exclude='.beads' --exclude='test-results' --exclude='scenarios' \
    sift_find_evil/ requirements.txt pyproject.toml README.md tests/

# Copy to VM
sshpass -p "forensics" scp -o StrictHostKeyChecking=no \
    /tmp/sift_install.tar.gz sansforensics@$VM_IP:/tmp/

# On VM: Install
sshpass -p "forensics" ssh -o StrictHostKeyChecking=no sansforensics@$VM_IP "
    mkdir -p ~/sift_project && \
    cd ~/sift_project && \
    tar -xzf /tmp/sift_install.tar.gz && \
    python3 -m venv ~/sift_find_evil_env && \
    source ~/sift_find_evil_env/bin/activate && \
    pip install -r requirements.txt && \
    pip install -e .
"
```

### Run Tests Manually

```bash
sshpass -p "forensics" ssh -o StrictHostKeyChecking=no sansforensics@$VM_IP "
    source ~/sift_find_evil_env/bin/activate && \
    cd ~/sift_project && \
    python3 -m sift_find_evil.cli demo
"
```

---

## Verified Functionality

### Demo Test Output

```
Demo completed successfully!
The self-correction engine detected the planted contradiction,
resolved it using Event Log evidence, and adjusted confidence.

Validation checks:
  [PASS] Contradiction detected
  [PASS] Resolution applied via Event Log
  [PASS] Confidence in expected range: 0.75
  [PASS] Comprehensive reasoning chain (5 steps)
```

### Installation Structure

```
/home/sansforensics/
├── sift_find_evil_env/          # Python venv
└── sift_project/                 # Project root
    ├── sift_find_evil/          # Package
    ├── tests/                    # Test fixtures
    ├── requirements.txt
    ├── pyproject.toml
    └── README.md
```

---

## Known Issues

### No Internet Access in VM

- **Issue:** VM has no internet connectivity (NAT routing issue)
- **Impact:** Cannot git clone from GitHub
- **Workaround:** Transfer packaged code via SCP from host

### MCP Not Configured

- **Status:** MCP server not running
- **Config:** ~/.config/claude/mcp_settings.json not found
- **Impact:** MCP integration not tested yet
- **Next Step:** Configure MCP server or document MCP-less workflow

### No USB Devices Attached

- **Status:** No USB devices currently passed through to VM
- **Next Step:** Configure USB passthrough for evidence testing

---

## Next Steps

### 1. USB Device Passthrough

To analyze evidence from USB-C drive:

```bash
# On host: Find USB device
lsusb
# Example: Bus 002 Device 005: ID 0781:5583 SanDisk Corp.

# Create passthrough config
cat > /tmp/usb-passthrough.xml <<EOF
<hostdev mode='subsystem' type='usb'>
  <source>
    <vendor id='0x0781'/>
    <product id='0x5583'/>
  </source>
</hostdev>
EOF

# Attach to VM
sudo virsh attach-device sift-workstation /tmp/usb-passthrough.xml --persistent

# Restart VM
./scripts/sift-commands.sh stop
./scripts/sift-commands.sh start

# On VM: Mount USB
ssh sansforensics@$VM_IP "sudo mkdir -p /mnt/usb-evidence"
ssh sansforensics@$VM_IP "sudo mount /dev/sdb1 /mnt/usb-evidence"
ssh sansforensics@$VM_IP "ls -la /mnt/usb-evidence"
```

### 2. Process Real Evidence

```bash
# Run analysis on evidence
ssh sansforensics@$VM_IP "
    source ~/sift_find_evil_env/bin/activate && \
    cd ~/sift_project && \
    python3 -m sift_find_evil.cli analyze \
        --image /mnt/usb-evidence/suspect.E01 \
        --output ~/findings.json
"

# Retrieve results
scp sansforensics@$VM_IP:~/findings.json ./results/
```

### 3. Test with Real Corpora

Transfer evidence corpora to VM and run full scenario harness:

```bash
# Copy scenarios (if needed)
tar -czf /tmp/scenarios.tar.gz scenarios/real/
scp /tmp/scenarios.tar.gz sansforensics@$VM_IP:/tmp/

# Extract and test
ssh sansforensics@$VM_IP "
    cd ~/sift_project && \
    tar -xzf /tmp/scenarios.tar.gz && \
    source ~/sift_find_evil_env/bin/activate && \
    PYTHONPATH=. python3 tests/scenario_harness.py
"
```

---

## Troubleshooting

### VM Won't Start

```bash
# Check libvirt status
sudo systemctl status libvirtd

# Check network
sudo virsh net-list --all

# Restart network
sudo virsh net-destroy default
sudo virsh net-start default

# Try starting VM again
sudo virsh start sift-workstation
```

### Can't Get VM IP

```bash
# Check VM is running
sudo virsh list --all

# Check DHCP leases
sudo virsh net-dhcp-leases default

# Try console access
sudo virsh console sift-workstation
# (Login and run: ip addr show)
```

### SSH Connection Issues

```bash
# Test network connectivity
ping $VM_IP

# Test SSH port
nc -zv $VM_IP 22

# Check SSH service in VM
sudo virsh console sift-workstation
# (Login and run: sudo systemctl status ssh)
```

---

## References

- **SIFT Workstation:** https://www.sans.org/tools/sift-workstation
- **Automation Guide:** docs/SIFT_AUTOMATION.md
- **Deployment Guide:** docs/SIFT_DEPLOYMENT_GUIDE.md
- **Evidence Results:** docs/EVIDENCE_PROCESSING_RESULTS.md
