# SIFT Workstation Setup Guide

**Date:** 2026-04-16  
**Purpose:** Step-by-step instructions for Phase 1 validation  
**Time Required:** 1-2 hours  
**Prerequisites:** VirtualBox or VMware, 16 GB RAM, 50 GB disk space

---

## Overview

This guide walks through setting up SANS SIFT Workstation with Protocol SIFT for our validation testing.

**What you'll have at the end:**
- SIFT Ubuntu VM running
- Protocol SIFT installed and configured
- All forensic tools verified (MFTECmd, PECmd, EvtxECmd, Plaso)
- Ready to execute Phase 2 validation tests

---

## Step 1: Download SIFT Workstation

### Option A: OVA Image (Recommended)

1. Visit https://www.sans.org/tools/sift-workstation/
2. Click "Download SIFT Workstation OVA"
3. Save to your machine (warning: 10+ GB download)
4. SHA256 hash will be provided on download page - save this for verification

### Option B: ISO Image (Alternative)

If OVA download fails or you prefer custom VM setup:
1. Download SIFT ISO from same page
2. Create new Ubuntu VM manually
3. Install from ISO
4. Follow post-install steps

**Recommended:** Use OVA - it's pre-configured and faster.

---

## Step 2: Import to Virtualization Platform

### VirtualBox

```bash
# Import OVA
VBoxManage import sift-workstation.ova --vsys 0 --vmname "SIFT-DFIR"

# Configure VM resources
VBoxManage modifyvm "SIFT-DFIR" --memory 16384 --cpus 4

# Start VM
VBoxManage startvm "SIFT-DFIR" --type gui
```

### VMware Workstation/Fusion

1. File → Open → Select sift-workstation.ova
2. Import with default settings
3. Edit VM Settings:
   - Memory: 16 GB (24 GB for memory analysis)
   - CPUs: 4
   - Network: NAT or Bridged
4. Power On VM

### Verify Boot

**Login credentials** (from SANS documentation):
- Username: `sansforensics`
- Password: Usually set during first boot or provided in download instructions

**First boot checklist:**
- [ ] VM boots to Ubuntu desktop
- [ ] Network connectivity works (`ping google.com`)
- [ ] Sufficient disk space (`df -h` shows >20 GB free in `/home`)

---

## Step 3: Verify Pre-Installed Tools

SIFT comes with 200+ forensic tools. Verify key tools we need:

```bash
# Sleuth Kit
fls -V
# Expected: "The Sleuth Kit ver X.X.X"

# EZ Tools (Zimmerman Tools)
dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll --help
# Expected: Help text for EvtxECmd

# Plaso
log2timeline.py --version
# Expected: "plaso - log2timeline version X.X.X"

# Volatility 3
python3 /opt/volatility3-2.20.0/vol.py -h
# Expected: Volatility 3 help text

# YARA
/usr/local/bin/yara --version
# Expected: "yara X.X.X"
```

**If any tool is missing or fails:**
- Check `/opt/` directory for tool location
- Run `apt update && apt upgrade` to get latest packages
- Consult SIFT documentation: https://github.com/teamdfir/sift-cli

---

## Step 4: Install Node.js (Required for Claude Code)

Protocol SIFT requires Node.js for Claude Code CLI.

```bash
# Install Node.js via NodeSource
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verify installation
node --version
# Expected: v20.x.x

npm --version
# Expected: 10.x.x
```

---

## Step 5: Install Claude Code CLI

```bash
# Install Claude Code globally
sudo npm install -g @anthropic-ai/claude-code

# Verify installation
claude --version
# Expected: Claude Code CLI version X.X.X

# Check installation path
which claude
# Expected: /usr/local/bin/claude or /usr/bin/claude
```

---

## Step 6: Configure Anthropic API Key

You need an Anthropic API key to use Claude Code.

### Get API Key

1. Visit https://console.anthropic.com/
2. Sign in or create account
3. Navigate to API Keys section
4. Create new key (name it "SIFT-DFIR-Agent")
5. Copy the key (starts with `sk-ant-...`)

### Configure Credentials

```bash
# Create Claude config directory
mkdir -p ~/.claude

# Set API key
cat > ~/.claude/.credentials.json <<EOF
{
  "apiKey": "sk-ant-YOUR_KEY_HERE"
}
EOF

# Secure the file
chmod 600 ~/.claude/.credentials.json
```

**Verify:**
```bash
# Test Claude Code
cd /tmp
claude --help
# Should show help text without authentication errors
```

---

## Step 7: Install Protocol SIFT

**This is the critical step** - Protocol SIFT configures Claude Code for forensic work.

```bash
# Download and run installer
curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash
```

**What this installs:**
- `~/.claude/CLAUDE.md` - Global behavioral instructions
- `~/.claude/settings.json` - Tool permissions + Stop hook
- `~/.claude/settings.local.json` - Local overrides
- `~/.claude/skills/` - 5 skill files (memory, sleuthkit, windows, plaso, yara)
- `~/.claude/case-templates/CLAUDE.md` - Per-case template
- `~/.claude/analysis-scripts/generate_pdf_report.py` - PDF generator

---

## Step 8: Verify Protocol SIFT Installation

```bash
# Check global config exists
ls -lh ~/.claude/CLAUDE.md
# Expected: File exists, ~5-10 KB

# Check settings exist
ls -lh ~/.claude/settings.json
# Expected: File exists

# Check skills directory
ls ~/.claude/skills/
# Expected: memory-analysis  plaso-timeline  sleuthkit  windows-artifacts  yara-hunting

# Read global CLAUDE.md
cat ~/.claude/CLAUDE.md
# Should show "DFIR Orchestrator" title and tool paths
```

---

## Step 9: Test Basic Tool Execution

Create a test case directory and verify Claude can execute tools.

```bash
# Create test case
export CASE=test-setup-verification
mkdir -p /cases/${CASE}/{analysis,exports,reports}

# Copy case template
cp ~/.claude/case-templates/CLAUDE.md /cases/${CASE}/CLAUDE.md

# Navigate to case directory
cd /cases/${CASE}

# Launch Claude Code
claude
```

**In Claude Code session, test tool execution:**

```
User: Run `fls -V` to verify Sleuth Kit works
```

Expected: Claude executes command and shows version output.

```
User: Run `dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll --help` to verify EZ Tools work
```

Expected: Claude shows EvtxECmd help text.

**Exit Claude:**
```
exit
```

---

## Step 10: Download SANS Starter Dataset

SANS provides starter evidence for testing.

### Option A: Egnyte Link (Preferred)

Check SANS course materials or FIND EVIL! hackathon resources for Egnyte link to starter datasets.

Expected datasets:
- Small disk image (E01 format, <10 GB)
- Memory dump (raw or .vmem, <8 GB)
- Windows Event Logs (EVTX files)
- MFT export (CSV or JSON)

### Option B: Use NIST CFReDS Hacking Case

If SANS starter data is unavailable:

```bash
# Create evidence directory
mkdir -p /cases/evidence

# Download NIST Hacking Case
cd /cases/evidence
wget https://cfreds-archive.nist.gov/Hacking_Case.zip
unzip Hacking_Case.zip

# Verify integrity
sha256sum 4Dell Latitude CPi.E01
# Compare with published hash from NIST CFReDS page
```

---

## Step 11: Mount Evidence (Test Read-Only Access)

Test that you can mount evidence read-only (required for forensic integrity).

```bash
# Create mount points
sudo mkdir -p /mnt/ewf_test /mnt/evidence_test

# Mount E01 image
sudo ewfmount /cases/evidence/4Dell\ Latitude\ CPi.E01 /mnt/ewf_test

# Verify mount
ls /mnt/ewf_test
# Expected: ewf1

# Get partition offset
sudo mmls /mnt/ewf_test/ewf1
# Expected: Partition table with NTFS partition

# Calculate offset (sector_start * 512)
OFFSET=$(sudo mmls /mnt/ewf_test/ewf1 | awk '/NTFS/{print $3 * 512; exit}')

# Mount partition read-only
sudo mount -o ro,loop,noatime,offset=$OFFSET /mnt/ewf_test/ewf1 /mnt/evidence_test

# Verify read-only mount
mount | grep evidence_test
# Should show "ro" in options

# List files
sudo ls /mnt/evidence_test
# Expected: Windows directory structure

# Verify we CANNOT write (forensic integrity test)
sudo touch /mnt/evidence_test/test.txt
# Expected: "Read-only file system" error

# Unmount
sudo umount /mnt/evidence_test
sudo umount /mnt/ewf_test
```

**Success criteria:**
- [ ] Evidence mounts successfully
- [ ] Read-only enforcement works (write attempts fail)
- [ ] Can list files in mounted evidence

---

## Step 12: Final Verification Checklist

Run through this checklist before proceeding to Phase 2:

### Environment
- [ ] SIFT VM running with 16+ GB RAM
- [ ] Network connectivity works
- [ ] 20+ GB free disk space

### Tools
- [ ] fls (Sleuth Kit) executes
- [ ] MFTECmd (EZ Tools) executes
- [ ] PECmd (Prefetch parser) executes
- [ ] EvtxECmd (Event Log parser) executes
- [ ] log2timeline.py (Plaso) executes
- [ ] Volatility 3 executes

### Protocol SIFT
- [ ] ~/.claude/CLAUDE.md exists
- [ ] ~/.claude/settings.json exists
- [ ] ~/.claude/skills/ has 5 skill directories
- [ ] Case template exists

### Claude Code
- [ ] Claude CLI installed and in PATH
- [ ] API key configured in ~/.claude/.credentials.json
- [ ] Can launch `claude` command without errors
- [ ] Can execute basic commands in Claude session

### Evidence
- [ ] Starter dataset downloaded
- [ ] Evidence mounts read-only
- [ ] Can list files in mounted evidence
- [ ] Write attempts correctly fail (integrity test)

---

## Troubleshooting

### Claude Code Install Fails

**Error:** `npm: command not found`

**Fix:** Install Node.js first (Step 4)

### Protocol SIFT Install Fails

**Error:** `curl: command not found`

**Fix:**
```bash
sudo apt-get update
sudo apt-get install -y curl
```

**Error:** Install script fails with permissions error

**Fix:** Run with explicit bash:
```bash
curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh -o /tmp/install-protocol-sift.sh
bash /tmp/install-protocol-sift.sh
```

### EZ Tools Don't Execute

**Error:** `dotnet: command not found`

**Fix:** Install .NET runtime:
```bash
sudo apt-get update
sudo apt-get install -y dotnet-runtime-6.0
```

### Evidence Mount Fails

**Error:** `ewfmount: command not found`

**Fix:** Install libewf:
```bash
sudo apt-get update
sudo apt-get install -y ewf-tools
```

**Error:** `mount: wrong fs type`

**Fix:** Verify partition offset calculation:
```bash
# Show partition table in sectors
sudo mmls /mnt/ewf_test/ewf1

# Manually calculate offset
# OFFSET = START_SECTOR * 512
```

### Claude Code Authentication Fails

**Error:** `Unauthorized: Invalid API key`

**Fix:** Verify API key format and permissions:
```bash
cat ~/.claude/.credentials.json
# Key should start with sk-ant-
# Should be valid JSON format
```

**Fix:** Test API key directly:
```bash
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: YOUR_KEY_HERE" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-4.5-20250929","max_tokens":10,"messages":[{"role":"user","content":"test"}]}'
```

If this returns 401, your key is invalid. Generate a new one.

---

## Next Steps

Once all verification checks pass:

**✅ Phase 1 Complete**

**➡️ Proceed to Phase 2: Single Tool Test**

See `docs/VALIDATION_PLAN.md` Phase 2 for next steps:
- Create test case directory
- Execute fls on disk image
- Parse output
- Verify evidence integrity (hash before/after)

**Estimated time for Phase 2:** 1 hour

---

## Reference Links

- SANS SIFT Workstation: https://www.sans.org/tools/sift-workstation/
- Protocol SIFT GitHub: https://github.com/teamdfir/protocol-sift
- Claude Code Documentation: https://claude.ai/code
- NIST CFReDS: https://cfreds-archive.nist.gov/
- EZ Tools Documentation: https://ericzimmerman.github.io/

---

*Last Updated: 2026-04-16*
