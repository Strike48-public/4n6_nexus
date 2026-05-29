# Installing SIFT Find Evil on SIFT Workstation

This guide covers installing the `sift_find_evil` detection engine on the SANS SIFT Workstation OVA.

---

## Prerequisites

- **SIFT Workstation** (Ubuntu-based VM with pre-installed forensic tools)
- **Python 3.10+** (included in SIFT)
- **Internet connection** (for pip packages)
- **Disk space:** ~500 MB for Python dependencies

---

## Quick Install

```bash
# 1. Clone repository
cd ~
git clone https://github.com/Strike48/sift_find_evil.git
cd sift_find_evil

# 2. Install Python dependencies
pip3 install --user -r requirements.txt

# 3. Install in development mode (editable)
pip3 install --user -e .

# 4. Verify installation
python3 -m sift_find_evil.cli --help

# 5. Run demo
python3 -m sift_find_evil.cli demo
```

---

## Installation Steps (Detailed)

### 1. System Preparation

Ensure SIFT is up to date:

```bash
sudo apt update
sudo apt upgrade -y
```

Verify Python version (3.10+ required):

```bash
python3 --version
# Should show Python 3.10.x or newer
```

### 2. Clone Repository

```bash
cd ~
git clone https://github.com/Strike48/sift_find_evil.git
cd sift_find_evil
```

### 3. Install Dependencies

**Option A: User-level install (recommended for SIFT)**

```bash
pip3 install --user -r requirements.txt
pip3 install --user -e .
```

**Option B: Virtual environment (isolated, recommended)**

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt   # core: demo, harness, TUI, detectors
pip install -e .
```

To process real evidence (E01/raw images, PST, memory dumps), also install the
native forensic extras (require a compiler + system headers):

```bash
sudo apt-get install libtsk-dev libewf-dev libpff-dev libyara-dev
pip install -r requirements-forensic.txt
```

**Option C: System-wide (requires sudo)**

```bash
sudo pip3 install -r requirements.txt
sudo pip3 install -e .
```

### 4. Verify Installation

```bash
# Check CLI is accessible
python3 -m sift_find_evil.cli --help

# Run synthetic demo
python3 -m sift_find_evil.cli demo

# Expected output: PASS with F1=1.00 for all scenarios
```

### 5. Configure PATH (if needed)

If the CLI isn't found, add user bin to PATH:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

---

## Required SIFT Tools

The following tools should already be installed in SIFT. Verify with:

```bash
# Sleuth Kit (disk forensics)
which mmls fls icat blkls mactime tsk_recover

# EWF tools (E01 image mounting)
which ewfmount ewfinfo

# Volatility 3 (memory forensics)
which vol.py

# Plaso (timeline analysis)
which log2timeline.py psort.py

# YARA (malware scanning)
which yara
```

**If missing**, install via:

```bash
# Sleuth Kit
sudo apt install sleuthkit

# EWF tools
sudo apt install libewf-tools

# Volatility 3
sudo apt install python3-volatility3

# Plaso
sudo add-apt-repository ppa:gift/stable
sudo apt update
sudo apt install plaso-tools

# YARA
sudo apt install yara
```

---

## Configuration

### 1. Create Workspace Directories

```bash
mkdir -p ~/dfir-workspace/{evidence,analysis,reports,test-results}
```

### 2. Set Environment Variables (optional)

```bash
cat >> ~/.bashrc <<'EOF'

# SIFT Find Evil Configuration
export SIFT_WORKSPACE="$HOME/dfir-workspace"
export SIFT_EVIDENCE="$SIFT_WORKSPACE/evidence"
export SIFT_ANALYSIS="$SIFT_WORKSPACE/analysis"
export SIFT_REPORTS="$SIFT_WORKSPACE/reports"

# Volatility 3 location (if custom install)
export VOLATILITY3_PATH="/opt/volatility3/vol.py"

# YARA rules directory
export YARA_RULES_DIR="$HOME/sift_find_evil/rules/yara"

EOF

source ~/.bashrc
```

---

## Usage Examples

### Run Against Evidence Image

```bash
# Analyze E01 disk image
python3 -m sift_find_evil.cli analyze \
    --image ~/dfir-workspace/evidence/suspect-disk.E01 \
    --output ~/dfir-workspace/analysis/suspect-findings.json

# Run scenario manifest
python3 -m sift_find_evil.cli run \
    --scenario ~/sift_find_evil/scenarios/real/m57-jean/ \
    --output ~/dfir-workspace/analysis/m57-jean-results.json
```

### Process Existing Artifacts

If you've already exported MFT, Prefetch, Event Logs:

```bash
python3 -m sift_find_evil.cli analyze \
    --mft ~/dfir-workspace/analysis/mft.csv \
    --prefetch ~/dfir-workspace/analysis/prefetch.csv \
    --evtx ~/dfir-workspace/analysis/evtx.csv \
    --output ~/dfir-workspace/reports/findings.json
```

### Generate Investigation Report

```bash
python3 -m sift_find_evil.cli report \
    --findings ~/dfir-workspace/analysis/suspect-findings.json \
    --output ~/dfir-workspace/reports/investigation-report.pdf
```

---

## Testing Installation

### Run Test Suite

```bash
cd ~/sift_find_evil
python3 -m pytest tests/ -v
```

Expected result: All tests pass (12/12 synthetic scenarios at F1=1.00)

### Run Scenario Harness

```bash
# Run all synthetic scenarios
PYTHONPATH=. python3 tests/scenario_harness.py

# Expected output:
# 12/12 scenarios PASS
# All F1 scores = 1.00
```

### Test Against Sample Evidence

```bash
# Download sample evidence (if not already present)
cd ~/sift_find_evil
./scripts/download-corpora/download-phase1-critical.sh

# Run against CIRCL wiped disk
python3 -m sift_find_evil.cli run \
    --scenario scenarios/real/circl-2023-wiped/ \
    --output ~/dfir-workspace/test-results/circl-test.json

# Expected: 1 finding (GPT wiping), F1=1.00
```

---

## Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'sift_find_evil'"

**Solution:** Install in editable mode:

```bash
cd ~/sift_find_evil
pip3 install --user -e .
```

### Issue: "pyewf not found"

**Solution:** Install libewf Python bindings:

```bash
sudo apt install python3-libewf
# Or via pip:
pip3 install --user pyewf
```

### Issue: "Volatility 3 not found"

**Solution:** Verify volatility3 is installed:

```bash
which vol.py
# If not found:
sudo apt install python3-volatility3
```

### Issue: Permission denied on evidence files

**Solution:** Evidence files should be readable:

```bash
chmod 644 ~/dfir-workspace/evidence/*.E01
```

### Issue: Out of disk space

**Solution:** Clean up test results:

```bash
rm -rf ~/dfir-workspace/analysis/*
rm -rf ~/sift_find_evil/test-results/*
```

---

## Uninstall

```bash
# Remove package
pip3 uninstall sift_find_evil

# Remove repository
rm -rf ~/sift_find_evil

# Remove workspace (optional)
rm -rf ~/dfir-workspace
```

---

## Integration with SIFT Workflow

### Mount Evidence Image

```bash
# Create mount point
sudo mkdir -p /mnt/evidence

# Mount E01 image
sudo ewfmount ~/dfir-workspace/evidence/suspect.E01 /mnt/evidence

# Analyze mounted image
python3 -m sift_find_evil.cli analyze \
    --image /mnt/evidence/ewf1 \
    --output ~/dfir-workspace/analysis/findings.json

# Unmount when done
sudo umount /mnt/evidence
```

### Extract Artifacts First (Traditional SIFT Workflow)

```bash
# 1. Mount image
sudo ewfmount evidence.E01 /mnt/ewf

# 2. Export MFT
fls -r /mnt/ewf/ewf1 > mft.csv

# 3. Export prefetch
# (extract from /mnt/ewf/ewf1/Windows/Prefetch/)

# 4. Export event logs
# (extract from /mnt/ewf/ewf1/Windows/System32/winevt/Logs/)

# 5. Run detection engine
python3 -m sift_find_evil.cli analyze \
    --mft mft.csv \
    --prefetch prefetch/ \
    --evtx evtx/ \
    --output findings.json
```

---

## Performance Notes

- **MFT parsing:** ~1-2 minutes for 100K entries
- **Prefetch parsing:** ~10-30 seconds for 1K files
- **Event log parsing:** ~2-5 minutes for 100K events
- **Memory analysis:** 5-15 minutes per GB of RAM (via Volatility)
- **Full disk analysis:** 10-30 minutes for typical workstation image

**Recommendation:** For large cases (>10 GB evidence), run overnight or use parallel processing.

---

## Updates

To update to the latest version:

```bash
cd ~/sift_find_evil
git pull origin main
pip3 install --user -e .
```

---

## Support

- **GitHub Issues:** https://github.com/Strike48/sift_find_evil/issues
- **Documentation:** https://github.com/Strike48/sift_find_evil/tree/main/docs
- **SIFT Workstation:** https://www.sans.org/tools/sift-workstation/

---

**Last Updated:** 2026-04-25
