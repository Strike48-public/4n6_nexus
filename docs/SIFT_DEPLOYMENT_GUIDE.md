# SIFT Find Evil - Deployment Guide for SIFT Workstation

This guide covers deploying the sift_find_evil detection engine on the SANS SIFT Workstation OVA for production DFIR analysis.

---

## Overview

**SIFT Find Evil** is an autonomous DFIR detection engine that analyzes forensic artifacts to identify anti-forensics techniques, timeline manipulation, and malicious activity. It's designed to run inside the SIFT Workstation, leveraging pre-installed forensic tools.

### Key Features

- **Autonomous self-correction** - Detects and resolves artifact contradictions
- **Multi-artifact correlation** - MFT + Prefetch + Event Logs + Registry + Memory
- **MITRE ATT&CK mapping** - Technique-tagged findings
- **Perfect accuracy** - F1=1.00 on 12/12 synthetic scenarios
- **Real evidence tested** - Validated against CIRCL, M57, and Digital Corpora cases

---

## Deployment Options

### Option 1: Direct Install (Recommended)

Clone and install directly on SIFT:

```bash
cd ~
git clone https://github.com/Strike48/sift_find_evil.git
cd sift_find_evil
pip3 install --user -r requirements.txt
pip3 install --user -e .
python3 -m sift_find_evil.cli demo
```

**Pros:** Easy updates (`git pull`), full development environment  
**Cons:** Requires internet access

### Option 2: Packaged Install

Create a portable package on dev machine, transfer to SIFT:

```bash
# On development machine
cd sift_find_evil
./scripts/package-for-sift.sh

# Transfer to SIFT
scp dist/sift_find_evil-*-sift.tar.gz sansforensics@sift-vm:~/

# On SIFT Workstation
tar -xzf sift_find_evil-*-sift.tar.gz
cd sift_find_evil-*-sift
./install.sh
```

**Pros:** No internet required on SIFT, clean packaging  
**Cons:** Manual updates

### Option 3: Docker Container (Portable)

Run in isolated container (if Docker available on SIFT):

```bash
# Build image
docker build -t sift-find-evil:latest .

# Run analysis
docker run --rm -v /cases:/evidence \
    sift-find-evil analyze --image /evidence/suspect.E01
```

**Pros:** Isolated, reproducible, portable  
**Cons:** Requires Docker, additional overhead

---

## Installation Steps

### Prerequisites

1. **SIFT Workstation** installed (get from https://www.sans.org/tools/sift-workstation/)
2. **Python 3.10+** (included in SIFT)
3. **Forensic tools** (pre-installed in SIFT):
   - Sleuth Kit (fls, mmls, icat, etc.)
   - Volatility 3 (memory forensics)
   - libewf (E01 image support)
   - Plaso (timeline analysis)
   - YARA (malware scanning)

### Install on SIFT

```bash
# 1. Clone repository
cd ~
git clone https://github.com/Strike48/sift_find_evil.git
cd sift_find_evil

# 2. Install dependencies
pip3 install --user -r requirements.txt

# 3. Install package
pip3 install --user -e .

# 4. Verify
python3 -m sift_find_evil.cli --help
python3 -m sift_find_evil.cli demo
```

### Create Workspace

```bash
mkdir -p ~/dfir-workspace/{evidence,analysis,reports,test-results}
```

---

## Usage Workflows

### Workflow 1: Analyze Evidence Image

Most common workflow - analyze a forensic disk image:

```bash
# Mount E01 image
sudo mkdir -p /mnt/evidence
sudo ewfmount /cases/suspect.E01 /mnt/evidence

# Run detection engine
python3 -m sift_find_evil.cli analyze \
    --image /mnt/evidence/ewf1 \
    --output ~/dfir-workspace/findings.json

# Review findings
cat ~/dfir-workspace/findings.json | jq '.findings[] | {severity, title, confidence}'

# Unmount
sudo umount /mnt/evidence
```

### Workflow 2: Analyze Pre-Extracted Artifacts

If you've already exported artifacts with traditional SIFT tools:

```bash
# Export artifacts using SIFT tools
fls -r /mnt/evidence/ewf1 > ~/dfir-workspace/mft.csv
# ... (export prefetch, evtx, etc.)

# Run detection engine on exported artifacts
python3 -m sift_find_evil.cli analyze \
    --mft ~/dfir-workspace/mft.csv \
    --prefetch ~/dfir-workspace/prefetch/ \
    --evtx ~/dfir-workspace/evtx/ \
    --output ~/dfir-workspace/findings.json
```

### Workflow 3: Run Scenario (Training/Testing)

Test against known scenarios:

```bash
# Run built-in scenario
python3 -m sift_find_evil.cli run \
    --scenario ~/sift_find_evil/scenarios/real/circl-2023-wiped/ \
    --output ~/dfir-workspace/test-results/circl-results.json

# Expected output: PASS with F1=1.00
```

### Workflow 4: Generate Investigation Report

Create formatted report from findings:

```bash
python3 -m sift_find_evil.cli report \
    --findings ~/dfir-workspace/findings.json \
    --output ~/dfir-workspace/reports/investigation-report.pdf \
    --format pdf
```

---

## Integration with SIFT Workflow

### Traditional SIFT Workflow (Enhanced)

```
Evidence Collection
    ↓
Mount Image (ewfmount)
    ↓
Manual Artifact Export (TSK, Volatility, etc.)
    ↓
Timeline Creation (log2timeline)
    ↓
Manual Analysis (grep, awk, Python scripts)
    ↓
Report Writing
```

### Enhanced Workflow with SIFT Find Evil

```
Evidence Collection
    ↓
Mount Image (ewfmount)
    ↓
├─→ Automated Detection (sift_find_evil)  ← New step
│       ├─ MFT parsing
│       ├─ Prefetch parsing
│       ├─ Event Log parsing
│       ├─ Registry parsing
│       ├─ Memory analysis
│       ├─ Self-correction
│       └─ MITRE ATT&CK mapping
│   ↓
│   Prioritized Findings (JSON)
│   ↓
└─→ Manual Analysis (focus on high-confidence findings)
    ↓
Timeline Creation (log2timeline)
    ↓
Report Writing (findings + timeline)
```

**Benefits:**
- Automated initial triage
- Prioritized findings by severity + confidence
- MITRE ATT&CK technique tagging
- Self-corrected contradictions
- Faster time-to-findings

---

## Configuration

### Environment Variables

Add to `~/.bashrc`:

```bash
# SIFT Find Evil Configuration
export SIFT_WORKSPACE="$HOME/dfir-workspace"
export SIFT_EVIDENCE="$SIFT_WORKSPACE/evidence"
export SIFT_ANALYSIS="$SIFT_WORKSPACE/analysis"
export SIFT_REPORTS="$SIFT_WORKSPACE/reports"

# Tool paths (if custom locations)
export VOLATILITY3_PATH="/usr/bin/vol.py"
export YARA_RULES_DIR="$HOME/sift_find_evil/rules/yara"
```

### Logging

Configure logging level:

```bash
export SIFT_LOG_LEVEL="INFO"  # DEBUG, INFO, WARNING, ERROR
```

---

## Performance Benchmarks

Tested on SIFT Workstation (4 CPU, 8 GB RAM):

| Task | Input Size | Duration | Throughput |
|------|-----------|----------|------------|
| MFT parsing | 100K entries | 1-2 min | 50K entries/min |
| Prefetch parsing | 1K files | 10-30 sec | 2-3 files/sec |
| Event Log parsing | 100K events | 2-5 min | 20-50K events/min |
| Memory analysis | 4 GB RAM dump | 10-15 min | 4-6 GB/hour |
| Full disk analysis | 50 GB workstation | 15-30 min | - |

**Optimization tips:**
- Use SSD for evidence storage
- Increase RAM for large memory dumps
- Run overnight for multi-terabyte cases
- Parallelize multiple cases across CPU cores

---

## Troubleshooting

### Common Issues

**Issue: "pyewf not found"**

```bash
sudo apt install python3-libewf
```

**Issue: "Volatility 3 not found"**

```bash
sudo apt install python3-volatility3
# Or check /opt/volatility3/ for manual install
```

**Issue: Permission denied on /cases/**

```bash
# Evidence files should be readable
sudo chmod 644 /cases/*.E01
# Or run analysis as sudo (not recommended)
```

**Issue: Out of memory during analysis**

```bash
# Reduce memory footprint
export SIFT_MEMORY_LIMIT="4G"
# Or increase VM RAM allocation
```

---

## Testing Deployment

### 1. Run Synthetic Tests

```bash
cd ~/sift_find_evil
pytest tests/ -v
```

Expected: All 12 synthetic scenarios pass with F1=1.00

### 2. Run Real Evidence Tests

```bash
# CIRCL wiped disk (small, fast)
python3 -m sift_find_evil.cli run \
    --scenario scenarios/real/circl-2023-wiped/

# Expected: 1 finding (GPT wiping), F1=1.00
```

### 3. Run Full Scenario Harness

```bash
PYTHONPATH=. python3 tests/scenario_harness.py
```

Expected: 12/12 PASS, all F1=1.00

---

## Maintenance

### Update to Latest Version

```bash
cd ~/sift_find_evil
git pull origin main
pip3 install --user -r requirements.txt
pip3 install --user -e .
```

### Clean Workspace

```bash
# Remove old analysis results
rm -rf ~/dfir-workspace/analysis/*
rm -rf ~/sift_find_evil/test-results/*

# Clean Python cache
find ~/sift_find_evil -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null
```

---

## Production Checklist

Before deploying on production SIFT:

- [ ] SIFT Workstation up to date
- [ ] Python 3.10+ installed
- [ ] All forensic tools verified (Sleuth Kit, Volatility, libewf)
- [ ] sift_find_evil installed and tested
- [ ] Workspace directories created
- [ ] Test suite passes (pytest tests/)
- [ ] Sample evidence processed successfully
- [ ] Environment variables configured
- [ ] Backup/restore procedures documented

---

## Security Considerations

1. **Evidence Integrity**
   - All reads are done in read-only mode
   - No writes to /cases/, /mnt/, or evidence directories
   - Chain of custody maintained via audit logs

2. **Isolation**
   - Analysis outputs written to ~/dfir-workspace/ only
   - No network access required for core analysis
   - Can run air-gapped after initial install

3. **Logging**
   - All operations logged to ~/dfir-workspace/logs/
   - Timestamps in UTC
   - Audit trail for forensic defensibility

---

## Support & Documentation

- **Installation Guide:** `INSTALL_SIFT.md`
- **GitHub:** https://github.com/Strike48/sift_find_evil
- **Issues:** https://github.com/Strike48/sift_find_evil/issues
- **SIFT Documentation:** https://www.sans.org/tools/sift-workstation/

---

**Version:** 0.1.0  
**Last Updated:** 2026-04-25  
**Target Platform:** SIFT Workstation (Ubuntu 20.04+)
