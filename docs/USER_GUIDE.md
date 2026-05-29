# SIFT Find Evil User Guide

Complete guide to using the SIFT Find Evil forensic analysis tool for detecting data exfiltration, disk wiping, and other suspicious activities.

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Core Concepts](#core-concepts)
4. [Common Workflows](#common-workflows)
5. [Analysis Modes](#analysis-modes)
6. [Case Studies](#case-studies)
7. [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

- Python 3.10 or higher
- Git

### Install from Source

```bash
# Clone repository
git clone https://github.com/jtomek-strike48/sift_find_evil.git
cd sift_find_evil

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# Install core dependencies (pure-Python; covers the demo, the harness,
# the TUI, and all detectors against synthetic fixtures)
pip install -r requirements.txt
```

To process real evidence (E01/raw disk images, PST email, memory dumps) you
also need the native forensic libraries, which are kept separate because they
require a compiler and system headers:

```bash
# Debian/Ubuntu/SIFT: install the system libraries first
sudo apt-get install libtsk-dev libewf-dev libpff-dev libyara-dev

# Then the Python bindings + Volatility 3
pip install -r requirements-forensic.txt
```

The application loads and runs without the forensic extras; features that need
them raise a clear, install-oriented error rather than failing at startup.

### Verify Installation

```bash
# Run the full test suite
pytest

# Check CLI
python -m sift_find_evil --help
```

---

## Quick Start

### Run Demo Mode

Try the self-correction engine with synthetic test data:

```bash
python -m sift_find_evil demo
```

This demonstrates:
- Causality violation detection
- Event Log tiebreaker resolution
- Confidence score adjustment
- Transparent reasoning chains

### Analyze Real Evidence

Analyze forensic artifacts from Eric Zimmerman's tools (MFTECmd, PECmd, EvtxECmd):

```bash
python -m sift_find_evil analyze \
  --mft /path/to/mft.csv \
  --prefetch /path/to/prefetch.csv \
  --evtx /path/to/evtx.csv \
  --output findings.json
```

### Analyze Disk Images with Email Exfiltration Detection

Detect files that were saved to disk and then emailed:

```bash
python -m sift_find_evil analyze \
  --image disk.E01 \
  --pst email.pst \
  --output exfil_findings.json
```

---

## Core Concepts

### Artifact-Centric Detection

SIFT Find Evil does NOT look for:
- Specific file names
- Specific user names
- Case-specific indicators
- Known malware signatures

It DOES look for:
- Cryptographic hash correlations (SHA-256)
- Temporal relationships between artifacts
- Timestamp anomalies (timestomping, causality violations)
- Cross-artifact consistency

### Self-Correction Engine

The system autonomously detects contradictions and triggers re-investigation:

1. **Contradiction Detection**: MFT timestamps conflict with Prefetch execution times
2. **Confidence Reduction**: Initial high confidence drops due to inconsistency
3. **Tiebreaker Resolution**: Queries Event Logs as third artifact source
4. **Reasoning Chain**: Complete audit trail of investigation decisions

### Evidence Integrity

- **Read-only enforcement**: Never modifies evidence files
- **Chain of custody**: SHA-256 hashing at intake, verification before analysis
- **Audit trails**: Complete JSONL logs with tool invocations and reasoning

---

## Common Workflows

### Workflow 1: Data Exfiltration Investigation

Scenario: Suspect insider threat emailing sensitive files.

**Step 1**: Extract forensic artifacts

```bash
# Mount disk image
ewfmount suspect_disk.E01 /mnt/ewf

# Parse MFT (file system metadata)
MFTECmd.exe -f /mnt/ewf/ewf1 --csv /cases/suspect/artifacts --csvf mft.csv

# Extract PST (Outlook email)
cp /mnt/ewf/ewf1/Users/suspect/Documents/Outlook.pst /cases/suspect/email.pst
```

**Step 2**: Run exfiltration detector

```bash
python -m sift_find_evil analyze \
  --image /cases/suspect/suspect_disk.E01 \
  --pst /cases/suspect/email.pst \
  --output /cases/suspect/findings.json
```

**Step 3**: Review findings

```bash
# View findings in terminal
cat /cases/suspect/findings.json | jq '.findings[] | {title, confidence, matches}'

# Extract primary evidence
cat /cases/suspect/findings.json | jq '.findings[0].evidence.correlations[] | select(.is_primary)'
```

**Expected Output**:

```json
{
  "title": "Data exfiltration detected: 2 file(s) emailed within 300s",
  "confidence": 0.95,
  "confidence_label": "Very High",
  "severity": "critical",
  "matches": 2,
  "primary_match": {
    "file_path": "C:\\Users\\suspect\\Documents\\Sensitive.xlsx",
    "file_size": 524288,
    "file_modified": "2009-12-11T16:30:45Z",
    "email_subject": "FW: Financial Report",
    "email_sent": "2009-12-11T16:31:15Z",
    "time_delta_seconds": 30.0,
    "is_primary": true
  }
}
```

### Workflow 2: Wiped Disk Recovery

Scenario: Suspect wiped disk to destroy evidence.

**Step 1**: Analyze GPT partition table

```bash
python -m sift_find_evil analyze \
  --image /cases/wiped/disk.E01 \
  --output /cases/wiped/findings.json
```

**Step 2**: Carve deleted files (if wiping detected)

```bash
# Run CIRCL executable analysis with NSRL filtering
python scripts/analyze_circl_executables.py --use-nsrl
```

**Expected Output**:

```json
{
  "title": "Wiped disk detected: GPT backup preserved",
  "confidence": 0.90,
  "confidence_label": "High",
  "severity": "critical",
  "evidence": {
    "primary_gpt_zeroed": true,
    "backup_gpt_valid": true,
    "partition_count": 2,
    "total_data_sectors": 15728640,
    "wiped_method": "Primary GPT zeroed, backup intact"
  }
}
```

### Workflow 3: Timeline Reconstruction

Scenario: Build unified timeline from multiple artifact sources.

```bash
python -m sift_find_evil analyze \
  --mft /cases/timeline/mft.csv \
  --prefetch /cases/timeline/prefetch.csv \
  --evtx /cases/timeline/evtx.csv \
  --output /cases/timeline/findings.json \
  --timeline /cases/timeline/timeline.csv
```

Timeline includes:
- MFT file modifications ($STANDARD_INFORMATION and $FILE_NAME)
- Prefetch last run times
- Event Log process creation (Event ID 4688)

---

## Analysis Modes

### Mode 1: CSV-Only Analysis (Fast)

Process pre-parsed CSV files from Eric Zimmerman's tools:

```bash
python -m sift_find_evil analyze \
  --mft mft.csv \
  --prefetch prefetch.csv \
  --evtx evtx.csv
```

**Capabilities**:
- Timestomping detection
- Causality violation detection
- Self-correction with Event Log tiebreakers

**Limitations**:
- No file content access
- No hash-based correlation

### Mode 2: Disk Image Analysis (Full)

Process raw disk images with file content access:

```bash
python -m sift_find_evil analyze \
  --image disk.E01 \
  --pst email.pst
```

**Capabilities**:
- Everything from CSV-only mode
- File content hashing (SHA-256)
- Hash-based correlation (file-to-email)
- File carving from wiped disks

**Requirements**:
- pytsk3 (Sleuth Kit Python bindings)
- libewf (E01 image support)

### Mode 3: Hybrid Analysis (Recommended)

Combine CSV parsing with disk image access:

```bash
python -m sift_find_evil analyze \
  --mft mft.csv \
  --image disk.E01 \
  --pst email.pst
```

**Benefits**:
- Fast MFT parsing from CSV
- File content access when needed
- Best of both worlds

---

## Case Studies

### M57 Jean Exfiltration (Real Dataset)

**Scenario**: Employee "Jean" exfiltrated files via email before termination.

**Dataset**: NIST CFReDS M57-Jean scenario (nps-2008-jean.E01)

**Analysis**:

```bash
# Extract artifacts (already done in analysis/m57-jean/)
cd analysis/m57-jean

# Run exfiltration detector
python ../../../scripts/extract_jean_artifacts.py

# View results
cat jean_exfil_findings.json | jq
```

**Key Findings**:
- 2 files exfiltrated (Resume.doc and Patent.doc)
- File-to-email correlation confidence: 0.95
- Time deltas: 30s and 45s (very high confidence)

See [JEAN_EXFILTRATION_REPORT.md](../analysis/m57-jean/JEAN_EXFILTRATION_REPORT.md) for complete analysis.

### CIRCL Wiped Disk (Real Dataset)

**Scenario**: Hard drive wiped with GPT partition table destroyed.

**Dataset**: CIRCL DFIR challenge (circl-2011-wiped.E01)

**Analysis**:

```bash
cd analysis/circl-2023-wiped

# Analyze GPT wipe
python -m sift_find_evil analyze \
  --image circl-2011-wiped.E01 \
  --output wipe_findings.json

# Carve executables with NSRL filtering
python ../../../scripts/analyze_circl_executables.py --use-nsrl
```

**Key Findings**:
- Primary GPT zeroed, backup GPT valid
- 5 executables carved (4 unknown, 1 NSRL match)
- Wipe detection confidence: 0.90

See [CIRCL_WIPE_ANALYSIS.md](../analysis/circl-2023-wiped/CIRCL_WIPE_ANALYSIS.md) for complete analysis.

---

## Troubleshooting

### Issue: "pytsk3 not found"

**Symptom**:
```
ModuleNotFoundError: No module named 'pytsk3'
```

**Solution**:
```bash
# Install pytsk3
pip install pytsk3
```

**Note**: pytsk3 requires libewf and libtsk development headers.

### Issue: "Cannot open E01 image"

**Symptom**:
```
RuntimeError: Cannot open image: disk.E01
```

**Solution**:
```bash
# Verify image integrity
ewfverify disk.E01

# Check mount status
ewfmount disk.E01 /mnt/ewf
ls -la /mnt/ewf
```

### Issue: "No exfiltration detected (false negative)"

**Symptom**: Known exfiltration case shows no findings.

**Common Causes**:
1. Email timestamps missing (submit_time and delivery_time both null)
2. Time window too narrow (increase from default 300s)
3. File modification time altered (timestomping)

**Solution**:
```bash
# Increase time window
python -m sift_find_evil analyze \
  --image disk.E01 \
  --pst email.pst \
  --time-window 600  # Increase to 600 seconds
```

### Issue: "Test failures"

**Symptom**:
```
FAILED tests/test_exfil_detector.py::test_detect_exfiltration
```

**Solution**:
```bash
# Run tests with verbose output
pytest -v

# Run specific test
pytest tests/test_exfil_detector.py::test_detect_exfiltration -v

# Check test coverage
pytest --cov=sift_find_evil --cov-report=html
```

---

## Advanced Usage

### Custom Time Windows

Adjust correlation time window for specific scenarios:

```bash
# Tighten window for immediate exfiltration (60s)
python -m sift_find_evil analyze \
  --image disk.E01 \
  --pst email.pst \
  --time-window 60

# Widen window for manual exfiltration (900s = 15 minutes)
python -m sift_find_evil analyze \
  --image disk.E01 \
  --pst email.pst \
  --time-window 900
```

### NSRL Integration

Filter known-good files when analyzing carved executables:

```bash
# Download NSRL database (one-time setup, 2-3 GB)
./scripts/download-nsrl.sh modern

# Analyze with NSRL filtering
python scripts/analyze_circl_executables.py --use-nsrl
```

**Benefits**:
- 90%+ noise reduction
- Instant identification of Windows/Office/Adobe system files
- Focus on unknown executables

### Batch Processing

Process multiple cases:

```bash
#!/bin/bash
for case in /cases/*; do
  echo "Analyzing $case..."
  python -m sift_find_evil analyze \
    --image "$case/disk.E01" \
    --pst "$case/email.pst" \
    --output "$case/findings.json"
done
```

---

## Getting Help

- **GitHub Issues**: https://github.com/jtomek-strike48/sift-find-evil/issues
- **Documentation**: [docs/](.)
- **API Reference**: [docs/API_REFERENCE.md](API_REFERENCE.md)

---

Demonstrating autonomous DFIR analysis.
