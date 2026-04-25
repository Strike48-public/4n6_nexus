# Batch Testing Guide

**Objective:** Systematically test all USB evidence scenarios and collect comprehensive results for regression testing.

---

## Quick Start

### Option 1: Run from Host (Automated)

```bash
# Ensure VM is running
./scripts/sift-commands.sh start

# Run batch test (copies script to VM, executes, retrieves results)
./scripts/run-batch-test-on-sift.sh
```

### Option 2: Run Directly on SIFT VM

```bash
# SSH into VM
ssh sansforensics@192.168.122.76
# Password: forensics

# Run batch test
bash /path/to/batch-test-usb.sh
```

---

## What It Does

The batch test script:

1. **Discovers** all `scenario.yaml` files on USB drive
2. **Checks** if required evidence files are present
3. **Filters** scenarios by size (skips > 20GB by default)
4. **Copies** each scenario to work directory
5. **Runs** `sift_find_evil.cli run` on each scenario
6. **Collects** results with 1-hour timeout per scenario
7. **Generates** summary report with pass/fail/skip counts

---

## Configuration

Environment variables (optional):

```bash
# USB mount point (default: /mnt/usb-evidence/sift_evidence)
export USB_MOUNT="/mnt/usb-evidence/sift_evidence"

# Work directory (default: ~/sift_project)
export WORK_DIR="$HOME/sift_project"

# Results directory (default: ~/batch-test-results)
export RESULTS_BASE="$HOME/batch-test-results"

# Python venv path (default: ~/sift_find_evil_env)
export VENV_PATH="$HOME/sift_find_evil_env"

# Max scenario size in bytes (default: 20GB)
export MAX_SCENARIO_SIZE=20000000000

# Then run
bash /tmp/batch-test-usb.sh
```

---

## Results Structure

### On SIFT VM

```
~/batch-test-results/
└── 2026-04-25_18-30-00/          # Timestamped run
    ├── SUMMARY.md                 # Human-readable summary
    ├── m57-charlie.log            # Individual scenario logs
    ├── ngdc-carry-tablet.log
    └── ngdc-tracy-external.log
```

### On Host (after retrieval)

```
test-results/usb-batch/
└── 2026-04-25_18-30-00/          # Timestamped run
    ├── SUMMARY.md                 # Copied from VM
    └── *.log                      # All scenario logs
```

### Detailed Findings (auto-saved)

```
test-results/real/                 # Auto-saved by CLI
├── m57-charlie/
│   └── 2026-04-25_18-31-23/
│       ├── findings.json          # Full Finding objects
│       ├── metadata.json          # Test metrics
│       └── SUMMARY.md            # Human-readable
├── ngdc-carry-tablet/
│   └── 2026-04-25_18-34-45/
│       ├── findings.json
│       ├── metadata.json
│       └── SUMMARY.md
└── ...
```

---

## Understanding Results

### SUMMARY.md Format

```markdown
# USB Evidence Batch Test Summary

**Date:** 2026-04-25 18:30:00
**Run ID:** 2026-04-25_18-30-00

---

## Overview

- **Total Scenarios**: 7
- **Passed**: 3
- **Failed**: 1
- **Skipped**: 3

---

## Passed Scenarios

- m57-charlie (180s)
- ngdc-carry-tablet (120s)
- ngdc-tracy-external (300s)

---

## Failed Scenarios

- blue_team_challenge (exit 1)

---

## Skipped Scenarios

- m57-jo (missing evidence)
- compromised_apt_attack (too large: 100GB)
- insider_threat_2022 (missing evidence)
```

### Scenario Status

| Status | Meaning | Next Action |
|--------|---------|-------------|
| **PASS** | F1=1.00, all checks passed | Review findings in test-results/ |
| **FAIL** | Exit code != 0 | Check .log file for errors |
| **SKIP (missing evidence)** | Required files not present | Download missing files |
| **SKIP (too large)** | Evidence > 20GB | Run individually or increase limit |
| **TIMEOUT** | Took > 1 hour | Run individually with more time |

---

## Troubleshooting

### Script Not Finding Scenarios

```bash
# Check USB mount
ls /mnt/usb-evidence/sift_evidence/

# Find scenarios manually
find /mnt/usb-evidence/sift_evidence -name "scenario.yaml"
```

### Python venv Not Found

```bash
# Check if venv exists
ls ~/sift_find_evil_env/

# Recreate if needed
python3 -m venv ~/sift_find_evil_env
source ~/sift_find_evil_env/bin/activate
pip install -r ~/sift_project/requirements.txt
pip install -e ~/sift_project/
```

### Out of Disk Space

```bash
# Check available space
df -h

# Clean up old results
rm -rf ~/batch-test-results/2026-04-*

# Or increase VM disk allocation
```

### Scenario Timeout

```bash
# Increase timeout (default: 3600s = 1 hour)
# Edit batch-test-usb.sh line:
timeout 7200 python3 -m sift_find_evil.cli run ...  # 2 hours
```

---

## Post-Processing Results

### Aggregate Statistics

```bash
# Count findings across all scenarios
find test-results/real -name "metadata.json" -exec jq '.findings_count' {} \; | awk '{sum+=$1} END {print "Total findings:", sum}'

# Calculate average F1 score
find test-results/real -name "metadata.json" -exec jq '.f1' {} \; | awk '{sum+=$1; count++} END {print "Average F1:", sum/count}'

# List HIGH severity findings
find test-results/real -name "findings.json" -exec jq -r '.[] | select(.severity=="high") | .title' {} \;
```

### Export All Findings

```bash
# Combine all findings into one JSON
find test-results/real -name "findings.json" -exec cat {} \; | jq -s 'add' > all-findings.json

# Or as CSV
echo "scenario,severity,category,confidence,title" > all-findings.csv
find test-results/real -name "findings.json" -exec jq -r '.[] | [.scenario, .severity, .category.value, .confidence, .title] | @csv' {} \; >> all-findings.csv
```

### Compare Multiple Runs

```bash
# Compare two batch test runs
BASELINE="test-results/usb-batch/2026-04-25_18-30-00/SUMMARY.md"
CURRENT="test-results/usb-batch/2026-04-25_20-00-00/SUMMARY.md"

diff -u "$BASELINE" "$CURRENT"
```

---

## Selective Testing

### Test Specific Scenarios

```bash
# Edit USB_MOUNT to point to a specific scenario parent dir
export USB_MOUNT="/mnt/usb-evidence/sift_evidence/m57-patents"
bash /tmp/batch-test-usb.sh
```

### Test Only Small Scenarios

```bash
# Reduce size limit (10GB)
export MAX_SCENARIO_SIZE=10000000000
bash /tmp/batch-test-usb.sh
```

### Skip Slow Scenarios

Create a skip list:

```bash
# In batch-test-usb.sh, add after scenario discovery:
SKIP_LIST=("blue_team_challenge" "compromised_apt_attack")

for skip_scenario in "${SKIP_LIST[@]}"; do
    SCENARIOS=("${SCENARIOS[@]/*${skip_scenario}*/}")
done
```

---

## Automation

### Daily Batch Testing

```bash
# Add to crontab on SIFT VM
crontab -e

# Run every night at 2 AM
0 2 * * * bash /tmp/batch-test-usb.sh > /tmp/batch-test-nightly.log 2>&1
```

### CI/CD Integration

```bash
# In GitHub Actions / Jenkins
./scripts/run-batch-test-on-sift.sh

# Check exit code
if [ $? -eq 0 ]; then
    echo "All tests passed"
else
    echo "Some tests failed, check logs"
    exit 1
fi
```

---

## Best Practices

### Before Running

1. **Ensure USB is mounted**
   ```bash
   sudo mount /dev/sda1 /mnt/usb-evidence
   ls /mnt/usb-evidence/sift_evidence/
   ```

2. **Check VM resources**
   ```bash
   free -h     # At least 4GB free RAM
   df -h       # At least 50GB free disk
   ```

3. **Update software**
   ```bash
   cd ~/sift_project
   git pull
   source ~/sift_find_evil_env/bin/activate
   pip install -e .
   ```

### During Running

- Monitor progress: `tail -f ~/batch-test-results/*/SUMMARY.md`
- Check resource usage: `htop` or `top`
- Watch for errors: `tail -f ~/batch-test-results/*/*.log`

### After Running

1. **Review summary**
   ```bash
   cat ~/batch-test-results/latest/SUMMARY.md
   ```

2. **Investigate failures**
   ```bash
   grep -r "ERROR" ~/batch-test-results/latest/*.log
   ```

3. **Copy results to host**
   ```bash
   ./scripts/run-batch-test-on-sift.sh  # Automated retrieval
   ```

4. **Archive results**
   ```bash
   tar -czf batch-results-$(date +%Y-%m-%d).tar.gz test-results/usb-batch/
   ```

---

## Performance Expectations

Based on testing:

| Scenario Size | Expected Time | Scenarios/Hour |
|---------------|---------------|----------------|
| 1-2 GB | 2-5 minutes | 10-20 |
| 3-5 GB | 5-10 minutes | 5-10 |
| 10-20 GB | 15-30 minutes | 2-4 |
| 50+ GB | 1+ hours | 0-1 |

**For 7 scenarios on USB (estimated):**
- M57-Charlie (3.7 GB): ~3 min
- NGDC-Carry-Tablet (1.1 GB): ~2 min
- NGDC-Tracy-External (3.6 GB): ~5 min
- Others: Variable (some will skip)

**Total estimated time: 10-30 minutes** (depending on which scenarios have complete evidence)

---

## Regression Testing Workflow

### First Baseline Run

```bash
# Run batch test to establish baseline
./scripts/run-batch-test-on-sift.sh

# Tag baseline
mv test-results/usb-batch/latest test-results/usb-batch/baseline-2026-04-25
```

### After Code Changes

```bash
# Run batch test again
./scripts/run-batch-test-on-sift.sh

# Compare results
python3 sift_find_evil/testing/compare_runs.py \
    test-results/usb-batch/baseline-2026-04-25 \
    test-results/usb-batch/latest
```

### Detect Regressions

Look for:
- Scenarios that changed from PASS → FAIL
- Decreased F1 scores
- Confidence drops > 10%
- New false positives
- Missed detections (false negatives)

---

## Next Steps

After successful batch testing:

1. **Review all findings** - Check for patterns across scenarios
2. **Document issues** - File bd issues for any problems found
3. **Update scenarios** - Add missing evidence or fix manifests
4. **Run regression tests** - Compare with baseline
5. **Generate reports** - Create comprehensive analysis

---

**Quick Reference:**

```bash
# Run from host
./scripts/run-batch-test-on-sift.sh

# Review results
cat test-results/usb-batch/latest/SUMMARY.md
find test-results/real -name "findings.json"

# Aggregate stats
find test-results/real -name "metadata.json" | wc -l  # Total scenarios
find test-results/real -name "findings.json" -exec jq '.[]' {} \; | wc -l  # Total findings
```
