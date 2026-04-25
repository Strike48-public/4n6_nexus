# Batch Testing - Quick Reference

**Run all USB evidence scenarios with one command.**

---

## Quick Start

```bash
# From project root on host machine
./scripts/run-batch-test-on-sift.sh
```

That's it! The script will:
1. Copy the batch test script to SIFT VM
2. Discover all scenarios on USB drive
3. Test each one automatically
4. Retrieve results back to host

---

## View Results

```bash
# Summary
cat test-results/usb-batch/latest/SUMMARY.md

# Detailed findings (auto-saved by CLI)
find test-results/real -name "findings.json"

# Individual logs
ls test-results/usb-batch/latest/*.log
```

---

## What Gets Tested

The batch script automatically discovers and tests all scenarios with:
- `scenario.yaml` file present
- Required evidence files available
- Size under 20GB (configurable)

Currently on USB:
- M57-Patents scenarios
- National Gallery DC 2012 scenarios  
- Compromised APT Attack scenarios
- Insider Threat scenarios
- Ransomware scenarios
- Blue Team Challenge
- Mobile evidence

---

## Configuration

Set environment variables before running:

```bash
# Increase size limit to 50GB
export MAX_SCENARIO_SIZE=50000000000
./scripts/run-batch-test-on-sift.sh

# Change USB mount point
export USB_MOUNT="/mnt/usb-evidence/custom-path"
./scripts/run-batch-test-on-sift.sh
```

---

## Expected Results

Based on current USB evidence:

**Available Complete Scenarios:**
- ✓ M57-Charlie (3.7 GB)
- ✓ NGDC-Carry-Tablet (1.1 GB)
- ✓ NGDC-Tracy-External (3.6 GB)
- ✓ NGDC-Tracy-Home (segments available)

**Will Skip (Missing Evidence):**
- M57-Jo (needs segment 2)
- M57-Pat (not downloaded)
- M57-Terry (not downloaded)
- Insider Threat 2022 (needs memory dump)

**Will Skip (Too Large):**
- Compromised APT Attack (100+ GB total)
- May need to test individually

**Estimated Runtime:** 15-30 minutes for complete scenarios

---

## After Testing

### Review Pass/Fail Summary

```bash
cat test-results/usb-batch/latest/SUMMARY.md
```

### Check Detailed Findings

```bash
# Count total findings
find test-results/real -name "metadata.json" -exec jq '.findings_count' {} \; | 
    awk '{sum+=$1} END {print "Total:", sum}'

# List HIGH severity findings
find test-results/real -name "findings.json" -exec jq -r '.[] | 
    select(.severity=="high") | "\(.title)"' {} \;
```

### Investigate Failures

```bash
# View error logs
grep -r "ERROR" test-results/usb-batch/latest/*.log
```

---

## Regression Testing

### Establish Baseline

```bash
# First run
./scripts/run-batch-test-on-sift.sh

# Save as baseline
cp -r test-results/usb-batch/latest test-results/usb-batch/baseline-$(date +%Y-%m-%d)
```

### Compare After Changes

```bash
# Make code changes, then run again
git pull
./scripts/run-batch-test-on-sift.sh

# Compare
diff -u test-results/usb-batch/baseline-2026-04-25/SUMMARY.md \
        test-results/usb-batch/latest/SUMMARY.md
```

---

## Troubleshooting

### VM Not Running

```bash
./scripts/sift-commands.sh start
```

### USB Not Mounted

```bash
# On SIFT VM
sudo mount /dev/sda1 /mnt/usb-evidence
```

### Out of Disk Space

```bash
# Clean old results
rm -rf ~/batch-test-results/2026-04-*  # On VM
```

---

## Full Documentation

See `docs/BATCH_TESTING_GUIDE.md` for:
- Detailed configuration options
- Post-processing examples
- Selective testing
- Performance tuning
- CI/CD integration

---

**Last Updated:** 2026-04-25
