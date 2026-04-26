# Regression Testing Guide

**Goal:** Run batch testing multiple times to establish a baseline and detect regressions after code changes.

---

## Current Status

**First batch test run:** 2026-04-25_23-09-45
- 5 scenarios discovered
- 1 passed (m57-patents with F1=1.00)
- 1 failed (national_gallery_2012 - missing segments)
- 3 skipped (archived evidence)

**Archive extraction:** In progress
- Extracting 23GB of archived evidence to USB
- Will enable testing of blue_team_challenge, ransomware_2021
- Extraction location: directly on USB drive (VM at 92% disk capacity)

---

## Regression Testing Workflow

### 1. Establish Baseline

Run batch test on clean USB evidence:

```bash
# Extract archives (one-time setup)
./scripts/run-extraction-on-sift.sh  # If needed

# Run first batch test
./scripts/run-batch-test-on-sift.sh

# Save as baseline
mkdir -p test-results/usb-batch/baseline
cp -r test-results/usb-batch/latest/* test-results/usb-batch/baseline/
```

### 2. Make Code Changes

```bash
# Normal development workflow
git checkout -b feature/improve-detection
# Edit code, add tests
git commit -m "feat: improve XYZ detection"
```

### 3. Run Regression Test

```bash
# Run batch test again
./scripts/run-batch-test-on-sift.sh

# Compare results
diff -u test-results/usb-batch/baseline/SUMMARY.md \
        test-results/usb-batch/latest/SUMMARY.md
```

### 4. Review Changes

Check for regressions:

- **Pass → Fail**: Critical regression (detection broke)
- **F1 score decreased**: Detection quality degraded
- **New false positives**: Precision dropped
- **Missed detections**: Recall dropped
- **Confidence changes**: Scoring algorithm affected

### 5. Update Baseline (if changes are improvements)

```bash
# After verifying improvements are intentional
cp -r test-results/usb-batch/latest/* test-results/usb-batch/baseline/
git add test-results/usb-batch/baseline/
git commit -m "chore: update regression test baseline"
```

---

## Monitoring Batch Tests

### During Execution

```bash
# Watch progress
./scripts/monitor-batch-test.sh

# Or use watch
watch -n 5 ./scripts/monitor-batch-test.sh
```

### After Completion

```bash
# View summary
cat test-results/usb-batch/latest/SUMMARY.md

# View detailed findings
find test-results/real -name "findings.json" | xargs jq .

# Check scenario logs
ls test-results/usb-batch/latest/*.log
```

---

## Expected Scenarios (After Extraction)

### Available for Testing

1. **m57-patents** (9GB)
   - charlie-2009-12-11.E01
   - jo-2009-12-11-001.E01 (single segment only)

2. **blue_team_challenge** (8.7GB extracted)
   - aamemend.dmp (memory dump)
   - alison_ws files

3. **ransomware_2021** (15GB extracted)
   - Forensic image files

4. **national_gallery_2012**
   - carry-tablet.E01
   - carry-phone (extracted from zip)
   - tracy-external.E01
   - tracy-home.E01

### Known Limitations

- **M57-Jo**: Missing E02 segment (multi-segment incomplete)
- **insider_threat_2022**: Missing required evidence files
- **national_gallery_2012**: Some multi-segment images incomplete

---

## Regression Detection Examples

### Example 1: Detection Breaks

```diff
--- baseline/SUMMARY.md
+++ latest/SUMMARY.md
@@ -10,7 +10,7 @@
 
 - **Total Scenarios**: 5
-- **Passed**: 3
+- **Passed**: 2
 - **Failed**: 1
 - **Skipped**: 1
```

**Action:** Investigate why scenario started failing. Check logs for errors.

### Example 2: Precision Drops

```diff
--- baseline/m57-charlie.log
+++ latest/m57-charlie.log
@@ -5,5 +5,5 @@
   Findings:    2
-  Precision:   1.00
+  Precision:   0.67
   Recall:      1.00
-  F1:          1.00
+  F1:          0.80
```

**Action:** New false positives detected. Review findings to identify spurious detections.

### Example 3: Recall Drops

```diff
--- baseline/m57-charlie.log
+++ latest/m57-charlie.log
@@ -4,6 +4,6 @@
   Directory:   /home/sansforensics/sift_project/scenarios/usb-batch/m57-charlie
   Findings:    2
   Precision:   1.00
-  Recall:      1.00
+  Recall:      0.50
-  F1:          1.00
+  F1:          0.67
```

**Action:** Missing detections. Identify which ground truth items were missed.

---

## Automation

### CI/CD Integration

```yaml
# .github/workflows/regression-test.yml
name: Regression Test
on: [push, pull_request]

jobs:
  regression:
    runs-on: self-hosted  # Requires SIFT VM access
    steps:
      - uses: actions/checkout@v3
      - name: Run batch test
        run: ./scripts/run-batch-test-on-sift.sh
      - name: Compare with baseline
        run: |
          diff test-results/usb-batch/baseline/SUMMARY.md \
               test-results/usb-batch/latest/SUMMARY.md
```

### Nightly Testing

```bash
# Add to crontab
0 2 * * * cd /path/to/sift_find_evil && ./scripts/run-batch-test-on-sift.sh >> /var/log/nightly-regression.log 2>&1
```

---

## Troubleshooting

### Extraction Issues

```bash
# Check USB mount
ssh sansforensics@192.168.122.76 "mount | grep usb"

# Check extraction progress
./scripts/check-extraction-progress.sh

# Manual extraction if needed
ssh sansforensics@192.168.122.76
cd /mnt/usb-evidence/sift_evidence/scenario_name/evidence
sudo 7z x archive.7z
sudo unzip archive.zip
```

### Batch Test Issues

```bash
# Check VM status
./scripts/sift-commands.sh status

# Check USB mount
ssh sansforensics@192.168.122.76 "ls /mnt/usb-evidence/sift_evidence"

# Check disk space
ssh sansforensics@192.168.122.76 "df -h"

# View test logs
ssh sansforensics@192.168.122.76 "tail -f ~/batch-test-results/*/SUMMARY.md"
```

---

## Best Practices

1. **Run baseline before major changes** - Establish known-good state
2. **Keep baseline in git** - Track expected results over time
3. **Review all changes** - Don't automatically accept regressions
4. **Test incrementally** - Run after each significant code change
5. **Document intentional changes** - Update baseline with clear commit messages

---

**Quick Reference:**

```bash
# Extract archives (one-time)
./scripts/run-extraction-on-sift.sh

# Run batch test
./scripts/run-batch-test-on-sift.sh

# Monitor progress
./scripts/monitor-batch-test.sh

# Check results
cat test-results/usb-batch/latest/SUMMARY.md
find test-results/real -name "findings.json"
```

---

*Last updated: 2026-04-25*
