# Regression Testing Guide

**Goal:** Run batch testing multiple times to establish a baseline and detect regressions after code changes.

**Status:** ✓ Fully operational with verified deterministic behavior (2026-04-26)

---

## Current Status

**Determinism Verified:** 2026-04-26
- 6/6 scenarios tested twice with identical results
- All findings, F1 scores, and confidence values match perfectly
- Detection engine is fully deterministic and regression-ready

**Baseline Established:**
- Run: FINAL-2026-04-26_03-52-54
- Total scenarios: 6
- Pass rate: 100% (6/6)
- Evidence: 213GB across 25+ files

**Available Scenarios:**
1. m57-patents (9GB) - 2 findings, F1=1.00
2. blue_team_challenge (22GB) - baseline, F1=1.00
3. insider_threat_2022 (9GB) - baseline, F1=1.00
4. ransomware_2021 (50GB) - baseline, F1=1.00
5. national_gallery_2012 (31GB) - 1 finding, F1=1.00
6. compromised_apt_attack (104GB) - baseline, F1=1.00

---

## Quick Start

```bash
# Run full regression test (all 6 scenarios)
./scripts/run-batch-test-on-sift.sh

# Compare with baseline (verify determinism)
./scripts/compare-batch-runs.sh FINAL-2026-04-26_03-52-54 <new_run_timestamp>

# View results
cat test-results/usb-batch/latest/SUMMARY.md
```

---

## Regression Testing Workflow

### 1. Establish Baseline (Already Done)

Current baseline: `FINAL-2026-04-26_03-52-54`

If you need to re-establish baseline:

```bash
# Run batch test
./scripts/run-batch-test-on-sift.sh

# Save as new baseline
mkdir -p test-results/usb-batch/baseline
cp -r test-results/usb-batch/<timestamp>/* test-results/usb-batch/baseline/
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

# Compare results (automated comparison)
./scripts/compare-batch-runs.sh FINAL-2026-04-26_03-52-54 <new_timestamp>
```

### 4. Review Changes

The comparison script checks:

- **Pass/Fail status** - Did any scenario change from PASS to FAIL?
- **Finding counts** - Did the number of detections change?
- **F1 scores** - Did precision, recall, or F1 scores change?
- **Confidence scores** - Did detection confidence change?
- **Log content** - Did output differ (excluding timestamps)?

**Determinism check:**
- ✓ Green checkmarks = Results match
- ✗ Red X marks = Non-deterministic behavior detected

### 5. Interpret Results

Check for regressions:

- **Pass → Fail**: Critical regression (detection broke)
- **Different finding counts**: Detection logic changed
- **F1 score decreased**: Detection quality degraded
- **New false positives**: Precision dropped
- **Missed detections**: Recall dropped
- **Confidence changes**: Scoring algorithm affected

### 6. Update Baseline (if changes are improvements)

```bash
# After verifying improvements are intentional
NEW_BASELINE="2026-04-26_XX-XX-XX"
cp -r test-results/usb-batch/$NEW_BASELINE/* test-results/usb-batch/baseline/
git add test-results/usb-batch/baseline/
git commit -m "chore: update regression test baseline after detection improvements"
```

---

## Monitoring Batch Tests

### During Execution

```bash
# Watch progress (recommended)
./scripts/monitor-batch-test.sh

# Or use watch for auto-refresh
watch -n 5 ./scripts/monitor-batch-test.sh
```

**Expected duration:** ~30 seconds for all 6 scenarios

### After Completion

```bash
# View summary
cat test-results/usb-batch/latest/SUMMARY.md

# View detailed findings
find test-results/real -name "findings.json" | xargs jq .

# Check scenario logs
ls test-results/usb-batch/latest/*.log
cat test-results/usb-batch/latest/m57-patents.log
```

---

## Determinism Verification Results

**Verified:** 2026-04-26

Two independent batch runs produced identical results:

| Run | Timestamp | Scenarios | Pass | Fail | Skip |
|-----|-----------|-----------|------|------|------|
| Run 1 | FINAL-2026-04-26_03-52-54 | 6 | 6 | 0 | 0 |
| Run 2 | 2026-04-26_11-27-23 | 6 | 6 | 0 | 0 |

**Findings comparison:**

| Scenario | Findings (Run 1) | Findings (Run 2) | Match |
|----------|------------------|------------------|-------|
| m57-patents | 2 (F1=1.00, conf=0.95) | 2 (F1=1.00, conf=0.95) | ✓ |
| national_gallery_2012 | 1 (F1=1.00, conf=0.95) | 1 (F1=1.00, conf=0.95) | ✓ |
| blue_team_challenge | 0 (baseline) | 0 (baseline) | ✓ |
| insider_threat_2022 | 0 (baseline) | 0 (baseline) | ✓ |
| ransomware_2021 | 0 (baseline) | 0 (baseline) | ✓ |
| compromised_apt_attack | 0 (baseline) | 0 (baseline) | ✓ |

**Conclusion:** Detection engine is fully deterministic.

---

## Scenario Details

### 1. m57-patents (9GB)
- **Tier:** real
- **Evidence:** 2 disk images (charlie, jo)
- **Findings:** 2 malicious executables detected
- **Status:** Perfect baseline (F1=1.00, confidence=0.95)

### 2. blue_team_challenge (22GB)
- **Tier:** training
- **Evidence:** Disk image + memory dump
- **Findings:** 0 (baseline scenario)
- **Status:** Linux compromise investigation

### 3. insider_threat_2022 (9GB)
- **Tier:** training
- **Evidence:** Disk image + memory capture
- **Findings:** 0 (baseline scenario)
- **Status:** Insider threat with anti-forensic tools (CCleaner)

### 4. ransomware_2021 (50GB)
- **Tier:** training
- **Evidence:** Multi-segment disk image (9 segments) + memory
- **Findings:** 0 (baseline scenario)
- **Status:** Ransomware/insider investigation

### 5. national_gallery_2012 (31GB)
- **Tier:** real
- **Evidence:** 4 evidence items (tablet, phone, external, home)
- **Findings:** 1 detection
- **Status:** Established baseline (F1=1.00, confidence=0.95)

### 6. compromised_apt_attack (104GB)
- **Tier:** real
- **Evidence:** 7 Windows systems (DC, file server, RDP, workstations, DMZ FTP)
- **Findings:** 0 (baseline scenario)
- **Status:** Enterprise APT investigation

---

## Regression Detection Examples

### Example 1: Detection Breaks

```diff
--- baseline/SUMMARY.md
+++ current/SUMMARY.md
@@ -10,7 +10,7 @@
 
 - **Total Scenarios**: 6
-- **Passed**: 6
+- **Passed**: 5
-- **Failed**: 0
+- **Failed**: 1
 - **Skipped**: 0
```

**Action:** Critical regression. Investigate why scenario failed. Check logs for errors.

### Example 2: Precision Drops (New False Positives)

```diff
--- baseline/m57-patents.log
+++ current/m57-patents.log
@@ -5,5 +5,5 @@
-  Findings:    2
+  Findings:    5
-  Precision:   1.00
+  Precision:   0.40
   Recall:      1.00
-  F1:          1.00
+  F1:          0.57
```

**Action:** 3 new false positives detected. Review findings to identify spurious detections.

### Example 3: Recall Drops (Missed Detections)

```diff
--- baseline/m57-patents.log
+++ current/m57-patents.log
@@ -4,6 +4,6 @@
-  Findings:    2
+  Findings:    1
   Precision:   1.00
-  Recall:      1.00
+  Recall:      0.50
-  F1:          1.00
+  F1:          0.67
```

**Action:** Missing 1 detection. Identify which ground truth item was missed.

### Example 4: Non-Deterministic Behavior

```
Comparison output:
✗ NON-DETERMINISTIC: Runs produced different finding counts.
```

**Action:** Critical issue. Detection logic has randomness or timing dependencies. Investigate immediately.

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
          LATEST=$(ls -t test-results/usb-batch/ | grep -v baseline | head -1)
          ./scripts/compare-batch-runs.sh FINAL-2026-04-26_03-52-54 $LATEST
      - name: Check for regressions
        run: |
          if grep -q "NON-DETERMINISTIC" test-results/usb-batch/comparison-*.md; then
            echo "❌ Regression detected!"
            exit 1
          fi
```

### Nightly Testing

```bash
# Add to crontab
0 2 * * * cd /path/to/sift_find_evil && ./scripts/run-batch-test-on-sift.sh >> /var/log/nightly-regression.log 2>&1
```

---

## Troubleshooting

### Batch Test Issues

```bash
# Check VM status
./scripts/sift-commands.sh status

# Check USB mount
ssh sansforensics@192.168.122.76 "ls /mnt/usb-evidence/sift_evidence"

# Check disk space
ssh sansforensics@192.168.122.76 "df -h"

# View test logs on VM
ssh sansforensics@192.168.122.76 "cat ~/batch-test-results/latest/SUMMARY.md"
```

### Comparison Script Issues

```bash
# List available runs
ls -lt test-results/usb-batch/

# Manual comparison
diff test-results/usb-batch/FINAL-2026-04-26_03-52-54/m57-patents.log \
     test-results/usb-batch/<new_run>/m57-patents.log
```

### Determinism Issues

If comparison shows non-deterministic behavior:

1. **Check for timing dependencies** - Are detections based on timestamps?
2. **Check for randomness** - Is there any random sampling or ordering?
3. **Check for external dependencies** - Do detections rely on network/external data?
4. **Check for race conditions** - Are there concurrent operations?

---

## Best Practices

1. **Run baseline before major changes** - Establish known-good state
2. **Use comparison script** - Automated checks catch subtle regressions
3. **Review all changes** - Don't automatically accept regressions
4. **Test incrementally** - Run after each significant code change
5. **Document intentional changes** - Update baseline with clear commit messages
6. **Verify determinism** - Run twice to confirm identical results
7. **Keep evidence stable** - Don't modify USB evidence between runs

---

## Quick Reference

```bash
# Run batch test
./scripts/run-batch-test-on-sift.sh

# Monitor progress
./scripts/monitor-batch-test.sh

# Compare runs (automated)
./scripts/compare-batch-runs.sh BASELINE_RUN CURRENT_RUN

# Check results
cat test-results/usb-batch/latest/SUMMARY.md
find test-results/real -name "findings.json"

# List all runs
ls -lt test-results/usb-batch/
```

---

**Current Baseline:** FINAL-2026-04-26_03-52-54

**Last Updated:** 2026-04-26

**Status:** ✓ Production-ready with verified determinism
