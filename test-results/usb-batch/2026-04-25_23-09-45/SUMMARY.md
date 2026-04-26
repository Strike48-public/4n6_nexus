# USB Evidence Batch Test Summary

**Date:** 2026-04-25 23:29:27
**Run ID:** 2026-04-25_23-09-45

---

## Overview

- **Total Scenarios**: 5
- **Passed**: 3
- **Failed**: 1
- **Skipped**: 1

---

## Passed Scenarios

- blue_team_challenge (0s)
- m57-patents (0s)
- ransomware_2021 (0s)

---

## Failed Scenarios

- national_gallery_2012 (exit 2)

---

## Skipped Scenarios

- insider_threat_2022 (missing evidence)

---

## Detailed Results

Individual scenario results are saved in:
`/home/sansforensics/batch-test-results/2026-04-25_23-09-45/`

Test-results with findings are saved in:
`test-results/` (timestamped directories)

---

## Next Steps

1. Review failed scenarios: `cat /home/sansforensics/batch-test-results/2026-04-25_23-09-45/*.log | grep ERROR`
2. Check detailed findings: `find test-results/ -name "findings.json"`
3. Generate aggregate report: `python -m sift_find_evil.cli review --results-dir test-results/`

