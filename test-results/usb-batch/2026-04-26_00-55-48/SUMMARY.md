# USB Evidence Batch Test Summary

**Date:** 2026-04-26 01:00:21
**Run ID:** 2026-04-26_00-55-48

---

## Overview

- **Total Scenarios**: 5
- **Passed**: 1
- **Failed**: 0
- **Skipped**: 4

---

## Passed Scenarios

- m57-patents (0s)

---

## Failed Scenarios

(none)

---

## Skipped Scenarios

- blue_team_challenge (too large: 22GB)
- insider_threat_2022 (missing evidence)
- national_gallery_2012 (too large: 25GB)
- ransomware_2021 (too large: 50GB)

---

## Detailed Results

Individual scenario results are saved in:
`/home/sansforensics/batch-test-results/2026-04-26_00-55-48/`

Test-results with findings are saved in:
`test-results/` (timestamped directories)

---

## Next Steps

1. Review failed scenarios: `cat /home/sansforensics/batch-test-results/2026-04-26_00-55-48/*.log | grep ERROR`
2. Check detailed findings: `find test-results/ -name "findings.json"`
3. Generate aggregate report: `python -m sift_find_evil.cli review --results-dir test-results/`

