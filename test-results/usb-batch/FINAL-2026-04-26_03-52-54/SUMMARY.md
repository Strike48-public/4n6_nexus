# USB Evidence Batch Test Summary

**Date:** 2026-04-26 03:53:23
**Run ID:** 2026-04-26_03-52-54

---

## Overview

- **Total Scenarios**: 6
- **Passed**: 6
- **Failed**: 0
- **Skipped**: 0

---

## Passed Scenarios

- blue_team_challenge (2s)
- compromised_apt_attack (0s)
- insider_threat_2022 (1s)
- m57-patents (1s)
- national_gallery_2012 (3s)
- ransomware_2021 (21s)

---

## Failed Scenarios

(none)

---

## Skipped Scenarios

(none)

---

## Detailed Results

Individual scenario results are saved in:
`/home/sansforensics/batch-test-results/2026-04-26_03-52-54/`

Test-results with findings are saved in:
`test-results/` (timestamped directories)

---

## Next Steps

1. Review failed scenarios: `cat /home/sansforensics/batch-test-results/2026-04-26_03-52-54/*.log | grep ERROR`
2. Check detailed findings: `find test-results/ -name "findings.json"`
3. Generate aggregate report: `python -m sift_find_evil.cli review --results-dir test-results/`

