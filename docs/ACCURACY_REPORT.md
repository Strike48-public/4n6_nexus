# Accuracy Report

Automated evaluation of the self-correction engine against five synthetic scenarios.

## How to reproduce

```bash
PYTHONPATH=. python tests/scenario_harness.py
```

Writes a machine-readable summary to `analysis/scenario_report.json`.

## Results

| Scenario | Expected | Detected | TP | FP | FN | Precision | Recall | F1 | Avg Confidence |
|----------|----------|----------|----|----|----|-----------|--------|----|----------------|
| 01_clean_baseline | 0 | 0 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 | n/a |
| 02_ransomware | 3 | 3 | 3 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.75 |
| 03_timestomping | 2 | 2 | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.35 |
| 04_edge_cases | 2 | 2 | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.72 |
| 05_missing_prefetch | 3 | 3 | 3 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.60 |
| **Aggregate** | **10** | **10** | **10** | **0** | **0** | **1.00** | **1.00** | **1.00** | - |

## Observations

- **Clean baseline** produces zero findings, confirming the engine does not raise false alarms on legitimate activity.
- **Ransomware** causality violations are all detected and resolved via Event ID 4688, moving confidence from 0.45 (contradiction) to 0.75 (resolved).
- **Timestomping** findings land at 0.35 confidence because the $SI/$FN discrepancy is a critical red flag with no Event Log tiebreaker path; this is the intended behavior.
- **Edge cases** validate the 5-minute tolerance window (a 4-minute gap produces no finding, a 6-minute gap does) and the Windows-epoch null-skip.
- **Missing prefetch** scenario exercises the "executable in MFT + Event Log but no Prefetch" detector.

## Caveats

- Scenarios are synthetic CSVs, not real forensic images. They validate the detection logic end-to-end but do not measure performance on adversarial real-world noise.
- The harness currently scores at the executable level. A finer-grained comparison (per contradiction) is future work.
- Timestomping currently only fires when a matching Prefetch entry exists; DLL-only timestomping is not yet detected.
