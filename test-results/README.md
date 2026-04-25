# Test Results

This directory contains timestamped test execution results for validation and auditing.

## Purpose

- **Test Isolation**: Results are separated from scenario definitions to prevent LLM bias
- **Temporal Tracking**: Each run creates a timestamped folder for comparison
- **Audit Trail**: Historical results show detection improvements over time
- **Regression Testing**: Compare runs to catch detection regressions

## Structure

```
test-results/
├── real/
│   └── <scenario_name>/
│       └── YYYY-MM-DD_HH-MM-SS/    # Timestamp of test run
│           ├── SUMMARY.md           # Overall findings
│           ├── <system_name>.md     # Per-system results
│           └── ...
└── synthetic/
    └── <scenario_name>/
        └── YYYY-MM-DD_HH-MM-SS/
```

## Workflow

1. Run analysis against a scenario
2. Results automatically saved to timestamped directory
3. Review results separately from scenario context
4. Run again later to generate new timestamped results
5. Compare runs using the regression testing framework:

```bash
# Compare two specific runs
python -m sift_find_evil.testing.compare_runs \
    --baseline test-results/real/<scenario>/2026-04-25_14-30-00 \
    --current test-results/real/<scenario>/2026-04-26_10-15-00 \
    --output test-results/comparisons/

# Or run regression test against latest baseline
python -m sift_find_evil.testing.run_regression_test --scenario <scenario_name>
```

See `sift_find_evil/testing/README.md` for detailed regression testing documentation.

## Retention Policy

- **Development**: Keep all results for audit trail
- **Before Public Release**: Remove this directory (contains evidence-specific findings)

## Current Results

### Real Scenarios

- `apt_attack_2015/` - SANS SRL-2015 APT enterprise compromise (7 systems)

### Synthetic Scenarios

(None yet)
