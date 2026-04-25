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
5. Compare runs: `diff test-results/real/<scenario>/{old,new}/SUMMARY.md`

## Retention Policy

- **Development**: Keep all results for audit trail
- **Before Public Release**: Remove this directory (contains evidence-specific findings)

## Current Results

### Real Scenarios

- `apt_attack_2015/` - SANS SRL-2015 APT enterprise compromise (7 systems)

### Synthetic Scenarios

(None yet)
