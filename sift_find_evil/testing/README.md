# Regression Testing Framework

Tools for comparing test results between runs to detect regressions in detection capabilities.

## Overview

The regression testing framework allows you to:

1. Save structured test results in timestamped directories
2. Compare two test runs to identify changes
3. Detect detection capability regressions
4. Track improvements over time

## Directory Structure

```
test-results/
├── real/
│   └── apt_attack_2015/
│       ├── 2026-04-25_14-30-00/    # Baseline run
│       │   ├── findings.json       # Structured Finding objects
│       │   ├── metadata.json       # Metrics, duration, counts
│       │   └── SUMMARY.md          # Human-readable summary
│       └── 2026-04-26_10-15-00/    # Current run
│           └── ...
└── comparisons/
    └── apt_attack_2015_2026-04-25_vs_2026-04-26.md  # Comparison report
```

## Usage

### 1. Run Regression Test (Recommended)

Compare current run to latest baseline:

```bash
python -m sift_find_evil.testing.run_regression_test --scenario apt_attack_2015
```

Specify a specific baseline:

```bash
python -m sift_find_evil.testing.run_regression_test \\
    --scenario apt_attack_2015 \\
    --baseline test-results/real/apt_attack_2015/2026-04-25_14-30-00
```

Run all scenarios with baselines:

```bash
python -m sift_find_evil.testing.run_regression_test --all
```

### 2. Compare Existing Runs

If you already have two timestamped runs saved:

```bash
python -m sift_find_evil.testing.compare_runs \\
    --baseline test-results/real/apt_attack_2015/2026-04-25_14-30-00 \\
    --current test-results/real/apt_attack_2015/2026-04-26_10-15-00 \\
    --output test-results/comparisons/
```

### 3. Save Results Manually

If you want to save results from a custom scenario run:

```python
from pathlib import Path
from tests.scenario_harness import discover_scenarios
from sift_find_evil.testing.save_results import run_and_save_scenario

repo_root = Path.cwd()
scenarios = discover_scenarios(repo_root)
expectation = scenarios[0]  # Pick a scenario

output_dir = repo_root / "test-results" / "real"
result, output_path = run_and_save_scenario(expectation, output_dir)

print(f"Results saved to: {output_path}")
print(f"F1 Score: {result.f1:.3f}")
```

## Comparison Report

The comparison report includes:

### Summary Table

| Metric | Baseline | Current | Delta |
|--------|----------|---------|-------|
| Total Findings | 150 | 155 | +5 |
| CRITICAL | 71 | 73 | +2 |
| HIGH | 3 | 3 | 0 |
| Avg Confidence | 0.875 | 0.882 | +0.007 |

### Regression Warnings

- **Missed Detections** - Attacks detected in baseline but not in current run
- **Confidence Drops** - Findings with >10% confidence decrease
- **Lost Coverage** - ATT&CK techniques no longer detected

### Improvements

- **New Detections** - Additional attacks found in current run
- **New Techniques** - Additional ATT&CK techniques covered
- **Confidence Gains** - Findings with increased confidence

### Detailed Changes

- Severity changes (e.g., MEDIUM → HIGH)
- Confidence deltas for all matching findings

## What Gets Flagged as Regression

### Critical Regressions

- **Missed detections** - Any attack detected in baseline but not in current
- **Significant confidence drops** - Any finding with >10% confidence decrease

### Warnings

- **Lost ATT&CK coverage** - Techniques detected in baseline but not current
- **Severity downgrades** - Findings moving from higher to lower severity

### Not Regressions

- New detections (improvements)
- Confidence increases
- Small confidence changes (<5%)
- Severity upgrades

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Regression Tests

on:
  pull_request:
    branches: [main]

jobs:
  regression:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.12'
      - name: Install dependencies
        run: pip install -e .
      - name: Run regression tests
        run: |
          python -m sift_find_evil.testing.run_regression_test --all
```

### Pre-commit Hook

Add to `.git/hooks/pre-commit`:

```bash
#!/bin/bash
# Run regression tests before commit
python -m sift_find_evil.testing.run_regression_test --all || {
    echo "⚠️  Regression tests failed"
    echo "Review reports in test-results/comparisons/"
    exit 1
}
```

## Metrics Tracked

### Detection Metrics

- **Findings count** - Total number of detections
- **Severity distribution** - CRITICAL/HIGH/MEDIUM/LOW/INFO breakdown
- **Confidence scores** - Average and per-finding confidence
- **ATT&CK coverage** - Unique techniques detected

### Comparison Metrics

- **True/False Positives** - Detection accuracy
- **Precision/Recall/F1** - Statistical measures
- **New vs. missed detections** - Change tracking
- **Confidence deltas** - Per-finding confidence changes

## Best Practices

### Establishing Baselines

1. Run scenarios against known-good evidence
2. Review results manually to ensure accuracy
3. Save as baseline when F1 = 1.00 or acceptable threshold
4. Document baseline characteristics in metadata

### Running Comparisons

1. Always compare to an established baseline
2. Review regression reports before merging code changes
3. Investigate any missed detections immediately
4. Accept new detections only after validation

### Maintaining Baselines

1. Update baselines when improving detection logic (intentional changes)
2. Keep historical baselines for audit trail
3. Document why baseline changed in commit message
4. Never silently accept regressions

### Example Workflow

```bash
# 1. Make code changes
vim sift_find_evil/detectors/...

# 2. Run regression test
python -m sift_find_evil.testing.run_regression_test --scenario apt_attack_2015

# 3. Review comparison report
cat test-results/comparisons/apt_attack_2015_*.md

# 4. If regressions found: fix and retest
# 5. If improvements found: validate and accept

# 6. If detection logic intentionally changed:
#    - Document why in commit message
#    - Latest run becomes new baseline
```

## Troubleshooting

### "No baseline found"

Create a baseline by running the scenario once:

```bash
python -m sift_find_evil.testing.save_results --scenario apt_attack_2015
```

### "Findings.json not found"

Older test results may not have structured JSON. Re-run the scenario:

```bash
python -m sift_find_evil.testing.run_regression_test --scenario apt_attack_2015
```

### False Regression Warnings

If legitimate improvements are flagged as regressions:

1. Review the comparison report details
2. Validate that changes are improvements
3. Update baseline by keeping latest run
4. Document the change in commit message

## Architecture

### Key Components

- `compare_runs.py` - Core comparison logic and report generation
- `save_results.py` - Save scenario results in structured format
- `run_regression_test.py` - CLI orchestration and workflow
- `tests/scenario_harness.py` - Underlying test execution framework

### Data Flow

```
Scenario Definition (scenario.yaml)
    ↓
Scenario Harness (run_scenario)
    ↓
Save Results (findings.json + metadata.json)
    ↓
Load Test Runs (baseline + current)
    ↓
Compare Runs (detect changes)
    ↓
Generate Report (markdown)
    ↓
Exit Code (0 = pass, 1 = regression)
```

### Finding Matching Algorithm

Findings are matched across runs using a composite key:

```python
(category, technique, executable) → unique finding
```

This allows tracking the same detection across runs even if:
- Confidence score changes
- Severity changes
- Description text changes
- Evidence metadata changes

## Extending

### Adding New Metrics

Edit `TestRun` class in `compare_runs.py`:

```python
@property
def custom_metric(self) -> float:
    """Calculate custom metric."""
    return sum(1 for f in self.findings if custom_condition(f))
```

### Custom Comparison Logic

Edit `compare_runs()` function to add new change detection:

```python
def compare_runs(baseline: TestRun, current: TestRun) -> ComparisonResult:
    # Existing comparisons...

    # Add custom comparison
    custom_changes = detect_custom_changes(baseline, current)

    return ComparisonResult(
        # ...
        custom_changes=custom_changes,
    )
```

### Alternative Report Formats

Create new report generator:

```python
def generate_json_report(comparison: ComparisonResult, output_path: Path) -> None:
    """Generate JSON comparison report."""
    report_data = {
        "baseline_timestamp": comparison.baseline.timestamp.isoformat(),
        "current_timestamp": comparison.current.timestamp.isoformat(),
        "regressions": len(comparison.missed_detections),
        "improvements": len(comparison.new_detections),
        # ... more fields
    }
    output_path.write_text(json.dumps(report_data, indent=2))
```
