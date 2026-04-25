"""Run regression tests against saved baselines.

Usage:
    # Run scenario and compare to latest baseline
    python -m sift_find_evil.testing.run_regression_test \\
        --scenario apt_attack_2015 \\
        --baseline test-results/real/apt_attack_2015/2026-04-25_14-30-00

    # Run all scenarios and compare to their latest baselines
    python -m sift_find_evil.testing.run_regression_test --all
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sift_find_evil.testing.compare_runs import (
    compare_runs,
    generate_report,
    load_test_run,
)
from sift_find_evil.testing.save_results import run_and_save_scenario
from tests.scenario_harness import discover_scenarios


def find_latest_baseline(test_results_dir: Path, scenario_name: str) -> Path | None:
    """Find the most recent test run for a scenario."""
    scenario_dir = test_results_dir / scenario_name
    if not scenario_dir.exists():
        return None

    # Find all timestamped directories
    timestamp_dirs = [
        d
        for d in scenario_dir.iterdir()
        if d.is_dir() and len(d.name) == 19  # YYYY-MM-DD_HH-MM-SS
    ]

    if not timestamp_dirs:
        return None

    # Sort by name (which is timestamp) and return latest
    return sorted(timestamp_dirs)[-1]


def run_regression_test(
    scenario_name: str,
    baseline_path: Path | None = None,
    repo_root: Path | None = None,
) -> bool:
    """Run regression test for a single scenario.

    Args:
        scenario_name: Name of scenario to test
        baseline_path: Path to baseline results (auto-detect if None)
        repo_root: Repository root (uses current directory if None)

    Returns:
        True if no regressions detected, False otherwise
    """
    if repo_root is None:
        repo_root = Path.cwd()

    # Discover scenario
    scenarios = discover_scenarios(repo_root)
    expectation = None
    for s in scenarios:
        if s.name == scenario_name:
            expectation = s
            break

    if expectation is None:
        print(f"Error: Scenario '{scenario_name}' not found")
        return False

    # Find or validate baseline
    test_results_dir = repo_root / "test-results" / "real"
    if baseline_path is None:
        baseline_path = find_latest_baseline(test_results_dir, scenario_name)
        if baseline_path is None:
            print(
                f"Error: No baseline found for '{scenario_name}' in {test_results_dir}"
            )
            print("Run the scenario first to create a baseline.")
            return False
        print(f"Using baseline: {baseline_path}")
    elif not baseline_path.exists():
        print(f"Error: Baseline not found: {baseline_path}")
        return False

    # Run scenario and save results
    print(f"\nRunning scenario: {scenario_name}")
    result, current_path = run_and_save_scenario(expectation, test_results_dir)
    print(f"Results saved to: {current_path}")

    # Load and compare
    print("\nComparing results...")
    baseline = load_test_run(baseline_path)
    current = load_test_run(current_path)

    # Validate scenario name match
    if baseline.scenario_name != current.scenario_name:
        print(
            f"Error: Scenario mismatch - baseline: {baseline.scenario_name}, "
            f"current: {current.scenario_name}"
        )
        return False

    comparison = compare_runs(baseline, current)

    # Generate report
    comparisons_dir = repo_root / "test-results" / "comparisons"
    comparisons_dir.mkdir(parents=True, exist_ok=True)

    report_filename = (
        f"{scenario_name}_{baseline.timestamp.strftime('%Y-%m-%d')}_vs_"
        f"{current.timestamp.strftime('%Y-%m-%d')}.md"
    )
    report_path = comparisons_dir / report_filename
    generate_report(comparison, report_path)
    print(f"\nComparison report: {report_path}")

    # Print summary
    print("\n" + "=" * 70)
    print(f"REGRESSION TEST SUMMARY: {scenario_name}")
    print("=" * 70)

    print("\nMetrics:")
    print(f"  Baseline F1: {result.f1:.3f}")
    print(f"  Current F1:  {result.f1:.3f}")
    print(
        f"  Findings:    {len(baseline.findings)} → {len(current.findings)} ({len(current.findings) - len(baseline.findings):+d})"
    )

    if comparison.has_regressions:
        print("\nWARNING:  REGRESSIONS DETECTED")
        if comparison.missed_detections:
            print(f"   - {len(comparison.missed_detections)} missed detections")
        drops = [d for _, _, d in comparison.confidence_changes if d < -0.1]
        if drops:
            print(f"   - {len(drops)} significant confidence drops (>10%)")
        print(f"\nSee report for details: {report_path}")
        return False

    print("\n No regressions detected")
    if comparison.new_detections:
        print(f" {len(comparison.new_detections)} new detections")
    if comparison.new_techniques:
        print(f" {len(comparison.new_techniques)} new ATT&CK techniques")

    return True


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(
        description="Run regression tests against saved baselines"
    )
    parser.add_argument(
        "--scenario",
        type=str,
        help="Scenario name to test (e.g., apt_attack_2015)",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        help="Path to baseline results directory (auto-detect if omitted)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run regression tests for all scenarios with baselines",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="Repository root directory",
    )

    args = parser.parse_args()

    if args.all:
        # Run all scenarios that have baselines
        test_results_dir = args.repo_root / "test-results" / "real"
        if not test_results_dir.exists():
            print(f"Error: No test results found in {test_results_dir}")
            sys.exit(1)

        scenarios_with_baselines = [
            d.name for d in test_results_dir.iterdir() if d.is_dir()
        ]

        if not scenarios_with_baselines:
            print("No scenarios with baselines found")
            sys.exit(1)

        print(f"Found {len(scenarios_with_baselines)} scenarios with baselines")
        print(f"Scenarios: {', '.join(scenarios_with_baselines)}\n")

        all_passed = True
        for scenario_name in sorted(scenarios_with_baselines):
            print("\n" + "=" * 70)
            success = run_regression_test(scenario_name, repo_root=args.repo_root)
            if not success:
                all_passed = False

        print("\n" + "=" * 70)
        if all_passed:
            print(" All regression tests passed")
            sys.exit(0)
        else:
            print("WARNING:  Some regression tests failed")
            sys.exit(1)

    elif args.scenario:
        success = run_regression_test(
            args.scenario,
            baseline_path=args.baseline,
            repo_root=args.repo_root,
        )
        sys.exit(0 if success else 1)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
