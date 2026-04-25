"""Save scenario harness results to timestamped directories.

This module extends the scenario harness to save structured results for regression testing.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from tests.scenario_harness import ScenarioExpectation, ScenarioResult, run_scenario


def save_scenario_results(
    result: ScenarioResult,
    expectation: ScenarioExpectation,
    findings: list[Any],
    output_dir: Path,
    metadata: dict[str, Any] | None = None,
) -> Path:
    """Save scenario results to a timestamped directory.

    Args:
        result: ScenarioResult from running the scenario
        expectation: ScenarioExpectation that was executed
        findings: List of Finding objects detected
        output_dir: Base output directory (e.g., test-results/real)
        metadata: Optional metadata dict (duration, entry counts, etc.)

    Returns:
        Path to the created timestamped directory
    """
    timestamp = datetime.now()
    timestamp_str = timestamp.strftime("%Y-%m-%d_%H-%M-%S")

    # Create timestamped directory
    scenario_dir = output_dir / expectation.name / timestamp_str
    scenario_dir.mkdir(parents=True, exist_ok=True)

    # Save findings as JSON
    findings_data = [f.to_dict() for f in findings]
    findings_path = scenario_dir / "findings.json"
    with findings_path.open("w", encoding="utf-8") as f:
        json.dump(findings_data, f, indent=2)

    # Save metadata
    metadata_dict = metadata or {}
    metadata_dict.update(
        {
            "timestamp": timestamp.isoformat(),
            "scenario_name": expectation.name,
            "scenario_description": expectation.description,
            "findings_count": result.findings_count,
            "detected_executables": result.detected_executables,
            "true_positives": result.true_positives,
            "false_positives": result.false_positives,
            "false_negatives": result.false_negatives,
            "precision": result.precision,
            "recall": result.recall,
            "f1": result.f1,
            "average_confidence": result.average_confidence,
        }
    )

    metadata_path = scenario_dir / "metadata.json"
    with metadata_path.open("w", encoding="utf-8") as f:
        json.dump(metadata_dict, f, indent=2)

    # Save summary report
    summary_lines = [
        f"# {expectation.name} - {timestamp_str}",
        "",
        "## Metrics",
        "",
        f"- **Precision**: {result.precision:.3f}",
        f"- **Recall**: {result.recall:.3f}",
        f"- **F1 Score**: {result.f1:.3f}",
        f"- **Average Confidence**: {result.average_confidence:.3f}",
        f"- **Total Findings**: {result.findings_count}",
        "",
        "## Detection Results",
        "",
        f"- **True Positives**: {len(result.true_positives)}",
        f"- **False Positives**: {len(result.false_positives)}",
        f"- **False Negatives**: {len(result.false_negatives)}",
        "",
        "## Detected Executables",
        "",
    ]

    if result.detected_executables:
        for exe in sorted(set(result.detected_executables)):
            tp_marker = " (TP)" if exe in result.true_positives else ""
            fp_marker = " (FP)" if exe in result.false_positives else ""
            summary_lines.append(f"- `{exe}`{tp_marker}{fp_marker}")
    else:
        summary_lines.append("(none)")

    summary_lines.extend(
        [
            "",
            "## False Negatives",
            "",
        ]
    )

    if result.false_negatives:
        for exe in sorted(result.false_negatives):
            summary_lines.append(f"- `{exe}`")
    else:
        summary_lines.append("(none)")

    summary_path = scenario_dir / "SUMMARY.md"
    with summary_path.open("w", encoding="utf-8") as f:
        f.write("\n".join(summary_lines))

    return scenario_dir


def run_and_save_scenario(
    expectation: ScenarioExpectation,
    output_dir: Path,
    metadata: dict[str, Any] | None = None,
) -> tuple[ScenarioResult, Path]:
    """Run a scenario and save results to timestamped directory.

    Args:
        expectation: Scenario to run
        output_dir: Base output directory
        metadata: Optional metadata

    Returns:
        Tuple of (ScenarioResult, output_directory_path)
    """
    import time

    start_time = time.time()
    result = run_scenario(expectation)
    duration = time.time() - start_time

    # Merge duration into metadata
    full_metadata = metadata or {}
    full_metadata["duration_seconds"] = duration

    # Get findings from the scenario run
    # Note: We need to re-run to get the Finding objects since run_scenario
    # only returns ScenarioResult with detection counts
    from tests.scenario_harness import (
        EventLogParser,
        MFTParser,
        PrefetchParser,
        SelfCorrectionEngine,
    )

    directory = expectation.directory
    findings = []

    # Run detection to get Finding objects
    if (
        expectation.mft_fixture
        and expectation.prefetch_fixture
        and expectation.evtx_fixture
    ):
        mft = MFTParser().parse_csv(directory / expectation.mft_fixture)
        prefetch = PrefetchParser().parse_csv(directory / expectation.prefetch_fixture)
        evtx = EventLogParser().parse_csv(
            directory / expectation.evtx_fixture, filter_event_ids=[4688]
        )
        findings = SelfCorrectionEngine().analyze(mft, prefetch, evtx)

    output_path = save_scenario_results(
        result, expectation, findings, output_dir, full_metadata
    )

    return result, output_path
