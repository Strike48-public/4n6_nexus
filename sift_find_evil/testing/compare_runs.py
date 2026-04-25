"""Compare test results between runs to detect regressions.

Usage:
    python -m sift_find_evil.testing.compare_runs \\
        --baseline test-results/real/apt_attack_2015/2026-04-25_14-30-00 \\
        --current test-results/real/apt_attack_2015/2026-04-26_10-15-00 \\
        --output test-results/comparisons/
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from sift_find_evil.self_correction.engine import Finding


@dataclass
class TestRun:
    """Represents a single test execution."""

    timestamp: datetime
    scenario_name: str
    directory: Path
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        """Count of CRITICAL severity findings."""
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        """Count of HIGH severity findings."""
        return sum(1 for f in self.findings if f.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        """Count of MEDIUM severity findings."""
        return sum(1 for f in self.findings if f.severity == "MEDIUM")

    @property
    def low_count(self) -> int:
        """Count of LOW severity findings."""
        return sum(1 for f in self.findings if f.severity == "LOW")

    @property
    def info_count(self) -> int:
        """Count of INFO severity findings."""
        return sum(1 for f in self.findings if f.severity == "INFO")

    @property
    def average_confidence(self) -> float:
        """Calculate average confidence score across all findings."""
        if not self.findings:
            return 0.0
        return sum(f.confidence for f in self.findings) / len(self.findings)

    @property
    def attack_techniques(self) -> set[str]:
        """Extract unique MITRE ATT&CK techniques detected."""
        techniques = set()
        for finding in self.findings:
            # Extract technique IDs from evidence or description
            if "technique" in finding.evidence:
                techniques.add(finding.evidence["technique"])
            # Also parse from description if present
            desc = finding.description.upper()
            if "T1" in desc:
                # Extract T#### pattern
                import re

                matches = re.findall(r"T\d{4}(?:\.\d{3})?", desc)
                techniques.update(matches)
        return techniques


@dataclass
class ComparisonResult:
    """Result of comparing two test runs."""

    baseline: TestRun
    current: TestRun
    new_detections: list[Finding] = field(default_factory=list)
    missed_detections: list[Finding] = field(default_factory=list)
    confidence_changes: list[tuple[Finding, Finding, float]] = field(
        default_factory=list
    )
    severity_changes: list[tuple[Finding, Finding]] = field(default_factory=list)

    @property
    def has_regressions(self) -> bool:
        """Check if any concerning regressions were detected."""
        return bool(
            self.missed_detections
            or any(delta < -0.1 for _, _, delta in self.confidence_changes)
        )

    @property
    def severity_delta(self) -> dict[str, int]:
        """Calculate change in findings by severity."""
        return {
            "CRITICAL": self.current.critical_count - self.baseline.critical_count,
            "HIGH": self.current.high_count - self.baseline.high_count,
            "MEDIUM": self.current.medium_count - self.baseline.medium_count,
            "LOW": self.current.low_count - self.baseline.low_count,
            "INFO": self.current.info_count - self.baseline.info_count,
        }

    @property
    def new_techniques(self) -> set[str]:
        """Attack techniques detected in current but not baseline."""
        return self.current.attack_techniques - self.baseline.attack_techniques

    @property
    def lost_techniques(self) -> set[str]:
        """Attack techniques detected in baseline but not current."""
        return self.baseline.attack_techniques - self.current.attack_techniques


def load_test_run(directory: Path) -> TestRun:
    """Load test results from a timestamped directory.

    Expects structure:
        test-results/real/<scenario>/<timestamp>/
            ├── findings.json        # Structured findings data
            ├── metadata.json        # Run metadata (duration, entry counts, etc.)
            └── *.md                 # Human-readable reports
    """
    if not directory.is_dir():
        raise ValueError(f"Directory not found: {directory}")

    # Parse timestamp from directory name (YYYY-MM-DD_HH-MM-SS)
    timestamp_str = directory.name
    try:
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d_%H-%M-%S")
    except ValueError as exc:
        raise ValueError(
            f"Invalid timestamp format in directory name: {timestamp_str}"
        ) from exc

    # Determine scenario name from parent directory
    scenario_name = directory.parent.name

    # Load findings if available
    findings_path = directory / "findings.json"
    findings = []
    if findings_path.exists():
        with findings_path.open(encoding="utf-8") as f:
            findings_data = json.load(f)
            findings = [Finding.from_dict(f) for f in findings_data]

    # Load metadata if available
    metadata_path = directory / "metadata.json"
    metadata = {}
    if metadata_path.exists():
        with metadata_path.open(encoding="utf-8") as f:
            metadata = json.load(f)

    return TestRun(
        timestamp=timestamp,
        scenario_name=scenario_name,
        directory=directory,
        findings=findings,
        metadata=metadata,
    )


def compare_runs(baseline: TestRun, current: TestRun) -> ComparisonResult:
    """Compare two test runs and identify changes.

    Matching strategy:
    - Findings are matched by (category, technique, executable) tuple
    - New findings: present in current but not baseline
    - Missed findings: present in baseline but not current
    - Confidence changes: same finding with different confidence score
    - Severity changes: same finding with different severity
    """

    def finding_key(f: Finding) -> tuple[str, str, str]:
        """Create a unique key for matching findings across runs."""
        technique = f.evidence.get("technique", "")
        executable = f.evidence.get("executable", "")
        return (f.category.value, technique, executable)

    baseline_map = {finding_key(f): f for f in baseline.findings}
    current_map = {finding_key(f): f for f in current.findings}

    new_detections = [f for k, f in current_map.items() if k not in baseline_map]
    missed_detections = [f for k, f in baseline_map.items() if k not in current_map]

    confidence_changes = []
    severity_changes = []

    for key in baseline_map:
        if key in current_map:
            baseline_finding = baseline_map[key]
            current_finding = current_map[key]

            # Check confidence changes
            delta = current_finding.confidence - baseline_finding.confidence
            if abs(delta) > 0.05:  # Only flag changes > 5%
                confidence_changes.append((baseline_finding, current_finding, delta))

            # Check severity changes
            if baseline_finding.severity != current_finding.severity:
                severity_changes.append((baseline_finding, current_finding))

    return ComparisonResult(
        baseline=baseline,
        current=current,
        new_detections=new_detections,
        missed_detections=missed_detections,
        confidence_changes=confidence_changes,
        severity_changes=severity_changes,
    )


def generate_report(comparison: ComparisonResult, output_path: Path) -> None:
    """Generate a markdown comparison report."""
    baseline = comparison.baseline
    current = comparison.current

    lines = [
        f"# Test Comparison Report: {baseline.scenario_name}",
        "",
        f"**Baseline:** {baseline.timestamp.strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Current:** {current.timestamp.strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Metric | Baseline | Current | Delta |",
        "|--------|----------|---------|-------|",
        f"| Total Findings | {len(baseline.findings)} | {len(current.findings)} | {len(current.findings) - len(baseline.findings):+d} |",
        f"| CRITICAL | {baseline.critical_count} | {current.critical_count} | {comparison.severity_delta['CRITICAL']:+d} |",
        f"| HIGH | {baseline.high_count} | {current.high_count} | {comparison.severity_delta['HIGH']:+d} |",
        f"| MEDIUM | {baseline.medium_count} | {current.medium_count} | {comparison.severity_delta['MEDIUM']:+d} |",
        f"| LOW | {baseline.low_count} | {current.low_count} | {comparison.severity_delta['LOW']:+d} |",
        f"| Avg Confidence | {baseline.average_confidence:.3f} | {current.average_confidence:.3f} | {current.average_confidence - baseline.average_confidence:+.3f} |",
        "",
    ]

    # Regression warnings
    if comparison.has_regressions:
        lines.extend(
            [
                "## ⚠️ REGRESSIONS DETECTED",
                "",
            ]
        )

        if comparison.missed_detections:
            lines.extend(
                [
                    f"### {len(comparison.missed_detections)} Missed Detections",
                    "",
                ]
            )
            for finding in comparison.missed_detections:
                technique = finding.evidence.get("technique", "N/A")
                executable = finding.evidence.get("executable", "N/A")
                lines.append(
                    f"- **{finding.severity}** | {technique} | `{executable}` | Confidence: {finding.confidence:.2f}"
                )
            lines.append("")

        significant_confidence_drops = [
            (b, c, d) for b, c, d in comparison.confidence_changes if d < -0.1
        ]
        if significant_confidence_drops:
            lines.extend(
                [
                    f"### {len(significant_confidence_drops)} Significant Confidence Drops (>10%)",
                    "",
                ]
            )
            for baseline_f, current_f, delta in significant_confidence_drops:
                technique = current_f.evidence.get("technique", "N/A")
                lines.append(
                    f"- {technique} | {baseline_f.confidence:.2f} → {current_f.confidence:.2f} ({delta:+.2f})"
                )
            lines.append("")

    # Improvements
    if comparison.new_detections or comparison.new_techniques:
        lines.extend(
            [
                "## ✅ Improvements",
                "",
            ]
        )

        if comparison.new_detections:
            lines.extend(
                [
                    f"### {len(comparison.new_detections)} New Detections",
                    "",
                ]
            )
            for finding in comparison.new_detections:
                technique = finding.evidence.get("technique", "N/A")
                executable = finding.evidence.get("executable", "N/A")
                lines.append(
                    f"- **{finding.severity}** | {technique} | `{executable}` | Confidence: {finding.confidence:.2f}"
                )
            lines.append("")

        if comparison.new_techniques:
            lines.extend(
                [
                    f"### {len(comparison.new_techniques)} New ATT&CK Techniques",
                    "",
                    ", ".join(sorted(comparison.new_techniques)),
                    "",
                ]
            )

    # Lost coverage
    if comparison.lost_techniques:
        lines.extend(
            [
                "## ⚠️ Lost Coverage",
                "",
                f"### {len(comparison.lost_techniques)} ATT&CK Techniques No Longer Detected",
                "",
                ", ".join(sorted(comparison.lost_techniques)),
                "",
            ]
        )

    # Severity changes
    if comparison.severity_changes:
        lines.extend(
            [
                f"## Severity Changes ({len(comparison.severity_changes)})",
                "",
                "| Technique | Baseline | Current |",
                "|-----------|----------|---------|",
            ]
        )
        for baseline_f, current_f in comparison.severity_changes:
            technique = current_f.evidence.get("technique", "N/A")
            lines.append(
                f"| {technique} | {baseline_f.severity} | {current_f.severity} |"
            )
        lines.append("")

    # Confidence changes
    if comparison.confidence_changes:
        lines.extend(
            [
                f"## Confidence Changes ({len(comparison.confidence_changes)})",
                "",
                "| Technique | Baseline | Current | Delta |",
                "|-----------|----------|---------|-------|",
            ]
        )
        for baseline_f, current_f, delta in comparison.confidence_changes:
            technique = current_f.evidence.get("technique", "N/A")
            lines.append(
                f"| {technique} | {baseline_f.confidence:.3f} | {current_f.confidence:.3f} | {delta:+.3f} |"
            )
        lines.append("")

    # Write report
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main() -> None:
    """CLI entrypoint for comparing test runs."""
    parser = argparse.ArgumentParser(
        description="Compare test results between runs to detect regressions"
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        required=True,
        help="Path to baseline test run directory",
    )
    parser.add_argument(
        "--current",
        type=Path,
        required=True,
        help="Path to current test run directory",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output directory for comparison report",
    )

    args = parser.parse_args()

    # Load test runs
    print(f"Loading baseline: {args.baseline}")
    baseline = load_test_run(args.baseline)
    print(f"  - {len(baseline.findings)} findings")

    print(f"Loading current: {args.current}")
    current = load_test_run(args.current)
    print(f"  - {len(current.findings)} findings")

    # Compare
    print("Comparing runs...")
    comparison = compare_runs(baseline, current)

    # Generate report
    report_filename = (
        f"{baseline.scenario_name}_{baseline.timestamp.strftime('%Y-%m-%d')}_vs_"
        f"{current.timestamp.strftime('%Y-%m-%d')}.md"
    )
    output_path = args.output / report_filename
    generate_report(comparison, output_path)

    print(f"\nReport generated: {output_path}")

    # Summary
    if comparison.has_regressions:
        print("\n⚠️  REGRESSIONS DETECTED")
        if comparison.missed_detections:
            print(f"   - {len(comparison.missed_detections)} missed detections")
        drops = [d for _, _, d in comparison.confidence_changes if d < -0.1]
        if drops:
            print(f"   - {len(drops)} significant confidence drops")
    else:
        print("\n✅ No regressions detected")

    if comparison.new_detections:
        print(f"✅ {len(comparison.new_detections)} new detections")


if __name__ == "__main__":
    main()
