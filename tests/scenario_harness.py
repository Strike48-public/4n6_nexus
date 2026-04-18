"""Run all scenarios and compute precision / recall / F1 metrics."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sift_find_evil.parsers.evtx_parser import EventLogParser
from sift_find_evil.parsers.mft_parser import MFTParser
from sift_find_evil.parsers.prefetch_parser import PrefetchParser
from sift_find_evil.self_correction.engine import SelfCorrectionEngine


@dataclass(frozen=True)
class ScenarioExpectation:
    """Expected ground truth for a scenario."""

    name: str
    directory: str
    malicious_executables: frozenset[str]
    description: str


@dataclass
class ScenarioResult:
    """Aggregated result for one scenario."""

    name: str
    findings_count: int
    detected_executables: list[str]
    true_positives: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    false_negatives: list[str] = field(default_factory=list)
    average_confidence: float = 0.0

    @property
    def precision(self) -> float:
        """Return precision metric (TP / (TP + FP))."""
        denom = len(self.true_positives) + len(self.false_positives)
        return len(self.true_positives) / denom if denom else 1.0

    @property
    def recall(self) -> float:
        """Return recall metric (TP / (TP + FN))."""
        denom = len(self.true_positives) + len(self.false_negatives)
        return len(self.true_positives) / denom if denom else 1.0

    @property
    def f1(self) -> float:
        """Calculate F1 score (2 * precision * recall / (precision + recall))."""
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


SCENARIOS: tuple[ScenarioExpectation, ...] = (
    ScenarioExpectation(
        name="01_clean_baseline",
        directory="test_data/scenarios/01_clean_baseline",
        malicious_executables=frozenset(),
        description="Legitimate activity only - expect zero findings.",
    ),
    ScenarioExpectation(
        name="02_ransomware",
        directory="test_data/scenarios/02_ransomware",
        malicious_executables=frozenset(
            {"ransom_note.exe", "crypt_engine.exe", "persist.exe"}
        ),
        description="Three causality violations resolvable via Event ID 4688.",
    ),
    ScenarioExpectation(
        name="03_timestomping",
        directory="test_data/scenarios/03_timestomping",
        malicious_executables=frozenset({"backdoor.exe", "keylogger.exe"}),
        description="$SI backdated relative to $FN (timestomping).",
    ),
    ScenarioExpectation(
        name="04_edge_cases",
        directory="test_data/scenarios/04_edge_cases",
        malicious_executables=frozenset(
            {"just_over_tolerance.exe", "future_timestamp.exe"}
        ),
        description="Boundary tolerance and null/future timestamp handling.",
    ),
    ScenarioExpectation(
        name="05_missing_prefetch",
        directory="test_data/scenarios/05_missing_prefetch",
        malicious_executables=frozenset(
            {"data_exfil.exe", "zip_tool.exe", "cleaner.exe"}
        ),
        description="Insider with deleted Prefetch - detected via MFT/Event Log gap.",
    ),
)


def run_scenario(expectation: ScenarioExpectation, repo_root: Path) -> ScenarioResult:
    """Execute the engine for one scenario and compare to ground truth.

    Args:
        expectation: Scenario expectation with ground truth executables.
        repo_root: Root directory of the repository.

    Returns:
        ScenarioResult with findings and metrics.
    """
    directory = repo_root / expectation.directory
    mft = MFTParser().parse_csv(directory / "mft.csv")
    prefetch = PrefetchParser().parse_csv(directory / "prefetch.csv")
    evtx = EventLogParser().parse_csv(directory / "evtx.csv", filter_event_ids=[4688])

    findings = SelfCorrectionEngine().analyze(mft, prefetch, evtx)

    detected = [f.evidence.get("executable", "").lower() for f in findings]
    expected = {e.lower() for e in expectation.malicious_executables}

    tp = [name for name in detected if name in expected]
    fp = [name for name in detected if name not in expected]
    fn = [name for name in expected if name not in detected]

    avg_conf = (
        sum(f.confidence for f in findings) / len(findings) if findings else 0.0
    )

    return ScenarioResult(
        name=expectation.name,
        findings_count=len(findings),
        detected_executables=detected,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        average_confidence=avg_conf,
    )


def aggregate(results: list[ScenarioResult]) -> dict[str, Any]:
    """Compute micro-averaged precision/recall/F1 across all scenarios.

    Args:
        results: List of ScenarioResult objects.

    Returns:
        Dict with aggregated metrics.
    """
    tp = sum(len(r.true_positives) for r in results)
    fp = sum(len(r.false_positives) for r in results)
    fn = sum(len(r.false_negatives) for r in results)

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def main() -> None:
    """Run all scenarios and print aggregated metrics."""
    repo_root = Path(__file__).resolve().parent.parent
    results = [run_scenario(s, repo_root) for s in SCENARIOS]

    print(f"\n{'Scenario':<22}{'TP':>4}{'FP':>4}{'FN':>4}{'Prec':>8}{'Rec':>8}{'F1':>8}{'AvgConf':>10}")
    print("-" * 78)
    for r in results:
        print(
            f"{r.name:<22}"
            f"{len(r.true_positives):>4}"
            f"{len(r.false_positives):>4}"
            f"{len(r.false_negatives):>4}"
            f"{r.precision:>8.2f}{r.recall:>8.2f}{r.f1:>8.2f}{r.average_confidence:>10.2f}"
        )

    agg = aggregate(results)
    print("-" * 78)
    print(
        f"{'TOTAL':<22}{agg['true_positives']:>4}{agg['false_positives']:>4}"
        f"{agg['false_negatives']:>4}{agg['precision']:>8.2f}"
        f"{agg['recall']:>8.2f}{agg['f1']:>8.2f}"
    )

    report_path = repo_root / "analysis" / "scenario_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "scenarios": [
                    {
                        "name": r.name,
                        "findings_count": r.findings_count,
                        "detected": r.detected_executables,
                        "true_positives": r.true_positives,
                        "false_positives": r.false_positives,
                        "false_negatives": r.false_negatives,
                        "precision": r.precision,
                        "recall": r.recall,
                        "f1": r.f1,
                        "average_confidence": r.average_confidence,
                    }
                    for r in results
                ],
                "aggregate": agg,
            },
            handle,
            indent=2,
        )

    print(f"\nReport written to {report_path}")


if __name__ == "__main__":
    main()
