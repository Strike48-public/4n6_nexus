"""Run all scenarios and compute precision / recall / F1 metrics.

Scenarios are discovered automatically from ``scenarios/**/scenario.yaml``
manifests that declare ``fixtures.mft``, ``fixtures.prefetch``, and
``fixtures.evtx`` inputs. Manifests without those fixtures (for example E01
or PCAP scenarios in ``real/`` and ``training/``) are skipped here because
they require disk-level parsing outside this harness.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sift_find_evil.parsers.evtx_parser import EventLogParser
from sift_find_evil.parsers.mft_parser import MFTParser
from sift_find_evil.parsers.prefetch_parser import PrefetchParser
from sift_find_evil.self_correction.engine import SelfCorrectionEngine


@dataclass(frozen=True)
class ScenarioExpectation:
    """Expected ground truth for a scenario."""

    name: str
    directory: Path
    malicious_executables: frozenset[str]
    description: str
    mft_fixture: str
    prefetch_fixture: str
    evtx_fixture: str


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


def discover_scenarios(repo_root: Path) -> list[ScenarioExpectation]:
    """Discover scenarios by loading every ``scenario.yaml`` under ``scenarios/``.

    Only scenarios that expose ``fixtures.mft``, ``fixtures.prefetch`` and
    ``fixtures.evtx`` (i.e. CSV-driven synthetic fixtures) are returned; disk
    image-based scenarios need a different runner.
    """
    scenarios_dir = repo_root / "scenarios"
    expectations: list[ScenarioExpectation] = []

    for manifest_path in sorted(scenarios_dir.glob("**/scenario.yaml")):
        # Skip schema reference file (scenarios/_schemas/scenario.yaml)
        if "_schemas" in manifest_path.parts:
            continue

        with manifest_path.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}

        fixtures = data.get("fixtures") or {}
        mft_fixture = fixtures.get("mft")
        prefetch_fixture = fixtures.get("prefetch")
        evtx_fixture = fixtures.get("evtx")
        if not (mft_fixture and prefetch_fixture and evtx_fixture):
            continue

        expected = data.get("expected") or {}
        malicious = expected.get("malicious_executables") or []

        # Skip scenarios whose ground truth is non-executable (e.g. webmail
        # exfiltration) — those need a dedicated harness that inspects other
        # finding categories.
        finding_counts = expected.get("finding_counts") or {}
        total_expected = finding_counts.get("total", 0)
        if total_expected and not malicious:
            continue

        expectations.append(
            ScenarioExpectation(
                name=data.get("name") or manifest_path.parent.name,
                directory=manifest_path.parent,
                malicious_executables=frozenset(str(m).lower() for m in malicious),
                description=str(data.get("description") or "").strip(),
                mft_fixture=str(mft_fixture),
                prefetch_fixture=str(prefetch_fixture),
                evtx_fixture=str(evtx_fixture),
            )
        )

    return expectations


def run_scenario(expectation: ScenarioExpectation) -> ScenarioResult:
    """Execute the engine for one scenario and compare to ground truth."""
    directory = expectation.directory
    mft = MFTParser().parse_csv(directory / expectation.mft_fixture)
    prefetch = PrefetchParser().parse_csv(directory / expectation.prefetch_fixture)
    evtx = EventLogParser().parse_csv(
        directory / expectation.evtx_fixture, filter_event_ids=[4688]
    )

    findings = SelfCorrectionEngine().analyze(mft, prefetch, evtx)

    detected = [f.evidence.get("executable", "").lower() for f in findings]
    expected = set(expectation.malicious_executables)

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
    """Compute micro-averaged precision/recall/F1 across all scenarios."""
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
    scenarios = discover_scenarios(repo_root)
    results = [run_scenario(s) for s in scenarios]

    print(
        f"\n{'Scenario':<26}{'TP':>4}{'FP':>4}{'FN':>4}"
        f"{'Prec':>8}{'Rec':>8}{'F1':>8}{'AvgConf':>10}"
    )
    print("-" * 82)
    for r in results:
        print(
            f"{r.name:<26}"
            f"{len(r.true_positives):>4}"
            f"{len(r.false_positives):>4}"
            f"{len(r.false_negatives):>4}"
            f"{r.precision:>8.2f}{r.recall:>8.2f}{r.f1:>8.2f}{r.average_confidence:>10.2f}"
        )

    agg = aggregate(results)
    print("-" * 82)
    print(
        f"{'TOTAL':<26}{agg['true_positives']:>4}{agg['false_positives']:>4}"
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
