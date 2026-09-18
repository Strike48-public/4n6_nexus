"""Regression guards: the webmail / cloud / yara finding_counts blocks must
score EXTRAS as false positives, not silently cap at the expected count
(SFE-3ff8).

Before this fix, the webmail_exfiltration / cloud_upload / yara_match count
blocks in BOTH scoring paths (``sift_find_evil.scenario_runner._score`` and
``tests.scenario_harness.run_scenario``) only ever added tp/fn. A detector
emitting MORE of those findings than the scenario declared would therefore
report precision=1.00, masking a precision regression. SFE-4qq5 fixed this for
the ``persistence`` block; these tests pin the same extras->fp treatment for the
remaining three categories in both harnesses.

Each test is a mutation guard: reverting the ``fp.extend(...)`` extras branch in
the harness under test turns the corresponding assertion red.
"""

from __future__ import annotations

from pathlib import Path

from sift_find_evil.findings.categories import FindingCategory
from sift_find_evil.findings.finding import Finding
from sift_find_evil.scenario_runner import ScenarioManifest, _score
from tests.scenario_harness import discover_scenarios, run_scenario

REPO_ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- #
# Fake findings                                                               #
# --------------------------------------------------------------------------- #
def _exfil_finding(exfil_type: str) -> Finding:
    """A DATA_EXFILTRATION finding tagged with the given structured exfil_type."""
    return Finding(
        title=f"{exfil_type} exfiltration",
        description="synthetic finding for scoring test",
        finding_type="behavior",
        severity="high",
        category=FindingCategory.DATA_EXFILTRATION,
        evidence={"exfil_type": exfil_type},
        confidence=0.9,
    )


def _yara_finding() -> Finding:
    """A MALWARE_CLASSIFICATION finding, as the yara block matches on."""
    return Finding(
        title="yara match",
        description="synthetic finding for scoring test",
        finding_type="indicator",
        severity="high",
        category=FindingCategory.MALWARE_CLASSIFICATION,
        evidence={"rule": "synthetic_rule"},
        confidence=0.9,
    )


def _manifest(finding_counts: dict[str, int]) -> ScenarioManifest:
    return ScenarioManifest(
        name="fp_test",
        tier="synthetic",
        directory=Path("/tmp"),
        description="",
        fixtures={},
        evidence=[],
        expected_malicious_executables=frozenset(),
        expected_finding_counts=finding_counts,
        min_precision=1.0,
        min_recall=1.0,
    )


# --------------------------------------------------------------------------- #
# scenario_runner._score (standalone / connector scoring path)                #
# --------------------------------------------------------------------------- #
def test_score_webmail_extras_count_as_false_positives() -> None:
    """Two webmail findings when one is declared -> 1 TP + 1 FP -> precision<1."""
    report = _score(
        _manifest({"webmail_exfiltration": 1}),
        findings=[],
        network_findings=[_exfil_finding("webmail"), _exfil_finding("webmail")],
        yara_findings=[],
        linux_findings=[],
    )

    assert report.true_positives.count("webmail_exfiltration") == 1
    assert report.false_positives.count("webmail_exfiltration") == 1
    assert report.precision < 1.0


def test_score_cloud_upload_extras_count_as_false_positives() -> None:
    """Two cloud uploads when one is declared -> 1 TP + 1 FP -> precision<1."""
    report = _score(
        _manifest({"cloud_upload": 1}),
        findings=[],
        network_findings=[
            _exfil_finding("cloud_upload"),
            _exfil_finding("cloud_upload"),
        ],
        yara_findings=[],
        linux_findings=[],
    )

    assert report.true_positives.count("cloud_upload") == 1
    assert report.false_positives.count("cloud_upload") == 1
    assert report.precision < 1.0


def test_score_yara_match_extras_count_as_false_positives() -> None:
    """Two yara matches when one is declared -> 1 TP + 1 FP -> precision<1."""
    report = _score(
        _manifest({"yara_match": 1}),
        findings=[],
        network_findings=[],
        yara_findings=[_yara_finding(), _yara_finding()],
        linux_findings=[],
    )

    assert report.true_positives.count("yara_match") == 1
    assert report.false_positives.count("yara_match") == 1
    assert report.precision < 1.0


# --------------------------------------------------------------------------- #
# tests.scenario_harness.run_scenario (recall / benchmark scoring path)       #
# --------------------------------------------------------------------------- #
def _scenario(name: str):
    scenario = next((s for s in discover_scenarios(REPO_ROOT) if s.name == name), None)
    assert scenario is not None, f"{name} not discovered"
    return scenario


def test_harness_webmail_extras_count_as_false_positives(monkeypatch) -> None:
    """Over-emitting webmail findings in the recall harness scores as FP.

    06_webmail_exfiltration declares webmail_exfiltration: 1; force the network
    detector to emit two so the surplus must show up as a false positive.
    """
    from sift_find_evil.detectors import NetworkDetector

    monkeypatch.setattr(
        NetworkDetector,
        "analyze",
        lambda self, **kwargs: [
            _exfil_finding("webmail"),
            _exfil_finding("webmail"),
        ],
    )
    result = run_scenario(_scenario("06_webmail_exfiltration"))

    assert result.false_positives.count("webmail_exfiltration") == 1
    assert result.precision < 1.0


def test_harness_cloud_upload_extras_count_as_false_positives(monkeypatch) -> None:
    """Over-emitting cloud uploads in the recall harness scores as FP."""
    from sift_find_evil.detectors import NetworkDetector

    monkeypatch.setattr(
        NetworkDetector,
        "analyze",
        lambda self, **kwargs: [
            _exfil_finding("cloud_upload"),
            _exfil_finding("cloud_upload"),
        ],
    )
    result = run_scenario(_scenario("07_cloud_upload"))

    assert result.false_positives.count("cloud_upload") == 1
    assert result.precision < 1.0


def test_harness_yara_match_extras_count_as_false_positives(monkeypatch) -> None:
    """Over-emitting yara matches in the recall harness scores as FP.

    11_yara_malware declares yara_match: 1; force the yara runner to emit two.
    """
    import tests.scenario_harness as harness

    monkeypatch.setattr(
        harness,
        "_run_yara_for_scenario",
        lambda expectation: [_yara_finding(), _yara_finding()],
    )
    result = run_scenario(_scenario("11_yara_malware"))

    assert result.false_positives.count("yara_match") == 1
    assert result.precision < 1.0
