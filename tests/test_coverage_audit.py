"""Tests for the coverage/completeness audit module.

These tests enforce the core distinction the audit exists to make:
'looked and found nothing' (covered) versus 'could not look'
(not_evaluated). Absence of findings for an unevaluated artifact class
must never be reported as 'clean'.
"""

from sift_find_evil.coverage.audit import (
    ARTIFACT_CATALOG,
    CoverageReport,
    assess_coverage,
)


def test_catalog_contains_expected_artifact_classes() -> None:
    # Arrange
    expected = {
        "mft",
        "usn",
        "amcache",
        "registry_hives",
        "prefetch",
        "lnk",
        "browser_history",
        "pcap",
        "memory",
        "security",
        "system",
        "powershell_operational",
        "dns_client",
        "sysmon",
        "task_scheduler",
    }

    # Act
    actual = set(ARTIFACT_CATALOG)

    # Assert
    assert expected <= actual
    for entry in ARTIFACT_CATALOG.values():
        assert "capability" in entry
        assert entry["importance"] in {"critical", "high", "medium"}
        assert "detecting_tool" in entry


def test_present_with_tool_run_is_covered_and_evaluated() -> None:
    # Arrange
    present = {"mft"}
    tool = ARTIFACT_CATALOG["mft"]["detecting_tool"]

    # Act
    report = assess_coverage(evidence_present=present, tools_run={tool})

    # Assert
    assert "mft" in report.covered
    assert "mft" not in report.not_evaluated
    assert report.evaluated["mft"] is True
    assert report.covered_count == 1


def test_present_without_tool_is_not_evaluated_not_clean() -> None:
    # Arrange
    present = {"mft"}

    # Act
    report = assess_coverage(evidence_present=present, tools_run=set())

    # Assert
    assert "mft" in report.not_evaluated
    assert "mft" not in report.covered
    assert report.evaluated["mft"] is False
    assert report.not_evaluated_count == 1


def test_absent_class_is_enumerated() -> None:
    # Arrange
    present: set[str] = set()

    # Act
    report = assess_coverage(evidence_present=present, tools_run=set())

    # Assert
    assert "memory" in report.absent
    assert "memory" not in report.covered
    assert "memory" not in report.not_evaluated
    assert report.evaluated["memory"] is False
    assert report.absent_count == len(ARTIFACT_CATALOG)


def test_gaps_surfaces_only_high_and_critical_unevaluated() -> None:
    # Arrange: present but no tool run for all classes.
    present = set(ARTIFACT_CATALOG)

    # Act
    report = assess_coverage(evidence_present=present, tools_run=set())

    # Assert
    gap_classes = set(report.gaps)
    assert gap_classes  # something should be gapped
    for name in gap_classes:
        assert ARTIFACT_CATALOG[name]["importance"] in {"critical", "high"}
    # A medium-importance unevaluated class is NOT a gap.
    medium = [n for n, e in ARTIFACT_CATALOG.items() if e["importance"] == "medium"]
    for name in medium:
        assert name not in gap_classes


def test_covered_class_is_never_a_gap() -> None:
    # Arrange
    present = set(ARTIFACT_CATALOG)
    tools = {e["detecting_tool"] for e in ARTIFACT_CATALOG.values()}

    # Act
    report = assess_coverage(evidence_present=present, tools_run=tools)

    # Assert
    assert report.gaps == []
    assert report.not_evaluated == []
    assert report.covered_count == len(ARTIFACT_CATALOG)


def test_to_dict_is_serializable_and_complete() -> None:
    # Arrange
    present = {"mft", "pcap"}
    tools = {ARTIFACT_CATALOG["mft"]["detecting_tool"]}

    # Act
    report = assess_coverage(
        evidence_present=present,
        tools_run=tools,
        iocs_flagged=["1.2.3.4"],
        findings_confirmed=3,
        verifications=2,
    )
    data = report.to_dict()

    # Assert
    assert isinstance(data, dict)
    assert set(data["covered"]) == {"mft"}
    assert "pcap" in data["not_evaluated"]
    assert data["covered_count"] == 1
    assert data["findings_confirmed"] == 3
    assert data["verifications"] == 2
    assert isinstance(data["evaluated"], dict)
    assert isinstance(data["gaps"], list)


def test_report_is_a_coverage_report_instance() -> None:
    # Arrange / Act
    report = assess_coverage(evidence_present=set(), tools_run=set())

    # Assert
    assert isinstance(report, CoverageReport)


def test_inputs_are_not_mutated() -> None:
    # Arrange
    present = {"mft"}
    tools = {ARTIFACT_CATALOG["mft"]["detecting_tool"]}
    iocs = ["8.8.8.8"]
    present_copy = set(present)
    tools_copy = set(tools)
    iocs_copy = list(iocs)

    # Act
    assess_coverage(
        evidence_present=present,
        tools_run=tools,
        iocs_flagged=iocs,
    )

    # Assert
    assert present == present_copy
    assert tools == tools_copy
    assert iocs == iocs_copy


def test_clean_evidence_yields_no_gaps_negative_control() -> None:
    # Arrange: a truly clean run where everything present was evaluated.
    present = {"mft", "security"}
    tools = {
        ARTIFACT_CATALOG["mft"]["detecting_tool"],
        ARTIFACT_CATALOG["security"]["detecting_tool"],
    }

    # Act
    report = assess_coverage(evidence_present=present, tools_run=tools)

    # Assert
    assert report.gaps == []
    assert report.not_evaluated == []
    assert set(report.covered) == {"mft", "security"}
