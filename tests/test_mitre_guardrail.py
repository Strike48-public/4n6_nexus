"""Tests for the deterministic MITRE synthesis guardrail.

Validates that the CONFIRMED MITRE matrix is built ONLY from fired-detector
technique tags and that LLM free-form techniques are quarantined separately.
"""

from __future__ import annotations

from sift_find_evil.reporting.mitre_guardrail import (
    CATALOG,
    MitreReport,
    confirmed_matrix,
    synthesize,
)


def test_finding_tagged_technique_is_confirmed_with_citation() -> None:
    # Arrange
    findings = [
        {
            "title": "Suspicious RWX allocation in lsass",
            "evidence": {"mitre_attack": ["T1055"]},
        }
    ]

    # Act
    report = confirmed_matrix(findings)

    # Assert
    assert isinstance(report, MitreReport)
    assert len(report.confirmed) == 1
    entry = report.confirmed[0]
    assert entry["technique_id"] == "T1055"
    assert entry["name"] == CATALOG["T1055"]["name"]
    assert entry["tactic"] == CATALOG["T1055"]["tactic"]
    assert entry["cited_by"] == ["Suspicious RWX allocation in lsass"]
    assert report.unconfirmed == []


def test_multiple_findings_citing_same_technique_are_merged() -> None:
    # Arrange
    findings = [
        {"title": "Alpha", "evidence": {"mitre_attack": ["T1071"]}},
        {"title": "Beta", "evidence": {"mitre_attack": ["T1071"]}},
    ]

    # Act
    report = confirmed_matrix(findings)

    # Assert
    assert len(report.confirmed) == 1
    assert report.confirmed[0]["cited_by"] == ["Alpha", "Beta"]


def test_sub_technique_id_is_confirmed() -> None:
    # Arrange
    findings = [{"title": "Log clear", "evidence": {"mitre_attack": ["T1070.006"]}}]

    # Act
    report = confirmed_matrix(findings)

    # Assert
    assert report.confirmed[0]["technique_id"] == "T1070.006"


def test_malformed_technique_id_is_dropped() -> None:
    # Arrange
    findings = [{"title": "Garbage", "evidence": {"mitre_attack": ["TXYZ"]}}]

    # Act
    report = confirmed_matrix(findings)

    # Assert
    assert report.confirmed == []
    assert report.unconfirmed == []


def test_unknown_but_valid_id_is_confirmed_with_unknown_name() -> None:
    # Arrange
    findings = [{"title": "Novel", "evidence": {"mitre_attack": ["T9999"]}}]

    # Act
    report = confirmed_matrix(findings)

    # Assert
    assert len(report.confirmed) == 1
    assert report.confirmed[0]["technique_id"] == "T9999"
    assert report.confirmed[0]["name"] == "unknown"
    assert report.confirmed[0]["tactic"] == "unknown"


def test_finding_without_mitre_tag_contributes_nothing() -> None:
    # Arrange (negative control)
    findings = [{"title": "Untagged", "evidence": {}}]

    # Act
    report = confirmed_matrix(findings)

    # Assert
    assert report.confirmed == []
    assert report.unconfirmed == []


def test_synthesize_llm_technique_not_backed_goes_to_unconfirmed() -> None:
    # Arrange
    detector_findings = [{"title": "Inject", "evidence": {"mitre_attack": ["T1055"]}}]
    llm_proposed = ["T1486"]

    # Act
    report = synthesize(detector_findings, llm_proposed)

    # Assert
    confirmed_ids = {e["technique_id"] for e in report.confirmed}
    assert confirmed_ids == {"T1055"}
    assert report.unconfirmed == ["T1486"]


def test_synthesize_llm_technique_already_confirmed_is_not_duplicated() -> None:
    # Arrange (negative control: LLM echoes a confirmed technique)
    detector_findings = [{"title": "Ransom", "evidence": {"mitre_attack": ["T1486"]}}]
    llm_proposed = ["T1486"]

    # Act
    report = synthesize(detector_findings, llm_proposed)

    # Assert
    assert {e["technique_id"] for e in report.confirmed} == {"T1486"}
    assert report.unconfirmed == []


def test_synthesize_drops_malformed_llm_ids() -> None:
    # Arrange
    detector_findings: list[dict] = []
    llm_proposed = ["not-a-technique", "T1071"]

    # Act
    report = synthesize(detector_findings, llm_proposed)

    # Assert
    assert report.confirmed == []
    assert report.unconfirmed == ["T1071"]
