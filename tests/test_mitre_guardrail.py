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


def test_legacy_mitre_technique_key_scalar_reaches_the_matrix() -> None:
    # SFE-katy PR1: linux_persistence / usn_timestomp emit techniques under the
    # legacy scalar key `mitre_technique`, which confirmed_matrix historically
    # IGNORED (it read only `mitre_attack` as a list) - so those detectors' whole
    # ATT&CK contribution silently never reached the matrix. Normalize it in.
    findings = [
        {
            "title": "systemd service persistence",
            "evidence": {"mitre_technique": "T1543.002"},
        },
    ]

    report = confirmed_matrix(findings)

    assert [e["technique_id"] for e in report.confirmed] == ["T1543.002"]
    assert report.confirmed[0]["cited_by"] == ["systemd service persistence"]


def test_legacy_mitre_key_scalar_reaches_the_matrix() -> None:
    # lateral_movement_detector emits under the bare scalar key `mitre`.
    findings = [
        {"title": "Password spray", "evidence": {"mitre": "T1110"}},
    ]

    report = confirmed_matrix(findings)

    assert [e["technique_id"] for e in report.confirmed] == ["T1110"]


def test_newly_surfaced_techniques_resolve_to_real_catalog_names() -> None:
    # The 9 techniques the 3 legacy-key detectors emit must resolve to real
    # ATT&CK names/tactics, not the "unknown" fallback - otherwise the matrix
    # confirms an id with no human-readable meaning. Guards the CATALOG additions.
    legacy_technique_ids = [
        "T1543.002",
        "T1053.003",
        "T1574.006",
        "T1548.003",
        "T1546.004",
        "T1110",
        "T1078",
        "T1070.006",  # usn timestomp (already in CATALOG)
        "T1021",  # lateral remote services (already in CATALOG)
    ]
    findings = [
        {"title": f"det-{tid}", "evidence": {"mitre_technique": tid}}
        for tid in legacy_technique_ids
    ]

    report = confirmed_matrix(findings)

    resolved = {e["technique_id"]: e for e in report.confirmed}
    assert set(resolved) == set(legacy_technique_ids)
    for tid, entry in resolved.items():
        assert entry["name"] != "unknown", f"{tid} missing a CATALOG name"
        assert entry["tactic"] != "unknown", f"{tid} missing a CATALOG tactic"


def test_canonical_key_wins_when_multiple_mitre_keys_present() -> None:
    # If a finding somehow carries more than one MITRE key, the canonical
    # `mitre_attack` is authoritative; legacy keys are only a fallback so we never
    # double-count the same finding's techniques.
    findings = [
        {
            "title": "Both keys",
            "evidence": {"mitre_attack": ["T1055"], "mitre": "T1110"},
        },
    ]

    report = confirmed_matrix(findings)

    assert [e["technique_id"] for e in report.confirmed] == ["T1055"]


def test_legacy_scalar_and_list_mitre_attack_both_accepted() -> None:
    # Defensive: a scalar `mitre_attack` (not the documented list) must still be
    # read, so a detector that forgets the list wrapper is not silently dropped.
    findings = [{"title": "Scalar canonical", "evidence": {"mitre_attack": "T1071"}}]

    report = confirmed_matrix(findings)

    assert [e["technique_id"] for e in report.confirmed] == ["T1071"]


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
