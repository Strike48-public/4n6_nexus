"""Tests for STIX 2.1 bundle export (SFE-b0om).

Guards the spec-critical invariants: spec_version lives on objects not the
bundle, indicator ids are stable UUIDv5 (idempotent re-ingest), and MITRE
techniques are referenced via external_references with source_name mitre-attack.
"""

from __future__ import annotations

import uuid

from sift_find_evil.findings import Finding, FindingCategory
from sift_find_evil.interop.stix import build_stix_bundle

_TS = "2026-01-01T00:00:00.000Z"


def _finding(evidence: dict | None = None, *, title: str = "t") -> Finding:
    return Finding(
        title=title,
        description="d",
        finding_type="indicator",
        severity="high",
        category=FindingCategory.COMMAND_AND_CONTROL,
        evidence=evidence or {},
    )


def _objs(bundle: dict, stix_type: str) -> list[dict]:
    return [o for o in bundle["objects"] if o["type"] == stix_type]


# --- bundle shape -----------------------------------------------------------


def test_bundle_has_type_and_uuid4_id_and_objects() -> None:
    bundle = build_stix_bundle([_finding({"dst_ip": "8.8.8.8"})], timestamp=_TS)
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    # bundle id is a valid uuid4-suffixed id
    uuid.UUID(bundle["id"].split("--", 1)[1])
    assert isinstance(bundle["objects"], list)


def test_spec_version_on_objects_not_bundle() -> None:
    # STIX 2.1 moved spec_version off the bundle onto each object.
    bundle = build_stix_bundle([_finding({"dst_ip": "8.8.8.8"})], timestamp=_TS)
    assert "spec_version" not in bundle
    for obj in bundle["objects"]:
        assert obj["spec_version"] == "2.1"


def test_empty_findings_yield_valid_empty_bundle() -> None:
    bundle = build_stix_bundle([], timestamp=_TS)
    assert bundle["type"] == "bundle"
    assert bundle["objects"] == []


# --- indicators -------------------------------------------------------------


def test_ipv4_indicator_pattern() -> None:
    bundle = build_stix_bundle([_finding({"dst_ip": "8.8.8.8"})], timestamp=_TS)
    (ind,) = _objs(bundle, "indicator")
    assert ind["pattern"] == "[ipv4-addr:value = '8.8.8.8']"
    assert ind["pattern_type"] == "stix"
    assert ind["id"].startswith("indicator--")
    assert ind["valid_from"] == _TS


def test_sha256_indicator_pattern() -> None:
    h = "a" * 64
    bundle = build_stix_bundle([_finding({"sha256": h})], timestamp=_TS)
    (ind,) = _objs(bundle, "indicator")
    assert ind["pattern"] == f"[file:hashes.'SHA-256' = '{h}']"


def test_domain_indicator_pattern() -> None:
    bundle = build_stix_bundle(
        [_finding({"domain": "evil.example.com"})], timestamp=_TS
    )
    (ind,) = _objs(bundle, "indicator")
    assert ind["pattern"] == "[domain-name:value = 'evil.example.com']"


def test_indicator_id_is_stable_uuid5_across_calls() -> None:
    # Idempotent re-ingest: same evidence -> same indicator id, even with a
    # different build timestamp.
    a = build_stix_bundle([_finding({"dst_ip": "8.8.8.8"})], timestamp=_TS)
    b = build_stix_bundle(
        [_finding({"dst_ip": "8.8.8.8"})], timestamp="2030-06-06T06:06:06.000Z"
    )
    id_a = _objs(a, "indicator")[0]["id"]
    id_b = _objs(b, "indicator")[0]["id"]
    assert id_a == id_b


def test_different_iocs_get_different_ids() -> None:
    bundle = build_stix_bundle(
        [_finding({"dst_ip": "8.8.8.8"}), _finding({"dst_ip": "1.1.1.1"})],
        timestamp=_TS,
    )
    ids = {o["id"] for o in _objs(bundle, "indicator")}
    assert len(ids) == 2


# --- attack-pattern + relationship ------------------------------------------


def test_confirmed_technique_becomes_attack_pattern_with_external_ref() -> None:
    findings = [_finding({"dst_ip": "8.8.8.8", "mitre_attack": ["T1071"]})]
    bundle = build_stix_bundle(findings, timestamp=_TS)
    (ap,) = _objs(bundle, "attack-pattern")
    ref = ap["external_references"][0]
    assert ref["source_name"] == "mitre-attack"
    assert ref["external_id"] == "T1071"
    assert ap["id"].startswith("attack-pattern--")


def test_indicator_links_to_attack_pattern_via_indicates_relationship() -> None:
    findings = [_finding({"dst_ip": "8.8.8.8", "mitre_attack": ["T1071"]})]
    bundle = build_stix_bundle(findings, timestamp=_TS)
    ind_id = _objs(bundle, "indicator")[0]["id"]
    ap_id = _objs(bundle, "attack-pattern")[0]["id"]
    (rel,) = _objs(bundle, "relationship")
    assert rel["relationship_type"] == "indicates"
    assert rel["source_ref"] == ind_id
    assert rel["target_ref"] == ap_id


def test_invalid_mitre_id_is_dropped_by_guardrail() -> None:
    # The guardrail rejects malformed ids, so no attack-pattern is emitted.
    findings = [_finding({"dst_ip": "8.8.8.8", "mitre_attack": ["not-a-technique"]})]
    bundle = build_stix_bundle(findings, timestamp=_TS)
    assert _objs(bundle, "attack-pattern") == []


def test_subtechnique_url_uses_slash() -> None:
    findings = [_finding({"sha256": "a" * 64, "mitre_attack": ["T1070.006"]})]
    bundle = build_stix_bundle(findings, timestamp=_TS)
    (ap,) = _objs(bundle, "attack-pattern")
    assert ap["external_references"][0]["url"].endswith("/techniques/T1070/006")


def test_accepts_dict_shaped_findings() -> None:
    bundle = build_stix_bundle(
        [{"title": "t", "evidence": {"dst_ip": "8.8.8.8"}}], timestamp=_TS
    )
    assert len(_objs(bundle, "indicator")) == 1


def test_md5_only_indicator_pattern() -> None:
    m = "b" * 32
    bundle = build_stix_bundle([_finding({"md5": m})], timestamp=_TS)
    (ind,) = _objs(bundle, "indicator")
    assert ind["pattern"] == f"[file:hashes.MD5 = '{m}']"


def test_ipv6_indicator_pattern() -> None:
    bundle = build_stix_bundle(
        [_finding({"dst_ip": "2001:4860:4860::8888"})], timestamp=_TS
    )
    (ind,) = _objs(bundle, "indicator")
    assert ind["pattern"] == "[ipv6-addr:value = '2001:4860:4860::8888']"


def test_default_timestamp_is_rfc3339_z() -> None:
    # No fixed timestamp -> current UTC, formatted with a trailing Z.
    bundle = build_stix_bundle([_finding({"dst_ip": "8.8.8.8"})])
    ind = _objs(bundle, "indicator")[0]
    assert ind["created"].endswith("Z")
    assert ind["created"][4] == "-" and ind["created"][10] == "T"


# --- per-finding relationships (no false cross-product) ---------------------


def test_relationships_are_per_finding_not_cross_product() -> None:
    # Finding A: exfil IP + T1041. Finding B: persistence hash + T1547.
    # The IP must NOT be linked to T1547, nor the hash to T1041.
    findings = [
        _finding({"dst_ip": "8.8.8.8", "mitre_attack": ["T1041"]}, title="exfil"),
        _finding({"sha256": "a" * 64, "mitre_attack": ["T1547"]}, title="persist"),
    ]
    bundle = build_stix_bundle(findings, timestamp=_TS)
    id_by_ext = {
        o["external_references"][0]["external_id"]: o["id"]
        for o in _objs(bundle, "attack-pattern")
    }
    ind_by_pattern = {o["pattern"]: o["id"] for o in _objs(bundle, "indicator")}
    ip_id = ind_by_pattern["[ipv4-addr:value = '8.8.8.8']"]
    hash_id = ind_by_pattern["[file:hashes.'SHA-256' = '" + "a" * 64 + "']"]
    pairs = {(r["source_ref"], r["target_ref"]) for r in _objs(bundle, "relationship")}

    # Exactly the two true relationships, and nothing crossed over.
    assert (ip_id, id_by_ext["T1041"]) in pairs
    assert (hash_id, id_by_ext["T1547"]) in pairs
    assert (ip_id, id_by_ext["T1547"]) not in pairs
    assert (hash_id, id_by_ext["T1041"]) not in pairs
    assert len(pairs) == 2


def test_indicator_deduped_across_findings() -> None:
    # Same IOC in two findings -> one indicator object, ids stable.
    findings = [_finding({"dst_ip": "8.8.8.8"}), _finding({"dst_ip": "8.8.8.8"})]
    bundle = build_stix_bundle(findings, timestamp=_TS)
    assert len(_objs(bundle, "indicator")) == 1


# --- IOC-less findings still represented (STIX/OCSF/Wazuh parity) -----------


def test_iocless_finding_with_subject_emits_file_and_observed_data() -> None:
    # A timestomp on a local file: no IP/hash/domain, no MITRE -> still represented.
    findings = [
        _finding(
            {"executable": "evil.exe"},
            title="timestomp",
        )
    ]
    # Give it a non-C2 category so it is clearly not IOC-bearing.
    findings[0].category = FindingCategory.TIMELINE_TAMPERING
    bundle = build_stix_bundle(findings, timestamp=_TS)
    assert _objs(bundle, "indicator") == []
    (file_sco,) = _objs(bundle, "file")
    # The FULL name, not canonical_entity's 14-char EPROCESS-truncated form.
    assert file_sco["name"] == "evil.exe"
    (observed,) = _objs(bundle, "observed-data")
    assert observed["object_refs"] == [file_sco["id"]]
    assert observed["number_observed"] == 1


def test_iocless_file_sco_name_is_not_truncated() -> None:
    # A >14-char name must appear in full on the file SCO (canonical_entity would
    # clip it to the EPROCESS boundary; a disk file SCO wants the real name).
    f = _finding({"executable": r"C:\Users\a\ransom_note.exe"}, title="ts")
    f.category = FindingCategory.TIMELINE_TAMPERING
    bundle = build_stix_bundle([f], timestamp=_TS)
    (file_sco,) = _objs(bundle, "file")
    assert file_sco["name"] == "ransom_note.exe"


def test_iocless_subjectless_finding_emits_custom_sdo() -> None:
    # No IOC, no technique, no subject name -> a custom x-4n6nexus-finding SDO,
    # so the finding never vanishes from STIX. Confidence is carried through.
    findings = [
        {"title": "vague signal", "description": "d", "evidence": {}, "confidence": 0.5}
    ]
    bundle = build_stix_bundle(findings, timestamp=_TS)
    (sdo,) = _objs(bundle, "x-4n6nexus-finding")
    assert sdo["name"] == "vague signal"
    assert sdo["confidence"] == 50


def test_iocless_finding_id_is_stable() -> None:
    findings = [{"title": "vague signal", "evidence": {}}]
    a = build_stix_bundle(findings, timestamp=_TS)
    b = build_stix_bundle(findings, timestamp="2030-01-01T00:00:00.000Z")
    assert (
        _objs(a, "x-4n6nexus-finding")[0]["id"]
        == _objs(b, "x-4n6nexus-finding")[0]["id"]
    )


def test_finding_with_non_dict_evidence_falls_back_to_custom_sdo() -> None:
    # Defensive: a finding whose evidence is not a mapping names no subject, so it
    # must fall back to the custom SDO rather than crash or vanish.
    findings = [{"title": "weird", "evidence": None}]
    bundle = build_stix_bundle(findings, timestamp=_TS)
    (sdo,) = _objs(bundle, "x-4n6nexus-finding")
    assert sdo["name"] == "weird"


# --- confidence + indicator_types -------------------------------------------


def test_indicator_carries_confidence_0_100() -> None:
    f = _finding({"dst_ip": "8.8.8.8"})
    f.confidence = 0.9
    bundle = build_stix_bundle([f], timestamp=_TS)
    assert _objs(bundle, "indicator")[0]["confidence"] == 90


def test_malicious_category_indicator_type() -> None:
    bundle = build_stix_bundle([_finding({"dst_ip": "8.8.8.8"})], timestamp=_TS)
    assert _objs(bundle, "indicator")[0]["indicator_types"] == ["malicious-activity"]


def test_analysis_gap_is_anomalous_not_malicious() -> None:
    # An ANALYSIS_GAP is a tooling limitation, not attacker behavior -> it must
    # not be asserted as malicious-activity.
    f = _finding({"dst_ip": "8.8.8.8"})
    f.category = FindingCategory.ANALYSIS_GAP
    bundle = build_stix_bundle([f], timestamp=_TS)
    assert _objs(bundle, "indicator")[0]["indicator_types"] == ["anomalous-activity"]
