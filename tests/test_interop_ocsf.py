"""Tests for OCSF Detection Finding (2004) export (SFE-b0om).

Pins the class identity (2004 / type_uid formula), the severity_id enum mapping,
and required-attribute presence so an OCSF consumer accepts the events.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sift_find_evil.findings import Finding, FindingCategory
from sift_find_evil.interop.ocsf import (
    ACTIVITY_CREATE,
    CLASS_UID,
    ocsf_export,
    type_uid,
)

_REQUIRED = (
    "activity_id",
    "category_uid",
    "class_uid",
    "metadata",
    "severity_id",
    "type_uid",
    "finding_info",
)


def _finding(
    *,
    severity: str = "high",
    evidence: dict | None = None,
    confidence: float = 0.9,
    detected_at: datetime | None = None,
) -> Finding:
    return Finding(
        title="Suspicious beacon",
        description="periodic C2",
        finding_type="indicator",
        severity=severity,
        category=FindingCategory.COMMAND_AND_CONTROL,
        evidence=evidence or {},
        confidence=confidence,
        detected_at=detected_at or datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


# --- class identity ---------------------------------------------------------


def test_class_and_category_uids() -> None:
    (event,) = ocsf_export([_finding()])
    assert event["class_uid"] == 2004
    assert event["category_uid"] == 2
    assert event["activity_id"] == ACTIVITY_CREATE


def test_type_uid_equals_formula() -> None:
    # type_uid must equal class_uid*100 + activity_id, computed not hardcoded.
    (event,) = ocsf_export([_finding()])
    assert event["type_uid"] == CLASS_UID * 100 + ACTIVITY_CREATE == 200401
    assert type_uid() == 200401


def test_all_required_attributes_present() -> None:
    (event,) = ocsf_export([_finding()])
    for attr in _REQUIRED:
        assert attr in event, f"missing required OCSF attribute: {attr}"


# --- severity mapping -------------------------------------------------------


def test_severity_critical_maps_to_5() -> None:
    (event,) = ocsf_export([_finding(severity="critical")])
    assert event["severity_id"] == 5


def test_severity_high_maps_to_4() -> None:
    assert ocsf_export([_finding(severity="high")])[0]["severity_id"] == 4


def test_severity_medium_low_info() -> None:
    assert ocsf_export([_finding(severity="medium")])[0]["severity_id"] == 3
    assert ocsf_export([_finding(severity="low")])[0]["severity_id"] == 2
    assert ocsf_export([_finding(severity="info")])[0]["severity_id"] == 1


def test_unknown_severity_maps_to_0() -> None:
    (event,) = ocsf_export([_finding(severity="bogus")])
    assert event["severity_id"] == 0


# --- content ----------------------------------------------------------------


def test_time_is_epoch_millis_int() -> None:
    (event,) = ocsf_export([_finding()])
    assert isinstance(event["time"], int)
    # 2026-01-01T00:00:00Z in millis
    assert event["time"] == 1767225600000


def test_confidence_scaled_to_0_100() -> None:
    (event,) = ocsf_export([_finding(confidence=0.9)])
    assert event["confidence_score"] == 90


def test_observables_from_iocs() -> None:
    (event,) = ocsf_export([_finding(evidence={"dst_ip": "8.8.8.8"})])
    values = {o["value"] for o in event["observables"]}
    assert "8.8.8.8" in values


def test_observables_cover_domain_and_hashes() -> None:
    # Domain (type_id 1), sha256 and md5 (type_id 8) observable branches.
    (event,) = ocsf_export(
        [_finding(evidence={"domain": "evil.example.com", "sha256": "a" * 64})]
    )
    by_type = {(o["type_id"], o["value"]) for o in event["observables"]}
    assert (1, "evil.example.com") in by_type
    assert (8, "a" * 64) in by_type

    # An md5-only finding contributes an md5 hash observable.
    (md5_event,) = ocsf_export([_finding(evidence={"md5": "b" * 32})])
    assert (8, "b" * 32) in {
        (o["type_id"], o["value"]) for o in md5_event["observables"]
    }


def test_non_datetime_detected_at_omits_time() -> None:
    # A dict-shaped finding whose detected_at is a string -> no int time key.
    (event,) = ocsf_export(
        [{"title": "t", "severity": "low", "evidence": {}, "detected_at": "not-a-dt"}]
    )
    assert "time" not in event


def test_attacks_from_confirmed_technique() -> None:
    (event,) = ocsf_export([_finding(evidence={"mitre_attack": ["T1071"]})])
    techniques = {a["technique"]["uid"] for a in event["finding_info"]["attacks"]}
    assert "T1071" in techniques


def test_finding_info_uid_is_stable() -> None:
    a = ocsf_export([_finding(evidence={"dst_ip": "8.8.8.8"})])[0]
    b = ocsf_export([_finding(evidence={"dst_ip": "8.8.8.8"})])[0]
    assert a["finding_info"]["uid"] == b["finding_info"]["uid"]


def test_finding_without_iocs_has_no_observables_key() -> None:
    (event,) = ocsf_export([_finding(evidence={})])
    assert "observables" not in event


def test_empty_findings_yield_empty_list() -> None:
    assert ocsf_export([]) == []


def test_accepts_dict_shaped_finding() -> None:
    events = ocsf_export(
        [{"title": "t", "description": "", "severity": "low", "evidence": {}}]
    )
    assert events[0]["severity_id"] == 2


def test_naive_detected_at_still_serializes() -> None:
    # A naive datetime (no tzinfo) still yields an int time (local-clock millis).
    (event,) = ocsf_export([_finding(detected_at=datetime(2026, 1, 1))])
    assert isinstance(event["time"], int)
