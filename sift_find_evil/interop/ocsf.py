"""OCSF Detection Finding (class_uid 2004) export from findings (SFE-b0om).

A PURE, deterministic, read-only exporter turning each finding into an OCSF
Detection Finding event so findings can land in an OCSF-native data lake without
hand-translation. Nothing here runs on the detection path, so F1 is unaffected.

Targets OCSF schema **v1.8.0**. Each event carries the required attributes
(``activity_id``, ``category_uid``, ``class_uid``, ``metadata``, ``severity_id``,
``time``, ``type_uid``, ``finding_info``) plus recommended ``observables`` (from
extracted IOCs) and the confirmed MITRE techniques under ``finding_info.attacks``.

The ``type_uid`` is computed, never hardcoded: ``class_uid * 100 + activity_id``
(2004 * 100 + 1 = 200401 for a Create). A test pins the identity so the two can
never silently drift.

Known, deliberate simplifications for this first version (tracked as follow-ups):

  * ``status_id`` is always ``1`` (New): findings carry no lifecycle state yet, so
    a re-exported finding is still "New" rather than "In Progress"/"Resolved".
  * ANALYSIS_GAP / UNKNOWN findings (meta findings about the analysis itself, not
    attacker behavior) are still emitted as Detection Findings, at their own
    severity. A consuming SIEM that does not want "we could not decide" events
    should filter on ``finding_info`` / severity; a future ``--include-gaps``-style
    filter can suppress them at export time.
"""

from __future__ import annotations

from typing import Any, Iterable

from ..findings.dedup import fingerprint
from ..reporting.mitre_guardrail import CATALOG, confirmed_matrix
from .iocs import finding_iocs

# OCSF Detection Finding class identity (schema.ocsf.io/classes/detection_finding).
CLASS_UID = 2004
CATEGORY_UID = 2  # Findings
ACTIVITY_CREATE = 1
OCSF_SCHEMA_VERSION = "1.8.0"

# Internal severity label -> OCSF severity_id enum.
_SEVERITY_ID = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "informational": 1,
}
_SEVERITY_UNKNOWN = 0


def type_uid(activity_id: int = ACTIVITY_CREATE) -> int:
    """OCSF ``type_uid`` = ``class_uid * 100 + activity_id`` (never hardcoded)."""
    return CLASS_UID * 100 + activity_id


def _severity_id(severity: Any) -> int:
    """Map an internal severity label to the OCSF ``severity_id`` enum."""
    return _SEVERITY_ID.get(str(severity).lower(), _SEVERITY_UNKNOWN)


def _get(finding: Any, key: str, default: Any) -> Any:
    if isinstance(finding, dict):
        return finding.get(key, default)
    return getattr(finding, key, default)


def _epoch_millis(dt: Any) -> int | None:
    """Epoch milliseconds for a datetime, or None when unavailable.

    OCSF ``time`` is an integer epoch in MILLISECONDS, not an ISO string.
    """
    try:
        return int(dt.timestamp() * 1000)
    except (AttributeError, TypeError, ValueError, OSError):
        return None


def _fingerprint_uid(finding: Any) -> str:
    """A stable finding uid from the category-aware fingerprint identity."""
    fp = fingerprint(finding)
    return f"{fp.identity.kind}:{fp.identity.value}:{fp.category}"


def _observables(finding: Any) -> list[dict]:
    """OCSF observables (type_id per OCSF observable vocab) from a finding's IOCs."""
    iocs = finding_iocs(finding)
    out: list[dict] = []
    for value in iocs.ipv4 + iocs.ipv6:
        out.append(
            {"name": "device.ip", "type_id": 2, "value": value}
        )  # 2 = IP Address
    for value in iocs.domains:
        out.append(
            {"name": "device.domain", "type_id": 1, "value": value}
        )  # 1 = Hostname
    for value in iocs.sha256:
        out.append({"name": "file.hashes", "type_id": 8, "value": value})  # 8 = Hash
    for value in iocs.md5:
        out.append({"name": "file.hashes", "type_id": 8, "value": value})
    return out


def _attacks(finding_dict: dict) -> list[dict]:
    """OCSF ``attacks`` array for the techniques a single finding confirms."""
    report = confirmed_matrix([finding_dict])
    attacks: list[dict] = []
    for entry in report.confirmed:
        technique_id = str(entry["technique_id"])
        meta = CATALOG.get(technique_id, {})
        attacks.append(
            {
                "technique": {
                    "uid": technique_id,
                    "name": str(entry.get("name") or meta.get("name") or technique_id),
                },
                "version": "14",
            }
        )
    return attacks


def _to_dict(finding: Any) -> dict:
    if isinstance(finding, dict):
        return finding
    if hasattr(finding, "to_dict"):
        return finding.to_dict()
    return {"title": _get(finding, "title", ""), "evidence": {}}  # pragma: no cover


def _detection_finding(finding: Any) -> dict:
    """Build one OCSF Detection Finding event from a finding."""
    finding_dict = _to_dict(finding)
    title = str(_get(finding, "title", "") or finding_dict.get("title", ""))
    description = str(_get(finding, "description", "") or "")
    severity = _get(finding, "severity", "unknown")
    confidence = _get(finding, "confidence", None)

    finding_info: dict[str, Any] = {
        "uid": _fingerprint_uid(finding),
        "title": title or "Untitled finding",
        "desc": description,
    }
    attacks = _attacks(finding_dict)
    if attacks:
        finding_info["attacks"] = attacks

    event: dict[str, Any] = {
        "activity_id": ACTIVITY_CREATE,
        "category_uid": CATEGORY_UID,
        "class_uid": CLASS_UID,
        "type_uid": type_uid(),
        "severity_id": _severity_id(severity),
        "status_id": 1,  # New
        "metadata": {
            "product": {"name": "4n6-nexus", "vendor_name": "Strike48"},
            "version": OCSF_SCHEMA_VERSION,
        },
        "finding_info": finding_info,
        "message": title,
    }

    millis = _epoch_millis(_get(finding, "detected_at", None))
    if millis is not None:
        event["time"] = millis
    if isinstance(confidence, (int, float)):
        # OCSF confidence is a 0-100 integer; internal confidence is 0-1.
        event["confidence_score"] = int(round(float(confidence) * 100))

    observables = _observables(finding)
    if observables:
        event["observables"] = observables

    return event


def ocsf_export(findings: Iterable[Any]) -> list[dict]:
    """Export ``findings`` as a list of OCSF Detection Finding events.

    Args:
        findings: Findings (:class:`~sift_find_evil.findings.finding.Finding` or
            their ``to_dict`` mappings).

    Returns:
        One OCSF Detection Finding (class_uid 2004) dict per finding, in input
        order. An empty findings list yields an empty list.
    """
    return [_detection_finding(finding) for finding in findings]
