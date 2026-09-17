"""Wazuh / OpenSearch SIEM alert export from findings (SFE-b0om).

A PURE, deterministic, read-only exporter turning findings into Wazuh-shaped
alerts plus the custom rule stanzas that classify them, so findings can be
indexed into OpenSearch and correlated in Wazuh without hand-translation.
Nothing here runs on the detection path, so F1 is unaffected.

Three mappings do the work:

  * **confidence -> Wazuh level.** Wazuh rule levels run 0-15 (0 = no alert).
    Confidence bands map to 12 / 9 / 6 / 3 (high -> low), all well inside 15.
  * **MITRE technique -> stable rule_id.** Wazuh reserves rule ids below
    100000; custom rules use 100000-120000. A finding's primary confirmed
    technique (or its category, when no technique is confirmed) is hashed into
    that window deterministically, so the SAME technique always classifies to
    the SAME rule id (stable correlation across runs). Distinct techniques may
    collide within the window -- acceptable, and the rule ``<description>``
    disambiguates.
  * **fingerprint -> dedup.** Alerts are collapsed on the category-aware finding
    fingerprint, mirroring :func:`sift_find_evil.findings.dedup.dedupe_findings`,
    so a restated finding does not double-alert.
"""

from __future__ import annotations

import hashlib
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Iterable

from ..findings.dedup import fingerprint
from ..reporting.mitre_guardrail import confirmed_matrix
from .iocs import finding_iocs

# Custom Wazuh rule-id window (ids below 100000 are reserved for stock rules).
RULE_ID_MIN = 100000
RULE_ID_MAX = 120000
_RULE_ID_SPAN = RULE_ID_MAX - RULE_ID_MIN

# Confidence -> Wazuh level band (levels are 0-15; 0 means "no alert").
_LEVEL_HIGH = 12
_LEVEL_MEDIUM = 9
_LEVEL_LOW = 6
_LEVEL_MINIMAL = 3
_CONF_HIGH = 0.8
_CONF_MEDIUM = 0.6
_CONF_LOW = 0.4


@dataclass(frozen=True)
class WazuhExport:
    """The two artifacts a Wazuh integration needs.

    Attributes:
        alerts: One alert dict per (deduplicated) finding, ready to bulk-index.
        rules_xml: A ``<group>`` of custom ``<rule>`` stanzas that classify the
            alerts (levels + MITRE ids), valid Wazuh local-rules XML.
    """

    alerts: list[dict]
    rules_xml: str


def _get(finding: Any, key: str, default: Any) -> Any:
    if isinstance(finding, dict):
        return finding.get(key, default)
    return getattr(finding, key, default)


def _to_dict(finding: Any) -> dict:
    if isinstance(finding, dict):
        return finding
    if hasattr(finding, "to_dict"):
        return finding.to_dict()
    return {"title": _get(finding, "title", ""), "evidence": {}}  # pragma: no cover


def _level_for(confidence: Any) -> int:
    """Map a 0-1 confidence to a Wazuh alert level (0-15)."""
    try:
        conf = float(confidence)
    except (TypeError, ValueError):
        conf = 0.0
    if conf >= _CONF_HIGH:
        return _LEVEL_HIGH
    if conf >= _CONF_MEDIUM:
        return _LEVEL_MEDIUM
    if conf >= _CONF_LOW:
        return _LEVEL_LOW
    return _LEVEL_MINIMAL


def _rule_id_for(key: str) -> int:
    """Deterministically map a technique/category key into the custom-id window.

    A stable hash (not Python's salted ``hash``) so the SAME key yields the SAME
    id across processes and runs -- the whole point of a correlatable rule id.

    Collisions are possible and accepted by design: the window is 20 000 wide, so
    at the low-hundreds of distinct techniques ATT&CK defines the birthday-paradox
    collision probability is a few percent. When two keys collide onto one id they
    share a ``<rule>`` stanza whose MITRE list carries BOTH techniques and whose
    ``<description>`` disambiguates -- no alert is lost, unrelated techniques are
    merely grouped. Widen the window (max 120000) only if collision noise is ever
    observed in practice.
    """
    digest = hashlib.sha256(key.encode("utf-8")).digest()
    offset = int.from_bytes(digest[:4], "big") % _RULE_ID_SPAN
    return RULE_ID_MIN + offset


def _primary_technique(finding_dict: dict) -> dict | None:
    """The first confirmed MITRE technique for a finding, or None."""
    confirmed = confirmed_matrix([finding_dict]).confirmed
    return confirmed[0] if confirmed else None


def _classification(finding: Any, finding_dict: dict) -> tuple[str, dict | None, str]:
    """Return ``(rule_key, technique_entry, category)`` for rule-id derivation.

    Keys off the primary confirmed technique when present, else the finding's
    category, so every finding classifies deterministically even with no MITRE.
    """
    category = str(_get(finding, "category", "unknown"))
    # A live Finding stores a FindingCategory enum; normalize to its value.
    category = getattr(_get(finding, "category", None), "value", category)
    technique = _primary_technique(finding_dict)
    if technique is not None:
        return f"technique:{technique['technique_id']}", technique, category
    return f"category:{category}", None, category


def _alert(finding: Any) -> tuple[dict, int, dict | None, str, str]:
    """Build one alert dict; also returns rule metadata for XML generation."""
    finding_dict = _to_dict(finding)
    title = (
        str(_get(finding, "title", "") or finding_dict.get("title", "")) or "finding"
    )
    description = str(_get(finding, "description", "") or "")
    confidence = _get(finding, "confidence", 0.0)
    level = _level_for(confidence)
    rule_key, technique, category = _classification(finding, finding_dict)
    rule_id = _rule_id_for(rule_key)

    iocs = finding_iocs(finding)
    data: dict[str, Any] = {}
    if iocs.ipv4 or iocs.ipv6:
        data["srcip"] = list(iocs.ipv4 + iocs.ipv6)
    if iocs.domains:
        data["domain"] = list(iocs.domains)
    if iocs.sha256 or iocs.md5:
        data["hash"] = list(iocs.sha256 + iocs.md5)

    rule_block: dict[str, Any] = {
        "id": rule_id,
        "level": level,
        "description": title,
        "groups": ["4n6nexus", category],
    }
    if technique is not None:
        rule_block["mitre"] = {
            "id": [str(technique["technique_id"])],
            "technique": [str(technique.get("name") or technique["technique_id"])],
            "tactic": [str(technique.get("tactic") or "unknown")],
        }

    alert = {
        "rule": rule_block,
        "agent": {"name": "4n6-nexus"},
        "manager": {"name": "4n6-nexus"},
        "full_log": description or title,
        "data": data,
        "_fingerprint": _fp_str(finding),
    }
    return alert, rule_id, technique, category, title


def _fp_str(finding: Any) -> str:
    fp = fingerprint(finding)
    return f"{fp.identity.kind}:{fp.identity.value}:{fp.category}"


def _rules_xml(rule_specs: dict[int, dict]) -> str:
    """Render the collected rule specs as a Wazuh local-rules ``<group>``.

    Built with ElementTree (never string concat) so the output is always
    well-formed XML.

    The trailing comma on the ``<group>`` name and on each rule's inner
    ``<group>`` text is intentional: Wazuh's local-rules format expects
    comma-delimited group lists WITH a trailing comma (the documented example is
    ``<group name="custom_rules_example,">``), so it is preserved deliberately,
    not a typo.
    """
    group = ET.Element("group", {"name": "4n6nexus,"})
    for rule_id in sorted(rule_specs):
        spec = rule_specs[rule_id]
        rule = ET.SubElement(
            group, "rule", {"id": str(rule_id), "level": str(spec["level"])}
        )
        desc = ET.SubElement(rule, "description")
        desc.text = spec["description"]
        for technique_id in spec.get("mitre_ids", []):
            mitre = ET.SubElement(rule, "mitre")
            mid = ET.SubElement(mitre, "id")
            mid.text = technique_id
        grp = ET.SubElement(rule, "group")
        grp.text = ",".join(spec["groups"]) + ","
    ET.indent(group, space="  ")
    return ET.tostring(group, encoding="unicode")


def wazuh_export(findings: Iterable[Any]) -> WazuhExport:
    """Export ``findings`` as Wazuh alerts + the custom rule stanzas.

    Alerts are deduplicated on the category-aware finding fingerprint (first
    occurrence wins), so a restated finding does not double-alert. Each distinct
    rule id contributes one ``<rule>`` stanza carrying the highest level seen for
    that id and its MITRE technique ids.

    Args:
        findings: Findings (:class:`~sift_find_evil.findings.finding.Finding` or
            their ``to_dict`` mappings).

    Returns:
        A :class:`WazuhExport`. Empty findings yield no alerts and an empty
        ``<group/>``.
    """
    alerts: list[dict] = []
    seen_fp: set[str] = set()
    rule_specs: dict[int, dict] = {}

    for finding in findings:
        alert, rule_id, technique, category, title = _alert(finding)
        fp = alert["_fingerprint"]
        if fp in seen_fp:
            continue
        seen_fp.add(fp)
        alerts.append(alert)

        spec = rule_specs.get(rule_id)
        if spec is None:
            spec = {
                "level": alert["rule"]["level"],
                "description": title,
                "groups": ["4n6nexus", category],
                "mitre_ids": [],
            }
            rule_specs[rule_id] = spec
        # A shared rule id keeps the HIGHEST level any finding assigned it.
        spec["level"] = max(spec["level"], alert["rule"]["level"])
        if technique is not None:
            tid = str(technique["technique_id"])
            if tid not in spec["mitre_ids"]:
                spec["mitre_ids"].append(tid)

    return WazuhExport(alerts=alerts, rules_xml=_rules_xml(rule_specs))
