"""Tests for Wazuh/OpenSearch SIEM export (SFE-b0om).

Guards the level bands, the stable-and-in-range rule id, fingerprint dedup, and
well-formed rule XML -- the four things a Wazuh integration relies on.
"""

from __future__ import annotations

import xml.dom.minidom

from sift_find_evil.findings import Finding, FindingCategory
from sift_find_evil.interop.siem import (
    RULE_ID_MAX,
    RULE_ID_MIN,
    WazuhExport,
    wazuh_export,
)


def _finding(
    *,
    title: str = "Suspicious beacon",
    confidence: float = 0.9,
    category: FindingCategory = FindingCategory.COMMAND_AND_CONTROL,
    evidence: dict | None = None,
) -> Finding:
    return Finding(
        title=title,
        description="periodic C2",
        finding_type="indicator",
        severity="high",
        category=category,
        evidence=evidence or {},
        confidence=confidence,
    )


# --- level bands ------------------------------------------------------------


def test_level_bands() -> None:
    assert wazuh_export([_finding(confidence=0.85)]).alerts[0]["rule"]["level"] == 12
    assert wazuh_export([_finding(confidence=0.65)]).alerts[0]["rule"]["level"] == 9
    assert wazuh_export([_finding(confidence=0.45)]).alerts[0]["rule"]["level"] == 6
    assert wazuh_export([_finding(confidence=0.2)]).alerts[0]["rule"]["level"] == 3


def test_level_never_exceeds_15() -> None:
    for conf in (0.0, 0.5, 0.99, 1.0):
        level = wazuh_export([_finding(confidence=conf)]).alerts[0]["rule"]["level"]
        assert 0 <= level <= 15


def test_non_numeric_confidence_defaults_to_minimal_level() -> None:
    export = wazuh_export([{"title": "t", "confidence": None, "evidence": {}}])
    assert export.alerts[0]["rule"]["level"] == 3


# --- rule id: stable + in range ---------------------------------------------


def test_rule_id_in_custom_range() -> None:
    export = wazuh_export([_finding(evidence={"mitre_attack": ["T1071"]})])
    rid = export.alerts[0]["rule"]["id"]
    assert RULE_ID_MIN <= rid < RULE_ID_MAX


def test_same_technique_gets_same_rule_id() -> None:
    a = wazuh_export([_finding(evidence={"mitre_attack": ["T1071"]})]).alerts[0]
    b = wazuh_export(
        [_finding(evidence={"mitre_attack": ["T1071"]}, title="other")]
    ).alerts[0]
    assert a["rule"]["id"] == b["rule"]["id"]


def test_finding_without_technique_uses_category_key() -> None:
    # No MITRE -> still a deterministic in-range id keyed on category.
    export = wazuh_export([_finding(evidence={})])
    rid = export.alerts[0]["rule"]["id"]
    assert RULE_ID_MIN <= rid < RULE_ID_MAX


def test_distinct_categories_generally_differ() -> None:
    c2 = wazuh_export([_finding(category=FindingCategory.COMMAND_AND_CONTROL)]).alerts[
        0
    ]
    persist = wazuh_export([_finding(category=FindingCategory.PERSISTENCE)]).alerts[0]
    assert c2["rule"]["id"] != persist["rule"]["id"]


# --- dedup ------------------------------------------------------------------


def test_duplicate_findings_collapse_to_one_alert() -> None:
    dup = {"mitre_attack": ["T1071"], "dst_ip": "8.8.8.8"}
    export = wazuh_export([_finding(evidence=dup), _finding(evidence=dup)])
    assert len(export.alerts) == 1


def test_distinct_findings_both_alert() -> None:
    export = wazuh_export(
        [
            _finding(evidence={"dst_ip": "8.8.8.8"}),
            _finding(evidence={"dst_ip": "1.1.1.1"}),
        ]
    )
    assert len(export.alerts) == 2


# --- MITRE + IOC content ----------------------------------------------------


def test_alert_carries_mitre_block() -> None:
    (alert,) = wazuh_export([_finding(evidence={"mitre_attack": ["T1071"]})]).alerts
    assert alert["rule"]["mitre"]["id"] == ["T1071"]


def test_alert_data_carries_iocs() -> None:
    (alert,) = wazuh_export(
        [
            _finding(
                evidence={
                    "dst_ip": "8.8.8.8",
                    "domain": "evil.example.com",
                    "sha256": "a" * 64,
                }
            )
        ]
    ).alerts
    assert "8.8.8.8" in alert["data"]["srcip"]
    assert "evil.example.com" in alert["data"]["domain"]
    assert "a" * 64 in alert["data"]["hash"]


# --- rule XML ---------------------------------------------------------------


def test_rules_xml_is_wellformed() -> None:
    export = wazuh_export([_finding(evidence={"mitre_attack": ["T1071"]})])
    # Raises if malformed.
    dom = xml.dom.minidom.parseString(export.rules_xml)
    assert dom.documentElement.tagName == "group"


def test_rules_xml_contains_rule_with_level_and_mitre() -> None:
    export = wazuh_export(
        [_finding(confidence=0.9, evidence={"mitre_attack": ["T1071"]})]
    )
    assert "<rule id=" in export.rules_xml
    assert 'level="12"' in export.rules_xml
    assert "<id>T1071</id>" in export.rules_xml


def test_shared_rule_id_keeps_highest_level() -> None:
    # Two findings on the same technique but different confidence share a rule id;
    # the rule stanza must carry the higher level.
    export = wazuh_export(
        [
            _finding(
                confidence=0.45,
                evidence={"mitre_attack": ["T1071"], "dst_ip": "8.8.8.8"},
            ),
            _finding(
                confidence=0.9,
                evidence={"mitre_attack": ["T1071"], "dst_ip": "1.1.1.1"},
            ),
        ]
    )
    assert 'level="12"' in export.rules_xml
    assert 'level="6"' not in export.rules_xml


# --- edge cases -------------------------------------------------------------


def test_empty_findings_yield_empty_export() -> None:
    export = wazuh_export([])
    assert isinstance(export, WazuhExport)
    assert export.alerts == []
    # An empty but well-formed <group/>.
    dom = xml.dom.minidom.parseString(export.rules_xml)
    assert dom.documentElement.tagName == "group"


def test_accepts_dict_shaped_finding() -> None:
    export = wazuh_export(
        [
            {
                "title": "t",
                "description": "",
                "confidence": 0.9,
                "category": "persistence",
                "evidence": {},
            }
        ]
    )
    assert export.alerts[0]["rule"]["level"] == 12
