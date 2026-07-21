"""Tests for the hermetic mini-Sigma matcher.

These tests validate that :func:`match_events` correctly evaluates a small
subset of the Sigma rule format against parsed event dictionaries, producing
one :class:`Finding` per (rule, event) hit. Every positive assertion is paired
with an inverse/negative control so the tests fail if matching becomes
over-eager.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from sift_find_evil.detectors.sigma_scan import match_events
from sift_find_evil.findings import Finding, FindingCategory


# --------------------------------------------------------------------------- #
# Inline example rules (ship ~4 rules)
# --------------------------------------------------------------------------- #
def _powershell_enc_rule() -> Dict[str, Any]:
    """Rule: suspicious PowerShell encoded command (contains modifier)."""
    return {
        "title": "Suspicious PowerShell Encoded Command",
        "level": "high",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {"CommandLine|contains": "-enc"},
            "condition": "selection",
        },
    }


def _whoami_recon_rule() -> Dict[str, Any]:
    """Rule: whoami reconnaissance (exact image match + endswith)."""
    return {
        "title": "Whoami Reconnaissance",
        "level": "medium",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {"Image|endswith": "\\whoami.exe"},
            "condition": "selection",
        },
    }


def _wmic_shadowcopy_delete_rule() -> Dict[str, Any]:
    """Rule: wmic shadowcopy delete (two selections joined with 'and')."""
    return {
        "title": "WMIC Shadowcopy Deletion",
        "level": "critical",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "image": {"Image|endswith": "\\wmic.exe"},
            "args": {"CommandLine|contains": "shadowcopy delete"},
            "condition": "image and args",
        },
    }


def _startswith_re_rule() -> Dict[str, Any]:
    """Rule: exercises startswith + regex modifiers together with 'or'."""
    return {
        "title": "Suspicious Parent Or Hash",
        "level": "low",
        "logsource": {"product": "windows"},
        "detection": {
            "parent": {"ParentImage|startswith": "C:\\Windows\\Temp\\"},
            "hash": {"Hashes|re": r"MD5=[0-9A-Fa-f]{32}"},
            "condition": "parent or hash",
        },
    }


# --------------------------------------------------------------------------- #
# contains modifier
# --------------------------------------------------------------------------- #
def test_contains_matches_powershell_enc_event() -> None:
    # Arrange
    rules = [_powershell_enc_rule()]
    events = [
        {
            "Image": "C:\\Windows\\System32\\powershell.exe",
            "CommandLine": "powershell.exe -enc SQBFAFgA",
        }
    ]

    # Act
    findings = match_events(rules, events)

    # Assert
    assert len(findings) == 1
    assert isinstance(findings[0], Finding)
    assert findings[0].title == "Suspicious PowerShell Encoded Command"
    assert findings[0].evidence["matched_fields"]["CommandLine|contains"] == "-enc"


def test_contains_does_not_match_benign_event() -> None:
    # Arrange - inverse control: no "-enc" substring
    rules = [_powershell_enc_rule()]
    events = [
        {
            "Image": "C:\\Windows\\System32\\powershell.exe",
            "CommandLine": "powershell.exe -Command Get-Process",
        }
    ]

    # Act
    findings = match_events(rules, events)

    # Assert
    assert findings == []


# --------------------------------------------------------------------------- #
# endswith modifier
# --------------------------------------------------------------------------- #
def test_endswith_matches_whoami() -> None:
    # Arrange
    rules = [_whoami_recon_rule()]
    events = [{"Image": "C:\\Windows\\System32\\whoami.exe"}]

    # Act
    findings = match_events(rules, events)

    # Assert
    assert len(findings) == 1
    assert findings[0].title == "Whoami Reconnaissance"


def test_endswith_does_not_match_different_binary() -> None:
    # Arrange - inverse control
    rules = [_whoami_recon_rule()]
    events = [{"Image": "C:\\Windows\\System32\\whoami_helper.exe"}]

    # Act
    findings = match_events(rules, events)

    # Assert
    assert findings == []


# --------------------------------------------------------------------------- #
# startswith modifier
# --------------------------------------------------------------------------- #
def test_startswith_matches_temp_parent() -> None:
    # Arrange
    rules = [_startswith_re_rule()]
    events = [{"ParentImage": "C:\\Windows\\Temp\\dropper.exe"}]

    # Act
    findings = match_events(rules, events)

    # Assert
    assert len(findings) == 1


def test_startswith_does_not_match_other_path() -> None:
    # Arrange - inverse control
    rules = [_startswith_re_rule()]
    events = [{"ParentImage": "C:\\Program Files\\app.exe"}]

    # Act
    findings = match_events(rules, events)

    # Assert
    assert findings == []


# --------------------------------------------------------------------------- #
# regex modifier
# --------------------------------------------------------------------------- #
def test_regex_matches_md5_hash() -> None:
    # Arrange
    rules = [_startswith_re_rule()]
    events = [{"Hashes": "MD5=0123456789ABCDEF0123456789ABCDEF"}]

    # Act
    findings = match_events(rules, events)

    # Assert
    assert len(findings) == 1


def test_regex_does_not_match_malformed_hash() -> None:
    # Arrange - inverse control: too short
    rules = [_startswith_re_rule()]
    events = [{"Hashes": "MD5=ABC"}]

    # Act
    findings = match_events(rules, events)

    # Assert
    assert findings == []


# --------------------------------------------------------------------------- #
# 'a and b' condition
# --------------------------------------------------------------------------- #
def test_and_condition_requires_both_selections() -> None:
    # Arrange
    rules = [_wmic_shadowcopy_delete_rule()]
    events = [
        {
            "Image": "C:\\Windows\\System32\\wbem\\wmic.exe",
            "CommandLine": "wmic shadowcopy delete",
        }
    ]

    # Act
    findings = match_events(rules, events)

    # Assert
    assert len(findings) == 1
    assert findings[0].title == "WMIC Shadowcopy Deletion"


def test_and_condition_fails_when_only_one_selection_matches() -> None:
    # Arrange - inverse control: correct image, wrong command line
    rules = [_wmic_shadowcopy_delete_rule()]
    events = [
        {
            "Image": "C:\\Windows\\System32\\wbem\\wmic.exe",
            "CommandLine": "wmic process list",
        }
    ]

    # Act
    findings = match_events(rules, events)

    # Assert
    assert findings == []


# --------------------------------------------------------------------------- #
# 'not selection' condition
# --------------------------------------------------------------------------- #
def test_not_condition_matches_when_selection_absent() -> None:
    # Arrange
    rule = {
        "title": "Unsigned Binary",
        "level": "medium",
        "logsource": {},
        "detection": {
            "selection": {"Signed": "true"},
            "condition": "not selection",
        },
    }
    events = [{"Signed": "false"}]

    # Act
    findings = match_events([rule], events)

    # Assert
    assert len(findings) == 1


def test_not_condition_does_not_match_when_selection_present() -> None:
    # Arrange - inverse control
    rule = {
        "title": "Unsigned Binary",
        "level": "medium",
        "logsource": {},
        "detection": {
            "selection": {"Signed": "true"},
            "condition": "not selection",
        },
    }
    events = [{"Signed": "true"}]

    # Act
    findings = match_events([rule], events)

    # Assert
    assert findings == []


# --------------------------------------------------------------------------- #
# list-of-values (OR within a single matchspec)
# --------------------------------------------------------------------------- #
def test_list_of_values_matches_any() -> None:
    # Arrange
    rule = {
        "title": "Recon Tools",
        "level": "low",
        "logsource": {},
        "detection": {
            "selection": {"Image|endswith": ["\\whoami.exe", "\\net.exe"]},
            "condition": "selection",
        },
    }
    events = [{"Image": "C:\\Windows\\System32\\net.exe"}]

    # Act
    findings = match_events([rule], events)

    # Assert
    assert len(findings) == 1


def test_list_of_values_matches_none() -> None:
    # Arrange - inverse control
    rule = {
        "title": "Recon Tools",
        "level": "low",
        "logsource": {},
        "detection": {
            "selection": {"Image|endswith": ["\\whoami.exe", "\\net.exe"]},
            "condition": "selection",
        },
    }
    events = [{"Image": "C:\\Windows\\System32\\explorer.exe"}]

    # Act
    findings = match_events([rule], events)

    # Assert
    assert findings == []


# --------------------------------------------------------------------------- #
# level -> severity/category mapping
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "level,expected_severity,expected_category",
    [
        ("critical", "critical", FindingCategory.EXECUTION),
        ("high", "high", FindingCategory.EXECUTION),
        ("medium", "medium", FindingCategory.EXECUTION),
        ("low", "low", FindingCategory.EXECUTION),
    ],
)
def test_level_maps_to_severity_and_category(
    level: str, expected_severity: str, expected_category: FindingCategory
) -> None:
    # Arrange
    rule = {
        "title": f"Level Test {level}",
        "level": level,
        "logsource": {},
        "detection": {
            "selection": {"CommandLine|contains": "evil"},
            "condition": "selection",
        },
    }
    events = [{"CommandLine": "run evil now"}]

    # Act
    findings = match_events([rule], events)

    # Assert
    assert len(findings) == 1
    assert findings[0].severity == expected_severity
    assert findings[0].category == expected_category


# --------------------------------------------------------------------------- #
# one finding per (rule, event) hit
# --------------------------------------------------------------------------- #
def test_one_finding_per_rule_event_hit() -> None:
    # Arrange - two rules, three events; only some combinations hit
    rules = [_powershell_enc_rule(), _whoami_recon_rule()]
    events = [
        {"CommandLine": "powershell -enc AAAA"},  # hits powershell rule
        {"Image": "C:\\Windows\\System32\\whoami.exe"},  # hits whoami rule
        {"CommandLine": "notepad.exe"},  # hits nothing
    ]

    # Act
    findings = match_events(rules, events)

    # Assert
    assert len(findings) == 2
    titles = {f.title for f in findings}
    assert titles == {
        "Suspicious PowerShell Encoded Command",
        "Whoami Reconnaissance",
    }


def test_does_not_mutate_inputs() -> None:
    # Arrange
    rules: List[Dict[str, Any]] = [_powershell_enc_rule()]
    events: List[Dict[str, Any]] = [{"CommandLine": "powershell -enc AAAA"}]
    import copy

    rules_before = copy.deepcopy(rules)
    events_before = copy.deepcopy(events)

    # Act
    match_events(rules, events)

    # Assert
    assert rules == rules_before
    assert events == events_before


# --------------------------------------------------------------------------- #
# unknown field modifier is treated as non-matching (never raises)
# --------------------------------------------------------------------------- #
def test_unknown_modifier_does_not_match() -> None:
    # Arrange - a malformed rule with a modifier the matcher does not know.
    # A single bad rule must not fire and must not abort the scan.
    rule = {
        "title": "Unknown Modifier Rule",
        "level": "low",
        "logsource": {},
        "detection": {
            "selection": {"CommandLine|bogusmod": "evil"},
            "condition": "selection",
        },
    }
    events = [{"CommandLine": "evil"}]

    # Act
    findings = match_events([rule], events)

    # Assert - unknown modifier yields no match (matcher.py line 81)
    assert findings == []


# --------------------------------------------------------------------------- #
# condition references a name whose value is not a selection Mapping
# --------------------------------------------------------------------------- #
def test_condition_name_pointing_at_non_mapping_is_false() -> None:
    # Arrange - "meta" is a scalar, not a selection block. The 'and' term that
    # references it must resolve to False, so the whole condition is False.
    rule = {
        "title": "Non-Mapping Selection Name",
        "level": "medium",
        "logsource": {},
        "detection": {
            "selection": {"CommandLine|contains": "evil"},
            "meta": "not-a-selection-block",
            "condition": "selection and meta",
        },
    }
    events = [{"CommandLine": "run evil now"}]

    # Act
    findings = match_events([rule], events)

    # Assert - non-mapping name resolves False (matcher.py line 140)
    assert findings == []


# --------------------------------------------------------------------------- #
# an explicitly empty selection block referenced by the condition never fires
# --------------------------------------------------------------------------- #
def test_empty_selection_block_referenced_by_condition_is_false() -> None:
    # Arrange - an empty selection must not vacuously match universally.
    rule = {
        "title": "Empty Selection Block",
        "level": "low",
        "logsource": {},
        "detection": {
            "empty": {},
            "condition": "empty",
        },
    }
    events = [{"CommandLine": "anything at all"}]

    # Act
    findings = match_events([rule], events)

    # Assert - empty selection is non-firing (matcher.py line 144)
    assert findings == []


# --------------------------------------------------------------------------- #
# an empty sibling block is skipped while collecting matched fields
# --------------------------------------------------------------------------- #
def test_empty_sibling_block_skipped_during_field_collection() -> None:
    # Arrange - a real selection fires the rule; a sibling empty block must be
    # skipped (not matched) when aggregating matched fields for the finding.
    rule = {
        "title": "Real Plus Empty Block",
        "level": "high",
        "logsource": {},
        "detection": {
            "selection": {"CommandLine|contains": "evil"},
            "empty": {},
            "condition": "selection",
        },
    }
    events = [{"CommandLine": "run evil now"}]

    # Act
    findings = match_events([rule], events)

    # Assert - fires on the real selection, empty block skipped (line 243)
    assert len(findings) == 1
    matched = findings[0].evidence["matched_fields"]
    assert "CommandLine|contains" in matched
    assert "empty" not in matched


# --------------------------------------------------------------------------- #
# rule whose 'detection' is not a Mapping is skipped
# --------------------------------------------------------------------------- #
def test_rule_with_non_mapping_detection_is_skipped() -> None:
    # Arrange - a malformed rule whose detection is a string, not a dict.
    rule = {"title": "Bad Detection", "level": "low", "detection": "not-a-dict"}
    events = [{"CommandLine": "run evil now"}]

    # Act
    findings = match_events([rule], events)

    # Assert - non-mapping detection skipped (matcher.py line 270)
    assert findings == []


# --------------------------------------------------------------------------- #
# rule with a missing/empty condition is skipped
# --------------------------------------------------------------------------- #
def test_rule_with_empty_condition_is_skipped() -> None:
    # Arrange - detection is a valid Mapping but has no condition string.
    rule = {
        "title": "No Condition",
        "level": "low",
        "logsource": {},
        "detection": {"selection": {"CommandLine|contains": "evil"}},
    }
    events = [{"CommandLine": "run evil now"}]

    # Act
    findings = match_events([rule], events)

    # Assert - empty condition skips the rule (matcher.py line 273)
    assert findings == []
