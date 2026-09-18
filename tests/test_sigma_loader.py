"""SFE-katy PR2: Sigma YAML corpus loader.

The matcher takes rule DICTS; the pinned corpus ships as auditable Sigma YAML in
rules/sigma/*.yaml (config-as-data). This loader parses that corpus into the
matcher's dict shape and rejects-to-record any rule using grammar the hermetic
mini-Sigma subset does not support (reject loudly, never silently mis-evaluate).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sift_find_evil.detectors.sigma_scan.loader import (
    RuleRejectedError,
    load_rule_text,
    load_sigma_corpus,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CORPUS_DIR = _REPO_ROOT / "rules" / "sigma"

_VALID_RULE = """
title: Suspicious PowerShell Encoded Command
level: high
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: '-enc'
  condition: selection
"""


# --- parsing a single valid rule -------------------------------------------


def test_valid_rule_parses_into_matcher_shape() -> None:
    rule = load_rule_text(_VALID_RULE)
    assert rule["title"] == "Suspicious PowerShell Encoded Command"
    assert rule["level"] == "high"
    assert rule["detection"]["condition"] == "selection"
    assert rule["detection"]["selection"]["CommandLine|contains"] == "-enc"


# --- reject-to-record: unsupported grammar must raise, never silently pass --


def test_aggregation_condition_is_rejected() -> None:
    # The mini-Sigma condition evaluator supports only named selections with
    # and/or/not. A `| count()` aggregation would silently never match, giving
    # false confidence - reject it instead.
    rule = _VALID_RULE.replace(
        "condition: selection", "condition: selection | count() > 5"
    )
    with pytest.raises(RuleRejectedError):
        load_rule_text(rule)


def test_rule_without_condition_is_rejected() -> None:
    rule = """
title: No condition
level: low
detection:
  selection:
    Image|endswith: '.exe'
"""
    with pytest.raises(RuleRejectedError):
        load_rule_text(rule)


def test_unknown_field_modifier_is_rejected() -> None:
    # The matcher supports contains/startswith/endswith/re (+ exact). A modifier
    # like `|base64` would be silently treated as non-matching by the matcher, so
    # the loader must reject it rather than ship a rule that never fires.
    rule = _VALID_RULE.replace("CommandLine|contains", "CommandLine|base64")
    with pytest.raises(RuleRejectedError):
        load_rule_text(rule)


def test_quantifier_condition_token_is_rejected() -> None:
    # `1 of selection*` / `all of them` quantifiers are outside the mini-Sigma
    # evaluator's grammar and would misfire silently - reject them.
    rule = _VALID_RULE.replace("condition: selection", "condition: all of them")
    with pytest.raises(RuleRejectedError):
        load_rule_text(rule)


def test_non_mapping_rule_is_rejected() -> None:
    # A YAML document that parses to a scalar/list (not a rule mapping).
    with pytest.raises(RuleRejectedError):
        load_rule_text("- just\n- a\n- list")


def test_rule_without_detection_block_is_rejected() -> None:
    with pytest.raises(RuleRejectedError):
        load_rule_text("title: No detection\nlevel: low")


def test_malformed_yaml_is_rejected() -> None:
    with pytest.raises(RuleRejectedError):
        load_rule_text("title: [unclosed")


# --- the pinned corpus loads and is non-empty ------------------------------


def test_pinned_corpus_loads_and_is_nonempty() -> None:
    rules = load_sigma_corpus(_CORPUS_DIR)
    assert len(rules) >= 3, "expected a committed rules/sigma/ corpus"
    # Every loaded rule is matcher-ready: has a title and a condition.
    for rule in rules:
        assert rule.get("title")
        assert rule.get("detection", {}).get("condition")


def test_missing_corpus_dir_returns_empty() -> None:
    # A missing corpus directory is not an error (Sigma is opt-in); it yields no
    # rules so the scan simply produces nothing.
    assert load_sigma_corpus(_REPO_ROOT / "rules" / "does_not_exist") == []
