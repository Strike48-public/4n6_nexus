"""Unit tests for the navigation-cache recorder's pure helpers (SFE-9v95).

``scripts/record-navigation-cache.py`` does a live Studio round-trip, but its
reply-parsing helpers are pure and mirror the Rust live path
(``ui/crates/tools/src/live_step.rs``). These guard the parse/gate logic WITHOUT
a live call, so a drift from the Rust behavior (which the committed fixture
depends on) is caught in CI even though the recorder itself never runs there.

The empty-agent-reply detector is the load-bearing one: it is what makes the
recorder fail fast with a clear "provider credential" diagnostic instead of
hanging the full poll budget when Studio's LLM backend is down.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

# Load the recorder by path -- it lives under scripts/ (not an importable
# package), exactly like build-judge-cache.py.
_SCRIPT = (
    Path(__file__).resolve().parent.parent / "scripts" / "record-navigation-cache.py"
)
_spec = importlib.util.spec_from_file_location("record_navigation_cache", _SCRIPT)
rec = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rec)


# -- first_json_object (mirror live_step.rs::first_json_object) -------------


def test_extracts_a_bare_object():
    assert rec.first_json_object('{"summary": "x"}') == '{"summary": "x"}'


def test_extracts_object_from_prose_and_code_fence():
    reply = 'Sure!\n```json\n{"summary": "s", "grounded_in": ["MFT"]}\n```\nHope that helps.'
    span = rec.first_json_object(reply)
    assert span == '{"summary": "s", "grounded_in": ["MFT"]}'


def test_brace_inside_a_string_does_not_close_the_object_early():
    text = r'prefix {"summary": "has a } brace", "x": 1} suffix'
    assert rec.first_json_object(text) == r'{"summary": "has a } brace", "x": 1}'


def test_escaped_quote_inside_string_is_honored():
    text = r'{"summary": "she said \"hi\""}'
    assert rec.first_json_object(text) == text


def test_no_object_returns_none():
    assert rec.first_json_object("no json here") is None
    assert rec.first_json_object("") is None


# -- parse_answer: the usability gate (mirror live_step.rs::parse_answer) ---


def test_parse_answer_accepts_a_nonblank_summary():
    ans = rec.parse_answer('{"summary": "trace parent", "grounded_in": ["MFT"]}')
    assert ans["summary"] == "trace parent"


def test_parse_answer_rejects_missing_blank_or_nonstring_summary():
    assert rec.parse_answer('{"grounded_in": []}') is None
    assert rec.parse_answer('{"summary": ""}') is None
    assert rec.parse_answer('{"summary": "   "}') is None
    assert rec.parse_answer('{"summary": null}') is None
    assert rec.parse_answer('{"summary": 42}') is None


def test_parse_answer_rejects_non_object_json():
    # A JSON array is valid JSON but not a usable answer object.
    assert rec.parse_answer("[1, 2, 3]") is None


# -- empty-agent-reply detector (the fast-fail-on-provider-down guard) ------


def _msg(sender_type: str, text: str) -> dict:
    parts = [{"text": text}] if text else []
    return {"profile": {"type": sender_type}, "parts": parts}


def test_empty_agent_message_detected_when_agent_replied_with_no_text():
    messages = [_msg("USER", "seed"), _msg("AGENT", "")]
    assert rec._has_empty_agent_message(messages) is True


def test_no_empty_agent_message_when_agent_has_text():
    messages = [_msg("USER", "seed"), _msg("AGENT", '{"summary": "ok"}')]
    assert rec._has_empty_agent_message(messages) is False


def test_no_empty_agent_message_when_only_the_user_seed_is_present():
    # Agent has not replied at all yet -- this is 'still working', NOT a provider
    # failure, so it must NOT trip the fast-fail (the poll keeps waiting).
    assert rec._has_empty_agent_message([_msg("USER", "seed")]) is False


# -- build_message carries the prompt + no-fabrication instruction ----------


def test_build_message_carries_prompt_finding_and_grounding_rule():
    finding = {"title": "t", "artifact_sources": ["MFT", "Prefetch"]}
    msg = rec.build_message(finding, "Compare the timestamps.")
    assert "Compare the timestamps." in msg
    assert "artifact_sources" in msg
    assert "Do NOT cite any artifact the finding does not list" in msg
