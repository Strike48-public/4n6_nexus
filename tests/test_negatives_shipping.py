"""Proven-negative emission on the shipping CLI path (SFE-fibx.5 PR-C).

Proven negatives (findings/absence.py) were emitted ONLY by the demo orchestrator
(_emit_proven_negatives). This wires the same mechanically-re-verified "[NEGATIVE]
tool ran and found zero X" claim onto the shipping ``analyze`` path, via a
reusable helper that both paths can call. Scope: the credential-dumping negative
over Event Log 4688 command-line text -- the one domain the CLI reliably has
re-readable output + a citation for.
"""

from __future__ import annotations

from sift_find_evil.findings import FindingCategory
from sift_find_evil.findings.negatives import (
    CREDENTIAL_DUMP_INDICATORS,
    credential_dump_negative,
)


def test_clean_evtx_yields_a_proven_credential_dump_negative():
    # Benign 4688 command lines, no positive credential finding fired.
    text = "C:\\Windows\\explorer.exe\nnotepad.exe report.txt\nchrome.exe"
    neg = credential_dump_negative(
        evtx_command_text=text,
        fired_categories=set(),
        tool_call_id="evtx-001",
    )
    assert neg is not None
    assert neg.finding_type == "negative"
    assert neg.severity == "info"
    assert neg.category is FindingCategory.CREDENTIAL_ACCESS
    assert neg.asserts_absence is True
    # It carries no executable key, so it can never enter F1 tp/fp/fn accounting.
    assert "executable" not in neg.evidence


def test_indicator_present_in_evtx_withholds_the_negative():
    # A credential-dump indicator physically present -> the negative is REFUTED,
    # so no clean claim ships.
    text = "powershell.exe -c Invoke-Mimikatz\nnotepad.exe"
    neg = credential_dump_negative(
        evtx_command_text=text,
        fired_categories=set(),
        tool_call_id="evtx-001",
    )
    assert neg is None


def test_credential_positive_already_fired_withholds_the_negative():
    # You cannot claim "no credential dumping" when a credential finding fired.
    text = "C:\\Windows\\explorer.exe\nnotepad.exe"
    neg = credential_dump_negative(
        evtx_command_text=text,
        fired_categories={FindingCategory.CREDENTIAL_ACCESS},
        tool_call_id="evtx-001",
    )
    assert neg is None


def test_empty_output_proves_nothing_so_no_negative():
    # Empty/whitespace captured output is UNPROVEN -> no negative ships.
    neg = credential_dump_negative(
        evtx_command_text="   ",
        fired_categories=set(),
        tool_call_id="evtx-001",
    )
    assert neg is None


def test_missing_tool_call_id_withholds_the_negative():
    # A negative needs a real cited run; no id -> UNPROVEN -> withheld.
    text = "C:\\Windows\\explorer.exe"
    neg = credential_dump_negative(
        evtx_command_text=text,
        fired_categories=set(),
        tool_call_id="",
    )
    assert neg is None


def test_none_command_text_withholds_the_negative():
    # No evtx text at all (e.g. evtx not supplied) -> nothing to re-read.
    neg = credential_dump_negative(
        evtx_command_text=None,
        fired_categories=set(),
        tool_call_id="evtx-001",
    )
    assert neg is None


def test_indicators_are_the_shared_single_source():
    # The indicator vocabulary is the shared constant, not a private duplicate.
    assert "mimikatz" in CREDENTIAL_DUMP_INDICATORS
    assert "lsass" in CREDENTIAL_DUMP_INDICATORS
    assert isinstance(CREDENTIAL_DUMP_INDICATORS, tuple)


def test_returned_negative_reverifies_as_proven():
    # The emitted negative must independently re-verify PROVEN against the same
    # text (closing the loop: emission and verification agree).
    from sift_find_evil.findings.absence import AbsenceStatus, check_absence

    text = "explorer.exe\nnotepad.exe report.txt"
    neg = credential_dump_negative(
        evtx_command_text=text,
        fired_categories=set(),
        tool_call_id="evtx-001",
    )
    assert neg is not None
    report = check_absence(neg, text)
    assert report.status is AbsenceStatus.PROVEN


def test_helper_does_not_mutate_fired_categories():
    fired = {FindingCategory.PROCESS_INJECTION}
    before = set(fired)
    credential_dump_negative(
        evtx_command_text="explorer.exe",
        fired_categories=fired,
        tool_call_id="evtx-001",
    )
    assert fired == before


# ---------------------------------------------------------------------------
# CLI wiring: _append_proven_negatives / _evtx_command_text
# ---------------------------------------------------------------------------


class _FakeFinding:
    """A positive finding stand-in carrying a category (for fired-set logic)."""

    def __init__(self, category):
        self.category = category


def test_cli_append_adds_negative_for_clean_evtx(tmp_path):
    from sift_find_evil.cli import _append_proven_negatives

    # Minimal EvtxECmd-shaped CSV with a benign 4688 command line.
    evtx = tmp_path / "evtx.csv"
    _write_evtx_csv(evtx, ["C:\\Windows\\explorer.exe"])
    out = _append_proven_negatives([], evtx, str(evtx))
    assert len(out) == 1
    assert out[0].finding_type == "negative"
    assert out[0].category is FindingCategory.CREDENTIAL_ACCESS


def test_cli_append_is_noop_when_no_evtx():
    from sift_find_evil.cli import _append_proven_negatives

    existing = [_FakeFinding(FindingCategory.EXECUTION)]
    out = _append_proven_negatives(existing, None, None)
    # No evtx -> nothing appended, original findings preserved (new list).
    assert len(out) == 1
    assert out is not existing


def test_cli_append_withholds_when_indicator_present(tmp_path):
    from sift_find_evil.cli import _append_proven_negatives

    evtx = tmp_path / "evtx.csv"
    _write_evtx_csv(evtx, ["powershell.exe -enc Invoke-Mimikatz"])
    out = _append_proven_negatives([], evtx, str(evtx))
    assert out == []  # indicator present -> negative withheld


def _write_evtx_csv(path, command_lines):
    """Write a minimal EvtxECmd CSV of 4688 events with the given command lines.

    Writes exactly the columns EventLogParser reads (TimeCreated, EventId,
    Payload); the command line is embedded in the JSON Payload's
    EventData/CommandLine field, mirroring how the parser extracts it for 4688.
    """
    import csv
    import json as _json

    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["TimeCreated", "EventId", "Payload"])
        writer.writeheader()
        for cmd in command_lines:
            payload = {"EventData": {"Data": [{"@Name": "CommandLine", "#text": cmd}]}}
            writer.writerow(
                {
                    "TimeCreated": "2024-01-01 00:00:00.000",
                    "EventId": "4688",
                    "Payload": _json.dumps(payload),
                }
            )
