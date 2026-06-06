"""Targeted coverage tests for sift_find_evil/self_correction/engine.py.

These tests drive the specific branches/guards that the broader integration
suite does not exercise:

- ``_pick_category`` COMMAND_AND_CONTROL / PROCESS_INJECTION precedence branches
- ``_generate_exfil_finding`` unknown-match-type fallback (Low confidence)
- ``_resolve_causality_violation`` early-return guards (no prefetch / no event /
  no time match)
- ``_determine_severity`` empty-contradiction guard
- ``_detect_attack_patterns`` skip paths (non-process-creation event,
  no primary pattern)

Construction mirrors the existing tests/test_self_correction_integration.py:
real dataclasses (PrefetchEntry, EventLogEntry, Contradiction) plus lightweight
fakes for duck-typed inputs.
"""

from datetime import datetime

import pytest

from sift_find_evil.findings import FindingCategory
from sift_find_evil.parsers.evtx_parser import EventLogEntry
from sift_find_evil.parsers.prefetch_parser import PrefetchEntry
from sift_find_evil.self_correction.contradiction_detector import (
    Contradiction,
    ContradictionType,
    Severity,
)
from sift_find_evil.self_correction.engine import (
    SelfCorrectionEngine,
    _pick_category,
)


def _contradiction(ctype: ContradictionType, **details) -> Contradiction:
    """Build a minimal Contradiction of the given type."""
    return Contradiction(
        type=ctype,
        severity=Severity.HIGH,
        description="synthetic",
        confidence_impact=-0.30,
        details=details,
    )


# ---------------------------------------------------------------------------
# _pick_category precedence branches (lines 42, 44)
# ---------------------------------------------------------------------------


def test_pick_category_command_and_control_takes_precedence():
    """NETWORK_PRESENCE_MISMATCH maps to COMMAND_AND_CONTROL (engine.py line 42)."""
    contradictions = [
        _contradiction(ContradictionType.NETWORK_PRESENCE_MISMATCH),
        _contradiction(ContradictionType.MEMORY_PRESENCE_MISMATCH),
        _contradiction(ContradictionType.MISSING_ARTIFACT),
    ]

    assert _pick_category(contradictions) == FindingCategory.COMMAND_AND_CONTROL


def test_pick_category_process_injection_when_no_c2():
    """MEMORY_PRESENCE_MISMATCH maps to PROCESS_INJECTION (engine.py line 44)."""
    contradictions = [
        _contradiction(ContradictionType.MEMORY_PRESENCE_MISMATCH),
        _contradiction(ContradictionType.MISSING_ARTIFACT),
        _contradiction(ContradictionType.TIMESTOMPING),
    ]

    # No C2 present, so PROCESS_INJECTION wins over anti-forensics/timeline.
    assert _pick_category(contradictions) == FindingCategory.PROCESS_INJECTION


# ---------------------------------------------------------------------------
# _generate_exfil_finding unknown-match-type fallback (lines 350, 351)
# ---------------------------------------------------------------------------


def test_generate_exfil_finding_unknown_match_type_is_low_confidence():
    """An exfil contradiction with an unrecognised match_type uses the 0.50/Low
    fallback branch (engine.py lines 350-351)."""
    engine = SelfCorrectionEngine()

    contradiction = Contradiction(
        type=ContradictionType.EXFIL_CORRELATION,
        severity=Severity.CRITICAL,
        description="file save then email",
        confidence_impact=-0.10,
        details={
            "match_type": "speculative",  # neither "hash" nor "size_name_fallback"
            "file_path": "C:\\secret.docx",
            "save_time": "2023-05-10T14:00:00",
            "send_time": "2023-05-10T14:01:00",
            "delta_seconds": 60.0,
            "email_subject": "stuff",
            "attachment_name": "secret.docx",
            "attachment_size": 1234,
        },
    )

    finding = engine._generate_exfil_finding(contradiction)

    assert finding.confidence == pytest.approx(0.50)
    assert finding.confidence_label == "Low"
    assert finding.category == FindingCategory.DATA_EXFILTRATION
    # Non-hash branch reasoning line is appended.
    assert any(
        "no hash verification" in line.lower() for line in finding.reasoning_chain
    )


# ---------------------------------------------------------------------------
# _resolve_causality_violation early-return guards (lines 603, 614, 641)
# ---------------------------------------------------------------------------


def _causality_contradiction() -> Contradiction:
    return _contradiction(ContradictionType.CAUSALITY_VIOLATION)


def test_resolve_causality_no_prefetch_entry_returns_none():
    """No Prefetch entry for the executable -> guard returns None (line 603)."""
    engine = SelfCorrectionEngine()

    result = engine._resolve_causality_violation(
        executable="malware.exe",
        contradiction=_causality_contradiction(),
        prefetch_entries=[],  # nothing matches
        event_log_entries=[],
    )

    assert result is None


def test_resolve_causality_prefetch_without_last_run_time_returns_none():
    """Prefetch entry exists but has no last_run_time -> guard returns None (line 603)."""
    engine = SelfCorrectionEngine()

    prefetch = PrefetchEntry(
        source_filename="MALWARE.EXE-ABCD1234.pf",
        executable="malware.exe",
        run_count=1,
        last_run_time=None,  # triggers the guard
    )

    result = engine._resolve_causality_violation(
        executable="malware.exe",
        contradiction=_causality_contradiction(),
        prefetch_entries=[prefetch],
        event_log_entries=[],
    )

    assert result is None


def test_resolve_causality_no_matching_events_returns_none():
    """Prefetch has a run time but no Event Log entry names the executable
    -> matching_events empty guard returns None (line 614)."""
    engine = SelfCorrectionEngine()

    prefetch = PrefetchEntry(
        source_filename="MALWARE.EXE-ABCD1234.pf",
        executable="malware.exe",
        run_count=1,
        last_run_time=datetime(2023, 5, 10, 14, 25, 0),
    )

    # Event for a different executable -> no match.
    other_event = EventLogEntry(
        time_created=datetime(2023, 5, 10, 14, 25, 0),
        event_id=4688,
        record_id=1,
        computer="WS01",
        channel="Security",
        level="Information",
        payload_data1="C:\\Windows\\System32\\notepad.exe",
        payload_data6="notepad.exe",
    )

    result = engine._resolve_causality_violation(
        executable="malware.exe",
        contradiction=_causality_contradiction(),
        prefetch_entries=[prefetch],
        event_log_entries=[other_event],
    )

    assert result is None


def test_resolve_causality_event_time_outside_tolerance_returns_none():
    """Matching event exists but its time is far outside the 10s tolerance of
    the prefetch run time -> falls through the loop to final return None (line 641)."""
    engine = SelfCorrectionEngine()

    prefetch = PrefetchEntry(
        source_filename="MALWARE.EXE-ABCD1234.pf",
        executable="malware.exe",
        run_count=1,
        last_run_time=datetime(2023, 5, 10, 14, 25, 0),
    )

    # Same executable, but an hour off -> comparison != 0.
    event = EventLogEntry(
        time_created=datetime(2023, 5, 10, 15, 25, 0),
        event_id=4688,
        record_id=2,
        computer="WS01",
        channel="Security",
        level="Information",
        payload_data1="C:\\malware.exe",
        payload_data6="malware.exe",
    )

    result = engine._resolve_causality_violation(
        executable="malware.exe",
        contradiction=_causality_contradiction(),
        prefetch_entries=[prefetch],
        event_log_entries=[event],
    )

    assert result is None


# ---------------------------------------------------------------------------
# _determine_severity empty guard (line 653)
# ---------------------------------------------------------------------------


def test_determine_severity_empty_returns_info():
    """No contradictions -> severity defaults to 'info' (engine.py line 653)."""
    engine = SelfCorrectionEngine()

    assert engine._determine_severity([]) == "info"


# ---------------------------------------------------------------------------
# _detect_attack_patterns skip paths (lines 715, 734)
# ---------------------------------------------------------------------------


def test_detect_attack_patterns_skips_non_process_creation_event():
    """An event that is not a process-creation event hits the ``continue``
    skip (engine.py line 715) and produces no findings."""
    engine = SelfCorrectionEngine()

    # Event ID 4624 (logon) is not a process creation event.
    logon_event = EventLogEntry(
        time_created=datetime(2023, 5, 10, 14, 30, 0),
        event_id=4624,
        record_id=10,
        computer="WS01",
        channel="Security",
        level="Information",
        payload_data1="C:\\Windows\\System32\\mimikatz.exe",
        payload_data6="mimikatz.exe sekurlsa::logonpasswords",
    )

    findings = engine._detect_attack_patterns([logon_event])

    assert findings == []


def test_detect_attack_patterns_skips_when_no_primary_pattern(monkeypatch):
    """When the detector reports patterns but no highest-severity primary
    pattern, the ``continue`` guard skips the event (engine.py line 734)."""
    engine = SelfCorrectionEngine()

    event = EventLogEntry(
        time_created=datetime(2023, 5, 10, 14, 30, 0),
        event_id=4688,
        record_id=11,
        computer="WS01",
        channel="Security",
        level="Information",
        payload_data1="C:\\Tools\\mimikatz.exe",
        payload_data6="mimikatz.exe sekurlsa::logonpasswords",
    )

    # Force a non-empty pattern list but a None primary pattern so the
    # `if not primary_pattern: continue` branch executes.
    monkeypatch.setattr(
        engine.attack_detector,
        "analyze_command_line",
        lambda cmd: ["pattern-sentinel"],
    )
    monkeypatch.setattr(
        engine.attack_detector,
        "get_highest_severity_pattern",
        lambda patterns: None,
    )

    findings = engine._detect_attack_patterns([event])

    assert findings == []
