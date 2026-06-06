"""Coverage tests for ContradictionDetector branch/guard paths.

These exercise the disk-correlation paths (missing-execution-artifact tiers,
temporal mismatch, save-then-exfil hash and size+name fallbacks) and the
external-IP helper guards that the scenario harness never drives, using
lightweight duck-typed fakes (the detector accepts ``Any`` and reads attributes
by name, so fakes are sufficient and avoid pulling in forensic libraries).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from sift_find_evil.parsers.pcap_parser import TCPConversation
from sift_find_evil.self_correction.contradiction_detector import (
    ContradictionDetector,
    ContradictionType,
    Severity,
    _is_external_ipv4,
)


_T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


# --- fakes --------------------------------------------------------------


def _mft(
    file_name: str,
    *,
    si_created=None,
    file_size: int = 100,
    is_directory: bool = False,
    creation_time=None,
):
    """A duck-typed MFT entry: only the attributes the detector reads."""
    return SimpleNamespace(
        file_name=file_name,
        file_path=f"C:\\\\Users\\\\{file_name}",
        file_size=file_size,
        is_directory=is_directory,
        si_created=si_created,
        get_creation_time=lambda: creation_time,
    )


def _prefetch(executable: str, last_run_time=None):
    return SimpleNamespace(executable=executable, last_run_time=last_run_time)


def _event(exe_name: str | None, time_created=_T0):
    return SimpleNamespace(
        get_executable_name=lambda: exe_name,
        time_created=time_created,
    )


def _attachment(name: str, size: int, sha256: str = "deadbeef"):
    return SimpleNamespace(name=name, size=size, sha256=sha256)


def _email(submit_time, attachments, subject="Re: report", folder="Sent"):
    return SimpleNamespace(
        submit_time=submit_time,
        attachments=attachments,
        subject=subject,
        folder=folder,
    )


# --- detect_missing_execution_artifact: guards & tiers ------------------


def test_missing_artifact_non_exe_returns_none():
    """A non-.exe MFT entry is never flagged (line 223 guard)."""
    detector = ContradictionDetector()
    result = detector.detect_missing_execution_artifact(
        _mft("notes.txt"), prefetch_entries=[]
    )
    assert result is None


def test_missing_artifact_high_frequency_is_info():
    """>=6 Event Log confirmations => INFO / system-service tier (249-251)."""
    detector = ContradictionDetector()
    mft = _mft("svchost.exe")
    other_pf = [_prefetch("explorer.exe")]  # no matching prefetch
    events = [_event("svchost.exe") for _ in range(6)]

    result = detector.detect_missing_execution_artifact(mft, other_pf, events)

    assert result is not None
    assert result.severity == Severity.INFO
    assert result.confidence_impact == -0.05
    assert result.details["event_log_confirmations"] == 6
    assert "system service" in result.details["note"].lower()


def test_missing_artifact_multiple_executions_is_low():
    """2..5 Event Log confirmations => LOW tier with -0.08 impact (254-256)."""
    detector = ContradictionDetector()
    mft = _mft("malware.exe")
    other_pf = [_prefetch("explorer.exe")]
    events = [_event("malware.exe"), _event("malware.exe")]

    result = detector.detect_missing_execution_artifact(mft, other_pf, events)

    assert result is not None
    assert result.severity == Severity.LOW
    assert result.confidence_impact == -0.08
    assert "multiple executions" in result.details["note"].lower()


# --- detect_temporal_mismatch -------------------------------------------


def test_temporal_mismatch_no_last_run_time_returns_none():
    """A Prefetch with no last_run_time short-circuits to None (line 323)."""
    detector = ContradictionDetector()
    pf = _prefetch("x.exe", last_run_time=None)
    events = [_event("x.exe", time_created=_T0)]
    assert detector.detect_temporal_mismatch(pf, events) is None


def test_temporal_mismatch_no_matching_event_emits_contradiction():
    """Prefetch run time with no Event 4688 in window => TEMPORAL_MISMATCH (337,339)."""
    detector = ContradictionDetector()
    pf = _prefetch("x.exe", last_run_time=_T0)
    # event far outside the default 300s tolerance window
    events = [_event("x.exe", time_created=_T0 + timedelta(hours=5))]

    result = detector.detect_temporal_mismatch(pf, events)

    assert result is not None
    assert result.type == ContradictionType.TEMPORAL_MISMATCH
    assert result.severity == Severity.MEDIUM
    assert result.details["event_count"] == 1
    assert result.details["executable"] == "x.exe"
    # event_times list comprehension (line 337) populated from the events
    assert result.details["event_log_times"]


def test_temporal_mismatch_within_tolerance_returns_none():
    """A matching event within tolerance suppresses the contradiction."""
    detector = ContradictionDetector()
    pf = _prefetch("x.exe", last_run_time=_T0)
    events = [_event("x.exe", time_created=_T0 + timedelta(seconds=10))]
    assert detector.detect_temporal_mismatch(pf, events) is None


# --- detect_all aggregates temporal mismatch ----------------------------


def test_detect_all_collects_temporal_mismatch(monkeypatch):
    """detect_all appends a temporal-mismatch contradiction (line 406)."""
    detector = ContradictionDetector()
    pf = _prefetch("x.exe", last_run_time=_T0)
    # No matching MFT (so no causality/timestomping), event outside window.
    events = [_event("x.exe", time_created=_T0 + timedelta(hours=5))]

    contradictions = detector.detect_all(
        mft_entries=[], prefetch_entries=[pf], event_log_entries=events
    )

    temporal = [
        c for c in contradictions if c.type == ContradictionType.TEMPORAL_MISMATCH
    ]
    assert len(temporal) == 1


# --- _destination_port helper -------------------------------------------


def test_destination_port_matches_endpoint_b():
    """When the external IP is endpoint B, return endpoint_b_port (line 611)."""
    conv = TCPConversation(
        endpoint_a_ip="10.0.0.5",
        endpoint_a_port=50111,
        endpoint_b_ip="203.0.113.50",
        endpoint_b_port=4444,
        frames_a_to_b=1,
        bytes_a_to_b=1,
        frames_b_to_a=1,
        bytes_b_to_a=1,
        total_frames=2,
        total_bytes=2,
    )
    assert ContradictionDetector._destination_port(conv, "203.0.113.50") == 4444


def test_destination_port_matches_endpoint_a():
    """When the external IP is endpoint A, return endpoint_a_port (line 611)."""
    conv = TCPConversation(
        endpoint_a_ip="203.0.113.50",
        endpoint_a_port=4444,
        endpoint_b_ip="10.0.0.5",
        endpoint_b_port=50111,
        frames_a_to_b=1,
        bytes_a_to_b=1,
        frames_b_to_a=1,
        bytes_b_to_a=1,
        total_frames=2,
        total_bytes=2,
    )
    assert ContradictionDetector._destination_port(conv, "203.0.113.50") == 4444


def test_destination_port_no_match_returns_none():
    """When the dst_ip matches neither endpoint, return None (line 614)."""
    conv = TCPConversation(
        endpoint_a_ip="10.0.0.5",
        endpoint_a_port=50111,
        endpoint_b_ip="203.0.113.50",
        endpoint_b_port=4444,
        frames_a_to_b=1,
        bytes_a_to_b=1,
        frames_b_to_a=1,
        bytes_b_to_a=1,
        total_frames=2,
        total_bytes=2,
    )
    assert ContradictionDetector._destination_port(conv, "9.9.9.9") is None


# --- detect_save_then_exfil + helpers -----------------------------------


def test_save_then_exfil_skips_email_with_no_attachments():
    """An email with no attachments is skipped (line 643 continue)."""
    detector = ContradictionDetector()
    email = _email(submit_time=_T0, attachments=[])
    assert detector.detect_save_then_exfil(mft_entries=[], emails=[email]) == []


def test_find_by_hash_skips_directories_and_late_files():
    """_find_by_hash skips directories (682) and files created after send (688)."""
    detector = ContradictionDetector()
    att = _attachment("secret.docx", size=10, sha256="abc123")

    directory = _mft("Documents", is_directory=True, si_created=_T0)
    too_old = _mft(
        "secret.docx", si_created=_T0 - timedelta(hours=1), file_size=10
    )  # created before the cutoff window (line 686)
    no_si = _mft("secret.docx", si_created=None, file_size=10)  # None si_created (686)
    late_file = _mft(
        "secret.docx", si_created=_T0 + timedelta(seconds=30), file_size=10
    )  # created AFTER submit
    email = _email(submit_time=_T0, attachments=[att])

    def reader(_entry):  # would match if reached, but temporal guards skip all
        return b"x" * 10

    result = detector.detect_save_then_exfil(
        mft_entries=[directory, too_old, no_si, late_file],
        emails=[email],
        content_reader=reader,
    )
    assert result == []


def test_find_by_hash_matches_in_window():
    """Hash match within the temporal window yields a CRITICAL contradiction."""
    detector = ContradictionDetector()
    payload = b"top-secret-bytes"
    import hashlib

    digest = hashlib.sha256(payload).hexdigest()
    att = _attachment("secret.docx", size=len(payload), sha256=digest)
    saved = _mft(
        "secret.docx",
        si_created=_T0 - timedelta(seconds=30),
        file_size=len(payload),
    )
    email = _email(submit_time=_T0, attachments=[att])

    result = detector.detect_save_then_exfil(
        mft_entries=[saved],
        emails=[email],
        content_reader=lambda _e: payload,
    )
    assert len(result) == 1
    assert result[0].type == ContradictionType.EXFIL_CORRELATION
    assert result[0].severity == Severity.CRITICAL


def test_find_by_size_and_name_skips_directories_and_late_files():
    """Fallback path skips directories (745) and files created after send (751)."""
    detector = ContradictionDetector()
    att = _attachment("report.xlsx", size=20)

    directory = _mft("Reports", is_directory=True, si_created=_T0)
    too_old = _mft(
        "report.xlsx", si_created=_T0 - timedelta(hours=1), file_size=20
    )  # before cutoff window (line 749)
    no_si = _mft("report.xlsx", si_created=None, file_size=20)  # None si_created (749)
    late_file = _mft(
        "report.xlsx", si_created=_T0 + timedelta(seconds=30), file_size=20
    )
    email = _email(submit_time=_T0, attachments=[att])

    # No content_reader -> size+name fallback path
    result = detector.detect_save_then_exfil(
        mft_entries=[directory, too_old, no_si, late_file], emails=[email]
    )
    assert result == []


def test_find_by_size_and_name_matches_in_window():
    """Size+name fallback match within window yields a HIGH contradiction."""
    detector = ContradictionDetector()
    att = _attachment("report.xlsx", size=20)
    saved = _mft("report.xlsx", si_created=_T0 - timedelta(seconds=30), file_size=20)
    email = _email(submit_time=_T0, attachments=[att])

    result = detector.detect_save_then_exfil(mft_entries=[saved], emails=[email])
    assert len(result) == 1
    assert result[0].type == ContradictionType.EXFIL_CORRELATION
    assert result[0].severity == Severity.HIGH
    assert result[0].details["match_type"] == "size_name_fallback"


# --- _is_external_ipv4 multicast guard ----------------------------------


def test_is_external_ipv4_excludes_multicast():
    """A multicast IPv4 address is not an external C2 destination (line 820)."""
    assert _is_external_ipv4("224.0.0.1") is False
    # sanity: a routable unicast address is external
    assert _is_external_ipv4("203.0.113.50") is True
