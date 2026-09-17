"""Forensic event-time propagation into finding evidence (SFE-fr7d).

The GUI/connector path (`cli.analyze_artifacts`) emitted findings whose only
temporal field was `detected_at` -- the analysis wall-clock (`datetime.now()`),
identical to microseconds across a run. A findings timeline (SFE-x44t) needs the
REAL forensic event time the detector already observed. This suite pins:

- `_finding_event_time` priority: prefetch last-run (actual execution) > evtx 4688
  TimeCreated (execution confirmation) > MFT creation (file birth). Whichever
  most-execution-relevant time is present wins.
- absence: no matching entry / no timestamp -> None (finding carries no
  `event_time`, and the timeline UI degrades rather than plotting a bogus mark).
- the field is ADDITIVE and display-only: it lands in evidence["event_time"] as
  ISO8601 and is NOT the correlation `timeline` dict, so hardening/subject_risk/F1
  are untouched by construction (guarded by the full scenario harness).
"""

from datetime import datetime

from sift_find_evil.cli import analyze_artifacts
from sift_find_evil.parsers.evtx_parser import EventLogEntry
from sift_find_evil.parsers.mft_parser import MFTEntry
from sift_find_evil.parsers.prefetch_parser import PrefetchEntry
from sift_find_evil.self_correction.engine import _finding_event_time


def _prefetch(executable: str, last_run: datetime | None) -> PrefetchEntry:
    return PrefetchEntry(
        source_filename=f"{executable}-ABCD1234.pf",
        executable=executable,
        run_count=1,
        last_run_time=last_run,
    )


def _evtx(executable: str, when: datetime) -> EventLogEntry:
    # Event ID 4688 (process creation); payload_data1 carries the process name,
    # which get_executable_name() reads.
    return EventLogEntry(
        time_created=when,
        event_id=4688,
        record_id=1,
        computer="HOST",
        channel="Security",
        level="Information",
        payload_data1=f"C:\\Windows\\Temp\\{executable}",
    )


def _mft(file_name: str, created: datetime | None) -> MFTEntry:
    return MFTEntry(
        entry_number=1,
        file_name=file_name,
        parent_path="C:\\Windows\\Temp",
        file_path="",
        file_size=1024,
        is_directory=False,
        in_use=True,
        si_created=created,
        si_modified=created,
        si_accessed=created,
        si_mft_modified=created,
        fn_created=created,
        fn_modified=created,
        fn_accessed=created,
        fn_mft_modified=created,
    )


def test_prefetch_last_run_wins_over_evtx_and_mft():
    """Prefetch last-run is the most execution-relevant time -> it wins."""
    prefetch_t = datetime(2026, 7, 27, 3, 15, 0)
    evtx_t = datetime(2026, 7, 27, 3, 14, 0)
    mft_t = datetime(2026, 7, 27, 1, 0, 0)
    ts = _finding_event_time(
        "evil.exe",
        mft_entries=[_mft("evil.exe", mft_t)],
        prefetch_entries=[_prefetch("evil.exe", prefetch_t)],
        event_log_entries=[_evtx("evil.exe", evtx_t)],
    )
    assert ts == prefetch_t.isoformat()


def test_evtx_wins_when_no_prefetch_time():
    """No prefetch (or a null last-run) -> the 4688 execution time is next."""
    evtx_t = datetime(2026, 7, 27, 3, 14, 0)
    mft_t = datetime(2026, 7, 27, 1, 0, 0)
    ts = _finding_event_time(
        "evil.exe",
        mft_entries=[_mft("evil.exe", mft_t)],
        prefetch_entries=[_prefetch("evil.exe", None)],
        event_log_entries=[_evtx("evil.exe", evtx_t)],
    )
    assert ts == evtx_t.isoformat()


def test_mft_creation_used_when_only_disk_artifact_present():
    """Only MFT for this executable -> fall back to its creation time."""
    mft_t = datetime(2026, 7, 27, 1, 0, 0)
    ts = _finding_event_time(
        "evil.exe",
        mft_entries=[_mft("evil.exe", mft_t)],
        prefetch_entries=[],
        event_log_entries=[],
    )
    assert ts == mft_t.isoformat()


def test_returns_none_when_no_event_time_available():
    """No matching entry with a timestamp -> None (the finding omits event_time,
    and the timeline UI degrades rather than plotting a bogus 'now')."""
    assert (
        _finding_event_time(
            "evil.exe",
            mft_entries=[_mft("evil.exe", None)],
            prefetch_entries=[_prefetch("evil.exe", None)],
            event_log_entries=[],
        )
        is None
    )


def test_matches_executable_case_insensitively():
    """Prefetch/evtx match the executable case-insensitively (mirrors the
    engine's own artifact-type matching), so a case difference must not drop the
    event time."""
    prefetch_t = datetime(2026, 7, 27, 3, 15, 0)
    ts = _finding_event_time(
        "EVIL.EXE",
        mft_entries=[],
        prefetch_entries=[_prefetch("evil.exe", prefetch_t)],
        event_log_entries=[],
    )
    assert ts == prefetch_t.isoformat()


def test_ignores_other_executables():
    """An event time belonging to a DIFFERENT executable must not leak into this
    finding -- else the timeline would misattribute one process's time to
    another."""
    other_t = datetime(2026, 7, 27, 3, 15, 0)
    assert (
        _finding_event_time(
            "evil.exe",
            mft_entries=[],
            prefetch_entries=[_prefetch("other.exe", other_t)],
            event_log_entries=[],
        )
        is None
    )


# --- Wiring guard (Lens 1): the helper is useless if its result never lands in
# the finding. This exercises the analyze_artifacts path end to end and goes RED
# if `evidence["event_time"] = event_time` is removed from _generate_finding --
# the pure-helper unit tests above would NOT catch that.


def _ransomware_scenario():
    from pathlib import Path

    b = Path(__file__).resolve().parent.parent / "scenarios/synthetic/02_ransomware"
    return analyze_artifacts(b / "mft.csv", b / "prefetch.csv", b / "evtx.csv")


def test_event_time_reaches_finding_evidence_on_the_analyze_path():
    """Findings from analyze_artifacts (the GUI/connector path) carry a real
    forensic event_time in evidence. Removing the wiring makes this RED."""
    findings = _ransomware_scenario()
    times = [f.to_dict()["evidence"].get("event_time") for f in findings]
    populated = [t for t in times if t]
    assert populated, "no finding carried event_time on the analyze path"
    # The ransomware fixtures give each executable a distinct LastRunTime, so the
    # attack sequence is legible -- not all clustered at one instant.
    assert len(set(populated)) > 1, "event times collapsed to a single instant"


def test_event_time_is_the_forensic_time_not_the_analysis_clock():
    """event_time must be the artifact's event time, NOT detected_at
    (datetime.now()). If they matched, the timeline would just replot 'now'."""
    findings = _ransomware_scenario()
    for f in findings:
        d = f.to_dict()
        ev = d["evidence"].get("event_time")
        if ev:
            assert ev != d["detected_at"], "event_time equals the analysis clock"
            # The fixture events are in 2025; detected_at is the run's wall-clock.
            assert ev.startswith("2025-"), f"unexpected event_time: {ev}"
