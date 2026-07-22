"""Missing-prefetch requires independent execution evidence (SFE-ucjc).

Real-evidence triage (SFE-hp0) ran the engine against the m57-jean Windows XP
image (digitalcorpora M57): MFT 32,781 rows / 846 unique .exe, Prefetch 126
entries (XP cap is 128 -> the LRU cache is AT CAPACITY), and a Security event
log with NO process-creation events (auditing was off). The engine emitted 765
MISSING_ARTIFACT false positives -- 236 of them System Restore point copies
(``System Volume Information\\_restore{GUID}\\RPn\\A00xxxxx.exe``, which are
never executed under that name) and the rest stock Windows binaries
(arp.exe, chkdsk.exe, control.exe...) that simply were not among the 128
most-recently-run programs. Ground truth for m57-jean is finding_counts.total:0.

Root cause: ``detect_missing_execution_artifact`` flagged any .exe present in
the MFT with no matching Prefetch, even with no other evidence it ever ran.
The premise "an .exe on disk without Prefetch is suspicious" is unsound: on a
real disk most executables have never run, aged out of the bounded Prefetch
cache, or are restore-point / WinSxS / installer copies.

The fix: a missing Prefetch is only a signal for a binary we have INDEPENDENT
evidence WAS executed (Event ID 4688 / XP 592) yet has no Prefetch -- the
Prefetch-deletion anti-forensic pattern. An .exe merely existing in the MFT
with no Prefetch and no execution evidence is NOT flagged.

This is consistent with synthetic scenario 05 (05_missing_prefetch): its three
genuine findings (data_exfil.exe, zip_tool.exe, cleaner.exe) all carry Event ID
4688 execution evidence but no Prefetch -- they come through the event-log
branch, which this fix keeps intact.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sift_find_evil.parsers.mft_parser import MFTEntry
from sift_find_evil.parsers.prefetch_parser import PrefetchEntry
from sift_find_evil.self_correction.contradiction_detector import (
    ContradictionDetector,
    ContradictionType,
)
from sift_find_evil.self_correction.engine import SelfCorrectionEngine

_TS = datetime(2008, 7, 21, 1, 30, 0, tzinfo=timezone.utc)


def _exe(entry_number: int, file_name: str, parent: str) -> MFTEntry:
    """Build a benign executable MFT entry with aligned SI/FN timestamps."""
    return MFTEntry(
        entry_number=entry_number,
        file_name=file_name,
        parent_path=parent,
        file_path="",
        file_size=123456,
        is_directory=False,
        in_use=True,
        si_created=_TS,
        si_modified=_TS,
        si_accessed=_TS,
        si_mft_modified=_TS,
        fn_created=_TS,
        fn_modified=_TS,
        fn_accessed=_TS,
        fn_mft_modified=_TS,
    )


def _prefetch(executable: str) -> PrefetchEntry:
    return PrefetchEntry(
        source_filename=f"{executable.upper()}-AAAA0001.pf",
        executable=executable.upper(),
        run_count=7,
        last_run_time=_TS,
    )


class _Event:
    """Minimal EventLogEntry stand-in exposing get_executable_name()."""

    def __init__(self, exe_name: str, time_created: datetime = _TS):
        self._exe = exe_name
        self.time_created = time_created

    def get_executable_name(self):
        return self._exe


# ─── SFE-ucjc: no execution evidence => no missing-prefetch flag ─────────────


def test_no_flag_for_ondisk_exe_without_execution_evidence():
    """An .exe in the MFT with a present-but-sparse Prefetch corpus and NO
    execution evidence must NOT be flagged (the m57-jean flood)."""
    # Prefetch corpus is non-empty but covers a different binary.
    prefetch = [_prefetch("explorer.exe")]
    # A stock system binary and a restore-point copy -- neither has any
    # Event Log execution evidence.
    mft = [
        _exe(1, "arp.exe", "C:\\WINDOWS\\system32"),
        _exe(
            2,
            "A0001968.exe",
            "C:\\System Volume Information\\_restore{72FA17C4}\\RP4",
        ),
    ]

    detector = ContradictionDetector()
    contradictions = detector.detect_all(
        mft, prefetch_entries=prefetch, event_log_entries=[]
    )
    missing = [
        c for c in contradictions if c.type == ContradictionType.MISSING_ARTIFACT
    ]
    assert missing == [], (
        "An on-disk .exe with no execution evidence must not be flagged as a "
        f"missing-prefetch contradiction; got {len(missing)}: "
        f"{[c.description for c in missing]}"
    )


def test_m57_shaped_flood_produces_no_findings():
    """End-to-end m57-jean shape: many uncovered .exe, sparse prefetch, no
    process-creation events -> zero missing-prefetch findings."""
    prefetch = [
        _prefetch(name) for name in ("explorer.exe", "aim6.exe", "iexplore.exe")
    ]
    # 25 stock/restore-point binaries with no execution evidence.
    mft = [_exe(100 + i, f"sysbin{i}.exe", "C:\\WINDOWS\\system32") for i in range(20)]
    mft += [
        _exe(
            200 + i, f"A000{i:04d}.exe", "C:\\System Volume Information\\_restore\\RP4"
        )
        for i in range(5)
    ]

    findings = SelfCorrectionEngine().analyze(
        mft_entries=mft, prefetch_entries=prefetch, event_log_entries=[]
    )
    missing = [
        f
        for f in findings
        if any(c.type == ContradictionType.MISSING_ARTIFACT for c in f.contradictions)
    ]
    assert missing == [], (
        f"m57-shaped input must yield zero missing-prefetch findings; got "
        f"{len(missing)} (e.g. {[f.title for f in missing[:3]]})"
    )


# ─── The genuine signal must survive: executed-but-no-prefetch ───────────────


def test_executed_binary_without_prefetch_is_still_flagged():
    """Prefetch-deletion signal: a binary with Event Log 4688 execution
    evidence but no matching Prefetch IS still flagged (scenario-05 shape)."""
    prefetch = [_prefetch("explorer.exe")]  # non-empty, different binary
    mft = [_exe(1, "cleaner.exe", "C:\\Users\\insider\\AppData\\Local\\Temp")]
    events = [_Event("cleaner.exe")]

    detector = ContradictionDetector()
    contradictions = detector.detect_all(
        mft, prefetch_entries=prefetch, event_log_entries=events
    )
    missing = [
        c for c in contradictions if c.type == ContradictionType.MISSING_ARTIFACT
    ]
    assert len(missing) == 1, (
        "A binary executed (Event Log 4688) with no Prefetch is a genuine "
        f"prefetch-deletion signal and must be flagged; got {len(missing)}"
    )


def test_executed_binary_missing_prefetch_deduped_across_mft_rows():
    """Repeated MFT rows for one executed binary dedup to a single finding
    with confidence > 0 (preserves the SFE-jji dedup intent)."""
    prefetch = [_prefetch("explorer.exe")]
    mft = [
        _exe(100 + i, "cleaner.exe", "C:\\Users\\insider\\AppData\\Local\\Temp")
        for i in range(8)
    ]
    events = [_Event("cleaner.exe")]

    findings = SelfCorrectionEngine().analyze(
        mft_entries=mft, prefetch_entries=prefetch, event_log_entries=events
    )
    cleaner = [f for f in findings if "cleaner.exe" in f.title.lower()]
    assert len(cleaner) == 1, f"Expected one cleaner.exe finding, got {len(cleaner)}"
    missing = [
        c
        for c in cleaner[0].contradictions
        if c.type == ContradictionType.MISSING_ARTIFACT
    ]
    assert (
        len(missing) == 1
    ), f"Finding should hold one missing-artifact contradiction; got {len(missing)}"
    assert cleaner[0].confidence > 0.0
