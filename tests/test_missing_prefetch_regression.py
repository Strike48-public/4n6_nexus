"""Regression tests for missing-prefetch over-firing (SFE-jji).

Real-evidence triage (SFE-hp0) extracted the LoneWolf $MFT (144,425 file
records / 184,910 MFTECmd entries) and ran ``SelfCorrectionEngine.analyze``
with an empty prefetch and event-log corpus. The engine emitted 1,117 MEDIUM
"Suspicious Activity" findings -- every one of them a legitimate
Microsoft/Windows binary (OneDrive.exe, winload.exe, consent.exe...), every
one at confidence=0.00, and at least one carrying the identical
``missing_artifact`` contradiction logged 8 times.

Three confirmed defects, all rooted in ``detect_missing_execution_artifact``
firing for every ``.exe`` when no Prefetch evidence exists:

1. ZERO-CONFIDENCE EMISSION -- a missing-prefetch finding with no Prefetch
   corpus to compare against is pure noise. A missing artifact is only
   meaningful *relative to a present Prefetch corpus*.
2. DUPLICATE CONTRADICTIONS -- the same exe appearing N times in the MFT
   yielded N identical contradictions (saw 8x for one binary).
3. OVER-FIRING WHEN PREFETCH ABSENT -- blanket "exe in MFT but no Prefetch"
   for every executable on a normal disk.

The fix: only emit ``MISSING_ARTIFACT`` when the Prefetch corpus is non-empty,
and dedup contradictions by (exe_name, contradiction_type). These tests pin
that behaviour while the existing scenario 05 (Prefetch present, 3 genuine
missing-artifact findings) and scenarios 03/10 (timestomps) must stay intact
-- enforced by the scenario harness, not duplicated here.
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


def _exe_entry(entry_number: int, file_name: str, parent: str) -> MFTEntry:
    """Build a benign executable MFT entry with aligned timestamps."""
    ts = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    return MFTEntry(
        entry_number=entry_number,
        file_name=file_name,
        parent_path=parent,
        file_path="",
        file_size=123456,
        is_directory=False,
        in_use=True,
        si_created=ts,
        si_modified=ts,
        si_accessed=ts,
        si_mft_modified=ts,
        fn_created=ts,
        fn_modified=ts,
        fn_accessed=ts,
        fn_mft_modified=ts,
    )


def _prefetch_entry(executable: str) -> PrefetchEntry:
    """Build a Prefetch entry so the corpus is non-empty."""
    return PrefetchEntry(
        source_filename=f"{executable.upper()}-AAAA0001.pf",
        executable=executable.upper(),
        run_count=10,
        last_run_time=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
    )


# ─── Issue 3: over-firing when Prefetch corpus is empty ──────────────────────


def test_no_missing_artifact_when_prefetch_corpus_empty():
    """A normal-disk MFT with NO prefetch produces zero missing-artifact noise.

    Mirrors the real LoneWolf triage: 184k MFT entries, empty prefetch/evtx.
    A missing Prefetch is only meaningful relative to a present Prefetch
    corpus, so an empty corpus must yield no MISSING_ARTIFACT contradictions.
    """
    mft = [
        _exe_entry(
            1, "OneDrive.exe", "C:\\Users\\u\\AppData\\Local\\Microsoft\\OneDrive"
        ),
        _exe_entry(2, "winload.exe", "C:\\Windows\\System32"),
        _exe_entry(3, "consent.exe", "C:\\Windows\\System32"),
    ]

    detector = ContradictionDetector()
    contradictions = detector.detect_all(mft, prefetch_entries=[], event_log_entries=[])

    missing = [
        c for c in contradictions if c.type == ContradictionType.MISSING_ARTIFACT
    ]
    assert missing == [], (
        "No MISSING_ARTIFACT should fire when the Prefetch corpus is empty; "
        f"got {len(missing)}"
    )


def test_engine_emits_no_findings_for_normal_mft_without_prefetch():
    """End-to-end: normal binaries, empty prefetch/evtx -> zero findings.

    This is the exact shape that produced 1,117 confidence=0.00 false
    positives before the fix.
    """
    mft = [
        _exe_entry(
            1, "OneDrive.exe", "C:\\Users\\u\\AppData\\Local\\Microsoft\\OneDrive"
        ),
        _exe_entry(2, "winload.exe", "C:\\Windows\\System32"),
        _exe_entry(3, "ie4uinit.exe", "C:\\Windows\\System32"),
        _exe_entry(4, "FlashPlayerApp.exe", "C:\\Windows\\System32\\Macromed\\Flash"),
    ]

    findings = SelfCorrectionEngine().analyze(
        mft_entries=mft, prefetch_entries=[], event_log_entries=[]
    )

    assert findings == [], (
        f"Normal MFT with no Prefetch corpus must yield zero findings; "
        f"got {len(findings)} (e.g. {[f.title for f in findings[:3]]})"
    )


# ─── Issue 2: duplicate contradictions for repeated exe names ────────────────


def test_missing_artifact_deduped_across_repeated_mft_entries():
    """The same exe appearing N times yields ONE missing-artifact contradiction.

    On the real disk a single binary (multiple hardlinks/paths/instances)
    produced the identical missing_artifact contradiction 8 times. With a
    non-empty Prefetch corpus that legitimately lacks the suspect exe, the
    detector must dedup by (exe_name, contradiction_type).
    """
    # cleaner.exe appears 8 times in the MFT (distinct entry numbers).
    mft = [_exe_entry(100 + i, "cleaner.exe", "C:\\Temp") for i in range(8)]
    # Non-empty corpus, but for a DIFFERENT executable -> cleaner.exe is
    # genuinely missing its Prefetch.
    prefetch = [_prefetch_entry("explorer.exe")]

    detector = ContradictionDetector()
    contradictions = detector.detect_all(
        mft, prefetch_entries=prefetch, event_log_entries=[]
    )

    missing = [
        c for c in contradictions if c.type == ContradictionType.MISSING_ARTIFACT
    ]
    assert len(missing) == 1, (
        f"Repeated exe must dedup to a single missing-artifact contradiction; "
        f"got {len(missing)}"
    )


def test_single_finding_has_no_duplicate_contradictions():
    """The generated finding carries exactly one missing-artifact contradiction."""
    mft = [_exe_entry(100 + i, "cleaner.exe", "C:\\Temp") for i in range(8)]
    prefetch = [_prefetch_entry("explorer.exe")]

    findings = SelfCorrectionEngine().analyze(
        mft_entries=mft, prefetch_entries=prefetch, event_log_entries=[]
    )

    cleaner = [f for f in findings if "cleaner.exe" in f.title.lower()]
    assert len(cleaner) == 1, f"Expected one cleaner.exe finding, got {len(cleaner)}"
    missing = [
        c
        for c in cleaner[0].contradictions
        if c.type == ContradictionType.MISSING_ARTIFACT
    ]
    assert len(missing) == 1, (
        f"Finding should hold one missing-artifact contradiction, not a "
        f"duplicated stack; got {len(missing)}"
    )
    # Confidence must not be crushed to 0.00 by a stack of identical penalties.
    assert cleaner[0].confidence > 0.0, (
        "A single missing-artifact contradiction must not produce a "
        "0.00-confidence finding"
    )
