"""detect_all indexes the MFT once, not once per prefetch entry (SFE-cj4n).

``ContradictionDetector.detect_all`` matched each prefetch entry to its MFT entry
with a full list comprehension over ``mft_entries`` -- O(prefetch x MFT). On a
10GB image (millions of MFT rows) that nested scan is the dominant CPU cost of the
core detector. The fix builds a ``{file_name_lower -> first MFTEntry}`` index in a
single pass, then looks up in O(1).

Two invariants are pinned here:
  1. BEHAVIOR-PRESERVING: the old code took ``matching_mft[0]`` -- the FIRST MFT
     entry (by list order) whose name matches. The index must keep the first
     occurrence per name, so a duplicate-name MFT yields the identical match.
  2. SINGLE PASS: the MFT is traversed a bounded number of times regardless of the
     prefetch count -- so 1 prefetch and 50 prefetch entries traverse the same MFT
     the same number of times (not 50x).
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from sift_find_evil.self_correction.contradiction_detector import (
    ContradictionDetector,
    ContradictionType,
)

_T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _mft(file_name, *, si_modified=None, fn_modified=None):
    return SimpleNamespace(
        file_name=file_name,
        file_path=f"C:\\\\{file_name}",
        si_modified=si_modified,
        fn_modified=fn_modified,
        get_modification_time=lambda prefer_fn=False: si_modified,
        get_creation_time=lambda: None,
    )


def _prefetch(executable, last_run_time=None):
    return SimpleNamespace(executable=executable, last_run_time=last_run_time)


class _CountingList(list):
    """A list that counts how many times it is fully iterated.

    ``detect_all``'s old per-prefetch comprehension iterates the MFT list once per
    prefetch entry; the indexed version iterates it a fixed number of times
    independent of the prefetch count. Counting __iter__ distinguishes the two.
    """

    def __init__(self, *args):
        super().__init__(*args)
        self.iterations = 0

    def __iter__(self):
        self.iterations += 1
        return super().__iter__()


def test_mft_iterated_a_bounded_number_of_times_regardless_of_prefetch_count():
    """The MFT traversal count must not scale with the number of prefetch entries."""
    detector = ContradictionDetector()
    mft = _CountingList(_mft(f"bin{i}.exe") for i in range(5))

    # One prefetch entry.
    mft.iterations = 0
    detector.detect_all(mft, [_prefetch("bin0.exe")], [])
    few = mft.iterations

    # Many prefetch entries against the SAME MFT list.
    mft.iterations = 0
    detector.detect_all(mft, [_prefetch(f"bin{i}.exe") for i in range(50)], [])
    many = mft.iterations

    # Indexed: the MFT is traversed the same fixed number of times either way.
    # The pre-fix code traversed it once per prefetch entry, so `many` would be
    # ~50x `few`. Equality is the strongest statement of "indexed once".
    assert many == few, (
        f"MFT traversed {many}x for 50 prefetch entries vs {few}x for 1 "
        "-- the scan still scales with prefetch count (index regressed)"
    )


def test_first_matching_mft_entry_is_used_on_duplicate_names():
    """Behavior-preserving: with two MFT rows sharing a name, the FIRST one wins
    (matches the old ``matching_mft[0]``). The causality check reads the matched
    entry's modification time, so the first row's timestamp must drive the result."""
    # First row: modified LONG after run -> a clear causality violation.
    # Second row (same name): modified before run -> no violation.
    run = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    late = datetime(2026, 1, 1, 15, 0, 0, tzinfo=timezone.utc)
    early = datetime(2026, 1, 1, 8, 0, 0, tzinfo=timezone.utc)
    first = _mft("dup.exe", si_modified=late, fn_modified=late)
    second = _mft("dup.exe", si_modified=early, fn_modified=early)

    detector = ContradictionDetector()
    contradictions = detector.detect_all(
        [first, second], [_prefetch("dup.exe", last_run_time=run)], []
    )

    # The FIRST entry (late mod) drives a causality violation; if the index had
    # kept the SECOND entry instead, no causality contradiction would be emitted.
    kinds = {c.type for c in contradictions}
    assert ContradictionType.CAUSALITY_VIOLATION in kinds, (
        "first-match semantics broken: the duplicate-name index did not keep the "
        "first MFT row"
    )


def test_case_insensitive_match_preserved():
    """The old comparison lowercased both sides; the index must too."""
    detector = ContradictionDetector()
    run = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    late = datetime(2026, 1, 1, 15, 0, 0, tzinfo=timezone.utc)
    mft = [_mft("Evil.EXE", si_modified=late, fn_modified=late)]

    contradictions = detector.detect_all(
        mft, [_prefetch("evil.exe", last_run_time=run)], []
    )
    assert any(
        c.type is ContradictionType.CAUSALITY_VIOLATION for c in contradictions
    ), "case-insensitive MFT match regressed"
