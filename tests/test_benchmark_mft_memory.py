"""MFT ingestion memory benchmark + a per-entry footprint ceiling (SFE-cj4n).

The MFT is the largest artifact on a real image -- millions of rows on a 10GB+
disk -- and ``MFTParser.parse_csv`` materializes the whole ``list[MFTEntry]`` in
RAM. Before bounding that ingestion you must be able to MEASURE it, so this
module is the measurement foundation Part B builds on. Two guards live here:

  1. ``test_mft_parse_peak_memory_per_entry_stays_bounded`` (ALWAYS runs, in CI):
     parses a modest synthetic MFT under ``tracemalloc`` and asserts the PEAK
     Python-heap cost stays under a PER-ENTRY ceiling. Per-entry (not absolute)
     makes the bound size-independent: a footprint regression -- a new heavy
     field on ``MFTEntry``, a retained transient buffer in the parse loop, an
     accidental second resident copy -- trips it at any row count. Baseline
     measured ~867 B/entry on the realistic fixture; the ceiling carries headroom
     so it catches a gross (~2x) regression without tracemalloc-noise flakiness.

  2. ``test_mft_ingestion_memory_benchmark`` (OPT-IN, ``benchmark`` marker): the
     quotable large-scale run. CI executes a bare ``pytest -q`` with no
     ``-m "not benchmark"`` de-selection, so the marker alone would NOT keep this
     out of CI -- the heavy body is therefore SKIPPED unless
     ``RUN_MFT_MEM_BENCHMARK=1`` is set. Row count is ``MFT_BENCHMARK_ROWS``
     (default 1,000,000 ~= 250MB CSV + ~0.9GB RAM; a genuine 10GB+ image is
     ~40M rows, which needs ~10GB temp disk AND ~35GB RAM, so size it to the
     host). It
     reports peak/resident MB, per-entry bytes, and process RSS, then asserts the
     SAME per-entry ceiling holds at scale (the property must not degrade with
     size).

Run the large benchmark out-of-band, e.g. ~40M rows for a ~10GB CSV::

    RUN_MFT_MEM_BENCHMARK=1 MFT_BENCHMARK_ROWS=40000000 \
        pytest -q -s -m benchmark tests/test_benchmark_mft_memory.py
"""

from __future__ import annotations

import csv
import os
import resource
import tracemalloc
from pathlib import Path
from typing import Tuple

import pytest

from sift_find_evil.parsers.mft_parser import MFTParser

# Per-entry PEAK-memory ceiling for a fully-populated MFTEntry (all 8 timestamps
# parsed). Baseline is ~867 B/entry on the realistic fixture below (distinct
# names/paths/timestamps, so string interning does not deflate the figure the way
# all-identical values would; ~915 before MFTEntry gained slots=True, SFE-s0nb),
# dominated by the eight per-row datetime objects. At 1100 the baseline sits ~21%
# under the ceiling (~27% above baseline) -- comfortably clear of the measured
# <1% run-to-run variance, but well below a doubled footprint, so a real
# per-entry regression still trips it. This ceiling
# guards against GROSS bloat, not the ~5% slots delta; that micro-optimization
# has its own crisp guard in test_mft_parser.py (no per-instance __dict__).
MAX_BYTES_PER_ENTRY = 1100

# Rows for the always-run guard: large enough to amortize fixed interpreter
# overhead into a stable per-entry figure, small enough to parse in well under a
# second and cost only a few MB of temp disk.
_GUARD_ROWS = 20_000

# The columns the parser actually reads (mft_parser.py:163-211). Populating all
# of them makes the measured entry a realistic full-weight entry rather than a
# sparse one that would understate the footprint.
_MFT_COLUMNS = [
    "EntryNumber",
    "FileName",
    "ParentPath",
    "FileSize",
    "IsDirectory",
    "InUse",
    "Created0x10",
    "LastModified0x10",
    "LastAccess0x10",
    "LastRecordChange0x10",
    "Created0x30",
    "LastModified0x30",
    "LastAccess0x30",
    "LastRecordChange0x30",
]


def _synthetic_row(i: int) -> list:
    """One realistic MFTECmd row derived deterministically from ``i``.

    Values VARY per row -- distinct filenames, a reused-but-diverse directory
    tree (real MFTs reuse directories heavily but span many of them), and
    distinct valid timestamps -- so the measured footprint reflects real MFT
    memory. All-identical values would let CPython share/intern strings and the
    parser reuse fewer objects, deflating the per-entry figure ~8% below reality
    (measured 848 identical vs ~913 distinct) and calibrating the ceiling too
    optimistically. Deterministic (no RNG) so the measurement is reproducible.
    """
    # Distinct, variable-length filename.
    name = f"file_{i}_{'x' * (i % 20)}.exe"
    # Diverse directory tree: many users/dirs, reused across files like a real FS.
    parent = rf"C:\Users\user{i % 500}\AppData\Local\Temp\dir{i % 1000}"
    # Distinct, always-valid timestamps (days 1-28, months 1-12 dodge calendar
    # edge cases). MFTECmd's "YYYY-MM-DD HH:MM:SS" shape the parser accepts.
    ts = (
        f"2026-{1 + i % 12:02d}-{1 + i % 28:02d} {i % 24:02d}:{i % 60:02d}:{i % 60:02d}"
    )
    return [i, name, parent, 4096 + i, "False", "True", ts, ts, ts, ts, ts, ts, ts, ts]


def _write_synthetic_mft(path: Path, n_rows: int) -> None:
    """Stream a synthetic MFTECmd-shaped CSV to ``path`` one row at a time.

    Written row-by-row (never a materialized list of ``n_rows``) so generating a
    10GB fixture never itself becomes the memory bottleneck the benchmark is
    trying to measure.
    """
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(_MFT_COLUMNS)
        for i in range(n_rows):
            writer.writerow(_synthetic_row(i))


def _measure_parse(csv_path: Path) -> Tuple[int, int, int]:
    """Parse ``csv_path`` under tracemalloc.

    Returns ``(n_entries, peak_bytes, resident_bytes)`` where ``peak`` is the max
    traced Python-heap size during the parse and ``resident`` is the size still
    live while the returned list is held -- i.e. the cost of keeping the whole
    ``list[MFTEntry]`` in RAM.
    """
    tracemalloc.start()
    try:
        entries = MFTParser().parse_csv(str(csv_path))
        # Read the counters while ``entries`` is still referenced so ``resident``
        # reflects the retained list, not a post-GC value.
        resident, peak = tracemalloc.get_traced_memory()
        n = len(entries)
    finally:
        tracemalloc.stop()
    return n, peak, resident


@pytest.mark.unit
def test_mft_parse_peak_memory_per_entry_stays_bounded(tmp_path: Path) -> None:
    """Peak parse memory must stay under a per-entry ceiling (regression guard).

    This is the size-independent form of the issue's "memory ceiling assertion":
    it pins the marginal cost of an MFT entry, so any change that inflates the
    per-entry footprint fails here regardless of image size. Mutation check:
    lowering ``MAX_BYTES_PER_ENTRY`` below the ~867 baseline, or adding a heavy
    field to ``MFTEntry``, turns this red.
    """
    csv_path = tmp_path / "mft.csv"
    _write_synthetic_mft(csv_path, _GUARD_ROWS)

    n, peak, _resident = _measure_parse(csv_path)

    assert n == _GUARD_ROWS, "synthetic MFT did not parse to the expected row count"
    bytes_per_entry = peak / n
    assert bytes_per_entry < MAX_BYTES_PER_ENTRY, (
        f"MFT parse peak {bytes_per_entry:.0f} B/entry exceeds the "
        f"{MAX_BYTES_PER_ENTRY} B/entry ceiling -- the per-entry footprint "
        "regressed (heavier MFTEntry, retained transient, or a second resident copy)"
    )


@pytest.mark.benchmark
def test_mft_ingestion_memory_benchmark(tmp_path: Path) -> None:
    """Large-scale MFT ingestion memory benchmark (opt-in, out-of-band).

    Skipped unless ``RUN_MFT_MEM_BENCHMARK=1`` -- CI runs a bare ``pytest`` with
    no marker de-selection, so env-gating (not the marker) is what keeps the
    heavy 10GB-class body out of the required job. Asserts the same per-entry
    ceiling holds at scale, proving the bound does not degrade with row count.
    """
    if os.environ.get("RUN_MFT_MEM_BENCHMARK") != "1":
        pytest.skip("set RUN_MFT_MEM_BENCHMARK=1 to run the large MFT memory benchmark")

    n_rows = int(os.environ.get("MFT_BENCHMARK_ROWS", "1000000"))
    csv_path = tmp_path / "mft_large.csv"
    _write_synthetic_mft(csv_path, n_rows)
    csv_mb = csv_path.stat().st_size / 1e6

    n, peak, resident = _measure_parse(csv_path)
    rss_mb = (
        resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1e3
    )  # KB -> MB on Linux
    bytes_per_entry = peak / n

    # -s surfaces this; it is the quotable line for the benchmark.
    print(
        f"\n[MFT MEMORY BENCHMARK] rows={n:,} csv={csv_mb:,.0f}MB "
        f"peak={peak / 1e6:,.0f}MB resident={resident / 1e6:,.0f}MB "
        f"maxrss={rss_mb:,.0f}MB peak_bytes/entry={bytes_per_entry:.0f}"
    )

    assert n == n_rows, "large synthetic MFT did not parse to the expected row count"
    assert bytes_per_entry < MAX_BYTES_PER_ENTRY, (
        f"at {n:,} rows the MFT parse peak is {bytes_per_entry:.0f} B/entry, over "
        f"the {MAX_BYTES_PER_ENTRY} B/entry ceiling -- ingestion does not scale"
    )
