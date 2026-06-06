"""Coverage top-up for VolatilityRunner uncovered lines.

Targets specific uncovered branches in
``sift_find_evil/memory/volatility_runner.py``:

* ``run_psscan`` (lines 279-280) — the windows.psscan invocation path that
  the existing suite never exercises (it only drives pslist on the Windows
  process side).
* ``_walk`` non-dict skip (line 386) — Volatility's JSON renderer can emit
  bare scalars/lists alongside dict rows; the flattener must skip them
  without crashing.
* ``_to_int`` coercion success and failure (lines 399-400) — the int()
  success path on string input and the TypeError/ValueError fallback to
  None.

We never invoke the real ``vol`` binary; subprocess.run and shutil.which
are monkeypatched exactly as in tests/test_volatility_runner.py.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from sift_find_evil.memory.volatility_runner import (
    ProcessRow,
    VolatilityRunner,
    _parse_json_output,
    _to_int,
    _walk,
)


# -- fixture helpers (mirror tests/test_volatility_runner.py) ---------------


def _fake_memory_image(tmp_path: Path) -> Path:
    """Produce a non-empty file that passes VolatilityRunner.__init__."""
    image = tmp_path / "fake.dmp"
    image.write_bytes(b"MEMORYIMAGE")
    return image


def _patch_which(
    monkeypatch: pytest.MonkeyPatch, path: str | None = "/fake/vol"
) -> None:
    monkeypatch.setattr(
        "sift_find_evil.memory.volatility_runner.shutil.which",
        lambda name: path,
    )


class _FakeCompleted:
    """Stand-in for subprocess.CompletedProcess."""

    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


# -- run_psscan (lines 279-280) --------------------------------------------


def test_run_psscan_invokes_psscan_plugin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run_psscan must shell out to windows.psscan.PsScan and map rows.

    psscan is the carve-from-pool scanner that surfaces hidden/terminated
    processes pslist misses, so the runner must drive a distinct plugin
    name and still coerce rows into ProcessRow.
    """
    image = _fake_memory_image(tmp_path)
    _patch_which(monkeypatch)

    captured: dict = {}
    payload = json.dumps(
        [
            {
                "PID": 666,
                "PPID": 4,
                "ImageFileName": "hidden.exe",
                "CreateTime": "2024-01-01T00:00:00",
                "ExitTime": "2024-01-01T00:05:00",
                "__children": [],
            },
        ]
    )

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return _FakeCompleted(stdout=payload)

    monkeypatch.setattr(subprocess, "run", fake_run)

    rows = VolatilityRunner(image).run_psscan()

    assert captured["argv"][-1] == "windows.psscan.PsScan"
    assert len(rows) == 1
    assert isinstance(rows[0], ProcessRow)
    assert rows[0].pid == 666
    assert rows[0].name == "hidden.exe"
    assert rows[0].exit_time == "2024-01-01T00:05:00"


# -- _walk non-dict skip (line 386) ----------------------------------------


def test_walk_skips_non_dict_nodes() -> None:
    """_walk must skip bare scalars/lists without appending or recursing.

    Volatility's JSON tree is normally a list of dict rows, but a
    malformed or odd plugin renderer can interleave non-dict entries. The
    flattener should drop them rather than raise on .get / .items.
    """
    flat: list[dict] = []
    _walk([42, "stray", None, ["nested"], {"PID": 7, "__children": []}], flat)
    assert flat == [{"PID": 7}]


def test_parse_json_output_skips_non_dict_top_level_entries() -> None:
    """End-to-end through _parse_json_output: non-dict siblings are dropped."""
    payload = json.dumps([1, {"PID": 2, "__children": []}, "x"])
    rows = _parse_json_output(payload)
    assert rows == [{"PID": 2}]


# -- _to_int coercion success + fallback (lines 399-400) -------------------


def test_to_int_coerces_numeric_string() -> None:
    """A numeric string flows through int() (line 399)."""
    assert _to_int("4242") == 4242


def test_to_int_passes_through_native_int() -> None:
    assert _to_int(4) == 4


def test_to_int_returns_none_for_unparseable_string() -> None:
    """A non-numeric string trips ValueError and falls back to None (line 400)."""
    assert _to_int("0xdeadbeef") is None


def test_to_int_returns_none_for_uncoercible_type() -> None:
    """A type int() cannot handle trips TypeError and falls back to None (line 400)."""
    assert _to_int(["not", "an", "int"]) is None


def test_to_int_returns_none_for_empty_and_none() -> None:
    assert _to_int("") is None
    assert _to_int(None) is None
