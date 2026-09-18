"""CLI safety hardening from the foundation review (post SFE-13yw).

Three narrow defensive fixes, none on the detection path:

1. Evidence-dir write guard: `--output` (and the derived `.hardened.json`) must
   not resolve into a read-only evidence directory (`/cases`, `/mnt`, `/media`,
   or any `evidence/` component) - enforced AFTER symlink resolution so a
   symlink into evidence is caught too. (Project CLAUDE.md: never write to
   evidence dirs; route output to ./analysis, ./exports, ./reports.)
2. Terminal-injection: adversary-controlled evidence strings (registry values,
   command lines) printed to the examiner's stdout must have ANSI escapes and
   C0 control chars stripped, so a crafted artifact cannot drive the terminal.
3. Private-key path: a failed pinned-key load must not echo the key file path.

RED-first: `_resolves_into_evidence_dir`, `_terminal_safe` did not exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sift_find_evil.cli import (
    _resolves_into_evidence_dir,
    _terminal_safe,
    _write_output,
)


# --- 1. Evidence-dir write guard -------------------------------------------


def test_normal_output_paths_are_allowed(tmp_path: Path) -> None:
    assert _resolves_into_evidence_dir(tmp_path / "reports" / "findings.json") is False
    assert _resolves_into_evidence_dir(Path("./analysis/out.json")) is False


def test_evidence_component_is_rejected(tmp_path: Path) -> None:
    assert _resolves_into_evidence_dir(tmp_path / "evidence" / "findings.json") is True


@pytest.mark.parametrize("root", ["/cases", "/mnt", "/media"])
def test_absolute_evidence_roots_are_rejected(root: str) -> None:
    assert _resolves_into_evidence_dir(Path(root) / "INC-001" / "findings.json") is True


def test_symlink_into_evidence_is_rejected(tmp_path: Path) -> None:
    """A symlink whose target resolves into an evidence dir must be caught -
    a path-string check alone would miss it."""
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    target = evidence / "findings.json"
    link = tmp_path / "innocent.json"
    link.symlink_to(target)
    assert _resolves_into_evidence_dir(link) is True


def test_evidence_substring_that_is_not_a_component_is_allowed(tmp_path: Path) -> None:
    """`evidence_backup` is a substring, not a path component - must NOT trip."""
    assert _resolves_into_evidence_dir(tmp_path / "evidence_backup" / "x.json") is False


def test_write_output_refuses_evidence_dir(tmp_path: Path) -> None:
    """The central write backstop guards every caller (demo included), not just
    the commands that check --output up front."""
    evidence_target = tmp_path / "evidence" / "findings.json"
    (tmp_path / "evidence").mkdir()
    with pytest.raises(SystemExit) as exc:
        _write_output([], evidence_target)
    assert exc.value.code == 1
    assert not evidence_target.exists()  # nothing written


def test_write_output_allows_normal_dir(tmp_path: Path) -> None:
    out = tmp_path / "reports" / "findings.json"
    out.parent.mkdir()
    _write_output([], out)  # must not raise
    assert out.exists()


# --- 2. Terminal-injection sanitize ----------------------------------------


def test_terminal_safe_strips_ansi_escape() -> None:
    # A crafted registry value that clears the screen + recolors the terminal.
    hostile = "evil.exe\x1b[2J\x1b[31mCLEARED"
    out = _terminal_safe(hostile)
    assert "\x1b" not in out
    assert "evil.exe" in out and "CLEARED" in out


def test_terminal_safe_strips_c0_control_but_keeps_newline_tab() -> None:
    out = _terminal_safe("a\x07b\x00c\td\ne")  # bell + NUL removed; tab/newline kept
    assert "\x07" not in out and "\x00" not in out
    assert "\t" in out and "\n" in out
    assert "a" in out and "e" in out


def test_terminal_safe_leaves_ordinary_text_unchanged() -> None:
    ordinary = r"C:\Windows\system32\vssadmin.exe Create Shadow /AutoRetry=15"
    assert _terminal_safe(ordinary) == ordinary


def test_terminal_safe_handles_non_str() -> None:
    # evidence values may be ints/None; the helper coerces without raising.
    assert _terminal_safe(5) == "5"
    assert _terminal_safe(None) == "None"
