"""Coverage-focused tests for lnk_jumplist_detector helpers and edge branches.

Targets the private path-normalization helpers and the empty/non-sensitive
guard branches inside the detector that the behavioural suite in
test_lnk_jumplist_detector.py does not exercise directly.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sift_find_evil.detectors.lnk_jumplist_detector import (
    LnkJumpListDetector,
    _basename,
    _extension,
    _in_user_writable,
    _is_known_signed_autostart,
    _is_unc_path,
    _iso_or_empty,
)
from sift_find_evil.parsers.lnk_jumplist_parser import JumpListEntry


_TS = datetime(2025, 3, 15, 10, 30, 0, tzinfo=timezone.utc)


def _jl(
    *,
    app_id: str = "9d1f905ce5044aee",
    app_name: str = "Microsoft Excel",
    entry_type: str = "automatic",
    target_path: str = "\\\\fileserver\\share\\budget.xlsx",
    drive_type: str = "network",
    opened_time=_TS,
    jumplist_path: str = "/ev/excel.automaticDestinations-ms",
) -> JumpListEntry:
    return JumpListEntry(
        app_id=app_id,
        app_name=app_name,
        entry_type=entry_type,
        target_path=target_path,
        drive_type=drive_type,
        opened_time=opened_time,
        jumplist_path=jumplist_path,
    )


# --- helper guard branches --------------------------------------------------


def test_basename_empty_returns_empty():
    # Line 168: empty path short-circuit.
    assert _basename("") == ""


def test_extension_without_dot_returns_empty():
    # Line 176: name with no '.' yields empty extension.
    assert _extension("README") == ""


def test_extension_with_dot_returns_lowercase():
    # Contrast: confirms the non-guard branch still returns the suffix.
    assert _extension("Report.PDF") == "pdf"


def test_in_user_writable_empty_returns_none():
    # Line 187: empty path short-circuits before lowering/scanning.
    assert _in_user_writable("") is None


def test_in_user_writable_matches_fragment():
    assert _in_user_writable("C:\\Users\\Public\\x.exe") == "users\\public"


def test_is_known_signed_autostart_empty_returns_false():
    # Line 207: empty target path is not a signed autostart.
    assert _is_known_signed_autostart("") is False


def test_is_unc_path_empty_returns_false():
    # Line 214: empty path is not a UNC path.
    assert _is_unc_path("") is False


def test_is_unc_path_true_for_unc():
    assert _is_unc_path("\\\\server\\share\\file.docx") is True


def test_iso_or_empty_none_returns_empty():
    # Line 587: None timestamp serializes to empty string.
    assert _iso_or_empty(None) == ""


def test_iso_or_empty_datetime_serializes():
    assert _iso_or_empty(_TS) == _TS.isoformat()


# --- detector guard branches ------------------------------------------------


def test_removable_network_skips_jumplist_with_empty_target():
    # Line 302: jumplist entry with falsy target_path is skipped in the
    # removable/network branch.
    entry = _jl(target_path="", drive_type="removable")
    findings = LnkJumpListDetector().analyze(jumplist_entries=[entry])
    assert findings == []


def test_removable_network_skips_jumplist_with_nonsensitive_target():
    # Line 302: jumplist entry on removable media but a non-sensitive
    # extension is skipped (the `not self._is_sensitive` half of the guard).
    entry = _jl(target_path="E:\\tools\\setup.exe", drive_type="removable")
    findings = LnkJumpListDetector().analyze(jumplist_entries=[entry])
    assert findings == []


def test_jumplist_unc_path_with_nonsensitive_ext_skipped():
    # Line 512: UNC path but a non-sensitive extension is filtered out of the
    # UNC-indicator branch, producing no finding.
    entry = _jl(target_path="\\\\server\\share\\notes.exe", drive_type="unknown")
    findings = LnkJumpListDetector().analyze(jumplist_entries=[entry])
    assert findings == []


def test_jumplist_unc_path_with_sensitive_ext_still_flagged():
    # Contrast for line 512: a sensitive UNC target on a non-network drive
    # type does produce the UNC indicator finding.
    entry = _jl(target_path="\\\\server\\share\\notes.pdf", drive_type="unknown")
    findings = LnkJumpListDetector().analyze(jumplist_entries=[entry])
    assert len(findings) == 1
    assert findings[0].confidence == 0.55
