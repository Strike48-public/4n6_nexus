"""Unit tests for the YaraScanner wrapper.

yara-python is an optional dependency. Tests skip gracefully on hosts where
the native libyara is not installed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

yara = pytest.importorskip("yara")

from sift_find_evil.yara_scan.scanner import (  # noqa: E402 — must import after yara-check
    MissingYaraError,
    YaraScanner,
)


# -- rule source helpers ---------------------------------------------------

_MZ_RULE = """
rule mz_header {
    meta:
        description = "Detects MZ header (PE/DOS executable)"
        severity = "low"
    strings:
        $mz = "MZ"
    condition:
        $mz at 0
}
"""

_UPX_RULE = """
rule upx_packed {
    meta:
        description = "Detects UPX section names"
        severity = "medium"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
    condition:
        any of them
}
"""

_BROKEN_RULE = """
rule totally_broken {
    strings:
        $missing_semicolon = "foo"
    condition:
        this_is_not_valid_yara_syntax
}
"""


# -- fixtures --------------------------------------------------------------


@pytest.fixture
def rules_dir(tmp_path: Path) -> Path:
    """One .yar file per rule so compile_from_directory must aggregate."""
    (tmp_path / "mz.yar").write_text(_MZ_RULE)
    (tmp_path / "upx.yar").write_text(_UPX_RULE)
    return tmp_path


@pytest.fixture
def mz_file(tmp_path: Path) -> Path:
    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00")
    return target


@pytest.fixture
def upx_file(tmp_path: Path) -> Path:
    target = tmp_path / "packed.bin"
    target.write_bytes(b"\x00UPX0\x00padding\x00UPX1\x00more")
    return target


@pytest.fixture
def clean_file(tmp_path: Path) -> Path:
    target = tmp_path / "clean.txt"
    target.write_text("just some plain text with nothing malicious")
    return target


# -- compilation -----------------------------------------------------------


def test_compile_from_directory_aggregates_rules(rules_dir: Path) -> None:
    scanner = YaraScanner.compile_from_directory(rules_dir)
    assert scanner.rule_count == 2


def test_compile_skips_broken_rules_by_default(tmp_path: Path) -> None:
    (tmp_path / "ok.yar").write_text(_MZ_RULE)
    (tmp_path / "broken.yar").write_text(_BROKEN_RULE)
    scanner = YaraScanner.compile_from_directory(tmp_path)
    assert scanner.rule_count == 1
    assert len(scanner.compile_errors) == 1
    assert "broken.yar" in scanner.compile_errors[0].source


def test_compile_strict_raises_on_broken_rule(tmp_path: Path) -> None:
    (tmp_path / "broken.yar").write_text(_BROKEN_RULE)
    with pytest.raises(yara.SyntaxError):
        YaraScanner.compile_from_directory(tmp_path, strict=True)


def test_compile_empty_directory_raises(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no YARA rule files"):
        YaraScanner.compile_from_directory(tmp_path)


def test_compile_nonexistent_directory_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        YaraScanner.compile_from_directory(tmp_path / "does-not-exist")


# -- scanning --------------------------------------------------------------


def test_scan_file_matches_mz_header(rules_dir: Path, mz_file: Path) -> None:
    scanner = YaraScanner.compile_from_directory(rules_dir)
    matches = scanner.scan_file(mz_file)
    assert len(matches) == 1
    assert matches[0].rule == "mz_header"
    assert matches[0].source_file == mz_file
    assert matches[0].meta["severity"] == "low"


def test_scan_file_matches_multiple_rules(rules_dir: Path, tmp_path: Path) -> None:
    # File containing both MZ header and UPX section names.
    target = tmp_path / "double.bin"
    target.write_bytes(b"MZ\x90\x00UPX0\x00UPX1\x00")
    scanner = YaraScanner.compile_from_directory(rules_dir)
    matches = scanner.scan_file(target)
    rule_names = {m.rule for m in matches}
    assert rule_names == {"mz_header", "upx_packed"}


def test_scan_file_no_match_returns_empty(
    rules_dir: Path, clean_file: Path
) -> None:
    scanner = YaraScanner.compile_from_directory(rules_dir)
    assert scanner.scan_file(clean_file) == []


def test_scan_file_nonexistent_raises(rules_dir: Path, tmp_path: Path) -> None:
    scanner = YaraScanner.compile_from_directory(rules_dir)
    with pytest.raises(FileNotFoundError):
        scanner.scan_file(tmp_path / "missing.bin")


def test_scan_file_respects_size_cap(
    rules_dir: Path, tmp_path: Path
) -> None:
    big = tmp_path / "big.bin"
    big.write_bytes(b"MZ" + b"\x00" * 2048)
    scanner = YaraScanner.compile_from_directory(rules_dir, max_file_size=1024)
    with pytest.raises(ValueError, match="exceeds max_file_size"):
        scanner.scan_file(big)


# -- directory scanning ----------------------------------------------------


def test_scan_directory_returns_matches_per_file(
    rules_dir: Path, tmp_path: Path
) -> None:
    targets_dir = tmp_path / "targets"
    targets_dir.mkdir()
    (targets_dir / "a.bin").write_bytes(b"MZ\x90\x00")
    (targets_dir / "b.bin").write_bytes(b"\x00UPX0\x00UPX1\x00")
    (targets_dir / "c.txt").write_text("clean")

    scanner = YaraScanner.compile_from_directory(rules_dir)
    results = scanner.scan_directory(targets_dir)

    assert len(results) == 3
    by_name = {p.name: ms for p, ms in results.items()}
    assert [m.rule for m in by_name["a.bin"]] == ["mz_header"]
    assert [m.rule for m in by_name["b.bin"]] == ["upx_packed"]
    assert by_name["c.txt"] == []


def test_scan_directory_recursive(rules_dir: Path, tmp_path: Path) -> None:
    nested = tmp_path / "outer" / "inner"
    nested.mkdir(parents=True)
    (nested / "deep.bin").write_bytes(b"MZ\x90\x00")
    scanner = YaraScanner.compile_from_directory(rules_dir)
    results = scanner.scan_directory(tmp_path / "outer", recursive=True)
    assert any(p.name == "deep.bin" and ms for p, ms in results.items())


def test_scan_directory_non_recursive_skips_subdirs(
    rules_dir: Path, tmp_path: Path
) -> None:
    (tmp_path / "top.bin").write_bytes(b"MZ\x90\x00")
    nested = tmp_path / "sub"
    nested.mkdir()
    (nested / "hidden.bin").write_bytes(b"MZ\x90\x00")
    scanner = YaraScanner.compile_from_directory(rules_dir)
    results = scanner.scan_directory(tmp_path, recursive=False)
    names = {p.name for p in results}
    assert "top.bin" in names
    assert "hidden.bin" not in names


# -- graceful degradation --------------------------------------------------


def test_missing_yara_error_is_importable_without_yara() -> None:
    """`MissingYaraError` must be importable even on hosts without libyara.

    The scanner module is always imported on CLI startup, so importing
    `sift_find_evil.yara_scan.scanner` must not fail when yara-python is absent.
    """
    # We can't simulate the absent-yara path here (yara is installed for these
    # tests), but we can at least confirm the exception class exists at the
    # expected path and is a subclass of RuntimeError.
    assert issubclass(MissingYaraError, RuntimeError)


# -- dataclass sanity ------------------------------------------------------


def test_yara_match_is_immutable(rules_dir: Path, mz_file: Path) -> None:
    scanner = YaraScanner.compile_from_directory(rules_dir)
    match = scanner.scan_file(mz_file)[0]
    with pytest.raises((AttributeError, TypeError)):
        match.rule = "hacked"  # type: ignore[misc]


def test_yara_match_carries_string_offsets(
    rules_dir: Path, mz_file: Path
) -> None:
    scanner = YaraScanner.compile_from_directory(rules_dir)
    match = scanner.scan_file(mz_file)[0]
    assert match.strings
    # MZ header is at offset 0 in the fixture.
    offsets = [s.offset for s in match.strings]
    assert 0 in offsets
