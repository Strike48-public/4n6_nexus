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


# -- compile_from_directories (SFE-qmh multi-source loader) -----------------


def test_compile_from_directories_aggregates_across_sources(
    tmp_path: Path,
) -> None:
    """Rules from two disjoint directories must all compile into one scanner."""
    seed_dir = tmp_path / "seed"
    community_dir = tmp_path / "community"
    seed_dir.mkdir()
    community_dir.mkdir()
    (seed_dir / "mz.yar").write_text(_MZ_RULE)
    (community_dir / "upx.yar").write_text(_UPX_RULE)

    scanner = YaraScanner.compile_from_directories([seed_dir, community_dir])

    assert scanner.rule_count == 2


def test_compile_from_directories_skips_broken_community_rules(
    tmp_path: Path,
) -> None:
    """A broken community rule must not knock out the whole scanner."""
    seed_dir = tmp_path / "seed"
    community_dir = tmp_path / "community"
    seed_dir.mkdir()
    community_dir.mkdir()
    (seed_dir / "mz.yar").write_text(_MZ_RULE)
    (community_dir / "ok.yar").write_text(_UPX_RULE)
    (community_dir / "broken.yar").write_text(_BROKEN_RULE)

    scanner = YaraScanner.compile_from_directories([seed_dir, community_dir])

    assert scanner.rule_count == 2
    assert len(scanner.compile_errors) == 1
    assert "broken.yar" in scanner.compile_errors[0].source


def test_compile_from_directories_rejects_empty_input() -> None:
    with pytest.raises(ValueError, match="at least one path"):
        YaraScanner.compile_from_directories([])


def test_compile_from_directories_all_dirs_empty_raises(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    with pytest.raises(ValueError, match="no YARA rule files"):
        YaraScanner.compile_from_directories([a, b])


def test_compile_from_directories_missing_dir_raises(tmp_path: Path) -> None:
    good = tmp_path / "good"
    good.mkdir()
    (good / "mz.yar").write_text(_MZ_RULE)
    with pytest.raises(FileNotFoundError):
        YaraScanner.compile_from_directories([good, tmp_path / "does-not-exist"])


def test_compile_from_directories_all_files_failed_raises(tmp_path: Path) -> None:
    """If every rule file across every directory fails to compile, fail loudly.

    An empty scanner would silently match nothing, which is worse than an
    upfront error when a whole community submodule is broken.
    """
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "broken1.yar").write_text(_BROKEN_RULE)
    (b / "broken2.yar").write_text(_BROKEN_RULE)

    with pytest.raises(ValueError, match="no YARA rules compiled successfully"):
        YaraScanner.compile_from_directories([a, b])


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


def test_scan_file_no_match_returns_empty(rules_dir: Path, clean_file: Path) -> None:
    scanner = YaraScanner.compile_from_directory(rules_dir)
    assert scanner.scan_file(clean_file) == []


def test_scan_file_nonexistent_raises(rules_dir: Path, tmp_path: Path) -> None:
    scanner = YaraScanner.compile_from_directory(rules_dir)
    with pytest.raises(FileNotFoundError):
        scanner.scan_file(tmp_path / "missing.bin")


def test_scan_file_respects_size_cap(rules_dir: Path, tmp_path: Path) -> None:
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


def test_scan_directory_logs_oversized_skips(
    rules_dir: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Oversized files must be logged rather than silently dropped."""
    import logging

    small = tmp_path / "ok.bin"
    small.write_bytes(b"MZ\x90\x00")
    big = tmp_path / "too_big.bin"
    big.write_bytes(b"MZ" + b"\x00" * 2048)

    scanner = YaraScanner.compile_from_directory(rules_dir, max_file_size=1024)
    with caplog.at_level(logging.WARNING, logger="sift_find_evil.yara_scan.scanner"):
        results = scanner.scan_directory(tmp_path)

    assert results[big] == []  # still returns empty list for caller
    assert any(
        "too_big.bin" in rec.getMessage() and "max_file_size" in rec.getMessage()
        for rec in caplog.records
    )


def test_scan_directory_details_returns_oversized_paths(
    rules_dir: Path, tmp_path: Path
) -> None:
    """scan_directory_details() surfaces oversized skips as structured data."""
    small = tmp_path / "ok.bin"
    small.write_bytes(b"MZ\x90\x00")
    big = tmp_path / "too_big.bin"
    big.write_bytes(b"MZ" + b"\x00" * 2048)

    scanner = YaraScanner.compile_from_directory(rules_dir, max_file_size=1024)
    details = scanner.scan_directory_details(tmp_path)

    assert big in details.oversized
    assert small not in details.oversized
    assert details.matches[small]
    assert details.matches[big] == []


def test_scan_directory_details_empty_when_no_skips(
    rules_dir: Path, tmp_path: Path
) -> None:
    target = tmp_path / "ok.bin"
    target.write_bytes(b"MZ\x90\x00")
    scanner = YaraScanner.compile_from_directory(rules_dir)
    details = scanner.scan_directory_details(tmp_path)
    assert details.oversized == ()
    assert details.unreadable == ()
    assert details.matches[target]


def test_scan_directory_survives_unreadable_file(
    rules_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A single OSError (I/O error, corrupt cluster) must not abort the scan.

    Real evidence (SFE-4e9, LoneWolf) contains files that raise OSError on
    stat()/read — e.g. Chrome's 'Network Persistent State'. The directory
    walk must skip the bad file and keep scanning the rest.
    """
    good = tmp_path / "good.bin"
    good.write_bytes(b"MZ\x90\x00")
    bad = tmp_path / "unreadable.bin"
    bad.write_bytes(b"MZ\x90\x00")

    scanner = YaraScanner.compile_from_directory(rules_dir)
    real_scan_file = scanner.scan_file

    def flaky_scan_file(target: Path) -> list:
        if target.name == "unreadable.bin":
            raise OSError(5, "Input/output error")
        return real_scan_file(target)

    monkeypatch.setattr(scanner, "scan_file", flaky_scan_file)

    # Must NOT raise — the good file is still scanned and matched.
    results = scanner.scan_directory(tmp_path)
    assert results[good], "good file should still be scanned and match"
    assert results[bad] == [], "unreadable file should yield an empty match list"


def test_scan_directory_logs_unreadable_skips(
    rules_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Unreadable files must be logged, not silently swallowed."""
    import logging

    good = tmp_path / "good.bin"
    good.write_bytes(b"MZ\x90\x00")
    bad = tmp_path / "unreadable.bin"
    bad.write_bytes(b"MZ\x90\x00")

    scanner = YaraScanner.compile_from_directory(rules_dir)
    real_scan_file = scanner.scan_file

    def flaky_scan_file(target: Path) -> list:
        if target.name == "unreadable.bin":
            raise OSError(5, "Input/output error")
        return real_scan_file(target)

    monkeypatch.setattr(scanner, "scan_file", flaky_scan_file)

    with caplog.at_level(logging.WARNING, logger="sift_find_evil.yara_scan.scanner"):
        scanner.scan_directory(tmp_path)

    assert any(
        "unreadable.bin" in rec.getMessage() for rec in caplog.records
    ), "expected a WARNING naming the unreadable file"


def test_scan_directory_survives_unstatable_path(
    rules_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """OSError from is_file()/stat() during the walk must not abort the scan.

    The crash in SFE-4e9 originated in the ``p.is_file()`` filter of the walk
    generator, BEFORE scan_file() was ever reached. Simulate a path whose
    is_file() raises to exercise that branch specifically, and assert the bad
    path is both surfaced (via details.unreadable) and logged — not silently
    dropped.
    """
    import logging

    targets = tmp_path / "targets"
    targets.mkdir()
    good = targets / "good.bin"
    good.write_bytes(b"MZ\x90\x00")
    bad = targets / "phantom.bin"
    bad.write_bytes(b"MZ\x90\x00")

    # Compile BEFORE patching so the rule-file walk is unaffected; the patch
    # targets only the scan-time is_file() filter over the evidence tree.
    scanner = YaraScanner.compile_from_directory(rules_dir)

    real_is_file = Path.is_file

    def flaky_is_file(self: Path) -> bool:
        if self.name == "phantom.bin":
            raise OSError(5, "Input/output error")
        return real_is_file(self)

    monkeypatch.setattr(Path, "is_file", flaky_is_file)

    # Must NOT raise; the good file is still scanned, the phantom is recorded.
    with caplog.at_level(logging.WARNING, logger="sift_find_evil.yara_scan.scanner"):
        details = scanner.scan_directory_details(targets)
    assert details.matches[good], "good file should still be scanned and match"
    assert bad in details.unreadable, "unstatable path must be recorded as unreadable"
    assert good not in details.unreadable
    assert any(
        "phantom.bin" in rec.getMessage() and "unstatable" in rec.getMessage()
        for rec in caplog.records
    ), "expected a WARNING naming the unstatable file"


def test_scan_directory_survives_recursive_subdir_unreadable(
    rules_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A recursive walk must survive an unreadable file in a nested subdir.

    Real evidence trees are deep (Chrome profile dirs, WinSxS); the bad file
    that triggered SFE-4e9 was several levels down. Exercise the recursive
    path with the unreadable file in a subdirectory.
    """
    outer = tmp_path / "outer"
    inner = outer / "inner"
    inner.mkdir(parents=True)
    good = outer / "good.bin"
    good.write_bytes(b"MZ\x90\x00")
    bad = inner / "unreadable.bin"
    bad.write_bytes(b"MZ\x90\x00")

    scanner = YaraScanner.compile_from_directory(rules_dir)
    real_scan_file = scanner.scan_file

    def flaky_scan_file(target: Path) -> list:
        if target.name == "unreadable.bin":
            raise OSError(5, "Input/output error")
        return real_scan_file(target)

    monkeypatch.setattr(scanner, "scan_file", flaky_scan_file)

    details = scanner.scan_directory_details(outer, recursive=True)
    assert details.matches[good], "readable file in a sibling dir must still scan"
    assert bad in details.unreadable


def test_scan_directory_mixed_oversized_and_unreadable(
    rules_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One scan with BOTH an oversized and an unreadable file classifies each.

    The two skip paths share the walk; verify they populate their own buckets
    independently and the good file still scans (no cross-contamination).
    """
    good = tmp_path / "good.bin"
    good.write_bytes(b"MZ\x90\x00")
    big = tmp_path / "too_big.bin"
    big.write_bytes(b"MZ" + b"\x00" * 2048)
    bad = tmp_path / "unreadable.bin"
    bad.write_bytes(b"MZ\x90\x00")

    scanner = YaraScanner.compile_from_directory(rules_dir, max_file_size=1024)
    real_scan_file = scanner.scan_file

    def flaky_scan_file(target: Path) -> list:
        if target.name == "unreadable.bin":
            raise OSError(5, "Input/output error")
        return real_scan_file(target)

    monkeypatch.setattr(scanner, "scan_file", flaky_scan_file)

    details = scanner.scan_directory_details(tmp_path)
    assert details.matches[good], "good file should still scan"
    assert big in details.oversized
    assert big not in details.unreadable
    assert bad in details.unreadable
    assert bad not in details.oversized


def test_scan_directory_details_returns_unreadable_paths(
    rules_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """scan_directory_details() surfaces unreadable skips as structured data."""
    good = tmp_path / "good.bin"
    good.write_bytes(b"MZ\x90\x00")
    bad = tmp_path / "unreadable.bin"
    bad.write_bytes(b"MZ\x90\x00")

    scanner = YaraScanner.compile_from_directory(rules_dir)
    real_scan_file = scanner.scan_file

    def flaky_scan_file(target: Path) -> list:
        if target.name == "unreadable.bin":
            raise OSError(5, "Input/output error")
        return real_scan_file(target)

    monkeypatch.setattr(scanner, "scan_file", flaky_scan_file)

    details = scanner.scan_directory_details(tmp_path)
    assert bad in details.unreadable
    assert good not in details.unreadable
    assert details.matches[good]
    assert details.matches[bad] == []


def test_scan_directory_details_matches_is_readonly(
    rules_dir: Path, tmp_path: Path
) -> None:
    """DirectoryScanResult.matches is a read-only view — mutation must raise."""
    target = tmp_path / "ok.bin"
    target.write_bytes(b"MZ\x90\x00")
    scanner = YaraScanner.compile_from_directory(rules_dir)
    details = scanner.scan_directory_details(tmp_path)
    with pytest.raises(TypeError):
        details.matches[target] = []  # type: ignore[index]


# -- yara-python 4.3+ StringMatch compatibility ----------------------------


def test_flatten_strings_handles_4_3_stringmatch_shape() -> None:
    """yara-python 4.3+ returns StringMatch objects; exercise that branch."""
    from sift_find_evil.yara_scan.scanner import _flatten_strings, YaraString

    class FakeInstance:
        def __init__(self, offset: int, matched_data: bytes) -> None:
            self.offset = offset
            self.matched_data = matched_data

    class FakeStringMatch:
        def __init__(self, identifier: str, instances: list) -> None:
            self.identifier = identifier
            self.instances = instances

    raw = [
        FakeStringMatch(
            "$mz",
            [FakeInstance(0, b"MZ"), FakeInstance(512, b"MZ")],
        ),
        FakeStringMatch("$upx", [FakeInstance(2048, b"UPX0")]),
    ]
    flat = _flatten_strings(raw)
    assert flat == [
        YaraString(identifier="$mz", offset=0, data=b"MZ"),
        YaraString(identifier="$mz", offset=512, data=b"MZ"),
        YaraString(identifier="$upx", offset=2048, data=b"UPX0"),
    ]


def test_flatten_strings_skips_4_3_item_without_instances() -> None:
    """StringMatch objects with no `instances` attr are silently skipped."""
    from sift_find_evil.yara_scan.scanner import _flatten_strings

    class WeirdShape:
        identifier = "$weird"
        # No `instances` attribute at all.

    assert _flatten_strings([WeirdShape()]) == []


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


def test_yara_match_carries_string_offsets(rules_dir: Path, mz_file: Path) -> None:
    scanner = YaraScanner.compile_from_directory(rules_dir)
    match = scanner.scan_file(mz_file)[0]
    assert match.strings
    # MZ header is at offset 0 in the fixture.
    offsets = [s.offset for s in match.strings]
    assert 0 in offsets
