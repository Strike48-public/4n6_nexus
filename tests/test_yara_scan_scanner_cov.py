"""Coverage-focused tests for YaraScanner internal guards and edge paths.

Targets the missing-yara guards, the all-files-failed compile path, the
namespace-fallback branch, and the yara-python 4.2.x tuple-shape string
normalization that the primary test suite does not exercise on a 4.5 host.
"""

from __future__ import annotations

from pathlib import Path

import pytest

yara = pytest.importorskip("yara")

from sift_find_evil.yara_scan import scanner as scanner_mod  # noqa: E402
from sift_find_evil.yara_scan.scanner import (  # noqa: E402
    MissingYaraError,
    YaraScanner,
    YaraString,
    _flatten_strings,
    _namespace_for,
)


_BROKEN_RULE = """
rule totally_broken {
    condition:
        this_is_not_valid_yara_syntax
}
"""


# -- missing-yara guards (lines 126, 169, 252) -----------------------------


def test_constructor_raises_when_yara_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """__init__ rejects construction when libyara is unavailable (line 126)."""
    monkeypatch.setattr(scanner_mod, "_yara", None)
    with pytest.raises(MissingYaraError, match="yara-python is not installed"):
        YaraScanner(rules=object(), rule_count=1)


def test_compile_from_directories_raises_when_yara_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """compile_from_directories guards on missing yara before any IO (line 169)."""
    monkeypatch.setattr(scanner_mod, "_yara", None)
    with pytest.raises(MissingYaraError, match="yara-python is not installed"):
        YaraScanner.compile_from_directories([tmp_path])


def test_compile_from_directory_raises_when_yara_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """compile_from_directory guards on missing yara before any IO (line 252)."""
    monkeypatch.setattr(scanner_mod, "_yara", None)
    with pytest.raises(MissingYaraError, match="yara-python is not installed"):
        YaraScanner.compile_from_directory(tmp_path)


# -- all-files-failed compile path (lines 280-281) -------------------------


def test_compile_from_directory_all_files_failed_includes_first_error(
    tmp_path: Path,
) -> None:
    """When every rule file fails, raise loudly and surface the first error.

    This drives the `first = errors[0]` non-None branch and the ValueError
    raise that follows it (lines 280-281), distinct from the no-files-found
    path which fails earlier.
    """
    (tmp_path / "broken.yar").write_text(_BROKEN_RULE)
    with pytest.raises(ValueError, match="no YARA rules compiled successfully"):
        YaraScanner.compile_from_directory(tmp_path)


def test_compile_from_directory_all_files_failed_first_error_text(
    tmp_path: Path,
) -> None:
    """The raised message embeds the first compile error detail."""
    (tmp_path / "broken.yar").write_text(_BROKEN_RULE)
    with pytest.raises(ValueError, match="first error"):
        YaraScanner.compile_from_directory(tmp_path)


# -- namespace fallback when rule file is not under rules_dir (392-393) ----


def test_namespace_for_falls_back_when_not_relative(tmp_path: Path) -> None:
    """A rule file outside rules_dir cannot be made relative; fall back.

    relative_to() raises ValueError, so the function keeps the absolute path
    (lines 392-393) and derives the namespace from it.
    """
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    outside = tmp_path / "elsewhere" / "rule.yar"
    outside.parent.mkdir()
    outside.write_text("rule x { condition: false }")

    namespace = _namespace_for(outside, rules_dir)

    # Derived from the full (absolute) path, not relative to rules_dir.
    assert namespace.endswith("elsewhere.rule")
    assert "rules" not in namespace.split(".")[:1]


# -- _flatten_strings edge paths (437, 441-442, 447) -----------------------


def test_flatten_strings_empty_returns_empty_list() -> None:
    """No raw strings -> early empty list (line 437)."""
    assert _flatten_strings([]) == []
    assert _flatten_strings(None) == []


def test_flatten_strings_handles_4_2_tuple_shape() -> None:
    """yara-python 4.2.x returns (offset, identifier, data) tuples.

    Drives the tuple unpacking + YaraString construction + continue
    (lines 441-442, 447) which a 4.5 host never hits via real matches.
    """
    raw = [
        (0, "$mz", b"MZ"),
        (512, "$upx", b"UPX0"),
    ]
    flat = _flatten_strings(raw)
    assert flat == [
        YaraString(identifier="$mz", offset=0, data=b"MZ"),
        YaraString(identifier="$upx", offset=512, data=b"UPX0"),
    ]


def test_flatten_strings_coerces_tuple_field_types() -> None:
    """Tuple-shape values are coerced to str/int/bytes."""
    # Correctly shaped 3-tuple with loosely typed members.
    raw = [(7, b"$ident", bytearray(b"DATA"))]
    flat = _flatten_strings(raw)
    assert flat == [YaraString(identifier="b'$ident'", offset=7, data=b"DATA")]


def test_flatten_strings_mixed_tuple_and_stringmatch() -> None:
    """A tuple item then a StringMatch item both normalize correctly."""

    class FakeInstance:
        def __init__(self, offset: int, matched_data: bytes) -> None:
            self.offset = offset
            self.matched_data = matched_data

    class FakeStringMatch:
        def __init__(self, identifier: str, instances: list) -> None:
            self.identifier = identifier
            self.instances = instances

    raw = [
        (0, "$mz", b"MZ"),
        FakeStringMatch("$upx", [FakeInstance(2048, b"UPX0")]),
    ]
    flat = _flatten_strings(raw)
    assert flat == [
        YaraString(identifier="$mz", offset=0, data=b"MZ"),
        YaraString(identifier="$upx", offset=2048, data=b"UPX0"),
    ]
