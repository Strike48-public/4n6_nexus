"""Tests for pre-flight evidence validation (idea #36).

Validates the size gate, format probe, and mount liveness checks in
``sift_find_evil.validation.preflight``. All fixtures are synthetic
(tmp_path files and fake probe callables); no real forensic tools run.
"""

from __future__ import annotations

from pathlib import Path

from sift_find_evil.validation.preflight import PreflightResult, preflight_check


def _make_file(tmp_path: Path, name: str, size: int) -> Path:
    """Create a synthetic file of ``size`` bytes and return its path."""
    target = tmp_path / name
    target.write_bytes(b"\x00" * size)
    return target


def test_missing_path_returns_code_10(tmp_path: Path) -> None:
    # Arrange
    missing = tmp_path / "does_not_exist.mem"

    # Act
    result = preflight_check(missing, kind="memory")

    # Assert
    assert isinstance(result, PreflightResult)
    assert result.ok is False
    assert result.code == 10
    assert "missing" in result.reason.lower()


def test_tiny_file_returns_code_11(tmp_path: Path) -> None:
    # Arrange
    tiny = _make_file(tmp_path, "tiny.dd", size=16)

    # Act
    result = preflight_check(tiny, kind="dd", min_bytes=1024)

    # Assert
    assert result.ok is False
    assert result.code == 11


def test_memory_with_failing_probe_returns_code_12(tmp_path: Path) -> None:
    # Arrange
    dump = _make_file(tmp_path, "mem.raw", size=4096)

    def failing_probe(_path: Path) -> bool:
        return False

    # Act
    result = preflight_check(dump, kind="memory", min_bytes=1024, probe=failing_probe)

    # Assert
    assert result.ok is False
    assert result.code == 12


def test_memory_probe_exception_returns_code_12(tmp_path: Path) -> None:
    # Arrange
    dump = _make_file(tmp_path, "mem.raw", size=4096)

    def exploding_probe(_path: Path) -> bool:
        raise RuntimeError("vol windows.info crashed")

    # Act
    result = preflight_check(dump, kind="memory", min_bytes=1024, probe=exploding_probe)

    # Assert
    assert result.ok is False
    assert result.code == 12


def test_good_file_with_passing_probe_returns_code_0(tmp_path: Path) -> None:
    # Arrange
    dump = _make_file(tmp_path, "good.raw", size=8192)

    def passing_probe(_path: Path) -> bool:
        return True

    # Act
    result = preflight_check(dump, kind="memory", min_bytes=1024, probe=passing_probe)

    # Assert
    assert result.ok is True
    assert result.code == 0
    assert "ok" in result.reason.lower()


def test_memory_without_probe_passes_on_size_alone(tmp_path: Path) -> None:
    # Arrange - clean/inverse control: no probe supplied means size is enough
    dump = _make_file(tmp_path, "nopr.raw", size=4096)

    # Act
    result = preflight_check(dump, kind="memory", min_bytes=1024)

    # Assert
    assert result.ok is True
    assert result.code == 0


def test_disk_image_not_mounted_returns_code_13(tmp_path: Path) -> None:
    # Arrange
    image = _make_file(tmp_path, "case.e01", size=4096)

    def not_mounted(_path: Path) -> bool:
        return False

    # Act
    result = preflight_check(
        image, kind="e01", min_bytes=1024, mount_predicate=not_mounted
    )

    # Assert
    assert result.ok is False
    assert result.code == 13


def test_disk_image_mounted_returns_code_0(tmp_path: Path) -> None:
    # Arrange
    image = _make_file(tmp_path, "case.e01", size=4096)

    def is_mounted(_path: Path) -> bool:
        return True

    # Act
    result = preflight_check(
        image, kind="e01", min_bytes=1024, mount_predicate=is_mounted
    )

    # Assert
    assert result.ok is True
    assert result.code == 0


def test_size_gate_runs_before_probe(tmp_path: Path) -> None:
    # Arrange - a tiny memory dump must fail on size, never invoking the probe
    tiny = _make_file(tmp_path, "tiny.raw", size=8)
    calls: list[Path] = []

    def tracking_probe(path: Path) -> bool:
        calls.append(path)
        return True

    # Act
    result = preflight_check(tiny, kind="memory", min_bytes=1024, probe=tracking_probe)

    # Assert
    assert result.code == 11
    assert calls == []


def test_result_is_immutable(tmp_path: Path) -> None:
    # Arrange
    dump = _make_file(tmp_path, "good.raw", size=4096)

    # Act
    result = preflight_check(dump, kind="dd", min_bytes=1024)

    # Assert - frozen dataclass rejects mutation
    try:
        result.ok = False  # type: ignore[misc]
        raised = False
    except Exception:
        raised = True
    assert raised is True
