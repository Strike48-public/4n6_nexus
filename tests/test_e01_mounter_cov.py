"""Coverage-focused tests for sift_find_evil.e01_mounter.

Targets previously-uncovered error paths, defensive guards, and branch
edges in the E01 mounting utility. Mirrors the conventions in
tests/test_e01_mounter.py (Mock/patch on subprocess + Path, AAA layout).
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from sift_find_evil.e01_mounter import E01Image, MountedImage, E01Mounter


# ---------------------------------------------------------------------------
# MountedImage.cleanup rmdir failure guards (lines 55-56, 65-66)
# ---------------------------------------------------------------------------


@patch("subprocess.run")
def test_cleanup_swallows_fs_mount_rmdir_exception(mock_run: Mock) -> None:
    """cleanup ignores rmdir failure on the filesystem mount point (55-56)."""
    # Arrange
    mock_run.return_value = subprocess.CompletedProcess(args=["umount"], returncode=0)
    mounted = MountedImage(
        e01_path=Path("/tmp/evidence.E01"),
        mount_point=Path("/tmp/e01"),
        fs_mount_point=Path("/tmp/fs"),
    )

    def rmdir_side_effect(self):
        # Fail only for the fs mount point so the e01 rmdir still runs.
        if str(self) == "/tmp/fs":
            raise OSError("Directory not empty")

    with (
        patch.object(Path, "exists", return_value=True),
        patch.object(Path, "rmdir", autospec=True, side_effect=rmdir_side_effect),
    ):
        # Act
        commands = mounted.cleanup()

    # Assert - both umount commands still recorded despite the fs rmdir error
    assert len(commands) == 2
    assert "/tmp/fs" in commands[0]
    assert "/tmp/e01" in commands[1]


@patch("subprocess.run")
def test_cleanup_swallows_e01_mount_rmdir_exception(mock_run: Mock) -> None:
    """cleanup ignores rmdir failure on the E01 mount point (65-66)."""
    # Arrange
    mock_run.return_value = subprocess.CompletedProcess(args=["umount"], returncode=0)
    mounted = MountedImage(
        e01_path=Path("/tmp/evidence.E01"),
        mount_point=Path("/tmp/e01"),
    )

    with (
        patch.object(Path, "exists", return_value=True),
        patch.object(Path, "rmdir", side_effect=OSError("busy")),
    ):
        # Act - must not raise even though rmdir blows up
        commands = mounted.cleanup()

    # Assert
    assert len(commands) == 1
    assert "/tmp/e01" in commands[0]


# ---------------------------------------------------------------------------
# detect_e01_images: missing-file guard + lowercase memory branch (89, 124)
# ---------------------------------------------------------------------------


def test_detect_skips_e01_file_that_does_not_exist() -> None:
    """detect_e01_images continues past .E01 entries failing exists() (89)."""
    # Arrange
    with patch.object(Path, "rglob") as mock_rglob:
        ghost = MagicMock(spec=Path)
        ghost.exists.return_value = False

        def side_effect(pattern):
            if pattern == "*.E01":
                return [ghost]
            return []

        mock_rglob.side_effect = side_effect

        # Act
        images = E01Mounter.detect_e01_images(Path("/tmp"))

    # Assert - the non-existent file is skipped, no images produced
    assert images == []
    ghost.stat.assert_not_called()


def test_detect_lowercase_e01_classifies_memory_image() -> None:
    """detect_e01_images marks a lowercase .e01 with 'mem' as memory (124)."""
    # Arrange
    mem_file = MagicMock(spec=Path)
    mem_file.exists.return_value = True
    mem_file.stat.return_value.st_size = 1024**3 * 4
    mem_file.stem = "host_memory"

    with patch.object(Path, "rglob") as mock_rglob:

        def side_effect(pattern):
            if pattern == "*.e01":
                return [mem_file]
            return []

        mock_rglob.side_effect = side_effect

        # Act
        images = E01Mounter.detect_e01_images(Path("/tmp"))

    # Assert
    assert len(images) == 1
    assert images[0].image_type == "memory"
    assert images[0].name == "host_memory"


# ---------------------------------------------------------------------------
# mount_e01: mkdtemp failure guard (lines 174-175)
# ---------------------------------------------------------------------------


@patch("subprocess.run")
@patch("tempfile.mkdtemp")
def test_mount_e01_handles_mkdtemp_failure(mock_mkdtemp: Mock, mock_run: Mock) -> None:
    """mount_e01 reports failure when temp mount point creation raises (174-175)."""
    # Arrange - dependencies present, but mkdtemp blows up
    mock_run.return_value = subprocess.CompletedProcess(
        args=["which", "ewfmount"], returncode=0, stdout="/usr/bin/ewfmount"
    )
    mock_mkdtemp.side_effect = OSError("No space left on device")

    image = E01Image(
        path=Path("/tmp/evidence.E01"),
        name="evidence",
        size_gb=10.0,
        image_type="disk",
    )

    # Act
    success, msg, mounted = E01Mounter.mount_e01(image)

    # Assert
    assert success is False
    assert "Failed to create mount point" in msg
    assert mounted is None


# ---------------------------------------------------------------------------
# mount_e01: raw device not found path (lines 206, 209, 210)
# ---------------------------------------------------------------------------


@patch("subprocess.run")
@patch("tempfile.mkdtemp")
@patch("time.sleep")
def test_mount_e01_raw_device_not_found(
    mock_sleep: Mock, mock_mkdtemp: Mock, mock_run: Mock
) -> None:
    """mount_e01 unmounts and fails when the ewf1 raw device is absent (206-210)."""
    # Arrange
    mock_mkdtemp.return_value = "/tmp/mount"

    def run_side_effect(*args, **kwargs):
        cmd = args[0]
        if "which" in cmd:
            return subprocess.CompletedProcess(args=cmd, returncode=0)
        if "ewfmount" in cmd:
            return subprocess.CompletedProcess(args=cmd, returncode=0)
        if "test" in cmd:
            # raw device check fails -> triggers cleanup branch
            return subprocess.CompletedProcess(args=cmd, returncode=1)
        # the cleanup umount call
        return subprocess.CompletedProcess(args=cmd, returncode=0)

    mock_run.side_effect = run_side_effect

    image = E01Image(
        path=Path("/tmp/evidence.E01"),
        name="evidence",
        size_gb=10.0,
        image_type="disk",
    )

    with patch.object(Path, "rmdir") as mock_rmdir:
        # Act
        success, msg, mounted = E01Mounter.mount_e01(image)

    # Assert
    assert success is False
    assert "Raw device not found" in msg
    assert mounted is None
    mock_rmdir.assert_called_once()
    # The cleanup umount must have been issued
    umount_calls = [
        c
        for c in mock_run.call_args_list
        if isinstance(c[0][0], list) and "umount" in c[0][0]
    ]
    assert umount_calls


# ---------------------------------------------------------------------------
# mount_e01: disk image filesystem-mounted success + fallback (218-220, 223)
# ---------------------------------------------------------------------------


@patch("subprocess.run")
@patch("tempfile.mkdtemp")
@patch("time.sleep")
def test_mount_e01_disk_with_filesystem_mounted(
    mock_sleep: Mock, mock_mkdtemp: Mock, mock_run: Mock
) -> None:
    """mount_e01 returns success message when disk filesystem mounts (218-220)."""
    # Arrange
    mock_mkdtemp.return_value = "/tmp/mount"
    mock_run.return_value = subprocess.CompletedProcess(args=["sudo"], returncode=0)

    image = E01Image(
        path=Path("/tmp/diskimg.E01"),
        name="diskimg",
        size_gb=100.0,
        image_type="disk",
    )

    with patch.object(E01Mounter, "_mount_filesystem", return_value=True):
        # Act
        success, msg, mounted = E01Mounter.mount_e01(image)

    # Assert
    assert success is True
    assert "successfully" in msg
    assert mounted is not None


@patch("subprocess.run")
@patch("tempfile.mkdtemp")
@patch("time.sleep")
def test_mount_e01_disk_filesystem_mount_falls_back_to_raw(
    mock_sleep: Mock, mock_mkdtemp: Mock, mock_run: Mock
) -> None:
    """mount_e01 falls back to raw-device-only when fs mount fails (223)."""
    # Arrange
    mock_mkdtemp.return_value = "/tmp/mount"
    mock_run.return_value = subprocess.CompletedProcess(args=["sudo"], returncode=0)

    image = E01Image(
        path=Path("/tmp/diskimg.E01"),
        name="diskimg",
        size_gb=100.0,
        image_type="disk",
    )

    with patch.object(E01Mounter, "_mount_filesystem", return_value=False):
        # Act
        success, msg, mounted = E01Mounter.mount_e01(image)

    # Assert
    assert success is True
    assert "raw device only" in msg
    assert mounted is not None


# ---------------------------------------------------------------------------
# mount_e01: timeout + generic exception handlers (228-231)
# ---------------------------------------------------------------------------


@patch("subprocess.run")
@patch("tempfile.mkdtemp")
def test_mount_e01_handles_timeout(mock_mkdtemp: Mock, mock_run: Mock) -> None:
    """mount_e01 reports timeout when ewfmount exceeds the limit (228-229)."""
    # Arrange
    mock_mkdtemp.return_value = "/tmp/mount"

    def run_side_effect(*args, **kwargs):
        cmd = args[0]
        if "which" in cmd:
            return subprocess.CompletedProcess(args=cmd, returncode=0)
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=30)

    mock_run.side_effect = run_side_effect

    image = E01Image(
        path=Path("/tmp/evidence.E01"),
        name="evidence",
        size_gb=10.0,
        image_type="memory",
    )

    # Act
    success, msg, mounted = E01Mounter.mount_e01(image)

    # Assert
    assert success is False
    assert "timed out" in msg
    assert mounted is None


@patch("subprocess.run")
@patch("tempfile.mkdtemp")
def test_mount_e01_handles_generic_exception(
    mock_mkdtemp: Mock, mock_run: Mock
) -> None:
    """mount_e01 wraps unexpected errors during mounting (230-231)."""
    # Arrange
    mock_mkdtemp.return_value = "/tmp/mount"

    def run_side_effect(*args, **kwargs):
        cmd = args[0]
        if "which" in cmd:
            return subprocess.CompletedProcess(args=cmd, returncode=0)
        raise RuntimeError("unexpected boom")

    mock_run.side_effect = run_side_effect

    image = E01Image(
        path=Path("/tmp/evidence.E01"),
        name="evidence",
        size_gb=10.0,
        image_type="memory",
    )

    # Act
    success, msg, mounted = E01Mounter.mount_e01(image)

    # Assert
    assert success is False
    assert "Mount error" in msg
    assert "unexpected boom" in msg
    assert mounted is None


# ---------------------------------------------------------------------------
# _mount_filesystem: per-offset exception continue + outer guard (282-283, 289-290)
# ---------------------------------------------------------------------------


@patch("subprocess.run")
@patch("tempfile.mkdtemp")
def test_mount_filesystem_continues_past_offset_exceptions(
    mock_mkdtemp: Mock, mock_run: Mock
) -> None:
    """_mount_filesystem swallows per-offset mount errors and keeps trying (282-283)."""
    # Arrange
    mock_mkdtemp.return_value = "/tmp/fs_mount"

    # fdisk call succeeds; every subsequent mount attempt raises so we hit
    # the per-offset `except Exception: continue`, then the final rmdir/False.
    def run_side_effect(*args, **kwargs):
        cmd = args[0]
        if "fdisk" in cmd:
            return subprocess.CompletedProcess(args=cmd, returncode=0)
        raise OSError("loop setup failed")

    mock_run.side_effect = run_side_effect

    mounted = MountedImage(
        e01_path=Path("/tmp/evidence.E01"),
        mount_point=Path("/tmp/e01_mount"),
        raw_device=Path("/tmp/e01_mount/ewf1"),
    )

    with patch.object(Path, "rmdir") as mock_rmdir:
        # Act
        result = E01Mounter._mount_filesystem(mounted)

    # Assert - all offsets exhausted, returns False after cleanup
    assert result is False
    mock_rmdir.assert_called_once()


@patch("tempfile.mkdtemp")
def test_mount_filesystem_outer_exception_returns_false(mock_mkdtemp: Mock) -> None:
    """_mount_filesystem returns False if mount-point creation itself fails (289-290)."""
    # Arrange - raw_device present so we pass the early guard, but mkdtemp raises
    mock_mkdtemp.side_effect = OSError("No space left on device")

    mounted = MountedImage(
        e01_path=Path("/tmp/evidence.E01"),
        mount_point=Path("/tmp/e01_mount"),
        raw_device=Path("/tmp/e01_mount/ewf1"),
    )

    # Act
    result = E01Mounter._mount_filesystem(mounted)

    # Assert
    assert result is False
