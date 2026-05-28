"""Tests for E01 forensic image mounting functionality."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest

from sift_find_evil.e01_mounter import E01Image, MountedImage, E01Mounter


# ---------------------------------------------------------------------------
# E01Image Detection Tests
# ---------------------------------------------------------------------------


def test_e01_image_is_memory_detection_with_mem_in_name() -> None:
    """E01Image.is_memory returns True when 'mem' is in filename."""
    # Arrange
    image = E01Image(
        path=Path("/tmp/evidence_mem.E01"),
        name="evidence_mem",
        size_gb=4.0,
        image_type="memory",
    )

    # Act
    result = image.is_memory

    # Assert
    assert result is True


def test_e01_image_is_memory_detection_with_ram_in_name() -> None:
    """E01Image.is_memory returns True when 'ram' is in filename."""
    # Arrange
    image = E01Image(
        path=Path("/tmp/system_ram_dump.E01"),
        name="system_ram_dump",
        size_gb=16.0,
        image_type="memory",
    )

    # Act
    result = image.is_memory

    # Assert
    assert result is True


def test_e01_image_is_memory_detection_with_dmp_in_name() -> None:
    """E01Image.is_memory returns True when 'dmp' is in filename."""
    # Arrange
    image = E01Image(
        path=Path("/tmp/crash.dmp.E01"),
        name="crash.dmp",
        size_gb=2.5,
        image_type="memory",
    )

    # Act
    result = image.is_memory

    # Assert
    assert result is True


def test_e01_image_is_memory_detection_with_memdump_in_name() -> None:
    """E01Image.is_memory returns True when 'memdump' is in filename (via 'mem')."""
    # Arrange
    image = E01Image(
        path=Path("/tmp/system_memdump.E01"),
        name="system_memdump",
        size_gb=8.0,
        image_type="memory",
    )

    # Act
    result = image.is_memory

    # Assert
    assert result is True


def test_e01_image_is_memory_detection_returns_false_for_disk_image() -> None:
    """E01Image.is_memory returns False for disk images."""
    # Arrange
    image = E01Image(
        path=Path("/tmp/disk_image.E01"),
        name="disk_image",
        size_gb=500.0,
        image_type="disk",
    )

    # Act
    result = image.is_memory

    # Assert
    assert result is False


# ---------------------------------------------------------------------------
# MountedImage Cleanup Tests
# ---------------------------------------------------------------------------


@patch("subprocess.run")
def test_mounted_image_cleanup_unmounts_ewf_mount(mock_run: Mock) -> None:
    """MountedImage.cleanup unmounts E01 mount point."""
    # Arrange
    mock_run.return_value = subprocess.CompletedProcess(
        args=["sudo", "umount", "/tmp/mount"], returncode=0
    )
    mount_point = Path("/tmp/mount")
    mounted = MountedImage(
        e01_path=Path("/tmp/evidence.E01"),
        mount_point=mount_point,
    )

    with patch.object(Path, "exists", return_value=True), patch.object(
        Path, "rmdir"
    ) as mock_rmdir:
        # Act
        commands = mounted.cleanup()

        # Assert
        assert len(commands) == 1
        assert "sudo umount /tmp/mount" in commands[0]
        mock_rmdir.assert_called_once()


@patch("subprocess.run")
def test_mounted_image_cleanup_unmounts_filesystem_mount(mock_run: Mock) -> None:
    """MountedImage.cleanup unmounts filesystem mount point before E01 mount."""
    # Arrange
    mock_run.return_value = subprocess.CompletedProcess(
        args=["sudo", "umount"], returncode=0
    )
    mount_point = Path("/tmp/e01_mount")
    fs_mount = Path("/tmp/fs_mount")
    mounted = MountedImage(
        e01_path=Path("/tmp/evidence.E01"),
        mount_point=mount_point,
        fs_mount_point=fs_mount,
    )

    with patch.object(Path, "exists", return_value=True), patch.object(Path, "rmdir"):
        # Act
        commands = mounted.cleanup()

        # Assert
        assert len(commands) == 2
        assert "sudo umount /tmp/fs_mount" in commands[0]
        assert "sudo umount /tmp/e01_mount" in commands[1]


@patch("subprocess.run")
def test_mounted_image_cleanup_removes_mount_point(mock_run: Mock) -> None:
    """MountedImage.cleanup removes mount point directories."""
    # Arrange
    mock_run.return_value = subprocess.CompletedProcess(
        args=["sudo", "umount"], returncode=0
    )
    mount_point = Path("/tmp/mount")
    mounted = MountedImage(
        e01_path=Path("/tmp/evidence.E01"),
        mount_point=mount_point,
    )

    with patch.object(Path, "exists", return_value=True), patch.object(
        Path, "rmdir"
    ) as mock_rmdir:
        # Act
        mounted.cleanup()

        # Assert
        mock_rmdir.assert_called_once()


@patch("subprocess.run")
def test_mounted_image_cleanup_handles_unmount_failure_gracefully(
    mock_run: Mock,
) -> None:
    """MountedImage.cleanup continues cleanup even if unmount fails."""
    # Arrange
    mock_run.return_value = subprocess.CompletedProcess(
        args=["sudo", "umount"], returncode=1, stderr="Device busy"
    )
    mount_point = Path("/tmp/mount")
    mounted = MountedImage(
        e01_path=Path("/tmp/evidence.E01"),
        mount_point=mount_point,
    )

    with patch.object(Path, "exists", return_value=True), patch.object(Path, "rmdir"):
        # Act
        commands = mounted.cleanup()

        # Assert
        assert len(commands) == 1
        mock_run.assert_called_once()


@patch("subprocess.run")
def test_mounted_image_cleanup_cleans_up_in_reverse_order(mock_run: Mock) -> None:
    """MountedImage.cleanup unmounts filesystem before E01 mount."""
    # Arrange
    mock_run.return_value = subprocess.CompletedProcess(
        args=["sudo", "umount"], returncode=0
    )
    mount_point = Path("/tmp/e01")
    fs_mount = Path("/tmp/fs")
    mounted = MountedImage(
        e01_path=Path("/tmp/evidence.E01"),
        mount_point=mount_point,
        fs_mount_point=fs_mount,
    )

    with patch.object(Path, "exists", return_value=True), patch.object(Path, "rmdir"):
        # Act
        commands = mounted.cleanup()

        # Assert
        assert "/tmp/fs" in commands[0]
        assert "/tmp/e01" in commands[1]


# ---------------------------------------------------------------------------
# E01Mounter Detection Tests
# ---------------------------------------------------------------------------


def test_e01_mounter_detect_images_finds_e01_files() -> None:
    """E01Mounter.detect_e01_images finds uppercase .E01 files."""
    # Arrange
    with patch.object(Path, "rglob") as mock_rglob:
        mock_file = MagicMock(spec=Path)
        mock_file.exists.return_value = True
        mock_file.stat.return_value.st_size = 1024**3 * 10
        mock_file.stem = "evidence"
        mock_rglob.return_value = [mock_file]

        # Act
        images = E01Mounter.detect_e01_images(Path("/tmp"))

        # Assert
        assert len(images) == 1
        assert images[0].name == "evidence"


def test_e01_mounter_detect_images_finds_lowercase_e01_files() -> None:
    """E01Mounter.detect_e01_images finds lowercase .e01 files."""
    # Arrange
    with patch.object(Path, "rglob") as mock_rglob:
        mock_file = MagicMock(spec=Path)
        mock_file.exists.return_value = True
        mock_file.stat.return_value.st_size = 1024**3 * 5
        mock_file.stem = "disk"

        def side_effect(pattern):
            if pattern == "*.E01":
                return []
            elif pattern == "*.e01":
                return [mock_file]
            return []

        mock_rglob.side_effect = side_effect

        # Act
        images = E01Mounter.detect_e01_images(Path("/tmp"))

        # Assert
        assert len(images) == 1
        assert images[0].name == "disk"


def test_e01_mounter_detect_images_filters_non_evidence_files() -> None:
    """E01Mounter.detect_e01_images skips files that fail stat()."""
    # Arrange
    with patch.object(Path, "rglob") as mock_rglob:
        mock_file = MagicMock(spec=Path)
        mock_file.exists.return_value = True
        mock_file.stat.side_effect = OSError("Permission denied")
        mock_rglob.return_value = [mock_file]

        # Act
        images = E01Mounter.detect_e01_images(Path("/tmp"))

        # Assert
        assert len(images) == 0


def test_e01_mounter_detect_images_returns_empty_for_no_matches() -> None:
    """E01Mounter.detect_e01_images returns empty list when no .E01 files found."""
    # Arrange
    with patch.object(Path, "rglob", return_value=[]):
        # Act
        images = E01Mounter.detect_e01_images(Path("/tmp"))

        # Assert
        assert len(images) == 0


def test_e01_mounter_detect_images_detects_memory_vs_disk_type() -> None:
    """E01Mounter.detect_e01_images correctly identifies memory vs disk images."""
    # Arrange
    with patch.object(Path, "rglob") as mock_rglob:
        mem_file = MagicMock(spec=Path)
        mem_file.exists.return_value = True
        mem_file.stat.return_value.st_size = 1024**3 * 4
        mem_file.stem = "memory_dump"

        disk_file = MagicMock(spec=Path)
        disk_file.exists.return_value = True
        disk_file.stat.return_value.st_size = 1024**3 * 500
        disk_file.stem = "disk_image"

        def side_effect(pattern):
            if pattern == "*.E01":
                return [mem_file, disk_file]
            return []

        mock_rglob.side_effect = side_effect

        # Act
        images = E01Mounter.detect_e01_images(Path("/tmp"))

        # Assert
        assert len(images) == 2
        mem_image = next(img for img in images if img.name == "memory_dump")
        disk_image = next(img for img in images if img.name == "disk_image")
        assert mem_image.image_type == "memory"
        assert disk_image.image_type == "disk"


# ---------------------------------------------------------------------------
# E01Mounter Mounting Tests
# ---------------------------------------------------------------------------


@patch("subprocess.run")
@patch("tempfile.mkdtemp")
@patch("time.sleep")
def test_e01_mounter_mount_image_creates_mount_point(
    mock_sleep: Mock, mock_mkdtemp: Mock, mock_run: Mock
) -> None:
    """E01Mounter.mount_e01 creates temporary mount point."""
    # Arrange
    mock_mkdtemp.return_value = "/tmp/sift_e01_test_12345"
    mock_run.return_value = subprocess.CompletedProcess(
        args=["sudo", "ewfmount"], returncode=0
    )

    image = E01Image(
        path=Path("/tmp/evidence.E01"),
        name="evidence",
        size_gb=10.0,
        image_type="memory",  # Use memory to avoid filesystem mount
    )

    # Act
    success, msg, mounted = E01Mounter.mount_e01(image)

    # Assert
    assert mock_mkdtemp.call_count >= 1
    first_call = mock_mkdtemp.call_args_list[0]
    assert "sift_e01_evidence_" in first_call[1]["prefix"]


@patch("subprocess.run")
@patch("tempfile.mkdtemp")
@patch("time.sleep")
def test_e01_mounter_mount_image_calls_ewfmount_subprocess(
    mock_sleep: Mock, mock_mkdtemp: Mock, mock_run: Mock
) -> None:
    """E01Mounter.mount_e01 calls ewfmount with correct arguments."""
    # Arrange
    mock_mkdtemp.return_value = "/tmp/mount"
    mock_run.return_value = subprocess.CompletedProcess(
        args=["sudo", "ewfmount"], returncode=0
    )

    image = E01Image(
        path=Path("/tmp/evidence.E01"),
        name="evidence",
        size_gb=10.0,
        image_type="memory",  # Use memory to avoid filesystem mount
    )

    # Act
    E01Mounter.mount_e01(image)

    # Assert - Find the sudo ewfmount call (not the 'which ewfmount' call)
    ewfmount_call = next(
        call
        for call in mock_run.call_args_list
        if isinstance(call[0][0], list) and "sudo" in call[0][0]
    )
    call_args = ewfmount_call[0][0]
    assert call_args[0] == "sudo"
    assert call_args[1] == "ewfmount"
    assert "-X" in call_args
    assert "allow_other" in call_args


@patch("subprocess.run")
@patch("tempfile.mkdtemp")
@patch("time.sleep")
def test_e01_mounter_mount_image_returns_mounted_image_on_success(
    mock_sleep: Mock, mock_mkdtemp: Mock, mock_run: Mock
) -> None:
    """E01Mounter.mount_e01 returns MountedImage on successful mount."""
    # Arrange
    mock_mkdtemp.return_value = "/tmp/mount"
    mock_run.return_value = subprocess.CompletedProcess(
        args=["sudo"], returncode=0
    )

    image = E01Image(
        path=Path("/tmp/evidence.E01"),
        name="evidence",
        size_gb=10.0,
        image_type="memory",
    )

    # Act
    success, msg, mounted = E01Mounter.mount_e01(image)

    # Assert
    assert success is True
    assert mounted is not None
    assert mounted.e01_path == image.path
    assert mounted.mount_point == Path("/tmp/mount")


@patch("subprocess.run")
@patch("tempfile.mkdtemp")
@patch("time.sleep")
def test_e01_mounter_mount_image_handles_ewfmount_failure(
    mock_sleep: Mock, mock_mkdtemp: Mock, mock_run: Mock
) -> None:
    """E01Mounter.mount_e01 handles ewfmount failure gracefully."""
    # Arrange
    mock_mkdtemp.return_value = "/tmp/mount"

    # Mock check_dependencies to succeed, then ewfmount to fail
    def mock_run_side_effect(*args, **kwargs):
        cmd = args[0]
        if "which" in cmd:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="/usr/bin/ewfmount"
            )
        else:
            return subprocess.CompletedProcess(
                args=cmd, returncode=1, stderr="Failed to open image"
            )

    mock_run.side_effect = mock_run_side_effect

    image = E01Image(
        path=Path("/tmp/evidence.E01"),
        name="evidence",
        size_gb=10.0,
        image_type="memory",  # Use memory to avoid filesystem mount
    )

    with patch.object(Path, "rmdir"):
        # Act
        success, msg, mounted = E01Mounter.mount_e01(image)

        # Assert
        assert success is False
        assert "ewfmount failed" in msg
        assert mounted is None


@patch("subprocess.run")
@patch("tempfile.mkdtemp")
@patch("time.sleep")
def test_e01_mounter_mount_image_cleans_up_on_failure(
    mock_sleep: Mock, mock_mkdtemp: Mock, mock_run: Mock
) -> None:
    """E01Mounter.mount_e01 removes mount point when ewfmount fails."""
    # Arrange
    mock_mkdtemp.return_value = "/tmp/mount"

    # Mock check_dependencies to succeed, then ewfmount to fail
    def mock_run_side_effect(*args, **kwargs):
        cmd = args[0]
        if "which" in cmd:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="/usr/bin/ewfmount"
            )
        else:
            return subprocess.CompletedProcess(
                args=cmd, returncode=1, stderr="Error"
            )

    mock_run.side_effect = mock_run_side_effect

    image = E01Image(
        path=Path("/tmp/evidence.E01"),
        name="evidence",
        size_gb=10.0,
        image_type="memory",
    )

    with patch.object(Path, "rmdir") as mock_rmdir:
        # Act
        E01Mounter.mount_e01(image)

        # Assert
        mock_rmdir.assert_called_once()


@patch("subprocess.run")
@patch("tempfile.mkdtemp")
@patch("time.sleep")
def test_e01_mounter_mount_image_skips_filesystem_mount_for_memory_images(
    mock_sleep: Mock, mock_mkdtemp: Mock, mock_run: Mock
) -> None:
    """E01Mounter.mount_e01 skips filesystem mounting for memory images."""
    # Arrange
    mock_mkdtemp.return_value = "/tmp/mount"
    mock_run.return_value = subprocess.CompletedProcess(
        args=["sudo"], returncode=0
    )

    image = E01Image(
        path=Path("/tmp/memory.E01"),
        name="memory",
        size_gb=4.0,
        image_type="memory",
    )

    # Act
    success, msg, mounted = E01Mounter.mount_e01(image)

    # Assert
    assert success is True
    assert mounted is not None
    assert mounted.fs_mount_point is None


# ---------------------------------------------------------------------------
# Filesystem Mounting Tests
# ---------------------------------------------------------------------------


@patch("subprocess.run")
@patch("tempfile.mkdtemp")
def test_e01_mounter_mount_filesystem_detects_raw_device(
    mock_mkdtemp: Mock, mock_run: Mock
) -> None:
    """E01Mounter._mount_filesystem requires raw_device in MountedImage."""
    # Arrange
    mounted = MountedImage(
        e01_path=Path("/tmp/evidence.E01"),
        mount_point=Path("/tmp/mount"),
        raw_device=None,
    )

    # Act
    result = E01Mounter._mount_filesystem(mounted)

    # Assert
    assert result is False


@patch("subprocess.run")
@patch("tempfile.mkdtemp")
def test_e01_mounter_mount_filesystem_creates_filesystem_mount_point(
    mock_mkdtemp: Mock, mock_run: Mock
) -> None:
    """E01Mounter._mount_filesystem creates temporary filesystem mount point."""
    # Arrange
    mock_mkdtemp.return_value = "/tmp/fs_mount"
    mock_run.return_value = subprocess.CompletedProcess(
        args=["sudo", "mount"], returncode=0
    )

    mounted = MountedImage(
        e01_path=Path("/tmp/evidence.E01"),
        mount_point=Path("/tmp/e01_mount"),
        raw_device=Path("/tmp/e01_mount/ewf1"),
    )

    # Act
    result = E01Mounter._mount_filesystem(mounted)

    # Assert
    mock_mkdtemp.assert_called()
    assert "sift_fs_evidence" in mock_mkdtemp.call_args[1]["prefix"]


@patch("subprocess.run")
@patch("tempfile.mkdtemp")
def test_e01_mounter_mount_filesystem_calls_mount_subprocess(
    mock_mkdtemp: Mock, mock_run: Mock
) -> None:
    """E01Mounter._mount_filesystem calls mount with multiple offsets."""
    # Arrange
    mock_mkdtemp.return_value = "/tmp/fs_mount"
    mock_run.return_value = subprocess.CompletedProcess(
        args=["sudo", "mount"], returncode=0
    )

    mounted = MountedImage(
        e01_path=Path("/tmp/evidence.E01"),
        mount_point=Path("/tmp/e01_mount"),
        raw_device=Path("/tmp/e01_mount/ewf1"),
    )

    # Act
    E01Mounter._mount_filesystem(mounted)

    # Assert
    assert mock_run.call_count >= 2
    call_args = mock_run.call_args_list[1][0][0]
    assert "sudo" in call_args
    assert "mount" in call_args


@patch("subprocess.run")
@patch("tempfile.mkdtemp")
def test_e01_mounter_mount_filesystem_handles_mount_failure(
    mock_mkdtemp: Mock, mock_run: Mock
) -> None:
    """E01Mounter._mount_filesystem returns False when all offsets fail."""
    # Arrange
    mock_mkdtemp.return_value = "/tmp/fs_mount"
    mock_run.return_value = subprocess.CompletedProcess(
        args=["sudo", "mount"], returncode=1
    )

    mounted = MountedImage(
        e01_path=Path("/tmp/evidence.E01"),
        mount_point=Path("/tmp/e01_mount"),
        raw_device=Path("/tmp/e01_mount/ewf1"),
    )

    with patch.object(Path, "rmdir"):
        # Act
        result = E01Mounter._mount_filesystem(mounted)

        # Assert
        assert result is False


@patch("subprocess.run")
@patch("tempfile.mkdtemp")
def test_e01_mounter_mount_filesystem_supports_read_only_mount(
    mock_mkdtemp: Mock, mock_run: Mock
) -> None:
    """E01Mounter._mount_filesystem uses read-only mount options."""
    # Arrange
    mock_mkdtemp.return_value = "/tmp/fs_mount"
    mock_run.return_value = subprocess.CompletedProcess(
        args=["sudo", "mount"], returncode=0
    )

    mounted = MountedImage(
        e01_path=Path("/tmp/evidence.E01"),
        mount_point=Path("/tmp/e01_mount"),
        raw_device=Path("/tmp/e01_mount/ewf1"),
    )

    # Act
    E01Mounter._mount_filesystem(mounted)

    # Assert
    call_args = str(mock_run.call_args_list[1][0][0])
    assert "ro" in call_args


# ---------------------------------------------------------------------------
# Dependency Check Tests
# ---------------------------------------------------------------------------


@patch("subprocess.run")
def test_e01_mounter_check_dependencies_finds_ewfmount(mock_run: Mock) -> None:
    """E01Mounter.check_dependencies returns success when ewfmount found."""
    # Arrange
    mock_run.return_value = subprocess.CompletedProcess(
        args=["which", "ewfmount"], returncode=0, stdout="/usr/bin/ewfmount\n"
    )

    # Act
    success, msg = E01Mounter.check_dependencies()

    # Assert
    assert success is True
    assert "OK" in msg


@patch("subprocess.run")
def test_e01_mounter_check_dependencies_handles_missing_ewfmount(
    mock_run: Mock,
) -> None:
    """E01Mounter.check_dependencies returns failure when ewfmount missing."""
    # Arrange
    mock_run.return_value = subprocess.CompletedProcess(
        args=["which", "ewfmount"], returncode=1
    )

    # Act
    success, msg = E01Mounter.check_dependencies()

    # Assert
    assert success is False
    assert "ewfmount not found" in msg


@patch("subprocess.run")
@patch("tempfile.mkdtemp")
def test_e01_mounter_mount_e01_checks_dependencies_first(
    mock_mkdtemp: Mock, mock_run: Mock
) -> None:
    """E01Mounter.mount_e01 checks dependencies before mounting."""
    # Arrange
    mock_run.return_value = subprocess.CompletedProcess(
        args=["which", "ewfmount"], returncode=1
    )

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
    assert "ewfmount not found" in msg
    assert mounted is None
    mock_mkdtemp.assert_not_called()
