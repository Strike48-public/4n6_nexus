"""
E01 forensic image mounting utility for TUI.

Handles mounting E01 disk and memory images using ewfmount and mount.
"""

import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional, Tuple, List
from dataclasses import dataclass


@dataclass
class E01Image:
    """Represents a detected E01 image."""

    path: Path
    name: str
    size_gb: float
    image_type: str  # 'disk' or 'memory'

    @property
    def is_memory(self) -> bool:
        """Check if this is a memory image."""
        name_lower = self.name.lower()
        return "mem" in name_lower or "ram" in name_lower or "dmp" in name_lower


@dataclass
class MountedImage:
    """Represents a successfully mounted E01 image."""

    e01_path: Path
    mount_point: Path
    fs_mount_point: Optional[Path] = None
    raw_device: Optional[Path] = None

    def cleanup(self) -> List[str]:
        """Unmount and clean up mount points.

        Returns:
            List of cleanup commands executed
        """
        commands = []

        # Unmount filesystem first (if mounted)
        if self.fs_mount_point and self.fs_mount_point.exists():
            cmd = f"sudo umount {self.fs_mount_point}"
            subprocess.run(cmd, shell=True, check=False, capture_output=True)
            commands.append(cmd)
            try:
                self.fs_mount_point.rmdir()
            except Exception:
                pass

        # Unmount E01
        if self.mount_point and self.mount_point.exists():
            cmd = f"sudo umount {self.mount_point}"
            subprocess.run(cmd, shell=True, check=False, capture_output=True)
            commands.append(cmd)
            try:
                self.mount_point.rmdir()
            except Exception:
                pass

        return commands


class E01Mounter:
    """Handles E01 image mounting operations."""

    @staticmethod
    def detect_e01_images(directory: Path) -> List[E01Image]:
        """Detect E01 images in a directory.

        Args:
            directory: Directory to scan for E01 files

        Returns:
            List of E01Image objects
        """
        images = []

        for e01_file in directory.rglob("*.E01"):
            # Also check for lowercase
            if not e01_file.exists():
                continue

            try:
                size_gb = e01_file.stat().st_size / (1024**3)

                # Detect if memory or disk image based on name
                name_lower = e01_file.stem.lower()
                if "mem" in name_lower or "ram" in name_lower or "dmp" in name_lower:
                    image_type = "memory"
                else:
                    image_type = "disk"

                images.append(
                    E01Image(
                        path=e01_file,
                        name=e01_file.stem,
                        size_gb=size_gb,
                        image_type=image_type,
                    )
                )
            except Exception:
                continue

        # Also check for .e01 (lowercase)
        for e01_file in directory.rglob("*.e01"):
            if e01_file not in [img.path for img in images]:
                try:
                    size_gb = e01_file.stat().st_size / (1024**3)
                    name_lower = e01_file.stem.lower()

                    if (
                        "mem" in name_lower
                        or "ram" in name_lower
                        or "dmp" in name_lower
                    ):
                        image_type = "memory"
                    else:
                        image_type = "disk"

                    images.append(
                        E01Image(
                            path=e01_file,
                            name=e01_file.stem,
                            size_gb=size_gb,
                            image_type=image_type,
                        )
                    )
                except Exception:
                    continue

        return images

    @staticmethod
    def check_dependencies() -> Tuple[bool, str]:
        """Check if required tools are installed.

        Returns:
            (success, message) tuple
        """
        # Check for ewfmount
        result = subprocess.run(["which", "ewfmount"], capture_output=True, text=True)

        if result.returncode != 0:
            return False, "ewfmount not found. Install: sudo apt install ewf-tools"

        return True, "Dependencies OK"

    @staticmethod
    def mount_e01(e01_image: E01Image) -> Tuple[bool, str, Optional[MountedImage]]:
        """Mount an E01 image.

        Args:
            e01_image: E01Image to mount

        Returns:
            (success, message, MountedImage or None) tuple
        """
        # Check dependencies
        deps_ok, deps_msg = E01Mounter.check_dependencies()
        if not deps_ok:
            return False, deps_msg, None

        # Create temporary mount point
        try:
            mount_point = Path(tempfile.mkdtemp(prefix=f"sift_e01_{e01_image.name}_"))
        except Exception as e:
            return False, f"Failed to create mount point: {e}", None

        # Mount E01 with ewfmount
        try:
            cmd = ["sudo", "ewfmount", str(e01_image.path), str(mount_point)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode != 0:
                mount_point.rmdir()
                return False, f"ewfmount failed: {result.stderr}", None

            # Wait for mount to complete
            time.sleep(1)

            # Check for raw device (usually ewf1)
            raw_device = mount_point / "ewf1"
            if not raw_device.exists():
                # Try to unmount
                subprocess.run(
                    ["sudo", "umount", str(mount_point)], capture_output=True
                )
                mount_point.rmdir()
                return False, f"Raw device not found at {raw_device}", None

            mounted = MountedImage(
                e01_path=e01_image.path, mount_point=mount_point, raw_device=raw_device
            )

            # If it's a disk image, try to mount the filesystem
            if e01_image.image_type == "disk":
                fs_mounted = E01Mounter._mount_filesystem(mounted)
                if fs_mounted:
                    return True, f"Mounted {e01_image.name} successfully", mounted
                else:
                    # Filesystem mount failed, but raw device is available
                    return True, f"Mounted {e01_image.name} (raw device only)", mounted
            else:
                # Memory image - just provide raw device
                return True, f"Mounted memory image {e01_image.name}", mounted

        except subprocess.TimeoutExpired:
            return False, "Mount operation timed out", None
        except Exception as e:
            return False, f"Mount error: {e}", None

    @staticmethod
    def _mount_filesystem(mounted: MountedImage) -> bool:
        """Try to mount the filesystem from a mounted E01 disk.

        Args:
            mounted: MountedImage with raw_device available

        Returns:
            True if filesystem mounted successfully
        """
        if not mounted.raw_device:
            return False

        try:
            # Create filesystem mount point
            fs_mount = Path(
                tempfile.mkdtemp(prefix=f"sift_fs_{mounted.e01_path.stem}_")
            )

            # Try to detect partitions using fdisk
            result = subprocess.run(
                ["sudo", "fdisk", "-l", str(mounted.raw_device)],
                capture_output=True,
                text=True,
                timeout=10,
            )

            # Try mounting with common offsets
            # Most common: 1048576 (1MB), 2048*512 bytes
            offsets = [0, 1048576, 2097152, 32256, 63 * 512]

            for offset in offsets:
                try:
                    cmd = [
                        "sudo",
                        "mount",
                        "-o",
                        f"ro,loop,offset={offset}",
                        str(mounted.raw_device),
                        str(fs_mount),
                    ]
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=10
                    )

                    if result.returncode == 0:
                        # Success!
                        mounted.fs_mount_point = fs_mount
                        return True
                except Exception:
                    continue

            # Filesystem mount failed, clean up
            fs_mount.rmdir()
            return False

        except Exception:
            return False
