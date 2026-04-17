"""Disk-level analysis: detect anti-forensic actions at the partition-table layer."""

from .gpt_inspector import (
    GPTEntry,
    GPTHeader,
    GPTInspection,
    inspect_gpt,
)
from .wipe_detector import WipedDiskFinding, detect_wiped_disk

__all__ = [
    "GPTEntry",
    "GPTHeader",
    "GPTInspection",
    "inspect_gpt",
    "WipedDiskFinding",
    "detect_wiped_disk",
]
