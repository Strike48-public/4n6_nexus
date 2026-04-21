"""YARA scanning surface for malware classification (SFE-86p).

yara-python is an optional dependency. Importing this package is always safe;
attempting to compile or scan without libyara installed raises ``MissingYaraError``.
"""

from __future__ import annotations

from .scanner import (
    CompileError,
    MissingYaraError,
    YaraMatch,
    YaraScanner,
    YaraString,
)

__all__ = [
    "CompileError",
    "MissingYaraError",
    "YaraMatch",
    "YaraScanner",
    "YaraString",
]
