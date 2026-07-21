"""Evidence fusion utilities for combining detector outputs.

Currently exposes a pure-Python Dempster-Shafer implementation over the
binary frame {malicious, benign} with conflict tracking (K) and a Yager
fallback for high-conflict evidence.
"""

from __future__ import annotations

from sift_find_evil.fusion.ds_fusion import (
    FusionResult,
    belief,
    dempster_combine,
    detector_bpa,
    fuse,
    plausibility,
)

__all__ = [
    "FusionResult",
    "belief",
    "dempster_combine",
    "detector_bpa",
    "fuse",
    "plausibility",
]
