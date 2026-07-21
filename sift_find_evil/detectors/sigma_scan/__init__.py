"""Hermetic mini-Sigma rule matching for parsed events.

Exposes :func:`match_events`, a dependency-free evaluator for a small subset of
the Sigma rule format. See :mod:`sift_find_evil.detectors.sigma_scan.matcher`
for the supported rule shape and modifiers.
"""

from __future__ import annotations

from .matcher import match_events

__all__ = ["match_events"]
