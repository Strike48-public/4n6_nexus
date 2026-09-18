"""Formalized detector contracts (SFE-t72i).

The engine's detectors are duck-typed: each exposes an ``analyze`` method that
returns ``list[Finding]``. That seam is *not* uniform across the whole roster --
the Windows/memory/network detectors take domain-specific argument shapes
(multiple parsed streams, keyword args, an iterable of strings, a ``Path``), so
a single universal detector Protocol would be inaccurate.

The **Linux dead-disk cluster is uniform**, however: every Linux detector reads
one collected-artifacts mapping and returns findings. :class:`LinuxArtifactDetector`
captures exactly that contract so new Linux detectors conform to a checked shape
rather than an unwritten convention.

Enforcement: ``runtime_checkable`` lets ``tests/test_detector_protocol.py``
assert conformance via ``isinstance`` (CI runs pytest; mypy is not in CI). The
type annotation at the call sites (``list[LinuxArtifactDetector]`` in
``cli._analyze_linux_artifacts`` and ``scenario_runner._run_linux_detectors``)
additionally gives local mypy/IDE a signature-level check.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from ..findings import Finding


@runtime_checkable
class LinuxArtifactDetector(Protocol):
    """A stateless detector over one collected Linux artifacts mapping.

    Implementations must:

    * be a **pure function** of ``artifacts`` -- never mutate the mapping and
      perform no I/O beyond what the public interface declares;
    * treat any missing key as an empty stream (so ``analyze({})`` is a valid
      no-op returning ``[]``);
    * return one :class:`~sift_find_evil.findings.Finding` per detection, each
      tagged with an appropriate ``FindingCategory``.

    Classes satisfy this Protocol structurally -- no explicit subclassing is
    required (or wanted); the detectors stay plain classes.
    """

    def analyze(self, artifacts: dict[str, Any]) -> list[Finding]:
        """Scan ``artifacts`` and return the findings it yields."""
        ...
