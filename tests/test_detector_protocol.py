"""Contract tests for the Linux artifact-detector Protocol (SFE-t72i).

The five Linux dead-disk detectors share one duck-typed seam:
``analyze(artifacts: dict[str, Any]) -> list[Finding]`` reading a single
collected-artifacts mapping. :class:`LinuxArtifactDetector` formalizes that
seam as a ``runtime_checkable`` :class:`typing.Protocol` so a new Linux
detector that drifts from the contract is caught here (CI runs pytest; mypy is
not in CI, so this executable check -- not the type annotations alone -- is
what gives the contract teeth).

These are structural/behavioral guards, not detection-signal tests: each Linux
detector must (a) satisfy the Protocol via ``isinstance`` and (b) return a
``list`` when handed an empty artifacts dict (the pure-function, no-input
degenerate case). The per-detector signal behavior is covered by each
detector's own test module.
"""

from __future__ import annotations

import pytest

from sift_find_evil.detectors import (
    LinuxArtifactDetector,
    LinuxAuthDetector,
    LinuxExecutionDetector,
    LinuxLoginSessionDetector,
    LinuxPersistenceDetector,
    LinuxProcessDetector,
)

# The full Linux cluster. A new Linux detector added to detectors/__init__.py
# should be added here too; conformance is then enforced by both parametrized
# tests below.
_LINUX_DETECTORS = [
    LinuxPersistenceDetector,
    LinuxAuthDetector,
    LinuxExecutionDetector,
    LinuxLoginSessionDetector,
    LinuxProcessDetector,
]


@pytest.mark.parametrize("detector_cls", _LINUX_DETECTORS)
def test_linux_detector_satisfies_protocol(detector_cls: type) -> None:
    """Every Linux detector structurally conforms to LinuxArtifactDetector."""
    assert isinstance(detector_cls(), LinuxArtifactDetector)


@pytest.mark.parametrize("detector_cls", _LINUX_DETECTORS)
def test_linux_detector_returns_list_on_empty_artifacts(detector_cls: type) -> None:
    """analyze({}) is a pure no-op returning an empty finding list, no raise."""
    result = detector_cls().analyze({})

    assert isinstance(result, list)
    assert result == []


def test_protocol_rejects_non_conforming_object() -> None:
    """A class lacking analyze() is not a LinuxArtifactDetector.

    Guards the guard: if the Protocol were degenerate (e.g. lost its only
    method), this would wrongly pass and the conformance tests above would
    stop meaning anything.
    """

    class NotADetector:
        def something_else(self) -> None: ...

    assert not isinstance(NotADetector(), LinuxArtifactDetector)
