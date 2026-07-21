"""Pre-flight evidence validation for the 4n6 Nexus detection engine.

Before an expensive detection pipeline touches a piece of evidence, this
module performs cheap, deterministic sanity checks: the path exists, the
file is large enough to be plausible, an optional format probe succeeds
(for example a ``vol windows.info`` marker on a memory dump), and an
optional mount-liveness predicate holds (for disk images).

All external interactions are injectable callables, so the checks are
fully testable with ``tmp_path`` fixtures and fake probes without running
any real forensic tools. The function is pure: it reads the filesystem
metadata but never mutates inputs or state.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

# Semantic result codes.
CODE_OK: int = 0
CODE_MISSING: int = 10
CODE_TOO_SMALL: int = 11
CODE_PROBE_FAILED: int = 12
CODE_NOT_MOUNTED: int = 13

# Kinds that support a format probe (memory analysis marker).
_MEMORY_KINDS: frozenset[str] = frozenset({"memory"})

# Kinds that support an optional mount-liveness predicate.
_DISK_KINDS: frozenset[str] = frozenset({"e01", "dd", "raw"})


@dataclass(frozen=True)
class PreflightResult:
    """Outcome of a pre-flight evidence validation check.

    Attributes:
        ok: True only when every applicable check passed.
        code: Semantic result code (see the ``CODE_*`` constants).
        reason: Short human-readable explanation of the outcome.
    """

    ok: bool
    code: int
    reason: str


def preflight_check(
    evidence_path: Path,
    kind: str,
    min_bytes: int = 1024,
    probe: Callable[[Path], bool] | None = None,
    mount_predicate: Callable[[Path], bool] | None = None,
) -> PreflightResult:
    """Run cheap sanity checks on an evidence file before processing.

    Checks run in order and short-circuit on the first failure:
        1. Path must exist (else code 10).
        2. Size must be at least ``min_bytes`` (else code 11).
        3. If ``kind`` is a memory kind and a ``probe`` is supplied, the
           probe must return truthy; any exception counts as failure
           (else code 12).
        4. If ``kind`` is a disk kind and a ``mount_predicate`` is
           supplied, it must return truthy (else code 13).

    Args:
        evidence_path: Path to the evidence file.
        kind: Evidence kind, for example "memory", "e01", "dd", or "raw".
        min_bytes: Minimum plausible size in bytes.
        probe: Optional format probe for memory kinds, for example a
            ``vol windows.info`` marker check. Returns truthy on success.
        mount_predicate: Optional mount-liveness predicate for disk kinds.
            Returns truthy when the image is mounted and readable.

    Returns:
        A :class:`PreflightResult` describing the outcome. It never raises
        for probe or predicate failures; those are reported via the code.
    """
    if not evidence_path.exists():
        return PreflightResult(
            ok=False,
            code=CODE_MISSING,
            reason=f"missing: evidence path does not exist: {evidence_path}",
        )

    size = evidence_path.stat().st_size
    if size < min_bytes:
        return PreflightResult(
            ok=False,
            code=CODE_TOO_SMALL,
            reason=(
                f"too_small: {size} bytes is below the minimum of " f"{min_bytes} bytes"
            ),
        )

    if kind in _MEMORY_KINDS and probe is not None:
        try:
            probe_ok = bool(probe(evidence_path))
        except Exception as exc:  # noqa: BLE001 - probe is untrusted
            return PreflightResult(
                ok=False,
                code=CODE_PROBE_FAILED,
                reason=f"probe_failed: probe raised {exc!r}",
            )
        if not probe_ok:
            return PreflightResult(
                ok=False,
                code=CODE_PROBE_FAILED,
                reason="probe_failed: format probe returned falsy",
            )

    if kind in _DISK_KINDS and mount_predicate is not None:
        if not bool(mount_predicate(evidence_path)):
            return PreflightResult(
                ok=False,
                code=CODE_NOT_MOUNTED,
                reason="not_mounted: mount predicate returned falsy",
            )

    return PreflightResult(
        ok=True, code=CODE_OK, reason="ok: evidence passed pre-flight"
    )
