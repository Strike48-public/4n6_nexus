"""Cross-source hidden-process correlation (Linux, MITRE T1014).

A process present in the memory kernel task list (Volatility ``linux.pslist``)
but ABSENT from the ``/proc`` filesystem capture is hidden from userland
enumeration by a rootkit hooking ``getdents()`` on ``/proc`` to conceal itself
from ``ps``/``ls`` (MITRE T1014, Rootkit).

This is the Linux analog of the Windows ``psscan``-vs-``pslist`` divergence in
``MemoryDetector._analyze_hidden_processes``: there the memory scanner sees a
process the doubly-linked list hides; here the memory task list sees a process
the procfs capture hides.

Unlike a single-artifact detector this needs TWO raw inputs -- the ``/proc``
capture rows (``parsers.linux_proc.parse_proc_processes``) and the
``linux.pslist`` memory rows (``memory.volatility_runner.LinuxProcessRow``) --
and neither single-artifact detector fires on a merely-hidden process. It
therefore lives in the correlation layer and is invoked where both inputs are
assembled (the CLI ``analyze`` path and the scenario harness), not inside either
detector.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from ..findings.categories import FindingCategory
from ..findings.finding import Finding

# Structural PIDs that a userland getdents hook cannot hide: 0 (idle/swapper),
# 1 (init/systemd), 2 (kthreadd, the kernel-thread parent). Their absence from a
# /proc capture is capture skew, never T1014.
_STRUCTURAL_PIDS: frozenset[int] = frozenset({0, 1, 2})

# ppid of every kernel thread (child of kthreadd, PID 2). Kernel threads are not
# hideable by a userland getdents hook and always carry a /proc entry on a
# healthy host, so their absence is capture skew, not a rootkit signal.
_KTHREADD_PID = 2


def _pslist_pid(row: Any) -> Optional[int]:
    pid = getattr(row, "pid", None)
    return pid if isinstance(pid, int) else None


def _proc_pid(row: Any) -> Optional[int]:
    pid = row.get("pid") if isinstance(row, dict) else getattr(row, "pid", None)
    return pid if isinstance(pid, int) else None


def _is_kernel_thread(row: Any) -> bool:
    return getattr(row, "ppid", None) == _KTHREADD_PID


def _divergence_span(row: Any) -> str:
    """Provenance span for the anchor falsifier.

    Must literally contain the asserted PID: the independent falsifier re-derives
    a finding's ``pid`` anchor against this text, and a pid-asserting finding
    whose span omits the pid is FALSIFIED.
    """
    pid = _pslist_pid(row)
    ppid = getattr(row, "ppid", None)
    name = getattr(row, "name", None) or ""
    return (
        f"linux.pslist pid={pid} ppid={ppid} name={name} present in kernel task "
        f"list; /proc/{pid} ABSENT from procfs capture"
    )


def detect_hidden_linux_processes(
    proc_rows: Optional[Iterable[Any]],
    pslist_rows: Optional[Iterable[Any]],
) -> list[Finding]:
    """Return T1014 findings for PIDs in ``linux.pslist`` but absent from ``/proc``.

    ``proc_rows``: /proc capture records (dicts with a ``pid`` key), from
    ``parsers.linux_proc.parse_proc_processes``.
    ``pslist_rows``: ``LinuxProcessRow`` records from ``linux.pslist``.

    Both inputs are required; either being ``None``/empty yields ``[]`` (no
    cross-check is possible with one view). The direction is intentional: a PID
    in ``/proc`` but not ``pslist`` is a process that started AFTER the memory
    capture, not a hidden one, and is never flagged.
    """
    if not proc_rows or not pslist_rows:
        return []

    proc_pids = {pid for pid in (_proc_pid(r) for r in proc_rows) if pid is not None}

    findings: list[Finding] = []
    seen: set[int] = set()
    for row in pslist_rows:
        pid = _pslist_pid(row)
        if pid is None or pid in proc_pids:
            continue
        if pid in _STRUCTURAL_PIDS or _is_kernel_thread(row):
            continue
        if pid in seen:  # linux.pslist emits one row per thread; dedupe by pid
            continue
        seen.add(pid)
        findings.append(_build_finding(row))
    return findings


def _build_finding(row: Any) -> Finding:
    pid = _pslist_pid(row)
    ppid = getattr(row, "ppid", None)
    name = getattr(row, "name", None) or "unknown"
    create_time = getattr(row, "create_time", None)
    return Finding(
        title=f"Hidden process: PID {pid} ({name}) in linux.pslist but not /proc",
        description=(
            f"Volatility linux.pslist reports PID {pid} ({name}) in the kernel "
            f"task list, but the /proc filesystem capture has no /proc/{pid} "
            "entry. A userland process present in kernel memory yet absent from "
            "procfs is the classic signature of a rootkit hooking getdents() on "
            "/proc to hide itself from ps/ls (MITRE T1014). Residual false-"
            "positive surface: a process that exited between the memory capture "
            "and the /proc walk -- corroborate against the timeline before acting."
        ),
        finding_type="behavior",
        severity="high",
        category=FindingCategory.PROCESS_INJECTION,
        evidence={
            "pid": pid,
            "ppid": ppid,
            "process": name,
            "create_time": create_time,
            "source": "pslist_without_proc",
            "mitre_attack": ["T1014"],
            "mitre_technique": "T1014",
            "source_span": _divergence_span(row),
            # Normalized timeline event so this cross-source finding correlates
            # with a same-process finding from another artifact in hardening.
            "timeline": {
                "ts": str(create_time or ""),
                "source": "linux.pslist",
                "actor": str(name or ""),
                "target": "",
                "type": "process_hidden",
            },
        },
        confidence=0.65,
        confidence_label="Medium",
        reasoning_chain=[
            f"linux.pslist reports PID {pid} ({name}); the /proc capture does not.",
            "A userland process in the kernel task list but missing from procfs "
            "is a classic getdents-hook rootkit signal used to hide malware "
            "(MITRE T1014).",
            "Structural PIDs (0/1/2) and kernel threads are excluded; the residual "
            "FP surface is a process terminated between the two captures.",
        ],
        artifact_sources=["memory", "proc"],
        techniques=["T1014"],
    )
