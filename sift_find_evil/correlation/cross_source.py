"""Cross-source memory-vs-disk-vs-network correlator (SFE-md4v).

A discrepancy pass that runs AFTER the domain analysts and consumes only their
verified evidence to emit typed cross-source contradictions that no single domain
can see on its own:

  * GHOST_PROCESS        -- a process live in memory with no on-disk artifact
                            backing it (process hollowing / rootkit). T1055/T1014.
  * UNINSTALLED_EXECUTION -- an execution recorded in prefetch with no registry
                            install footprint (dropped-and-run). T1543/T1547.
  * PHANTOM_CONNECTION   -- a connection live in memory to an IP that no DNS query
                            in the capture resolved (hardcoded-IP C2). T1071.

Two design points carried over from sibling detectors:

  * ``_EPROCESS.ImageFileName`` is a 15-byte buffer, so a memory process name is
    truncated to 15 characters. ``names_reconcile`` treats a truncated memory
    name as matching its full disk name ("iCloudDrive.ex" == "iCloudDrive.exe")
    rather than misreading the truncation as a ghost.
  * present-but-empty (``[]``) is distinct from absent (``None``): an empty disk
    source means "we looked and found nothing", so every memory process is a
    genuine ghost; a ``None`` disk source means disk was never consulted and the
    ghost check simply has nothing to compare against.

The pass is gated: it runs only when a memory image is present, at least one
finding was verified upstream, and at least two source types are available (there
is nothing to correlate a lone source against). Pure and deterministic: same
inputs always yield the same discrepancies in a stable, sorted order.
"""

from __future__ import annotations

import ntpath
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Sequence

# _EPROCESS.ImageFileName is UCHAR[15]: a process name longer than 15 bytes is
# stored truncated. Names are compared after normalizing to this length.
_EPROCESS_NAME_LEN = 15

# A truncated memory name is a PREFIX of the full disk name (the 15-byte buffer
# commonly loses the trailing char to a null terminator, so "iCloudDrive.exe"
# surfaces as "iCloudDrive.ex"). A prefix only counts as a truncation match when
# the shorter name is at the truncation boundary -- i.e. long enough that it was
# plausibly clipped -- so a genuinely short name never reconciles with an
# unrelated longer one.
_TRUNCATION_MIN_LEN = _EPROCESS_NAME_LEN - 1

# File-less kernel pseudo-processes: they have no backing image on disk, so their
# absence from disk artifacts is expected and must never be read as a ghost.
_DEFAULT_SYSTEM_ALLOWLIST = frozenset(
    {
        "system",
        "registry",
        "memcompression",
        "memory compression",
        "secure system",
        "idle",
        "system idle process",
    }
)

# Public DNS resolvers clients legitimately reach by hardcoded IP with no prior
# DNS lookup. A memory connection to one of these with no PCAP resolution is
# expected, not a phantom C2 signal (consistent with the network-presence
# detector's known-benign-direct-IP-infrastructure rule).
_BENIGN_DIRECT_IPS = frozenset(
    {
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "1.0.0.1",
        "9.9.9.9",
        "208.67.222.222",
        "208.67.220.220",
    }
)


class DiscrepancyType(str, Enum):
    """The typed cross-source contradictions this pass can emit."""

    GHOST_PROCESS = "ghost_process"
    UNINSTALLED_EXECUTION = "uninstalled_execution"
    PHANTOM_CONNECTION = "phantom_connection"


@dataclass(frozen=True)
class CrossSourceDiscrepancy:
    """One cross-source contradiction with its citations and MITRE mapping.

    Attributes:
        type: The kind of discrepancy.
        subject: The offending entity (process name / executable / IP).
        description: Human-readable explanation for the report.
        memory_evidence: Memory-source citations backing the discrepancy.
        disk_evidence: Disk/registry/PCAP citations (what was searched).
        mitre: MITRE ATT&CK technique ids this discrepancy maps to.
        needs_verification: Always True -- each discrepancy auto-spawns a
            verifier re-check rather than being trusted as final.
    """

    type: DiscrepancyType
    subject: str
    description: str
    memory_evidence: tuple[str, ...] = field(default_factory=tuple)
    disk_evidence: tuple[str, ...] = field(default_factory=tuple)
    mitre: tuple[str, ...] = field(default_factory=tuple)
    needs_verification: bool = True


@dataclass(frozen=True)
class CrossSourceInput:
    """Verified per-source evidence handed to the correlator.

    Every source is ``None`` when that source was not consulted and a (possibly
    empty) sequence when it was. Distinguishing ``None`` from ``[]`` matters: an
    empty disk source proves every memory process is a ghost, whereas an absent
    one means the ghost check has nothing to compare against.
    """

    memory_process_names: Optional[Sequence[str]] = None
    disk_artifact_names: Optional[Sequence[str]] = None
    prefetch_executions: Optional[Sequence[str]] = None
    registry_installed: Optional[Sequence[str]] = None
    memory_foreign_ips: Optional[Sequence[str]] = None
    pcap_resolved_ips: Optional[Sequence[str]] = None
    verified_finding_count: int = 0


def normalize_eprocess_name(name: str) -> str:
    """Normalize a process name for comparison: basename, lowered, 15-byte clip.

    Disk artifacts arrive as full paths; the basename is what matches a memory
    process name. The result is truncated to the ``_EPROCESS.ImageFileName``
    buffer length so a full disk name is compared on equal footing with a
    memory name that the kernel already truncated.
    """
    base = ntpath.basename(name.strip().replace("/", "\\"))
    return base.lower()[:_EPROCESS_NAME_LEN]


def names_reconcile(memory_name: str, disk_name: str) -> bool:
    """True if a memory process name and a disk artifact name are the same file.

    Two names reconcile when their normalized (basename, lowered, 15-byte-clipped)
    forms are equal, OR when the memory name is an EPROCESS truncation of the
    disk name: the memory form is a prefix of the disk form and is at the
    truncation boundary (>= 14 chars), i.e. long enough that the kernel plausibly
    clipped it. The boundary guard means a genuinely short name ("evil.exe")
    never reconciles with an unrelated longer one ("evilcorp_installer.exe").
    """
    mem = normalize_eprocess_name(memory_name)
    disk = normalize_eprocess_name(disk_name)
    if mem == disk:
        return True
    # Truncation only shortens; the memory form must be the shorter prefix.
    if len(mem) >= _TRUNCATION_MIN_LEN and disk.startswith(mem):
        return True
    return False


def _present(seq: Optional[Sequence[str]]) -> bool:
    """True if a source was consulted (not None), even if it is empty."""
    return seq is not None


def _source_type_count(inp: CrossSourceInput) -> int:
    """Count the distinct source *types* that were consulted."""
    return sum(
        _present(s)
        for s in (
            inp.memory_process_names,
            inp.disk_artifact_names,
            inp.prefetch_executions,
            inp.registry_installed,
            inp.memory_foreign_ips,
            inp.pcap_resolved_ips,
        )
    )


def _memory_present(inp: CrossSourceInput) -> bool:
    """True if any memory-derived source was consulted."""
    return _present(inp.memory_process_names) or _present(inp.memory_foreign_ips)


def correlate_cross_source(
    inp: CrossSourceInput,
    system_allowlist: Optional[set[str]] = None,
) -> list[CrossSourceDiscrepancy]:
    """Emit typed cross-source discrepancies from verified per-source evidence.

    Gate: returns ``[]`` unless a memory source is present, at least one finding
    was verified upstream, and at least two source types are available.

    Args:
        inp: The verified per-source evidence.
        system_allowlist: Lowercased file-less process names exempt from the
            ghost check. Defaults to the kernel pseudo-process set.

    Returns:
        Discrepancies in a stable, sorted order (by type then subject).
    """
    if not _memory_present(inp):
        return []
    if inp.verified_finding_count < 1:
        return []
    if _source_type_count(inp) < 2:
        return []

    allow = (
        {name.lower() for name in system_allowlist}
        if system_allowlist is not None
        else set(_DEFAULT_SYSTEM_ALLOWLIST)
    )

    discrepancies: list[CrossSourceDiscrepancy] = []
    discrepancies.extend(_ghost_processes(inp, allow))
    discrepancies.extend(_uninstalled_executions(inp))
    discrepancies.extend(_phantom_connections(inp))

    # Stable order so the report and any downstream diff are reproducible.
    return sorted(discrepancies, key=lambda d: (d.type.value, d.subject))


def _ghost_processes(
    inp: CrossSourceInput, allow: set[str]
) -> list[CrossSourceDiscrepancy]:
    """Memory processes with no reconciling on-disk artifact."""
    if not _present(inp.memory_process_names) or not _present(inp.disk_artifact_names):
        return []
    disk = list(inp.disk_artifact_names or [])
    out: list[CrossSourceDiscrepancy] = []
    seen: set[str] = set()
    for proc in inp.memory_process_names or []:
        key = normalize_eprocess_name(proc)
        if not key or key in seen:
            continue
        seen.add(key)
        if key in allow:
            continue
        if any(names_reconcile(proc, d) for d in disk):
            continue
        out.append(
            CrossSourceDiscrepancy(
                type=DiscrepancyType.GHOST_PROCESS,
                subject=proc,
                description=(
                    f"Process '{proc}' is live in memory but has no backing "
                    "on-disk artifact — process hollowing or a rootkit-dropped "
                    "image (MITRE T1055 / T1014)."
                ),
                memory_evidence=(proc,),
                disk_evidence=tuple(disk),
                mitre=("T1055", "T1014"),
            )
        )
    return out


def _uninstalled_executions(inp: CrossSourceInput) -> list[CrossSourceDiscrepancy]:
    """Prefetch executions with no registry install footprint."""
    if not _present(inp.prefetch_executions) or not _present(inp.registry_installed):
        return []
    installed = {normalize_eprocess_name(r) for r in (inp.registry_installed or [])}
    out: list[CrossSourceDiscrepancy] = []
    seen: set[str] = set()
    for exe in inp.prefetch_executions or []:
        key = normalize_eprocess_name(exe)
        if not key or key in seen:
            continue
        seen.add(key)
        if key in installed:
            continue
        out.append(
            CrossSourceDiscrepancy(
                type=DiscrepancyType.UNINSTALLED_EXECUTION,
                subject=exe,
                description=(
                    f"'{exe}' executed (prefetch) but has no registry install "
                    "footprint — a dropped-and-run binary or service/run-key "
                    "persistence gap (MITRE T1543 / T1547)."
                ),
                memory_evidence=(),
                disk_evidence=(exe,),
                mitre=("T1543", "T1547"),
            )
        )
    return out


def _phantom_connections(inp: CrossSourceInput) -> list[CrossSourceDiscrepancy]:
    """Memory connections to IPs no DNS query in the capture resolved."""
    if not _present(inp.memory_foreign_ips) or not _present(inp.pcap_resolved_ips):
        return []
    resolved = {ip.strip() for ip in (inp.pcap_resolved_ips or [])}
    out: list[CrossSourceDiscrepancy] = []
    seen: set[str] = set()
    for ip in inp.memory_foreign_ips or []:
        addr = ip.strip()
        if not addr or addr in seen:
            continue
        seen.add(addr)
        if addr in resolved:
            continue
        if addr in _BENIGN_DIRECT_IPS:
            continue
        out.append(
            CrossSourceDiscrepancy(
                type=DiscrepancyType.PHANTOM_CONNECTION,
                subject=addr,
                description=(
                    f"Memory shows a connection to {addr} but no DNS query in "
                    "the capture resolved that address — a hardcoded-IP "
                    "command-and-control signal (MITRE T1071)."
                ),
                memory_evidence=(addr,),
                disk_evidence=tuple(sorted(resolved)),
                mitre=("T1071",),
            )
        )
    return out
