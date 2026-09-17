"""Linux ``/proc`` hidden/suspicious-process detector (SFE-4fnv.6, Tranche 2).

Consumes a procfs capture (parsed by
:func:`~sift_find_evil.parsers.linux_proc.parse_proc_processes`) and flags a
running process as suspicious on two high-signal, filesystem-visible shapes:

- **Deleted-binary execution** (MITRE **T1070.004**). ``/proc/<pid>/exe`` targets
  a path ending ``" (deleted)"``: the on-disk executable was unlinked while the
  process kept running -- the canonical Linux trick to defeat filesystem-only IR
  tooling (fileless / anti-forensic).
- **Memory-staging execution** (MITRE **T1059**). The executable runs from a
  world-writable staging directory (``/tmp``, ``/var/tmp``, ``/dev/shm``,
  ``/run/shm``). A *running process* whose backing binary lives there is
  execution-from-staging, not a benign file merely sitting in ``/tmp`` -- the
  process context is what makes it high-signal (contrast the interactive
  shell-history surface, where a bare ``/tmp`` reference is noisy).

Both shapes read straight off the ``/proc/<pid>/exe`` symlink target, so they
carry low false-positive risk on typical systems -- unlike a comm/name
heuristic. They are not FP-free: known benign shapes that also fire are a
browser/user download-and-run out of ``/tmp`` and the occasional installer that
executes from ``/var/tmp``; an analyst should correlate with parent/cmdline
context before escalating. (A common ``ps``-style "kernel-worker masquerade"
check keys off the
bracketed ``[kworker]`` name, but those brackets are a ``ps`` *display*
convention for empty-``cmdline`` tasks and are **not** present in
``/proc/<pid>/comm``, so that heuristic does not belong on the procfs surface.)

This detector reasons over the **filesystem** procfs view. The complementary
*memory* view (Volatility ``linux.pslist``) is analyzed by
:class:`~sift_find_evil.detectors.memory_detector.MemoryDetector`; the
procfs-vs-memory divergence cross-check (a process in the kernel task list but
hidden from ``/proc``) is a two-input correlation deferred to the correlation
layer, not this single-artifact detector.

One finding is emitted per PID (the highest-severity shape wins) so a process
matching both shapes is never double-counted. The detector is stateless and
never mutates the artifacts dict it is given.
"""

from __future__ import annotations

from typing import Any, Optional

from ..findings import Finding, FindingCategory

# World-writable staging directories an interactive user can drop a payload
# into. A *running* process backed by a binary here is execution-from-staging.
# The trailing slash matches on the directory boundary, so ``/tmpfoo/x`` (which
# is not inside ``/tmp``) does not match ``/tmp/``.
_STAGING_PREFIXES: tuple[str, ...] = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/shm/",
)

# The kernel appends this suffix to /proc/<pid>/exe when the backing inode was
# unlinked while the process kept running. The LEADING SPACE is part of the
# kernel format ("<path> (deleted)"); matching on the bare "(deleted)" would
# false-positive on a benign path that merely ends in that literal (e.g.
# "/opt/app(deleted)").
_DELETED_SUFFIX = " (deleted)"


class LinuxProcessDetector:
    """Detects deleted-binary and staged-executable processes from ``/proc``.

    The detector is stateless; :meth:`analyze` is a pure function of its input
    and never mutates the artifacts dict it is given.
    """

    def analyze(self, artifacts: dict[str, Any]) -> list[Finding]:
        """Scan parsed ``/proc`` processes and return process-anomaly findings.

        Args:
            artifacts: Mapping that may contain ``proc_processes`` (see
                :func:`~sift_find_evil.parsers.linux_proc.parse_proc_processes`).
                A missing key is treated as empty.

        Returns:
            One :class:`Finding` per anomalous PID, tagged
            :attr:`FindingCategory.PROCESS_INJECTION`, in first-appearance
            (PID) order. A process matching both shapes yields a single finding
            for the higher-severity shape (deleted-binary).
        """
        processes = artifacts.get("proc_processes") or []
        findings: list[Finding] = []
        for proc in processes:
            finding = self._classify(proc)
            if finding is not None:
                findings.append(finding)
        return findings

    def _classify(self, proc: dict[str, Any]) -> Optional[Finding]:
        """Return the finding for one process, or None when it is benign.

        Deleted-binary outranks staged-exec, so a process whose exe is both a
        staged path and marked deleted yields the single deleted-binary finding.
        A record with no PID (only reachable via a hand-authored JSON artifact
        bundle, never the parser) is skipped rather than emitting a "PID None"
        finding.
        """
        if proc.get("pid") is None:
            return None
        exe = str(proc.get("exe_target") or "")
        if exe.endswith(_DELETED_SUFFIX):
            return self._deleted_binary_finding(proc)
        if exe.startswith(_STAGING_PREFIXES):
            return self._staged_exec_finding(proc)
        return None

    @staticmethod
    def _base_evidence(proc: dict[str, Any]) -> dict[str, Any]:
        """Common evidence fields stamped on every /proc finding.

        ``source_span`` reconstructs the specific procfs record the finding was
        derived from, so the independent re-derivation falsifier re-checks the
        asserted ``pid`` anchor against THIS record (SFE-fsno provenance) rather
        than the whole-corpus blob -- which, for a /proc capture, holds no
        CSV/JSON the raw-evidence reader would pick up.
        """
        pid = proc.get("pid")
        comm = str(proc.get("comm") or "")
        cmdline = str(proc.get("cmdline") or "")
        exe = str(proc.get("exe_target") or "")
        ppid = proc.get("ppid")
        return {
            "pid": pid,
            "ppid": ppid,
            "process": comm,
            "cmdline": cmdline,
            "exe_target": exe,
            "source_path": str(proc.get("source_path") or ""),
            "source_span": (
                f"/proc/{pid}/exe -> {exe} (comm={comm}, ppid={ppid}, "
                f"cmdline={cmdline})"
            ),
        }

    def _deleted_binary_finding(self, proc: dict[str, Any]) -> Finding:
        """Build the deleted-binary (T1070.004) finding for one process."""
        pid = proc.get("pid")
        comm = str(proc.get("comm") or "?")
        exe = str(proc.get("exe_target") or "?")
        evidence = self._base_evidence(proc)
        evidence.update(
            {
                "reason": "process executing from a deleted on-disk binary",
                "mitre_technique": "T1070.004",
            }
        )
        return Finding(
            title=f"Process running from deleted binary: PID {pid} ({comm})",
            description=(
                f"/proc/{pid}/exe points to '{exe}'. The kernel appends "
                "'(deleted)' when the backing executable is unlinked while the "
                "process keeps running -- a canonical Linux anti-forensic / "
                "fileless-execution technique that defeats filesystem-only IR "
                "tooling (MITRE T1070.004)."
            ),
            finding_type="behavior",
            severity="high",
            category=FindingCategory.PROCESS_INJECTION,
            evidence=evidence,
            reasoning_chain=[
                f"/proc/{pid}/exe targets '{exe}', ending in '(deleted)'.",
                "The backing binary was unlinked while the process kept "
                "running -- it no longer exists on disk to be scanned.",
                "Unlinking a running executable is a defense-evasion / "
                "anti-forensic technique (MITRE T1070.004).",
            ],
            artifact_sources=["proc"],
        )

    def _staged_exec_finding(self, proc: dict[str, Any]) -> Finding:
        """Build the memory-staging execution (T1059) finding for one process."""
        pid = proc.get("pid")
        comm = str(proc.get("comm") or "?")
        exe = str(proc.get("exe_target") or "?")
        evidence = self._base_evidence(proc)
        evidence.update(
            {
                "reason": "process executing from a world-writable staging directory",
                "mitre_technique": "T1059",
            }
        )
        return Finding(
            title=f"Process running from staging directory: PID {pid} ({comm})",
            description=(
                f"/proc/{pid}/exe points to '{exe}', inside a world-writable "
                "staging directory (/tmp, /var/tmp, /dev/shm, /run/shm). A "
                "running process backed by an executable there is "
                "execution-from-staging, a common post-exploitation shape "
                "(MITRE T1059)."
            ),
            finding_type="behavior",
            severity="high",
            category=FindingCategory.PROCESS_INJECTION,
            evidence=evidence,
            reasoning_chain=[
                f"/proc/{pid}/exe targets '{exe}'.",
                "The backing binary lives in a world-writable staging "
                "directory any user can drop a payload into.",
                "A running process executing from staging is a "
                "post-exploitation execution shape (MITRE T1059).",
            ],
            artifact_sources=["proc"],
        )
