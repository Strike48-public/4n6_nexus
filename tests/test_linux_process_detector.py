"""Tests for the Linux /proc hidden/suspicious-process detector (SFE-4fnv.6).

Exercises the two filesystem-visible process shapes recovered from a procfs
capture: a process running from a deleted binary (T1070.004) and a process
backed by an executable in a world-writable staging directory (T1059). Also
covers the precision guards (genuine kernel threads, staging-prefix boundaries)
and the single-finding-per-PID rule. Inputs are synthetic in-memory dicts.
"""

from __future__ import annotations

from typing import Any, Optional

from sift_find_evil.detectors.linux_proc import LinuxProcessDetector
from sift_find_evil.findings import FindingCategory


def _proc(
    pid: int,
    *,
    comm: str = "bash",
    cmdline: str = "/bin/bash",
    ppid: Optional[int] = 1000,
    exe_target: str = "/usr/bin/bash",
) -> dict[str, Any]:
    return {
        "pid": pid,
        "comm": comm,
        "cmdline": cmdline,
        "ppid": ppid,
        "exe_target": exe_target,
        "source_path": f"/proc/{pid}",
    }


def _analyze(*procs: dict[str, Any]) -> list:
    return LinuxProcessDetector().analyze({"proc_processes": list(procs)})


def test_deleted_binary_process_is_flagged() -> None:
    """A process whose exe target ends in '(deleted)' fires T1070.004."""
    findings = _analyze(_proc(4242, comm="x", exe_target="/usr/sbin/httpd (deleted)"))

    assert len(findings) == 1
    f = findings[0]
    assert f.category is FindingCategory.PROCESS_INJECTION
    assert f.evidence["mitre_technique"] == "T1070.004"
    assert f.evidence["pid"] == 4242
    assert f.artifact_sources == ["proc"]


def test_finding_carries_source_span_containing_pid_anchor() -> None:
    """The PID anchor must be re-derivable from the finding's own source_span.

    The independent entailment falsifier re-checks the asserted ``pid`` against
    ``evidence['source_span']`` (SFE-fsno). If the span omits the PID, a grounded
    finding is wrongly FALSIFIED on the hardening path, so guard it here.
    """
    findings = _analyze(_proc(4242, exe_target="/tmp/.x/beacon"))

    span = findings[0].evidence["source_span"]
    assert "4242" in span
    assert "/tmp/.x/beacon" in span


def test_staging_directory_process_is_flagged() -> None:
    """A process backed by a binary under a staging dir fires T1059."""
    for staged in (
        "/tmp/.hidden/beacon",
        "/var/tmp/x",
        "/dev/shm/impl",
        "/run/shm/y",
    ):
        findings = _analyze(_proc(7, comm="beacon", exe_target=staged))
        assert len(findings) == 1, staged
        assert findings[0].evidence["mitre_technique"] == "T1059"


def test_kernel_thread_does_not_fire() -> None:
    """A genuine kernel thread (no exe symlink) produces no finding.

    Kernel threads have no backing executable, so exe_target is empty; the
    detector keys solely off the exe target, so they are inherently benign.
    """
    assert _analyze(_proc(2, comm="kthreadd", cmdline="", exe_target="")) == []


def test_benign_process_does_not_fire() -> None:
    """A normal user process (real exe, plain comm) produces no finding."""
    assert _analyze(_proc(1234, comm="bash", exe_target="/usr/bin/bash")) == []


def test_staging_prefix_boundary_does_not_over_match() -> None:
    """Paths that merely start with the staging stem but are not inside it.

    ``/tmpfoo/x`` and ``/home/tmp/x`` must NOT match ``/tmp/`` -- the guard
    matches the directory prefix (with trailing slash), not a bare substring.
    """
    assert _analyze(_proc(1, exe_target="/tmpfoo/x")) == []
    assert _analyze(_proc(2, exe_target="/home/user/tmp/report")) == []


def test_deleted_binary_takes_precedence_over_staging() -> None:
    """A process both deleted AND staged yields ONE finding (deleted wins)."""
    findings = _analyze(_proc(88, exe_target="/tmp/x (deleted)"))

    assert len(findings) == 1
    assert findings[0].evidence["mitre_technique"] == "T1070.004"


def test_bare_deleted_literal_without_leading_space_does_not_fire() -> None:
    """A benign path ending in the literal '(deleted)' (no space) must not fire.

    The kernel format is '<path> (deleted)' with a leading space; matching the
    bare token would false-positive on real filenames such as
    '/opt/app(deleted)' or '/usr/bin/report(deleted)'.
    """
    assert _analyze(_proc(11, exe_target="/opt/app(deleted)")) == []
    assert _analyze(_proc(12, exe_target="/usr/bin/report(deleted)")) == []
    # The genuine kernel format still fires.
    assert len(_analyze(_proc(13, exe_target="/usr/sbin/httpd (deleted)"))) == 1


def test_process_with_none_pid_is_skipped() -> None:
    """A record with no PID (malformed JSON bundle) is skipped, not emitted.

    Guards against a "PID None" finding leaking to analysts.
    """
    assert _analyze(_proc(0, exe_target="/tmp/x") | {"pid": None}) == []


def test_one_finding_per_pid_across_processes() -> None:
    """Each anomalous process contributes exactly one finding, PID-ordered."""
    findings = _analyze(
        _proc(3, comm="a", exe_target="/usr/bin/a"),  # benign
        _proc(1, comm="b", exe_target="/tmp/b"),  # staged
        _proc(2, comm="c", exe_target="/opt/c (deleted)"),  # deleted
    )

    assert [f.evidence["pid"] for f in findings] == [1, 2]


def test_empty_and_missing_input_returns_no_findings() -> None:
    """Missing/empty proc_processes yields an empty list, not an error."""
    assert LinuxProcessDetector().analyze({}) == []
    assert LinuxProcessDetector().analyze({"proc_processes": []}) == []
