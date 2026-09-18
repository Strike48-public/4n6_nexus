"""Unit tests for the Linux hidden-process cross-source correlation (T1014).

A process present in the memory kernel task list (``linux.pslist``) but absent
from the ``/proc`` filesystem capture is hidden from userland enumeration by a
rootkit hooking ``getdents`` on ``/proc``. These tests pin the divergence logic,
its false-positive guards, and the non-vacuous provenance the finding must carry
(so the independent anchor falsifier cannot reject it).
"""

from __future__ import annotations

from sift_find_evil.correlation.hidden_process import detect_hidden_linux_processes
from sift_find_evil.findings.categories import FindingCategory
from sift_find_evil.memory.volatility_runner import LinuxProcessRow


def _pslist_row(pid: int, name: str, ppid: int = 1000, euid: int | None = 0):
    return LinuxProcessRow(
        pid=pid,
        ppid=ppid,
        name=name,
        euid=euid,
        create_time="2026-01-01 00:00:00.000000 UTC",
        raw_row={"PID": pid, "PPID": ppid, "COMM": name},
    )


def _proc_row(pid: int, comm: str = "proc"):
    return {
        "pid": pid,
        "comm": comm,
        "cmdline": comm,
        "ppid": 1000,
        "exe_target": f"/usr/bin/{comm}",
        "source_path": f"/proc/{pid}",
    }


def test_pid_in_pslist_but_not_proc_fires_hidden_process():
    # Arrange: pslist knows PID 1337; the /proc capture does not.
    pslist = [_pslist_row(1000, "systemd", ppid=1), _pslist_row(1337, "beacon")]
    proc = [_proc_row(1000, "systemd")]

    # Act
    findings = detect_hidden_linux_processes(proc, pslist)

    # Assert
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == FindingCategory.PROCESS_INJECTION
    assert "T1014" in finding.techniques
    assert "1337" in finding.title
    assert set(finding.artifact_sources) == {"memory", "proc"}


def test_process_only_in_proc_not_pslist_does_not_fire():
    # A PID present in /proc but absent from pslist is a process that started
    # AFTER the memory capture, not a hidden one. Direction matters.
    pslist = [_pslist_row(1000, "systemd", ppid=1)]
    proc = [_proc_row(1000, "systemd"), _proc_row(4242, "late_starter")]

    findings = detect_hidden_linux_processes(proc, pslist)

    assert findings == []


def test_no_divergence_when_pid_sets_match():
    pslist = [_pslist_row(1000, "systemd", ppid=1), _pslist_row(2050, "sshd")]
    proc = [_proc_row(1000, "systemd"), _proc_row(2050, "sshd")]

    assert detect_hidden_linux_processes(proc, pslist) == []


def test_kernel_thread_absent_from_proc_does_not_fire():
    # kthreadd children (ppid == 2) are not hideable by a userland getdents hook;
    # their absence is capture skew, not T1014. Must NOT false-positive.
    pslist = [
        _pslist_row(1000, "systemd", ppid=1),
        _pslist_row(9, "kworker/0:1", ppid=2),
    ]
    proc = [_proc_row(1000, "systemd")]

    assert detect_hidden_linux_processes(proc, pslist) == []


def test_structural_pids_absent_from_proc_do_not_fire():
    # PID 0/1/2 (idle, init, kthreadd) are structural and never rootkit-hidden.
    pslist = [
        _pslist_row(0, "swapper", ppid=0),
        _pslist_row(1, "systemd", ppid=0),
        _pslist_row(2, "kthreadd", ppid=0),
    ]
    proc: list[dict] = []  # deliberately empty /proc

    # proc empty -> no cross-check possible anyway, but assert on a non-empty proc
    proc = [_proc_row(1000, "systemd")]
    pslist.append(_pslist_row(1000, "systemd", ppid=1))

    assert detect_hidden_linux_processes(proc, pslist) == []


def test_missing_either_input_yields_no_findings():
    row = _pslist_row(1337, "beacon")
    assert detect_hidden_linux_processes(None, [row]) == []
    assert detect_hidden_linux_processes([_proc_row(1)], None) == []
    assert detect_hidden_linux_processes([], [row]) == []
    assert detect_hidden_linux_processes([_proc_row(1)], []) == []


def test_finding_source_span_contains_pid_for_anchor_falsifier():
    # The independent falsifier re-derives the asserted ``pid`` against the
    # finding's own ``source_span``; a pid-asserting finding whose span omits the
    # pid is FALSIFIED. Guard the provenance explicitly.
    pslist = [_pslist_row(1337, "beacon")]
    proc = [_proc_row(1000, "systemd")]

    finding = detect_hidden_linux_processes(proc, pslist)[0]

    assert finding.evidence["pid"] == 1337
    assert "1337" in finding.evidence["source_span"]
    # source_exec_id must derive non-empty (construction would raise otherwise).
    assert finding.source_exec_id


def test_multiple_pslist_threads_same_pid_dedupe_to_one_finding():
    # linux.pslist can emit one row per thread; a hidden PID with helper threads
    # must yield exactly one finding, not one per thread.
    pslist = [
        _pslist_row(1000, "systemd", ppid=1),
        _pslist_row(1337, "beacon"),
        _pslist_row(1337, "beacon"),
    ]
    proc = [_proc_row(1000, "systemd")]

    findings = detect_hidden_linux_processes(proc, pslist)

    assert len(findings) == 1
