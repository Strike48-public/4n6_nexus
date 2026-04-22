"""Tests for MemoryDetector.

The detector consumes already-parsed Volatility rows — we never invoke
Volatility here. That keeps tests fast and independent of which exact
Vol3 version is installed.
"""

from __future__ import annotations

from sift_find_evil.detectors.memory_detector import MemoryDetector
from sift_find_evil.findings import FindingCategory
from sift_find_evil.memory.volatility_runner import (
    CommandLineRow,
    InjectionRow,
    ProcessRow,
)


# -- fixture helpers -------------------------------------------------------


def _proc(pid: int, name: str, *, ppid: int = 4, exit_time: str | None = None) -> ProcessRow:
    return ProcessRow(
        pid=pid,
        ppid=ppid,
        name=name,
        create_time="2024-01-01T00:00:00",
        exit_time=exit_time,
        raw_row={},
    )


def _malfind_row(
    pid: int,
    *,
    protection: str = "PAGE_EXECUTE_READWRITE",
    process: str = "evil.exe",
) -> InjectionRow:
    return InjectionRow(
        pid=pid,
        process=process,
        start_vpn=100,
        end_vpn=200,
        tag="VadS",
        protection=protection,
        commit_charge=1,
        private_memory=1,
        file_output="Disabled",
        hexdump="MZ...",
        raw_row={},
    )


def _cmdline_row(pid: int, process: str, args: str) -> CommandLineRow:
    return CommandLineRow(pid=pid, process=process, args=args, raw_row={})


# -- malfind / process injection -------------------------------------------


def test_malfind_rwx_emits_process_injection_finding() -> None:
    findings = MemoryDetector().analyze(malfind=[_malfind_row(1234)])
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.PROCESS_INJECTION
    assert findings[0].evidence["pid"] == 1234
    assert "T1055" in findings[0].evidence["mitre_attack"]


def test_malfind_writecopy_also_counts() -> None:
    """PAGE_EXECUTE_WRITECOPY is the other RWX variant Volatility emits."""
    row = _malfind_row(1234, protection="PAGE_EXECUTE_WRITECOPY")
    findings = MemoryDetector().analyze(malfind=[row])
    assert len(findings) == 1


def test_malfind_read_only_does_not_fire() -> None:
    """Non-RWX regions are noise; skip them."""
    row = _malfind_row(1234, protection="PAGE_EXECUTE_READ")
    findings = MemoryDetector().analyze(malfind=[row])
    assert findings == []


def test_malfind_handles_missing_protection_gracefully() -> None:
    row = InjectionRow(
        pid=1234,
        process="evil.exe",
        start_vpn=0,
        end_vpn=0,
        tag=None,
        protection=None,
        commit_charge=None,
        private_memory=None,
        file_output=None,
        hexdump=None,
        raw_row={},
    )
    assert MemoryDetector().analyze(malfind=[row]) == []


# -- pslist / psscan divergence --------------------------------------------


def test_hidden_process_detected_via_psscan_without_pslist() -> None:
    pslist = [_proc(1, "System"), _proc(1234, "explorer.exe")]
    psscan = [
        _proc(1, "System"),
        _proc(1234, "explorer.exe"),
        _proc(9999, "rootkit.exe"),
    ]
    findings = MemoryDetector().analyze(pslist=pslist, psscan=psscan)
    assert len(findings) == 1
    assert findings[0].evidence["pid"] == 9999
    assert findings[0].category == FindingCategory.PROCESS_INJECTION
    assert "T1620" in findings[0].evidence["mitre_attack"]


def test_system_idle_pids_whitelisted() -> None:
    """PIDs 0 (System Idle) and 4 (System) routinely desync across dumps."""
    pslist = [_proc(1234, "explorer.exe")]
    psscan = [
        _proc(0, "System Idle Process"),
        _proc(4, "System"),
        _proc(1234, "explorer.exe"),
    ]
    findings = MemoryDetector().analyze(pslist=pslist, psscan=psscan)
    assert findings == []


def test_exited_processes_skipped() -> None:
    """A process that already exited legitimately shows up in psscan
    but not pslist. Skip it to avoid flooding with benign terminations."""
    pslist = [_proc(1234, "cmd.exe")]
    psscan = [
        _proc(1234, "cmd.exe"),
        _proc(5555, "terminated.exe", exit_time="2024-01-01T00:00:05"),
    ]
    findings = MemoryDetector().analyze(pslist=pslist, psscan=psscan)
    assert findings == []


def test_hidden_process_requires_both_streams() -> None:
    """No pslist -> we can't compute divergence at all; no findings."""
    psscan = [_proc(9999, "rootkit.exe")]
    findings = MemoryDetector().analyze(psscan=psscan)
    assert findings == []


# -- cmdline (LOLBAS + hidden flags) ---------------------------------------


def test_cmdline_powershell_with_hidden_flags_fires_high() -> None:
    row = _cmdline_row(
        1234,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell -nop -w hidden -enc aGVsbG8=",
    )
    findings = MemoryDetector().analyze(cmdline=[row])
    assert len(findings) == 1
    f = findings[0]
    assert f.category == FindingCategory.PERSISTENCE
    assert f.severity == "high"
    assert f.confidence >= 0.80
    # Normalized basename appears in reasons.
    assert any("powershell.exe" in r for r in f.evidence["reasons"])


def test_cmdline_lolbas_alone_fires_low() -> None:
    """LOLBAS host without hidden flags is generic — admin scripts do
    this. Fire medium/low to keep it visible but not alarming."""
    row = _cmdline_row(1234, "powershell.exe", "powershell Get-Process")
    findings = MemoryDetector().analyze(cmdline=[row])
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].confidence < 0.80


def test_cmdline_hidden_flags_alone_fires() -> None:
    """Encoded-command flags even from a non-LOLBAS host should trip."""
    row = _cmdline_row(1234, "notmalware.exe", "arg -enc aGVsbG8=")
    findings = MemoryDetector().analyze(cmdline=[row])
    assert len(findings) == 1
    assert findings[0].severity == "medium"  # single reason only


def test_cmdline_benign_process_no_finding() -> None:
    row = _cmdline_row(1234, "notepad.exe", "notepad C:\\Users\\Alice\\notes.txt")
    findings = MemoryDetector().analyze(cmdline=[row])
    assert findings == []


def test_cmdline_null_args_skipped() -> None:
    """Some processes expose a CmdLine row but have no Args field
    (system / kernel-side). Skip rather than crash on None."""
    row = CommandLineRow(pid=4, process="System", args=None, raw_row={})
    findings = MemoryDetector().analyze(cmdline=[row])
    assert findings == []


# -- multi-stream integration ---------------------------------------------


def test_analyze_aggregates_across_streams() -> None:
    pslist = [_proc(1234, "explorer.exe")]
    psscan = [_proc(1234, "explorer.exe"), _proc(9999, "rootkit.exe")]
    malfind = [_malfind_row(1234)]
    cmdline = [_cmdline_row(1234, "powershell.exe", "powershell -enc aGk=")]

    findings = MemoryDetector().analyze(
        pslist=pslist, psscan=psscan, malfind=malfind, cmdline=cmdline,
    )

    # Three unique findings: malfind RWX, hidden process, cmdline.
    assert len(findings) == 3
    categories = {f.category for f in findings}
    assert FindingCategory.PROCESS_INJECTION in categories
    assert FindingCategory.PERSISTENCE in categories


def test_analyze_with_no_streams_returns_empty() -> None:
    assert MemoryDetector().analyze() == []
