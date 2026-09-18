"""Per-finding provenance: each memory finding carries its producing record.

SFE-fsno (verification 3->4). The EntailmentFalsifier re-derives a finding's
asserted IP/PID anchors against evidence text. Historically the scenario harness
fed EVERY finding the same whole-corpus blob, so a real-but-MISATTRIBUTED anchor
(a PID/IP that belongs to a DIFFERENT finding's record but still lives somewhere
in the corpus) passed the check. The fix is per-finding provenance: each finding
records the SPECIFIC tool-output record (``evidence["source_span"]``) that
produced it, so the falsifier re-derives against that record, not the blob.

These tests pin the detector-level contract: every anchored memory finding
emits a ``source_span`` drawn from the Volatility ``raw_row`` it consumed, and
that span actually contains the anchor the finding asserts.
"""

from __future__ import annotations

import json

from sift_find_evil.detectors.memory_detector import MemoryDetector
from sift_find_evil.memory.volatility_runner import (
    CommandLineRow,
    NetworkRow,
    ProcessRow,
)


def _anchored(findings):
    """Findings that assert a re-derivable IP/PID identity anchor."""
    keys = ("dst_ip", "foreign_addr", "pid")
    return [f for f in findings if any(f.evidence.get(k) for k in keys)]


def test_cmdline_finding_carries_source_span_with_its_own_pid() -> None:
    # Two distinct records, two distinct PIDs. Each finding's source_span must
    # contain ITS OWN pid, not the other record's.
    rows = [
        CommandLineRow(
            pid=5580,
            process="powershell.exe",
            args="powershell.exe -WindowStyle Hidden -EncodedCommand ZQBjAGgAbwA=",
            raw_row={"PID": 5580, "Process": "powershell.exe", "Args": "..."},
        ),
        CommandLineRow(
            pid=6001,
            process="pwsh.exe",
            args="pwsh.exe -NoProfile -enc ZQBjAGgAbwA=",
            raw_row={"PID": 6001, "Process": "pwsh.exe", "Args": "..."},
        ),
    ]
    findings = _anchored(MemoryDetector().analyze(cmdline=rows))
    assert findings, "expected anchored cmdline findings"
    for f in findings:
        span = f.evidence.get("source_span")
        assert span, f"finding {f.title!r} missing source_span"
        assert str(f.evidence["pid"]) in span
        # The OTHER record's pid must NOT appear in this finding's span.
        others = {"5580", "6001"} - {str(f.evidence["pid"])}
        for other in others:
            assert (
                other not in span
            ), f"{f.title!r} span leaked another record's pid {other}"


def test_netscan_finding_source_span_contains_foreign_addr() -> None:
    row = NetworkRow(
        pid=5580,
        owner="powershell.exe",
        protocol="TCPv4",
        local_addr="10.0.0.42",
        local_port=49218,
        foreign_addr="203.0.113.9",
        foreign_port=4444,
        state="ESTABLISHED",
        raw_row={
            "PID": 5580,
            "Owner": "powershell.exe",
            "ForeignAddr": "203.0.113.9",
            "ForeignPort": 4444,
            "State": "ESTABLISHED",
        },
    )
    findings = _anchored(MemoryDetector().analyze(netscan=[row]))
    assert findings, "expected an anchored netscan finding"
    for f in findings:
        span = f.evidence.get("source_span")
        assert span, f"finding {f.title!r} missing source_span"
        assert "203.0.113.9" in span
        assert "5580" in span


def test_hidden_process_finding_source_span_contains_pid() -> None:
    pslist = [
        ProcessRow(
            pid=4, ppid=0, name="System", create_time="t", exit_time=None, raw_row={}
        )
    ]
    psscan = [
        ProcessRow(
            pid=4, ppid=0, name="System", create_time="t", exit_time=None, raw_row={}
        ),
        ProcessRow(
            pid=7412,
            ppid=1,
            name="rootkit.exe",
            create_time="2024-01-01T00:00:00",
            exit_time=None,
            raw_row={"PID": 7412, "ImageFileName": "rootkit.exe", "ExitTime": None},
        ),
    ]
    findings = _anchored(MemoryDetector().analyze(pslist=pslist, psscan=psscan))
    assert findings, "expected a hidden-process finding"
    span = findings[0].evidence.get("source_span")
    assert span and "7412" in span


def test_source_span_is_serializable_text() -> None:
    # source_span rides in evidence, which is JSON-serialized into the report.
    rows = [
        CommandLineRow(
            pid=6002,
            process="mshta.exe",
            args="mshta.exe javascript:alert(1)",
            raw_row={"PID": 6002, "Process": "mshta.exe", "Args": "javascript:..."},
        )
    ]
    findings = _anchored(MemoryDetector().analyze(cmdline=rows))
    assert findings
    span = findings[0].evidence["source_span"]
    assert isinstance(span, str)
    json.dumps({"source_span": span})  # must not raise


def test_source_span_survives_mixed_key_types() -> None:
    # _source_span takes ``row: Any``; a raw_row with mixed str/int keys is not
    # sortable by sort_keys and would raise TypeError. Real Vol3 JSON only has
    # string keys, but the helper must not crash on the Any contract - it
    # stringifies keys before sorting. The span must still carry the anchor.
    from sift_find_evil.detectors.memory_detector import _source_span

    class _Row:
        raw_row = {1: "one", "PID": 5580, "ForeignAddr": "203.0.113.9"}

    span = _source_span(_Row())
    assert isinstance(span, str)
    assert "5580" in span
    assert "203.0.113.9" in span
    json.dumps({"source_span": span})  # must not raise
