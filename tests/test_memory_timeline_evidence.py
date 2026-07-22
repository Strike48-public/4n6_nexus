"""Move B: memory findings emit timeline evidence so correlation fires LIVE.

Correlation was wired into the hardening pipeline (move #3) but DORMANT - no
detector emitted the `timeline` evidence it consumes, so 0 real findings
correlated. This has the memory detector attach a normalized `timeline` dict
(ts/source/actor/type) to its process findings, so when two cross-source memory
findings concern the same process they correlate in a real run. Additive: the
detection result (which findings, which PIDs) is unchanged, so F1 is unaffected.
"""

from sift_find_evil.detectors.memory_detector import MemoryDetector
from sift_find_evil.memory.volatility_runner import (
    _to_injection_row,
    _to_process_row,
)


def _pslist_row(pid, name):
    return _to_process_row(
        {
            "PID": pid,
            "PPID": 4,
            "ImageFileName": name,
            "CreateTime": "2026-07-20T10:00:00",
        }
    )


def _malfind_row(pid, name):
    return _to_injection_row(
        {
            "PID": pid,
            "Process": name,
            "Protection": "PAGE_EXECUTE_READWRITE",
            "Tag": "VadS",
            "Start VPN": 0x1000,
            "End VPN": 0x2000,
            "CommitCharge": 1,
            "PrivateMemory": 1,
        }
    )


def test_hidden_process_finding_carries_timeline_evidence():
    # A process in psscan but absent from a NON-EMPTY pslist is hidden (DKOM).
    # (An empty pslist triggers the analysis-gap path, not hidden-process.)
    det = MemoryDetector()
    pslist = [_pslist_row(1234, "explorer.exe")]
    psscan = [_pslist_row(1234, "explorer.exe"), _pslist_row(6666, "rootkit.exe")]
    findings = det.analyze(pslist=pslist, psscan=psscan)
    hidden = [
        f for f in findings if f.evidence.get("source") == "psscan_without_pslist"
    ]
    assert hidden, "expected a hidden-process finding"
    tl = hidden[0].evidence.get("timeline")
    assert isinstance(tl, dict)
    assert tl.get("source") and tl.get("actor") and tl.get("ts")
    # Actor is the process identity so cross-source findings can correlate on it.
    assert "rootkit" in tl["actor"].lower()


def test_malfind_finding_carries_timeline_evidence():
    det = MemoryDetector()
    findings = det.analyze(malfind=[_malfind_row(6666, "rootkit.exe")])
    inj = [f for f in findings if "T1055" in f.evidence.get("mitre_attack", [])]
    assert inj
    tl = inj[0].evidence.get("timeline")
    assert isinstance(tl, dict)
    assert tl.get("source") == "malfind"


def test_cross_source_same_process_findings_correlate_live():
    """Two memory findings about the SAME process from different sources correlate.

    An RWX injection (malfind) and a hidden-process (psscan) finding for the same
    svchost.exe now carry timeline evidence with a shared actor + real timestamp
    (malfind inherits the process create_time), so the hardening pipeline
    correlates them - the capability that was dormant is now live on genuine
    same-actor multi-source output.
    """
    from sift_find_evil.hardening import harden_findings

    pslist = [_pslist_row(1, "explorer.exe")]
    psscan = [_pslist_row(1, "explorer.exe"), _pslist_row(3120, "svchost.exe")]
    malfind = [_malfind_row(3120, "svchost.exe")]
    findings = MemoryDetector().analyze(pslist=pslist, psscan=psscan, malfind=malfind)
    report = harden_findings(findings, image_sha256="a" * 64, receipt_key=b"k" * 32)
    assert report.correlations, "cross-source same-actor findings should correlate"
    assert any(c["relation"] == "actor" for c in report.correlations)


def test_timeline_evidence_does_not_change_detected_pids():
    # F1-safety: adding timeline evidence must not change which PIDs are found.
    det = MemoryDetector()
    pslist = [_pslist_row(1234, "explorer.exe")]
    psscan = [_pslist_row(1234, "explorer.exe"), _pslist_row(6666, "rootkit.exe")]
    findings = det.analyze(pslist=pslist, psscan=psscan)
    pids = {f.evidence.get("pid") for f in findings if f.evidence.get("pid")}
    assert 6666 in pids
