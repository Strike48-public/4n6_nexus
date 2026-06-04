"""Tests for the MEMORY contradiction type in the self-correction engine (SFE-11v).

The memory contradiction is a genuine cross-plugin inconsistency:
a ``netscan`` socket whose owning PID is *present* but does not appear in
``pslist`` — a live network connection owned by a process that has been
unlinked from the active process list (DKOM / hidden process, MITRE T1014).

The self-correction loop mirrors the disk/timeline causality pattern:

* DETECT: socket owner PID absent from pslist  -> MEMORY_PRESENCE_MISMATCH
* RESOLVE: if that PID *does* appear in psscan, the unlink is corroborated by
  a second source -> ``contradiction_resolved`` via a psscan tiebreaker.

These tests exercise the engine path directly (the scenario harness never
routes memory rows into the engine, so the F1=1.00 regression gate is
untouched by construction).
"""

from __future__ import annotations

from sift_find_evil.memory.volatility_runner import NetworkRow, ProcessRow
from sift_find_evil.self_correction.contradiction_detector import (
    ContradictionDetector,
    ContradictionType,
    Severity,
)
from sift_find_evil.self_correction.engine import SelfCorrectionEngine
from sift_find_evil.findings.categories import FindingCategory


# --- fixtures -----------------------------------------------------------


def _proc(pid: int, name: str, ppid: int = 100, exit_time=None) -> ProcessRow:
    return ProcessRow(
        pid=pid,
        ppid=ppid,
        name=name,
        create_time="2026-01-01T00:00:00Z",
        exit_time=exit_time,
    )


def _socket(pid: int, owner: str, foreign="203.0.113.10", port=4444) -> NetworkRow:
    return NetworkRow(
        pid=pid,
        owner=owner,
        protocol="TCPv4",
        local_addr="10.0.0.5",
        local_port=50111,
        foreign_addr=foreign,
        foreign_port=port,
        state="ESTABLISHED",
    )


# --- detector-level: detect ---------------------------------------------


def test_socket_owner_absent_from_pslist_is_a_contradiction():
    """A socket owned by a PID not in pslist is a presence mismatch."""
    detector = ContradictionDetector()
    pslist = [_proc(4, "System"), _proc(800, "svchost.exe")]
    netscan = [_socket(6666, "evil.exe")]

    contradictions = detector.detect_memory_presence_mismatch(
        netscan=netscan, pslist=pslist, psscan=[]
    )

    assert len(contradictions) == 1
    c = contradictions[0]
    assert c.type == ContradictionType.MEMORY_PRESENCE_MISMATCH
    assert c.severity == Severity.HIGH
    assert c.details["pid"] == 6666
    assert c.details["owner"] == "evil.exe"
    assert c.confidence_impact < 0


def test_socket_owner_present_in_pslist_is_not_flagged():
    """A normal socket whose owner is in pslist produces no contradiction."""
    detector = ContradictionDetector()
    pslist = [_proc(800, "svchost.exe")]
    netscan = [_socket(800, "svchost.exe")]

    contradictions = detector.detect_memory_presence_mismatch(
        netscan=netscan, pslist=pslist, psscan=[]
    )

    assert contradictions == []


def test_unowned_socket_is_not_a_presence_mismatch():
    """Sockets with no owning PID are handled by MemoryDetector, not here."""
    detector = ContradictionDetector()
    pslist = [_proc(800, "svchost.exe")]
    netscan = [
        NetworkRow(
            pid=None,
            owner=None,
            protocol="TCPv4",
            local_addr="10.0.0.5",
            local_port=50111,
            foreign_addr="203.0.113.10",
            foreign_port=4444,
            state="ESTABLISHED",
        )
    ]

    contradictions = detector.detect_memory_presence_mismatch(
        netscan=netscan, pslist=pslist, psscan=[]
    )

    assert contradictions == []


def test_multiple_hidden_pids_dedup_to_one_contradiction_each():
    """Each unique hidden PID gets exactly one contradiction.

    A PID owning several sockets must not produce several near-duplicate
    contradictions — the finding is about the hidden process, not each
    individual connection.
    """
    detector = ContradictionDetector()
    pslist = [_proc(800, "svchost.exe")]
    netscan = [
        _socket(6666, "evil1.exe"),
        _socket(7777, "evil2.exe"),
        _socket(6666, "evil1.exe", port=5555),  # same PID, second socket
    ]

    contradictions = detector.detect_memory_presence_mismatch(
        netscan=netscan, pslist=pslist, psscan=[]
    )

    assert len(contradictions) == 2
    assert {c.details["pid"] for c in contradictions} == {6666, 7777}


# --- detector-level: resolve --------------------------------------------


def test_hidden_owner_present_in_psscan_is_resolvable():
    """The contradiction carries enough detail to be resolved via psscan."""
    detector = ContradictionDetector()
    pslist = [_proc(800, "svchost.exe")]
    psscan = [_proc(6666, "evil.exe")]  # appears in psscan: genuine unlink
    netscan = [_socket(6666, "evil.exe")]

    contradictions = detector.detect_memory_presence_mismatch(
        netscan=netscan, pslist=pslist, psscan=psscan
    )

    assert len(contradictions) == 1
    assert contradictions[0].details["corroborated_by_psscan"] is True


# --- engine-level: detect + resolve + score -----------------------------


def test_engine_emits_resolved_memory_finding():
    """End-to-end: hidden socket owner corroborated by psscan -> resolved."""
    engine = SelfCorrectionEngine()
    pslist = [_proc(800, "svchost.exe")]
    psscan = [_proc(6666, "evil.exe")]
    netscan = [_socket(6666, "evil.exe")]

    findings = engine.analyze(
        mft_entries=[],
        prefetch_entries=[],
        event_log_entries=[],
        netscan=netscan,
        pslist=pslist,
        psscan=psscan,
    )

    mem = [
        f
        for f in findings
        if any(
            c.type == ContradictionType.MEMORY_PRESENCE_MISMATCH
            for c in f.contradictions
        )
    ]
    assert len(mem) == 1
    finding = mem[0]
    assert finding.category == FindingCategory.PROCESS_INJECTION
    # Resolution applied -> confidence recovers above the contradicted floor
    assert finding.resolutions
    assert finding.confidence > 0.0
    assert "psscan" in " ".join(finding.reasoning_chain).lower()


def test_engine_emits_unresolved_memory_finding_without_psscan():
    """No psscan corroboration -> contradiction stands unresolved."""
    engine = SelfCorrectionEngine()
    pslist = [_proc(800, "svchost.exe")]
    netscan = [_socket(6666, "evil.exe")]

    findings = engine.analyze(
        mft_entries=[],
        prefetch_entries=[],
        event_log_entries=[],
        netscan=netscan,
        pslist=pslist,
        psscan=[],
    )

    mem = [
        f
        for f in findings
        if any(
            c.type == ContradictionType.MEMORY_PRESENCE_MISMATCH
            for c in f.contradictions
        )
    ]
    assert len(mem) == 1
    assert mem[0].resolutions == []


def test_engine_without_memory_args_is_unchanged():
    """Default call (no memory kwargs) emits no memory findings."""
    engine = SelfCorrectionEngine()
    findings = engine.analyze(mft_entries=[], prefetch_entries=[], event_log_entries=[])
    assert all(
        not any(
            c.type == ContradictionType.MEMORY_PRESENCE_MISMATCH
            for c in f.contradictions
        )
        for f in findings
    )


# --- adapter-level: domain=memory ---------------------------------------


def test_memory_finding_maps_to_memory_domain_verification():
    """The verifier adapter reports domain=memory for this contradiction."""
    from sift_find_evil.self_correction.verifier_adapter import (
        finding_to_verification,
    )

    engine = SelfCorrectionEngine()
    findings = engine.analyze(
        mft_entries=[],
        prefetch_entries=[],
        event_log_entries=[],
        netscan=[_socket(6666, "evil.exe")],
        pslist=[_proc(800, "svchost.exe")],
        psscan=[_proc(6666, "evil.exe")],
    )
    mem = next(
        f
        for f in findings
        if any(
            c.type == ContradictionType.MEMORY_PRESENCE_MISMATCH
            for c in f.contradictions
        )
    )

    v = finding_to_verification(mem, finding_id="F-MEM-1")
    assert v.domain == "memory"
    assert v.contradiction_type == "memory_presence_mismatch"
    assert v.verdict == "contradiction_resolved"
