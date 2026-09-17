"""Same-actor multi-behavior overlaps are co-occurrences, not contradictions (SFE-nh4h).

``find_contradictions`` labelled ANY same-actor + different-type + in-window
overlap a 'contradiction' surfaced ``status='UNRESOLVED'`` for a verifier to
adjudicate. But the pair that fires on the real corpus -- malfind rwx_injection +
netscan c2_connection for ONE injected powershell.exe -- is mutually REINFORCING,
the scenario's strongest corroboration, not a conflict. The detector has no signal
that distinguishes a genuine conflict (presence-vs-absence, mutually-exclusive
states) from co-occurring behaviour, so calling it a contradiction overclaims.

This renames the honest thing it detects: a co-occurrence
(``same_actor_multi_behavior``). Report metadata only -- no scoring/verdict gate
consumes it -- so F1 is unaffected.

RED-first: before the rename there was no ``find_co_occurrences`` and
``HardeningReport`` carried ``contradictions`` tagged ``status='UNRESOLVED'``.
"""

from __future__ import annotations

from sift_find_evil.correlation.sql_timeline import find_co_occurrences
from sift_find_evil.findings import Finding, FindingCategory
from sift_find_evil.hardening import harden_findings

KEY = b"k" * 32
IMAGE = "a" * 64


def _event(ts, source, actor, target, etype):
    return {
        "ts": ts,
        "source": source,
        "actor": actor,
        "target": target,
        "type": etype,
        "raw": "",
    }


def test_co_occurrence_is_relation_tagged_not_unresolved_contradiction() -> None:
    events = [
        _event(
            "2026-07-20T10:00:00", "memory", "powershell.exe", "hostA", "rwx_injection"
        ),
        _event(
            "2026-07-20T10:00:03", "pcap", "powershell.exe", "hostA", "c2_connection"
        ),
    ]
    found = find_co_occurrences(events, window_seconds=5)
    assert len(found) == 1
    c = found[0]
    # The honest label: a co-occurrence relation, NOT an unresolved conflict.
    assert c["relation"] == "same_actor_multi_behavior"
    assert "status" not in c, "co-occurrence must not carry a conflict 'status'"
    assert c["actor"] == "powershell.exe"
    assert {c["type_a"], c["type_b"]} == {"rwx_injection", "c2_connection"}


def test_same_actor_same_type_is_not_a_co_occurrence() -> None:
    events = [
        _event("2026-07-20T10:00:00", "memory", "mal.exe", "hostA", "process_start"),
        _event("2026-07-20T10:00:03", "evtx", "mal.exe", "hostA", "process_start"),
    ]
    assert find_co_occurrences(events, window_seconds=5) == []


def _f(title, source, actor, ts, etype):
    return Finding(
        title=title,
        description="d",
        finding_type="indicator",
        severity="high",
        category=FindingCategory.EXECUTION,
        evidence={
            "executable": actor,
            "timeline": {
                "ts": ts,
                "source": source,
                "actor": actor,
                "target": "",
                "type": etype,
            },
        },
        confidence=0.9,
        artifact_sources=[source],
    )


def test_hardening_report_exposes_co_occurrences_field() -> None:
    findings = [
        _f("a", "memory", "svc.exe", "2026-07-20T10:00:00", "rwx_injection"),
        _f("b", "pcap", "svc.exe", "2026-07-20T10:00:01", "c2_connection"),
    ]
    report = harden_findings(findings, image_sha256=IMAGE, receipt_key=KEY)
    assert report.co_occurrences, "expected a same-actor multi-behavior co-occurrence"
    assert all(
        c["relation"] == "same_actor_multi_behavior" for c in report.co_occurrences
    )
    # The report dict exposes the honestly-named key, not 'contradictions'.
    as_dict = report.to_dict()
    assert "co_occurrences" in as_dict
    assert "contradictions" not in as_dict
