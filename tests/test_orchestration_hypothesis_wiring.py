"""Tests for the HypothesisLedger wiring into the orchestrator (SFE-n69x).

The hypothesis_ledger primitive (HypothesisLedger / Verdict / SelfCorrection)
landed and was unit-tested standalone (PR #81). This wires it as a READ-ONLY
overlay onto the single-pass run_demo_investigation: the orchestrator registers
one falsifiable hypothesis per investigative subject, attaches each emitted
finding as SUPPORTS, and -- for a finding the engine itself EXONERATES (a
known-benign direct-IP downgrade) -- routes the verdict change through
ledger.revise_finding() so the elimination is a logged, unforgeable
SelfCorrection. The report gains a candidate-elimination section.

What these tests pin down, grounded in the REAL demo output (not invented):

  * ``1.1.1.1:53`` is first flagged a hardcoded-IP C2 candidate, then the
    engine's ``known_benign_direct_ip_infrastructure`` resolution exonerates it
    -> its hypothesis is RETRACTED via a logged self-correction (SUPPORTS ->
    REFUTES) that cites a real tool execution.
  * ``203.0.113.66:4444`` (the genuine C2, corroborated in memory) has no
    exonerating resolution -> its hypothesis stays CONFIRMED.
  * The disk causality (``event_log_confirms_prefetch``) and memory
    (``psscan_confirms_unlinked_process``) resolutions CONFIRM their findings,
    so they must NOT log a REFUTES -- exactly ONE self-correction occurs.

RED-first: before this change the report carried no ``hypothesis_ledger`` key
and no hypothesis-derived self-correction count.
"""

from __future__ import annotations

from sift_find_evil.orchestration import InvestigationOrchestrator


def _run(tmp_path):
    orch = InvestigationOrchestrator(
        case_id="INC-HYP-001", audit_path=tmp_path / "audit.jsonl"
    )
    return orch, orch.run_demo_investigation()


def _find_by_subject(entries, needle):
    """Return the single entry whose statement mentions ``needle`` (or None)."""
    matches = [h for h in entries if needle in h["statement"]]
    return matches[0] if matches else None


# -- the candidate-elimination section exists -------------------------------


def test_report_carries_hypothesis_ledger_summary(tmp_path):
    _, report = _run(tmp_path)
    assert "hypothesis_ledger" in report, "no candidate-elimination section emitted"
    summary = report["hypothesis_ledger"]
    for key in (
        "hypothesis_count",
        "finding_count",
        "self_correction_count",
        "confirmed",
        "retracted",
        "open",
        "correction_trail",
    ):
        assert key in summary, f"summary missing {key!r}"
    assert summary["hypothesis_count"] >= 1
    # Every emitted finding is attached to a hypothesis (overlay is complete).
    assert summary["finding_count"] == len(report["findings"])


def test_integrity_block_carries_hypothesis_metrics(tmp_path):
    _, report = _run(tmp_path)
    integ = report["integrity"]
    assert (
        integ["hypothesis_self_corrections"]
        == report["hypothesis_ledger"]["self_correction_count"]
    )
    assert integ["hypotheses_retracted"] == len(
        report["hypothesis_ledger"]["retracted"]
    )
    assert integ["hypotheses_confirmed"] == len(
        report["hypothesis_ledger"]["confirmed"]
    )


# -- the ONE genuine self-correction (benign IP exonerated) -----------------


def test_benign_ip_candidate_is_retracted_via_logged_self_correction(tmp_path):
    _, report = _run(tmp_path)
    summary = report["hypothesis_ledger"]
    retracted = _find_by_subject(summary["retracted"], "1.1.1.1")
    assert retracted is not None, "benign 1.1.1.1 candidate was not eliminated"
    # The elimination is a LOGGED self-correction, not a silent status flip.
    trail = summary["correction_trail"]
    assert len(trail) >= 1
    benign_corrections = [
        c
        for c in trail
        if c["from_verdict"] == "supports" and c["to_verdict"] == "refutes"
    ]
    assert benign_corrections, "no SUPPORTS->REFUTES correction logged"
    for c in benign_corrections:
        assert c["reason"].strip(), "a correction must carry a reason"
        assert c["trigger_exec_id"].strip(), "a correction must cite a tool execution"


def test_real_c2_subject_stays_confirmed(tmp_path):
    _, report = _run(tmp_path)
    summary = report["hypothesis_ledger"]
    confirmed = _find_by_subject(summary["confirmed"], "203.0.113.66")
    assert confirmed is not None, "the real C2 (203.0.113.66) was not confirmed"
    # ...and it is NOT sitting in the retracted (eliminated) bucket.
    assert _find_by_subject(summary["retracted"], "203.0.113.66") is None


# -- confirming resolutions must NOT masquerade as eliminations -------------


def test_only_the_benign_exoneration_logs_a_correction(tmp_path):
    """event_log/psscan resolutions CONFIRM findings -> zero REFUTES from them.

    Mutation guard: if the wiring naively triggered a REFUTES on ANY resolution,
    the disk causality + memory findings (which resolve-to-confirm) would each
    log a spurious correction and this count would jump above 1.
    """
    _, report = _run(tmp_path)
    summary = report["hypothesis_ledger"]
    assert summary["self_correction_count"] == 1, (
        "exactly one genuine elimination (benign 1.1.1.1) is expected; a higher "
        "count means a confirming resolution was mistaken for an exoneration"
    )


# -- overlay invariants: findings + F1 path untouched -----------------------


def test_ledger_is_a_readonly_overlay(tmp_path):
    """The ledger must not drop, add, or alter the scored findings."""
    _, report = _run(tmp_path)
    # The demo emits six findings; the overlay leaves that list intact.
    assert len(report["findings"]) == 6
    assert len(report["case_findings"]) == 6
    # Every logged correction obeys the unforgeability contract.
    for c in report["hypothesis_ledger"]["correction_trail"]:
        assert c["from_verdict"] != c["to_verdict"]
        assert c["finding_id"]
        assert c["trigger_exec_id"]
