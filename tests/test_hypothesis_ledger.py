"""Tests for the falsifiable hypothesis ledger (SFE-udkk).

A competing-hypothesis structure where the lead registers falsifiable hypotheses
(each naming the artifact that would confirm/kill it), findings attach to a
hypothesis, and the ONLY way to change a finding's verdict is ``revise_finding``,
which appends a ``SelfCorrection{from,to,reason,trigger_exec_id}``. A verdict flip
without a logged self-correction is structurally impossible: the records are frozen
and the store is private, so revise is the sole mutation path.

RED-first: the module did not exist before this test.
"""

import pytest

from sift_find_evil.self_correction.hypothesis_ledger import (
    AttachedFinding,
    Hypothesis,
    HypothesisLedger,
    HypothesisStatus,
    SelfCorrection,
    Verdict,
)


# -- helpers ---------------------------------------------------------------


def _seeded_ledger():
    """A ledger with one hypothesis and one SUPPORTS finding attached."""
    ledger = HypothesisLedger()
    hyp = ledger.add_hypothesis(
        statement="Host was ransomwared by the LockThis family.",
        falsifier="No .lockthis-extensioned files present anywhere on the volume.",
    )
    finding = ledger.add_finding(
        hypothesis_id=hyp.id,
        summary="47 files renamed with .lockthis extension in C:/Users.",
        verdict=Verdict.SUPPORTS,
        source_exec_id="mftecmd-001",
    )
    return ledger, hyp, finding


# -- registration ----------------------------------------------------------


def test_add_hypothesis_assigns_id_and_is_open():
    ledger = HypothesisLedger()
    hyp = ledger.add_hypothesis(
        statement="Data was exfiltrated over DNS.",
        falsifier="No outbound DNS TXT records exceed 200 bytes.",
    )
    assert isinstance(hyp, Hypothesis)
    assert hyp.id == "H-001"
    assert ledger.status_of(hyp.id) is HypothesisStatus.OPEN


def test_hypothesis_ids_are_monotonic():
    ledger = HypothesisLedger()
    first = ledger.add_hypothesis(statement="A", falsifier="fa")
    second = ledger.add_hypothesis(statement="B", falsifier="fb")
    assert (first.id, second.id) == ("H-001", "H-002")


def test_hypothesis_requires_nonempty_statement():
    ledger = HypothesisLedger()
    with pytest.raises(ValueError):
        ledger.add_hypothesis(statement="   ", falsifier="a real falsifier")


def test_hypothesis_requires_a_falsifier():
    # The whole point: a hypothesis with no named artifact that could kill it is
    # not falsifiable and must be rejected.
    ledger = HypothesisLedger()
    with pytest.raises(ValueError):
        ledger.add_hypothesis(statement="Something happened.", falsifier="")


# -- attaching findings ----------------------------------------------------


def test_add_finding_attaches_with_initial_verdict_and_no_correction():
    ledger, hyp, finding = _seeded_ledger()
    assert isinstance(finding, AttachedFinding)
    assert finding.id == "F-001"
    assert finding.hypothesis_id == hyp.id
    assert finding.verdict is Verdict.SUPPORTS
    # An initial verdict is the first assertion, not a self-correction.
    assert finding.corrections == ()
    assert ledger.self_correction_count() == 0


def test_add_finding_to_unknown_hypothesis_is_rejected():
    ledger = HypothesisLedger()
    with pytest.raises(KeyError):
        ledger.add_finding(
            hypothesis_id="H-999",
            summary="orphan",
            verdict=Verdict.SUPPORTS,
            source_exec_id="x-1",
        )


def test_add_finding_requires_a_source_exec_id():
    # A finding IS evidence; it must cite the tool execution it came from.
    ledger = HypothesisLedger()
    hyp = ledger.add_hypothesis(statement="A", falsifier="fa")
    with pytest.raises(ValueError):
        ledger.add_finding(
            hypothesis_id=hyp.id,
            summary="ungrounded",
            verdict=Verdict.SUPPORTS,
            source_exec_id="",
        )


# -- the sole mutation path: revise_finding --------------------------------


def test_revise_finding_flips_verdict_and_logs_self_correction():
    ledger, _hyp, finding = _seeded_ledger()
    revised = ledger.revise_finding(
        finding_id=finding.id,
        new_verdict=Verdict.RETRACTED,
        reason="Re-read the MFT: the 47 renames predate the incident window.",
        trigger_exec_id="mftecmd-002",
    )
    assert revised.verdict is Verdict.RETRACTED
    assert ledger.self_correction_count() == 1
    (correction,) = revised.corrections
    assert isinstance(correction, SelfCorrection)
    assert correction.from_verdict is Verdict.SUPPORTS
    assert correction.to_verdict is Verdict.RETRACTED
    assert correction.trigger_exec_id == "mftecmd-002"


def test_revise_is_the_only_mutation_path_records_are_frozen():
    # There is no other way to change a verdict: the record is immutable.
    _ledger, _hyp, finding = _seeded_ledger()
    with pytest.raises((AttributeError, TypeError)):
        finding.verdict = Verdict.REFUTES  # type: ignore[misc]


def test_revise_unknown_finding_is_rejected():
    ledger, _hyp, _finding = _seeded_ledger()
    with pytest.raises(KeyError):
        ledger.revise_finding(
            finding_id="F-999",
            new_verdict=Verdict.REFUTES,
            reason="r",
            trigger_exec_id="x-1",
        )


def test_revise_to_same_verdict_is_rejected_as_noop():
    # A "correction" that changes nothing is not a self-correction.
    ledger, _hyp, finding = _seeded_ledger()
    with pytest.raises(ValueError):
        ledger.revise_finding(
            finding_id=finding.id,
            new_verdict=Verdict.SUPPORTS,
            reason="no change",
            trigger_exec_id="x-1",
        )


def test_revise_requires_a_reason():
    ledger, _hyp, finding = _seeded_ledger()
    with pytest.raises(ValueError):
        ledger.revise_finding(
            finding_id=finding.id,
            new_verdict=Verdict.REFUTES,
            reason="   ",
            trigger_exec_id="x-1",
        )


def test_revise_requires_a_trigger_exec_id():
    # A self-correction must be grounded in the tool execution that triggered it.
    ledger, _hyp, finding = _seeded_ledger()
    with pytest.raises(ValueError):
        ledger.revise_finding(
            finding_id=finding.id,
            new_verdict=Verdict.REFUTES,
            reason="a real reason",
            trigger_exec_id="",
        )


def test_successive_revisions_chain_from_to_coherently():
    ledger, _hyp, finding = _seeded_ledger()
    ledger.revise_finding(
        finding_id=finding.id,
        new_verdict=Verdict.INCONCLUSIVE,
        reason="timeline ambiguous",
        trigger_exec_id="x-1",
    )
    final = ledger.revise_finding(
        finding_id=finding.id,
        new_verdict=Verdict.REFUTES,
        reason="second tool run kills it",
        trigger_exec_id="x-2",
    )
    trail = ledger.correction_trail()
    assert [c.sequence for c in trail] == [1, 2]
    # The chain is coherent: each correction's `from` is the previous `to`.
    assert trail[0].from_verdict is Verdict.SUPPORTS
    assert trail[0].to_verdict is Verdict.INCONCLUSIVE
    assert trail[1].from_verdict is Verdict.INCONCLUSIVE
    assert trail[1].to_verdict is Verdict.REFUTES
    assert final.verdict is Verdict.REFUTES


# -- derived hypothesis status ---------------------------------------------


def test_status_confirmed_when_supported_and_uncontradicted():
    ledger, hyp, _finding = _seeded_ledger()
    assert ledger.status_of(hyp.id) is HypothesisStatus.CONFIRMED
    assert hyp in ledger.confirmed()


def test_live_refutation_eliminates_the_hypothesis():
    # A live REFUTES finding dominates: the candidate is eliminated (retracted),
    # never CONFIRMED, even if a SUPPORTS finding also exists -- the contradiction
    # hard-block is automatic.
    ledger, hyp, _finding = _seeded_ledger()
    ledger.add_finding(
        hypothesis_id=hyp.id,
        summary="Files were renamed by a legit backup tool, not ransomware.",
        verdict=Verdict.REFUTES,
        source_exec_id="evtx-010",
    )
    assert ledger.status_of(hyp.id) is HypothesisStatus.RETRACTED
    assert hyp in ledger.retracted()
    assert hyp not in ledger.confirmed()


def test_retracting_a_refutation_reopens_the_candidate():
    # The self-correction story: eliminate a hypothesis, then withdraw the
    # refutation on re-read -> the candidate comes back, fully log-backed.
    ledger, hyp, _finding = _seeded_ledger()
    refutation = ledger.add_finding(
        hypothesis_id=hyp.id,
        summary="backup tool did the renames",
        verdict=Verdict.REFUTES,
        source_exec_id="evtx-010",
    )
    assert ledger.status_of(hyp.id) is HypothesisStatus.RETRACTED
    ledger.revise_finding(
        finding_id=refutation.id,
        new_verdict=Verdict.RETRACTED,
        reason="The 'backup tool' was attacker-renamed; refutation withdrawn.",
        trigger_exec_id="mftecmd-003",
    )
    # A RETRACTED (withdrawn) finding no longer bears on status.
    assert ledger.status_of(hyp.id) is HypothesisStatus.CONFIRMED


def test_status_of_unknown_hypothesis_is_rejected():
    ledger = HypothesisLedger()
    with pytest.raises(KeyError):
        ledger.status_of("H-404")


def test_get_hypothesis_returns_registered_and_rejects_unknown():
    ledger, hyp, _finding = _seeded_ledger()
    assert ledger.get_hypothesis(hyp.id) == hyp
    with pytest.raises(KeyError):
        ledger.get_hypothesis("H-404")


def test_findings_for_unknown_hypothesis_is_rejected():
    ledger, hyp, finding = _seeded_ledger()
    assert ledger.findings_for(hyp.id) == (finding,)
    with pytest.raises(KeyError):
        ledger.findings_for("H-404")


def test_open_hypothesis_has_no_supports_or_refutes():
    ledger = HypothesisLedger()
    hyp = ledger.add_hypothesis(statement="Maybe X.", falsifier="artifact Y")
    ledger.add_finding(
        hypothesis_id=hyp.id,
        summary="ambiguous timeline, neither for nor against",
        verdict=Verdict.INCONCLUSIVE,
        source_exec_id="x-1",
    )
    assert ledger.status_of(hyp.id) is HypothesisStatus.OPEN
    assert hyp in ledger.open_hypotheses()


# -- report + persistence --------------------------------------------------


def test_report_summary_exposes_candidate_elimination_trail():
    ledger, hyp, finding = _seeded_ledger()
    ledger.revise_finding(
        finding_id=finding.id,
        new_verdict=Verdict.REFUTES,
        reason="predates incident window",
        trigger_exec_id="mftecmd-002",
    )
    summary = ledger.report_summary()
    assert summary["self_correction_count"] == 1
    assert summary["hypothesis_count"] == 1
    assert hyp.id in {h["id"] for h in summary["retracted"]}
    assert len(summary["correction_trail"]) == 1


def test_ledger_round_trips_through_dict():
    ledger, _hyp, finding = _seeded_ledger()
    ledger.revise_finding(
        finding_id=finding.id,
        new_verdict=Verdict.INCONCLUSIVE,
        reason="ambiguous",
        trigger_exec_id="x-1",
    )
    restored = HypothesisLedger.from_dict(ledger.to_dict())
    assert restored.to_dict() == ledger.to_dict()
    assert restored.self_correction_count() == 1


def test_save_and_load_are_atomic_round_trip(tmp_path):
    path = tmp_path / "ledger.json"
    ledger, _hyp, finding = _seeded_ledger()
    ledger.revise_finding(
        finding_id=finding.id,
        new_verdict=Verdict.REFUTES,
        reason="killed by second run",
        trigger_exec_id="x-9",
    )
    ledger.save(path)
    # No stray temp file left behind after an atomic write.
    assert list(tmp_path.glob("*.tmp")) == []

    reloaded = HypothesisLedger.load(path)
    assert reloaded.to_dict() == ledger.to_dict()


def test_save_without_path_raises():
    ledger, _hyp, _finding = _seeded_ledger()
    with pytest.raises(ValueError):
        ledger.save()
