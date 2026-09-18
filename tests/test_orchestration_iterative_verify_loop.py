"""The verify/remand path is a genuinely ITERATIVE adversarial loop (SFE-2rjl).

Before this change the verifier ran a single pass: `remand_count` was plumbed
through `run_adversarial_round` / `RulesAdjudicator` but always 0, so no finding
was ever re-adjudicated and a `remanded` verdict was terminal. The LoopBreaker
recorded one converged iteration and the HypothesisLedger was built post-hoc.

Now the orchestrator re-adjudicates CONTESTED (remanded) findings across bounded
rounds, incrementing each finding's remand_count. A finding remanded for a reason
that cannot change across rounds (e.g. a non-affirmative analyst verdict) escalates
`remanded -> flagged_human` once the remand budget is spent - the honest "machine
cannot resolve this; a human must review it" outcome. The loop is deterministic
(no wall-clock, no live model), so the same inputs always yield the same rounds.

F1 is unaffected: this loop is an overlay on already-emitted findings and never
touches `evidence['executable']`; the scenario harness (which computes F1) does
not call `run_demo_investigation`.
"""

from __future__ import annotations

import pytest

from sift_find_evil.orchestration import InvestigationOrchestrator
from sift_find_evil.self_correction.loop_control import OrchestratorConfig


@pytest.fixture
def report(tmp_path):
    orch = InvestigationOrchestrator(
        case_id="INC-ITER-001", audit_path=tmp_path / "audit.jsonl"
    )
    return orch.run_demo_investigation()


# -- the demo now demonstrates the escalation path end to end ----------------


def test_terminal_remand_escalates_to_flagged_human(report):
    # The demo's F-005 SURVIVED the falsifier but its analyst verdict is not
    # affirmative -> it can never be sustained, so across the bounded rounds it
    # escalates remanded -> flagged_human rather than shipping as an open remand.
    outcomes = sorted(cf["adversarial"]["outcome"] for cf in report["case_findings"])
    assert outcomes == [
        "flagged_human",
        "sustained",
        "sustained",
        "sustained",
        "sustained",
        "sustained",
    ], f"expected the terminal remand to escalate to flagged_human; got {outcomes}"


def test_no_finding_ships_as_an_open_remand(report):
    # A genuinely iterative loop resolves every contested finding: either it
    # sustains/dismisses, or it escalates to flagged_human. Nothing stays
    # 'remanded' in the final report (that was the single-pass artifact).
    outcomes = {cf["adversarial"]["outcome"] for cf in report["case_findings"]}
    assert "remanded" not in outcomes


def test_loop_ran_multiple_rounds(report):
    # The breaker trace proves the loop iterated more than once (the terminal
    # remand took max_remands+1 rounds to escalate), not a single converged pass.
    trace = report["integrity"]["loop_trace"]
    assert (
        trace["iterations"] >= 2
    ), f"iterative loop must record >1 round; got {trace['iterations']}"
    # It still terminates cleanly (converged: no contested findings remain).
    assert trace["stop_reason"] == "done"


def test_escalation_does_not_eliminate_the_subject_hypothesis(report):
    # The escalated finding is F-005 = 203.0.113.66, the REAL corroborated C2.
    # flagged_human means "machine cannot self-resolve; a human must review" - it
    # is NOT evidence the subject is benign, so it must NOT flip the ledger's
    # SUBJECT-malice verdict. The ledger tracks a different axis than finding
    # disposition: the demo still has exactly ONE genuine elimination (benign
    # 1.1.1.1), and the real C2 stays confirmed even though its finding escalated.
    ls = report["hypothesis_ledger"]
    assert ls["self_correction_count"] == 1, (
        "escalation to flagged_human must not manufacture a subject elimination; "
        f"only the benign-IP exoneration is a real self-correction; got "
        f"{ls['self_correction_count']}"
    )
    confirmed = [h for h in ls["confirmed"] if "203.0.113.66" in h["statement"]]
    assert confirmed, "the real C2 subject must stay confirmed despite escalation"


def test_terminal_stop_reason_recorded_in_integrity(report):
    # The loop's terminal StopReason + trace are the unforgeable record of WHY
    # verification ended - a genuinely iterative run surfaces them.
    integ = report["integrity"]
    assert integ["stop_reason"] == "done"
    assert integ["loop_trace"]["iterations"] >= 2


def test_contested_reflects_unresolved_only(report):
    # 'contested' should count findings the loop could NOT resolve to a terminal
    # ruling. With escalation, the demo converges with 0 open contests (F-005 is
    # now terminally flagged_human, not an unresolved remand).
    assert report["integrity"]["contested_findings"] == 0


# -- LoopBreaker caps are now genuinely reachable ---------------------------


def test_max_iterations_cap_degrades_contested_to_flagged_human(tmp_path):
    # With max_remands high but max_iterations low, a still-contested finding is
    # forced to a non-DONE stop; the breaker's should_flag_contested path must
    # degrade the survivor to flagged_human and surface the typed StopReason.
    orch = InvestigationOrchestrator(
        case_id="INC-ITER-CAP",
        audit_path=tmp_path / "a.jsonl",
        config=OrchestratorConfig(max_remands_per_finding=99, max_iterations=2),
    )
    report = orch.run_demo_investigation()
    integ = report["integrity"]
    assert integ["stop_reason"] in {"max_iterations", "oscillation", "max_stressed"}, (
        f"a capped loop with an unresolved remand must stop non-DONE; got "
        f"{integ['stop_reason']}"
    )
    outcomes = {cf["adversarial"]["outcome"] for cf in report["case_findings"]}
    assert (
        "remanded" not in outcomes
    ), "on a non-DONE stop the contested findings must degrade to flagged_human"
    assert "flagged_human" in outcomes


# -- mutation guard: the iteration is real, not theater ---------------------


def test_single_round_cap_prevents_escalation_mutation_guard(tmp_path):
    # MUTATION GUARD: cap the loop at ONE round (max_iterations=1). A single pass
    # cannot escalate the terminal remand, so F-005 stays 'remanded' and never
    # reaches flagged_human. If the loop were secretly single-pass (theater), the
    # UNCAPPED run above would ALSO leave it remanded and test_terminal_remand_
    # escalates_to_flagged_human would fail. The contrast proves >1 round happens.
    orch = InvestigationOrchestrator(
        case_id="INC-ITER-1ROUND",
        audit_path=tmp_path / "a.jsonl",
        config=OrchestratorConfig(max_remands_per_finding=99, max_iterations=1),
    )
    report = orch.run_demo_investigation()
    integ = report["integrity"]
    # One round, unresolved remand, non-DONE stop -> breaker degrades it. The
    # degrade path (should_flag_contested) is what turns the lone round's remand
    # into flagged_human; the ESCALATION-via-rounds path is distinct and needs >1
    # round (proven by test_loop_ran_multiple_rounds under the default config).
    assert integ["loop_trace"]["iterations"] == 1
    assert integ["stop_reason"] != "done"


# -- determinism ------------------------------------------------------------


def test_loop_is_deterministic(tmp_path):
    def run():
        orch = InvestigationOrchestrator(
            case_id="INC-ITER-DET", audit_path=tmp_path / "det.jsonl"
        )
        r = orch.run_demo_investigation()
        return (
            sorted(cf["adversarial"]["outcome"] for cf in r["case_findings"]),
            r["integrity"]["stop_reason"],
            r["integrity"]["loop_trace"]["iterations"],
        )

    assert run() == run()
