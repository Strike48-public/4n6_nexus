"""Tests for the (partial) LoopBreaker wiring into the orchestrator (SFE-xxdd).

The loop_control primitive (OrchestratorConfig / LoopBreaker / StopReason) landed
and was unit-tested standalone (PR #73). SFE-2rjl made run_demo_investigation's
verify/remand path genuinely ITERATIVE, so the LoopBreaker now drives a real loop
(per-round record_iteration, reachable caps, degrade-on-non-DONE). These tests
pin the wiring:

  * config.max_remands_per_finding flows into RulesAdjudicator(max_remands=...),
    so the per-finding remand cap is configurable at the orchestrator boundary
    rather than hardcoded;
  * every verify round is recorded through a LoopBreaker and its typed StopReason
    (DONE on clean convergence) + trace land in the report integrity block, so the
    report states WHY the run terminated rather than assuming it.

The full iterative behavior (escalation, cap-driven degrade, determinism) is
pinned in test_orchestration_iterative_verify_loop.py.

RED-first: before the original wiring the orchestrator hardcoded RulesAdjudicator()
and the integrity block carried no stop_reason.
"""

from __future__ import annotations

from sift_find_evil.orchestration import InvestigationOrchestrator
from sift_find_evil.self_correction.loop_control import OrchestratorConfig


def _run(tmp_path, config=None):
    orch = InvestigationOrchestrator(
        case_id="INC-LB-001", audit_path=tmp_path / "audit.jsonl", config=config
    )
    return orch, orch.run_demo_investigation()


# -- typed StopReason in the integrity block --------------------------------


def test_integrity_block_carries_typed_stop_reason(tmp_path):
    _, report = _run(tmp_path)
    integ = report["integrity"]
    assert "stop_reason" in integ, "no typed StopReason emitted into the report"
    # A single pass that adjudicates every finding converges -> DONE.
    assert integ["stop_reason"] == "done"


def test_integrity_block_carries_loop_trace(tmp_path):
    _, report = _run(tmp_path)
    trace = report["integrity"].get("loop_trace")
    assert isinstance(trace, dict), "loop breaker trace not surfaced"
    assert trace["stop_reason"] == "done"
    assert trace["iterations"] >= 1


def test_contested_findings_counted_in_integrity(tmp_path):
    # SFE-2rjl made the verify path iterative: the demo's one contested finding
    # (F-005, the real C2 whose analyst verdict is not affirmative) no longer
    # ships as an open 'remanded' -- it escalates to a TERMINAL flagged_human once
    # the remand budget is spent. So the loop converges with ZERO open contests.
    # (flagged_human is a resolved terminal ruling: "a human must review this",
    # not an unresolved remand.)
    _, report = _run(tmp_path)
    assert report["integrity"]["contested_findings"] == 0


def test_iterative_loop_converges_done_not_spurious_stress(tmp_path):
    """The iterative loop converges DONE on the demo, not a spurious MAX_STRESSED.

    The state hash keys on the SET of (finding, ruling) pairs (order-independent),
    so a round that only re-adjudicates the SAME contested finding does not read as
    N separate stressed iterations. The demo's one contested finding escalates over
    a few rounds and the loop then converges (no remaining remand). The terminal
    reason must be the honest DONE, never MAX_STRESSED from counting re-challenges.
    """
    _, report = _run(tmp_path)
    trace = report["integrity"]["loop_trace"]
    assert trace["stop_reason"] == "done", (
        "the demo loop must converge DONE, not trip a spurious stress/oscillation "
        f"cap while escalating its one contested finding; got {trace['stop_reason']}"
    )
    # It genuinely iterated (escalation needs >1 round) yet still converged.
    assert trace["iterations"] >= 2


# -- config-driven remand cap flows to the adjudicator ----------------------


def test_config_max_remands_reaches_the_adjudicator(tmp_path):
    orch = InvestigationOrchestrator(
        case_id="INC-LB-CFG",
        audit_path=tmp_path / "a.jsonl",
        config=OrchestratorConfig(max_remands_per_finding=0),
    )
    orch.run_demo_investigation()
    # The adjudicator the run built must carry the configured cap, not the default.
    assert orch._adjudicator.max_remands == 0


def test_default_config_uses_primitive_default(tmp_path):
    orch, _ = _run(tmp_path)
    # No config passed -> the OrchestratorConfig default (2) is used.
    assert orch._adjudicator.max_remands == OrchestratorConfig().max_remands_per_finding


# -- F1 / behavior preservation ---------------------------------------------


def test_wiring_does_not_change_findings(tmp_path):
    # The loop is an overlay: it must not change the finding SET (still 6). The
    # verdict distribution DID change with SFE-2rjl -- the previously-open remand
    # now escalates to a terminal flagged_human across the iterative rounds -- but
    # no finding is added, dropped, or has its evidence['executable'] altered, so
    # F1 is untouched (the scenario harness scores off that field, not verdicts).
    _, report = _run(tmp_path)
    assert len(report["findings"]) == 6
    outcomes = sorted(cf["adversarial"]["outcome"] for cf in report["case_findings"])
    assert outcomes == [
        "flagged_human",
        "sustained",
        "sustained",
        "sustained",
        "sustained",
        "sustained",
    ]
