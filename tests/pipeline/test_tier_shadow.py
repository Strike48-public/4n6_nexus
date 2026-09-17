"""Tests for nexus_pipeline.tier.shadow (spec section 4 + 7 Phase 1).

Covers: the shadow store lives under the non-replicated state root, every
record() also emits a tier_decision to the .4 audit trail, record() fails
closed on a write error, record_outcome() attaches an outcome observed after
the fact, and agreement() computes the documented tier<->outcome mapping over
a bounded recent window. No test in this module ever asserts a merge action
was taken -- shadow mode takes none.
"""

import pytest

from nexus_pipeline.containment import audit
from nexus_pipeline.tier.classifier import Tier
from nexus_pipeline.tier.policy import Action
from nexus_pipeline.tier.shadow import (
    MIN_AGREEMENT_SAMPLE,
    ActionAgreement,
    AgreementReport,
    ShadowDecision,
    agreement,
    record,
    record_outcome,
)


@pytest.fixture(autouse=True)
def isolated_pipeline_state(tmp_path, monkeypatch):
    """Isolates both the non-replicated state root (shadow store) and the
    cwd-relative audit trail (./reports/audit), matching the pattern used by
    tests/pipeline/test_audit.py and test_ledger.py for the layers this
    module builds on.
    """
    monkeypatch.setenv("NEXUS_PIPELINE_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _decision(
    issue_id="SFE-1",
    pr_ref="pr-1",
    tier=Tier.T0,
    action=Action.AUTO_MERGE,
    gates_passed=True,
    reason="test decision",
    recorded_at="2026-08-24T00:00:00+00:00",
):
    return ShadowDecision(
        issue_id=issue_id,
        pr_ref=pr_ref,
        computed_tier=tier,
        would_do_action=action,
        gates_passed=gates_passed,
        reason=reason,
        recorded_at=recorded_at,
    )


def test_shadow_decision_is_frozen():
    decision = _decision()

    with pytest.raises(AttributeError):
        decision.actual_outcome = "merged"


def test_record_writes_under_the_non_replicated_state_root(isolated_pipeline_state):
    record(_decision())

    shadow_store = isolated_pipeline_state / "state" / "shadow" / "decisions.jsonl"
    assert shadow_store.exists()
    assert "SFE-1" in shadow_store.read_text()


def test_record_emits_a_tier_decision_to_the_audit_trail():
    decision = _decision(issue_id="SFE-42", tier=Tier.T1, action=Action.REQUIRE_REVIEW)

    record(decision)

    assert audit.verify_chain("SFE-42") is True
    head = audit.read_head("SFE-42")
    assert head is not None


def test_record_rejects_a_decision_that_already_carries_an_outcome():
    decision = ShadowDecision(
        issue_id="SFE-1",
        pr_ref="pr-1",
        computed_tier=Tier.T0,
        would_do_action=Action.AUTO_MERGE,
        gates_passed=True,
        reason="test",
        recorded_at="2026-08-24T00:00:00+00:00",
        actual_outcome="merged",
    )

    with pytest.raises(ValueError):
        record(decision)


def test_record_fails_closed_when_the_shadow_store_cannot_be_created(
    isolated_pipeline_state,
):
    """Empirically triggers the write failure rather than reasoning about
    it: pre-creates the shadow directory's target path as a plain file, so
    the module's own mkdir collides and raises.
    """
    state_dir = isolated_pipeline_state / "state"
    state_dir.mkdir(mode=0o700, parents=True)
    (state_dir / "shadow").write_text("blocks the shadow directory from forming")

    with pytest.raises(OSError):
        record(_decision())


def test_record_fails_closed_when_the_decisions_file_itself_cannot_be_opened(
    isolated_pipeline_state,
):
    """Distinct from the mkdir-collision test above, which raises inside
    _shadow_dir() before _append_json_line is ever reached: this pre-
    creates decisions.jsonl's own path as a directory, so the write-open
    call inside _append_json_line specifically is what fails.
    """
    state_dir = isolated_pipeline_state / "state"
    state_dir.mkdir(mode=0o700, parents=True)
    shadow_dir = state_dir / "shadow"
    shadow_dir.mkdir(mode=0o700)
    (shadow_dir / "decisions.jsonl").mkdir()

    with pytest.raises(OSError):
        record(_decision())


def test_record_outcome_rejects_an_empty_outcome():
    with pytest.raises(ValueError):
        record_outcome("SFE-1", "pr-1", "")


def test_agreement_with_no_decisions_reports_none_rate():
    report = agreement()

    assert isinstance(report, AgreementReport)
    assert report.decisions_considered == 0
    assert report.agreement_rate is None


def test_agreement_ignores_decisions_with_no_outcome_yet():
    record(_decision(issue_id="SFE-1", pr_ref="pr-1"))

    report = agreement()

    assert report.decisions_considered == 0


def test_agreement_auto_merge_agrees_only_with_merged_outcome():
    record(
        _decision(
            issue_id="SFE-1", pr_ref="pr-1", tier=Tier.T0, action=Action.AUTO_MERGE
        )
    )
    record_outcome("SFE-1", "pr-1", "merged")

    report = agreement()

    assert report.decisions_considered == 1
    assert report.agreements == 1
    assert report.agreement_rate == pytest.approx(1.0)


@pytest.mark.parametrize("disagreeing_outcome", ["changes_requested", "closed"])
def test_agreement_auto_merge_disagrees_with_non_merged_outcomes(disagreeing_outcome):
    record(
        _decision(
            issue_id="SFE-1", pr_ref="pr-1", tier=Tier.T0, action=Action.AUTO_MERGE
        )
    )
    record_outcome("SFE-1", "pr-1", disagreeing_outcome)

    report = agreement()

    assert report.decisions_considered == 1
    assert report.agreements == 0
    assert report.agreement_rate == pytest.approx(0.0)


@pytest.mark.parametrize("action", [Action.REQUIRE_REVIEW, Action.BLOCK])
@pytest.mark.parametrize("outcome", ["merged", "changes_requested", "closed"])
def test_require_review_and_block_agree_with_every_human_gated_outcome(action, outcome):
    """Documents and locks the design's literal mapping: 'BLOCK/REQUIRE_REVIEW
    agree with changes_requested/closed/human-gated-merge'. Because Phase 1
    requires a human gate on every merge already, ANY recorded outcome for a
    T1/T2 prediction is by construction human-gated, so both actions agree
    with all three canonical outcomes. The only prediction that a recorded
    outcome can falsify is AUTO_MERGE (see the tests above).
    """
    record(_decision(issue_id="SFE-1", pr_ref="pr-1", tier=Tier.T1, action=action))
    record_outcome("SFE-1", "pr-1", outcome)

    report = agreement()

    assert report.decisions_considered == 1
    assert report.agreements == 1
    assert report.agreement_rate == pytest.approx(1.0)


def test_agreement_window_limits_to_the_most_recent_n_decisions():
    # Three disagreeing AUTO_MERGE decisions, then two agreeing ones.
    for index in range(3):
        pr_ref = f"pr-old-{index}"
        record(
            _decision(
                issue_id="SFE-1", pr_ref=pr_ref, tier=Tier.T0, action=Action.AUTO_MERGE
            )
        )
        record_outcome("SFE-1", pr_ref, "changes_requested")
    for index in range(2):
        pr_ref = f"pr-new-{index}"
        record(
            _decision(
                issue_id="SFE-1", pr_ref=pr_ref, tier=Tier.T0, action=Action.AUTO_MERGE
            )
        )
        record_outcome("SFE-1", pr_ref, "merged")

    windowed_report = agreement(window=2)
    full_report = agreement(window=20)

    assert windowed_report.decisions_considered == 2
    assert windowed_report.agreement_rate == pytest.approx(1.0)
    assert full_report.decisions_considered == 5
    assert full_report.agreement_rate == pytest.approx(2 / 5)


def test_agreement_rejects_a_non_positive_window():
    with pytest.raises(ValueError):
        agreement(window=0)


def test_record_outcome_last_write_wins_for_the_same_key():
    record(
        _decision(
            issue_id="SFE-1", pr_ref="pr-1", tier=Tier.T0, action=Action.AUTO_MERGE
        )
    )
    record_outcome("SFE-1", "pr-1", "changes_requested")
    record_outcome("SFE-1", "pr-1", "merged")

    report = agreement()

    assert report.decisions_considered == 1
    assert report.agreements == 1


# --- Per-action breakdown and minimum-sample floor (security/code review ---
# --- CRITICAL fix: a single pooled agreement_rate is gameable) -------------


def _record_and_resolve(issue_id, pr_ref, tier, action, outcome):
    record(_decision(issue_id=issue_id, pr_ref=pr_ref, tier=tier, action=action))
    record_outcome(issue_id, pr_ref, outcome)


def test_per_action_auto_merge_rate_is_not_hidden_by_a_dominant_aggregate():
    """Reproduces the exact CRITICAL finding: 9 REQUIRE_REVIEW + 9 BLOCK
    decisions (each tautologically agrees with any outcome in Phase 1) plus
    2 AUTO_MERGE decisions that were BOTH wrong. The pooled aggregate reads
    as 90% (>= the spec's unlock threshold) while the only falsifiable
    action, AUTO_MERGE, was wrong 100% of the time in the same window --
    the per-action breakdown must expose this even though the aggregate
    hides it.
    """
    for index in range(9):
        _record_and_resolve(
            "SFE-1",
            f"pr-t1-{index}",
            Tier.T1,
            Action.REQUIRE_REVIEW,
            "changes_requested",
        )
    for index in range(9):
        _record_and_resolve("SFE-1", f"pr-t2-{index}", Tier.T2, Action.BLOCK, "closed")
    for index in range(2):
        _record_and_resolve(
            "SFE-1",
            f"pr-t0-{index}",
            Tier.T0,
            Action.AUTO_MERGE,
            "changes_requested",
        )

    report = agreement(window=20)

    # The misleading aggregate the finding is named for.
    assert report.decisions_considered == 20
    assert report.agreement_rate == pytest.approx(0.9)

    auto_merge = report.per_action[Action.AUTO_MERGE]
    assert isinstance(auto_merge, ActionAgreement)
    assert auto_merge.decisions_considered == 2
    assert auto_merge.agreements == 0
    assert auto_merge.agreement_rate == pytest.approx(0.0)
    assert auto_merge.meets_minimum_sample is False


def test_per_action_meets_minimum_sample_when_enough_decisions_exist():
    for index in range(MIN_AGREEMENT_SAMPLE):
        _record_and_resolve(
            "SFE-1", f"pr-{index}", Tier.T0, Action.AUTO_MERGE, "merged"
        )

    report = agreement(window=MIN_AGREEMENT_SAMPLE)
    auto_merge = report.per_action[Action.AUTO_MERGE]

    assert auto_merge.decisions_considered == MIN_AGREEMENT_SAMPLE
    assert auto_merge.agreement_rate == pytest.approx(1.0)
    assert auto_merge.meets_minimum_sample is True


def test_per_action_reports_none_rate_for_an_action_with_no_decisions_in_window():
    _record_and_resolve("SFE-1", "pr-1", Tier.T1, Action.REQUIRE_REVIEW, "merged")

    report = agreement()
    block = report.per_action[Action.BLOCK]

    assert block.decisions_considered == 0
    assert block.agreement_rate is None
    assert block.meets_minimum_sample is False


def test_per_action_breakdown_always_has_all_three_actions():
    _record_and_resolve("SFE-1", "pr-1", Tier.T0, Action.AUTO_MERGE, "merged")

    report = agreement()

    assert set(report.per_action) == set(Action)
