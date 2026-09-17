"""Tests for nexus_pipeline.tier.policy (spec section 4 tier table).

would_do_action reports what the pipeline WOULD do in shadow mode; it never
takes any action itself. The safety invariant under test throughout: AUTO_MERGE
is reachable only for T0 with gates_passed=True, never for T1 or T2 under any
gates_passed value.
"""

import pytest

from nexus_pipeline.tier.classifier import Tier
from nexus_pipeline.tier.policy import Action, would_do_action


def test_t0_with_gates_passed_is_auto_merge():
    assert would_do_action(Tier.T0, gates_passed=True) is Action.AUTO_MERGE


def test_t0_without_gates_passed_is_block():
    assert would_do_action(Tier.T0, gates_passed=False) is Action.BLOCK


@pytest.mark.parametrize("gates_passed", [True, False])
def test_t1_is_always_require_review(gates_passed):
    assert would_do_action(Tier.T1, gates_passed=gates_passed) is Action.REQUIRE_REVIEW


@pytest.mark.parametrize("gates_passed", [True, False])
def test_t2_is_always_block(gates_passed):
    assert would_do_action(Tier.T2, gates_passed=gates_passed) is Action.BLOCK


@pytest.mark.parametrize("tier", list(Tier))
@pytest.mark.parametrize("gates_passed", [True, False])
def test_auto_merge_is_reachable_only_via_t0_with_gates_passed(tier, gates_passed):
    action = would_do_action(tier, gates_passed=gates_passed)

    if action is Action.AUTO_MERGE:
        assert tier is Tier.T0
        assert gates_passed is True
