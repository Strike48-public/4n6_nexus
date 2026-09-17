"""Tests for the oscillation-aware loop breaker (gallery idea #21, SFE-jrwx).

Upgrades an N-consecutive-failure breaker into one that trips on LOGICAL
non-progress: a recurring (evidence + claim + objection + ruling) state hash, an
A-B-A-B verdict ping-pong, exhausted multi-dimensional budgets (tokens, USD, tool
calls, wall clock), or a run of confused tool-less agent decisions. Every stop is
a typed ``StopReason`` and a non-DONE stop asks the caller to degrade contested
findings to human review while still sealing the report.

The breaker is pure code with an INJECTABLE clock, so it is fully deterministic
and CI-reproducible. RED-first: the module did not exist before.
"""

import pytest

from sift_find_evil.self_correction.loop_control import (
    LoopBreaker,
    OrchestratorConfig,
    StopDecision,
    StopReason,
    state_hash,
)


class _FakeClock:
    """A hand-cranked monotonic clock so wall-timeout tests are deterministic."""

    def __init__(self, start: float = 1000.0):
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


# -- state_hash ------------------------------------------------------------


def test_state_hash_is_deterministic():
    a = state_hash(["mft", "prefetch"], "executed", "misread?", "sustained")
    b = state_hash(["mft", "prefetch"], "executed", "misread?", "sustained")
    assert a == b
    assert len(a) == 64  # sha256 hex


def test_state_hash_is_evidence_order_independent():
    # Sorted evidence keys: the same set in a different order is the same state.
    a = state_hash(["mft", "prefetch", "evtx"], "c", "o", "r")
    b = state_hash(["evtx", "mft", "prefetch"], "c", "o", "r")
    assert a == b


def test_state_hash_changes_when_ruling_changes():
    a = state_hash(["mft"], "c", "o", "sustained")
    b = state_hash(["mft"], "c", "o", "remanded")
    assert a != b


# -- baseline / DONE -------------------------------------------------------


def test_fresh_breaker_is_running_not_stopped():
    breaker = LoopBreaker()
    assert breaker.decision.reason is StopReason.RUNNING
    assert breaker.decision.stopped is False


def test_converged_iteration_stops_with_done():
    breaker = LoopBreaker()
    decision = breaker.record_iteration(
        state_hash(["mft"], "c", "o", "sustained"),
        accepted_finding=True,
        converged=True,
    )
    assert decision.stopped is True
    assert decision.reason is StopReason.DONE
    # DONE is a clean stop: the caller must NOT flag contested findings.
    assert decision.should_flag_contested is False


# -- OSCILLATION (the headline feature) ------------------------------------


def test_forced_identical_state_loop_trips_oscillation():
    # A loop that keeps re-deriving the identical (evidence, claim, objection,
    # ruling) state is making no logical progress -> OSCILLATION.
    breaker = LoopBreaker(OrchestratorConfig(max_state_recurrences=2))
    h = state_hash(["mft"], "evil.exe executed", "seat: misread?", "remanded")
    d1 = breaker.record_iteration(h, accepted_finding=False)
    d2 = breaker.record_iteration(h, accepted_finding=False)
    assert d1.stopped is False
    assert d2.stopped is False  # 2 recurrences allowed
    d3 = breaker.record_iteration(h, accepted_finding=False)
    assert d3.stopped is True
    assert d3.reason is StopReason.OSCILLATION
    # A non-DONE stop degrades contested findings to human review.
    assert d3.should_flag_contested is True


def test_two_distinct_progress_states_do_not_trip_oscillation():
    # Regression: at the minimum window (4), two ordinary distinct-state
    # iterations are normal progress, NOT a ping-pong. The window must be wide
    # enough that a genuine A-then-B step is never mistaken for A-B-A-B.
    breaker = LoopBreaker(
        OrchestratorConfig(oscillation_window=4, max_state_recurrences=99)
    )
    a = state_hash(["mft"], "a", "o", "r")
    b = state_hash(["mft"], "b", "o", "r")
    assert breaker.record_iteration(a, accepted_finding=False).stopped is False
    d = breaker.record_iteration(b, accepted_finding=False)
    assert d.stopped is False


def test_verdict_ping_pong_trips_oscillation():
    # A-B-A-B: the verdict flips between two states without converging. Caught by
    # tail-oscillation detection even though neither hash has recurred > cap yet.
    breaker = LoopBreaker(OrchestratorConfig(max_state_recurrences=5))
    a = state_hash(["mft"], "c", "o", "sustained")
    b = state_hash(["mft"], "c", "o", "remanded")
    assert breaker.record_iteration(a, accepted_finding=False).stopped is False
    assert breaker.record_iteration(b, accepted_finding=False).stopped is False
    assert breaker.record_iteration(a, accepted_finding=False).stopped is False
    d = breaker.record_iteration(b, accepted_finding=False)  # A-B-A-B complete
    assert d.stopped is True
    assert d.reason is StopReason.OSCILLATION


# -- MAX_STRESSED + stress reset -------------------------------------------


def test_consecutive_stressed_trips_max_stressed():
    breaker = LoopBreaker(OrchestratorConfig(max_consecutive_stressed=3))
    # Distinct states each round so OSCILLATION does not fire first.
    for i in range(2):
        d = breaker.record_iteration(
            state_hash(["mft"], f"c{i}", "o", "remanded"), accepted_finding=False
        )
        assert d.stopped is False
    d = breaker.record_iteration(
        state_hash(["mft"], "c2", "o", "remanded"), accepted_finding=False
    )
    assert d.stopped is True
    assert d.reason is StopReason.MAX_STRESSED


def test_accepted_finding_resets_stress_counter():
    # Stress must only accumulate on non-progress; an accepted finding is real
    # progress and resets the counter (the issue: "Reset stress counter only on
    # an accepted finding").
    breaker = LoopBreaker(OrchestratorConfig(max_consecutive_stressed=3))
    breaker.record_iteration(
        state_hash(["mft"], "c0", "o", "remanded"), accepted_finding=False
    )
    breaker.record_iteration(
        state_hash(["mft"], "c1", "o", "remanded"), accepted_finding=False
    )
    assert breaker.consecutive_stressed == 2
    # An accepted finding resets the strike count to zero.
    breaker.record_iteration(
        state_hash(["mft"], "c2", "o", "sustained"), accepted_finding=True
    )
    assert breaker.consecutive_stressed == 0


# -- tool-less decisions ("burn the budget") -------------------------------


def test_tool_less_decisions_are_strikes():
    # A confused agent that "decides" without calling any tool makes no progress;
    # each such decision is a strike, so a run of them trips MAX_STRESSED even
    # though the caller never explicitly said accepted_finding=False.
    breaker = LoopBreaker(OrchestratorConfig(max_consecutive_stressed=2))
    breaker.record_iteration(
        state_hash(["mft"], "c0", "o", "remanded"),
        accepted_finding=True,  # even claiming acceptance...
        tool_less=True,  # ...a tool-less decision is still a strike
    )
    d = breaker.record_iteration(
        state_hash(["mft"], "c1", "o", "remanded"),
        accepted_finding=True,
        tool_less=True,
    )
    assert d.stopped is True
    assert d.reason is StopReason.MAX_STRESSED


def test_tool_less_decisions_burn_the_token_budget():
    # A tool-less decision still costs model tokens while producing nothing. With
    # a token budget set, confused spinning is bounded by BUDGET_EXHAUSTED.
    breaker = LoopBreaker(
        OrchestratorConfig(max_tokens=1000, max_consecutive_stressed=99)
    )
    d1 = breaker.record_iteration(
        state_hash(["mft"], "c0", "o", "remanded"),
        accepted_finding=False,
        tool_less=True,
        tokens=600,
    )
    assert d1.stopped is False
    d2 = breaker.record_iteration(
        state_hash(["mft"], "c1", "o", "remanded"),
        accepted_finding=False,
        tool_less=True,
        tokens=600,  # cumulative 1200 > 1000
    )
    assert d2.stopped is True
    assert d2.reason is StopReason.BUDGET_EXHAUSTED
    assert "token" in d2.detail.lower()


# -- multi-dimensional budgets ---------------------------------------------


def test_usd_budget_exhaustion():
    breaker = LoopBreaker(OrchestratorConfig(max_usd=0.50, max_consecutive_stressed=99))
    d = breaker.record_iteration(
        state_hash(["mft"], "c0", "o", "remanded"), accepted_finding=False, usd=0.75
    )
    assert d.stopped is True
    assert d.reason is StopReason.BUDGET_EXHAUSTED
    assert "usd" in d.detail.lower()


def test_tool_call_budget_exhaustion():
    breaker = LoopBreaker(
        OrchestratorConfig(max_tool_calls=5, max_consecutive_stressed=99)
    )
    d = breaker.record_iteration(
        state_hash(["mft"], "c0", "o", "remanded"),
        accepted_finding=False,
        tool_calls=6,
    )
    assert d.stopped is True
    assert d.reason is StopReason.BUDGET_EXHAUSTED
    assert "tool" in d.detail.lower()


# -- wall clock (injected) -------------------------------------------------


def test_wall_timeout_uses_injected_clock():
    clock = _FakeClock()
    breaker = LoopBreaker(
        OrchestratorConfig(max_wall_seconds=30.0, max_consecutive_stressed=99),
        time_source=clock,
    )
    breaker.start()
    d1 = breaker.record_iteration(
        state_hash(["mft"], "c0", "o", "remanded"), accepted_finding=False
    )
    assert d1.stopped is False
    clock.advance(31.0)
    d2 = breaker.record_iteration(
        state_hash(["mft"], "c1", "o", "remanded"), accepted_finding=False
    )
    assert d2.stopped is True
    assert d2.reason is StopReason.WALL_TIMEOUT


def test_check_polls_wall_clock_without_advancing_iteration():
    # A long-running tool between iterations can blow the deadline; check() lets
    # the caller poll time/budget mid-iteration without counting an iteration.
    clock = _FakeClock()
    breaker = LoopBreaker(OrchestratorConfig(max_wall_seconds=10.0), time_source=clock)
    breaker.start()
    clock.advance(11.0)
    d = breaker.check()
    assert d.stopped is True
    assert d.reason is StopReason.WALL_TIMEOUT
    assert breaker.iterations == 0  # check() did not advance the iteration count


def test_check_returns_running_when_under_limits():
    # Under the deadline and budget, check() is a no-op that leaves RUNNING.
    clock = _FakeClock()
    breaker = LoopBreaker(
        OrchestratorConfig(max_wall_seconds=10.0, max_tokens=100), time_source=clock
    )
    clock.advance(5.0)  # lazy start on first check; elapsed 0 here
    d = breaker.check()
    assert d.stopped is False
    assert d.reason is StopReason.RUNNING


def test_check_is_sticky_after_a_prior_stop():
    breaker = LoopBreaker(OrchestratorConfig(max_iterations=1))
    breaker.record_iteration(
        state_hash(["mft"], "c0", "o", "remanded"), accepted_finding=False
    )
    assert breaker.decision.stopped is True
    # A poll after a terminal decision returns that same decision unchanged.
    assert breaker.check() == breaker.decision


def test_check_catches_budget_between_iterations():
    breaker = LoopBreaker(OrchestratorConfig(max_tool_calls=2))
    breaker.record_iteration(
        state_hash(["mft"], "c0", "o", "remanded"),
        accepted_finding=False,
        tool_calls=3,  # cumulative 3 > 2, but assert via check() path
    )
    # (record_iteration already trips here; verify check() would too on a fresh run)
    fresh = LoopBreaker(OrchestratorConfig(max_tool_calls=2))
    fresh.tool_calls = 3  # simulate a long tool call that overran mid-iteration
    d = fresh.check()
    assert d.stopped is True
    assert d.reason is StopReason.BUDGET_EXHAUSTED


def test_non_alternating_window_does_not_trip_oscillation():
    # A window whose two most recent states are EQUAL is a recurrence case, not a
    # ping-pong; the tail-oscillation guard must not fire on it (line-350 guard).
    breaker = LoopBreaker(
        OrchestratorConfig(max_state_recurrences=99, oscillation_window=4)
    )
    a = state_hash(["mft"], "a", "o", "r")
    b = state_hash(["mft"], "b", "o", "r")
    c = state_hash(["mft"], "c", "o", "r")
    # Window [a, a, b, c]: the first two window entries are equal, so the tail is
    # not a period-2 alternation and the guard returns early (not oscillation).
    for h in (a, a, b, c):
        d = breaker.record_iteration(h, accepted_finding=False)
    assert d.stopped is False


# -- iteration backstop + precedence ---------------------------------------


def test_max_iterations_backstop():
    breaker = LoopBreaker(
        OrchestratorConfig(max_iterations=3, max_consecutive_stressed=99)
    )
    last = None
    for i in range(3):
        last = breaker.record_iteration(
            state_hash(["mft"], f"c{i}", "o", "remanded"), accepted_finding=False
        )
    assert last.stopped is True
    assert last.reason is StopReason.MAX_ITERATIONS


def test_oscillation_takes_precedence_over_max_iterations():
    # When both an identical-state loop and the iteration cap would fire on the
    # same iteration, the more informative OSCILLATION reason wins.
    breaker = LoopBreaker(OrchestratorConfig(max_iterations=3, max_state_recurrences=2))
    h = state_hash(["mft"], "c", "o", "remanded")
    breaker.record_iteration(h, accepted_finding=False)
    breaker.record_iteration(h, accepted_finding=False)
    d = breaker.record_iteration(
        h, accepted_finding=False
    )  # 3rd iter AND 3rd recurrence
    assert d.reason is StopReason.OSCILLATION


# -- idempotence + trace ---------------------------------------------------


def test_decision_is_sticky_after_stop():
    breaker = LoopBreaker(OrchestratorConfig(max_iterations=1))
    d1 = breaker.record_iteration(
        state_hash(["mft"], "c0", "o", "remanded"), accepted_finding=False
    )
    assert d1.stopped is True
    iters_at_stop = breaker.iterations
    # Further calls return the same terminal decision and do not advance counters.
    d2 = breaker.record_iteration(
        state_hash(["mft"], "c1", "o", "remanded"), accepted_finding=False
    )
    assert d2 == d1
    assert breaker.iterations == iters_at_stop


def test_trace_is_json_serializable_and_reports_stop():
    import json

    breaker = LoopBreaker(OrchestratorConfig(max_iterations=2))
    breaker.record_iteration(
        state_hash(["mft"], "c0", "o", "remanded"), accepted_finding=False, tokens=10
    )
    breaker.record_iteration(
        state_hash(["mft"], "c1", "o", "remanded"), accepted_finding=False, tokens=10
    )
    trace = breaker.trace()
    # Round-trips through JSON (this is the artifact dumped on trip).
    json.dumps(trace)
    assert trace["stop_reason"] == StopReason.MAX_ITERATIONS.value
    assert trace["iterations"] == 2
    assert trace["tokens_spent"] == 20


# -- config validation + immutability --------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_iterations": 0},
        {"max_consecutive_stressed": 0},
        {"max_state_recurrences": 0},
        {"oscillation_window": 1},
        {"oscillation_window": 3},  # < 4 cannot distinguish ping-pong from progress
        {"max_tokens": -1},
        {"max_usd": -0.01},
        {"max_wall_seconds": 0},
        {"max_tool_calls": -1},
        {"max_remands_per_finding": -1},
    ],
)
def test_config_rejects_invalid_values(kwargs):
    with pytest.raises(ValueError):
        OrchestratorConfig(**kwargs)


def test_config_is_frozen():
    cfg = OrchestratorConfig()
    with pytest.raises(Exception):
        cfg.max_iterations = 99  # frozen


def test_stop_decision_is_frozen():
    d = StopDecision(stopped=True, reason=StopReason.DONE)
    with pytest.raises(Exception):
        d.stopped = False  # frozen
