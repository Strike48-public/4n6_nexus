"""Oscillation-aware loop breaker for the self-correction orchestrator (SFE-jrwx).

Gallery idea #21. A plain N-consecutive-failure breaker only catches a loop that
*errors* repeatedly; it is blind to a loop that runs cleanly forever while making
no LOGICAL progress -- re-deriving the identical (evidence, claim, objection,
ruling) state, or ping-ponging a verdict A-B-A-B. It is also blind to a confused
agent that "decides" without calling a tool, and to a run that is quietly burning
its token / USD / wall-clock budget.

This module is the model-free core the orchestrator wraps around its verify/remand
loop:

  * ``StopReason`` -- a typed enum for every way a run can end, so the run summary
    records *why* it stopped rather than just *that* it stopped.
  * ``OrchestratorConfig`` -- an immutable, validated bundle of the caps: iteration
    backstop, consecutive-stress limit, wall-clock deadline, and multi-dimensional
    budgets (tokens, USD, tool calls, per-finding remands, state recurrences).
  * ``state_hash`` -- a stable sha256 over the *sorted* evidence keys plus the
    claim, objection, and ruling. Sorting the evidence keys makes the hash depend
    on the SET of evidence, not the order it was gathered.
  * ``LoopBreaker`` -- tracks the per-run state and returns a ``StopDecision`` each
    iteration. Trips on logical non-progress (recurring state, tail oscillation),
    exhausted budgets, a run of stressed/tool-less decisions, the wall-clock
    deadline, or the iteration backstop. The clock is INJECTABLE, so wall-timeout
    behavior is fully deterministic and CI-reproducible.

On any non-DONE stop the decision carries ``should_flag_contested=True`` so the
caller degrades still-contested findings to human review and dumps ``trace()``
while still sealing the report -- the loop stops, the investigation does not.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional


class StopReason(str, Enum):
    """Every terminal (and the non-terminal RUNNING) state of a self-correction run."""

    RUNNING = "running"  # not stopped
    DONE = "done"  # converged: all findings adjudicated, no open contradictions
    MAX_ITERATIONS = "max_iterations"  # iteration backstop hit
    WALL_TIMEOUT = "wall_timeout"  # wall-clock deadline exceeded
    MAX_STRESSED = "max_stressed"  # too many consecutive non-progress iterations
    OSCILLATION = "oscillation"  # logical non-progress: state recurred / ping-pong
    BUDGET_EXHAUSTED = "budget_exhausted"  # tokens / USD / tool-call budget spent


def state_hash(
    evidence_keys: list[str],
    claim: str,
    objection: str,
    ruling: str,
) -> str:
    """Hash one loop state into a stable sha256 hex digest.

    The digest binds the four things that define "where the loop is": the SET of
    evidence in play (sorted, so gather-order does not change the state), the
    analyst's claim, the adversary's objection, and the adjudicator's ruling. Two
    iterations that produce byte-identical values here are, by definition, the
    same state -- and a loop revisiting the same state is making no progress.
    """
    digest = hashlib.sha256()
    digest.update(b"v1")
    for key in sorted(evidence_keys):
        digest.update(b"\x1f")
        digest.update(key.encode("utf-8"))
    for part in (claim, objection, ruling):
        digest.update(b"\x1e")
        digest.update(part.encode("utf-8"))
    return digest.hexdigest()


@dataclass(frozen=True)
class OrchestratorConfig:
    """Immutable, validated caps governing a self-correction run.

    Every ``max_*`` budget that is ``None`` means "no limit on this dimension".
    The count-based caps (iterations, stress, recurrences, window) are always
    active and must be positive.
    """

    max_iterations: int = 10
    max_consecutive_stressed: int = 5
    max_state_recurrences: int = 3
    oscillation_window: int = 4
    # The per-finding remand cap is enforced by ``RulesAdjudicator`` (see
    # adversarial.py); it lives here so the run's caps have one config home and
    # the orchestrator hands the same value to the adjudicator at wire-up.
    #
    # Interaction with the stress/oscillation caps (deliberately NOT forbidden):
    # a deterministic remand escalates ``remanded -> flagged_human`` at
    # ``remand_count == max_remands_per_finding``. If ``max_consecutive_stressed``
    # or ``max_state_recurrences`` is smaller than the rounds that escalation
    # needs, the breaker legitimately stops the loop FIRST (on MAX_STRESSED /
    # OSCILLATION) and its ``should_flag_contested`` degrades the survivor to the
    # SAME terminal ``flagged_human``. The result is identical and correct; only
    # the recorded StopReason differs. This is intended - the breaker caps are an
    # independent bound the operator may deliberately set below the remand cap -
    # so it is documented, not validated away.
    max_remands_per_finding: int = 2
    max_wall_seconds: Optional[float] = None
    max_tokens: Optional[int] = None
    max_usd: Optional[float] = None
    max_tool_calls: Optional[int] = None

    def __post_init__(self) -> None:
        if self.max_iterations < 1:
            raise ValueError("max_iterations must be >= 1")
        if self.max_consecutive_stressed < 1:
            raise ValueError("max_consecutive_stressed must be >= 1")
        if self.max_state_recurrences < 1:
            raise ValueError("max_state_recurrences must be >= 1")
        if self.oscillation_window < 4:
            # A period-2 ping-pong (A-B-A-B) needs 4 samples to confirm: with a
            # smaller window, two ordinary distinct-state iterations of genuine
            # progress would false-positive as oscillation.
            raise ValueError("oscillation_window must be >= 4")
        if self.max_remands_per_finding < 0:
            raise ValueError("max_remands_per_finding must be >= 0")
        if self.max_wall_seconds is not None and self.max_wall_seconds <= 0:
            raise ValueError("max_wall_seconds must be > 0 when set")
        if self.max_tokens is not None and self.max_tokens < 0:
            raise ValueError("max_tokens must be >= 0 when set")
        if self.max_usd is not None and self.max_usd < 0:
            raise ValueError("max_usd must be >= 0 when set")
        if self.max_tool_calls is not None and self.max_tool_calls < 0:
            raise ValueError("max_tool_calls must be >= 0 when set")


@dataclass(frozen=True)
class StopDecision:
    """The breaker's verdict for one iteration (or poll).

    ``should_flag_contested`` tells the caller whether, on stopping, it must
    degrade still-contested findings to human review: true for every non-DONE
    stop, false for a clean convergence.
    """

    stopped: bool
    reason: StopReason
    detail: str = ""
    should_flag_contested: bool = False


class LoopBreaker:
    """Tracks a self-correction run and decides, each iteration, whether to stop.

    Usage::

        breaker = LoopBreaker(OrchestratorConfig(max_wall_seconds=120))
        breaker.start()
        while True:
            decision = breaker.record_iteration(
                state_hash(evidence_keys, claim, objection, ruling),
                accepted_finding=accepted,
                tokens=tokens_this_round,
            )
            if decision.stopped:
                if decision.should_flag_contested:
                    flag_contested_findings_for_human_review()
                    dump_trace(breaker.trace())
                break
    """

    def __init__(
        self,
        config: Optional[OrchestratorConfig] = None,
        time_source: Callable[[], float] = time.monotonic,
    ):
        self.config = config or OrchestratorConfig()
        self._now = time_source
        # Public run counters (read by callers and by ``trace``).
        self.iterations = 0
        self.consecutive_stressed = 0
        self.tokens_spent = 0
        self.usd_spent = 0.0
        self.tool_calls = 0
        # Internal state-progress tracking.
        self._state_counts: dict[str, int] = {}
        self._recent_hashes: list[str] = []
        self._start_time: Optional[float] = None
        self._decision = StopDecision(stopped=False, reason=StopReason.RUNNING)

    # -- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        """Mark the run's start for wall-clock accounting.

        Optional: the clock also starts lazily on the first ``record_iteration``
        or ``check`` if ``start`` was never called.
        """
        self._start_time = self._now()

    @property
    def decision(self) -> StopDecision:
        """The current (possibly terminal) decision."""
        return self._decision

    # -- the per-iteration gate ---------------------------------------------

    def record_iteration(
        self,
        state_digest: str,
        *,
        accepted_finding: bool,
        converged: bool = False,
        tool_less: bool = False,
        tokens: int = 0,
        usd: float = 0.0,
        tool_calls: int = 0,
    ) -> StopDecision:
        """Record one loop iteration and return whether the run should stop.

        Args:
            state_digest: ``state_hash`` of this iteration's state.
            accepted_finding: True when this iteration accepted a real finding --
                the only signal that resets the consecutive-stress counter.
            converged: True when the loop has logically finished (all findings
                adjudicated, no open contradictions) -> DONE.
            tool_less: True when the agent produced a decision WITHOUT calling any
                tool. Such a decision is never progress, so it is always a strike
                even if ``accepted_finding`` is set -- a confused, tool-less agent
                cannot self-certify its way past the breaker.
            tokens: model tokens spent this iteration (added to the budget).
            usd: USD spent this iteration.
            tool_calls: tool calls made this iteration.
        """
        if self._decision.stopped:
            return self._decision  # terminal decision is sticky; do not advance

        if self._start_time is None:
            self._start_time = self._now()

        self.iterations += 1
        self.tokens_spent += tokens
        self.usd_spent += usd
        self.tool_calls += tool_calls

        # Progress = an accepted finding produced by an actual tool call. Only
        # progress resets the stress counter; everything else is a strike.
        if accepted_finding and not tool_less:
            self.consecutive_stressed = 0
        else:
            self.consecutive_stressed += 1

        self._state_counts[state_digest] = self._state_counts.get(state_digest, 0) + 1
        self._recent_hashes.append(state_digest)

        # 1. Clean convergence beats every budget/limit.
        if converged:
            return self._stop(StopReason.DONE, "Converged: no open contradictions.")

        # 2. Hard real-time deadline and spent budgets.
        wall = self._wall_decision()
        if wall is not None:
            return wall
        budget = self._budget_decision()
        if budget is not None:
            return budget

        # 3. Logical non-progress (more informative than the raw iteration cap).
        recurrences = self._state_counts[state_digest]
        if recurrences > self.config.max_state_recurrences:
            return self._stop(
                StopReason.OSCILLATION,
                f"State recurred {recurrences} times "
                f"(> max_state_recurrences={self.config.max_state_recurrences}).",
            )
        if self._tail_oscillating():
            return self._stop(
                StopReason.OSCILLATION,
                "Verdict ping-pong: the tail alternates between states without "
                "converging.",
            )

        # 4. Too many consecutive non-progress / tool-less decisions.
        if self.consecutive_stressed >= self.config.max_consecutive_stressed:
            return self._stop(
                StopReason.MAX_STRESSED,
                f"{self.consecutive_stressed} consecutive stressed iterations "
                f"(>= max_consecutive_stressed={self.config.max_consecutive_stressed}).",
            )

        # 5. Iteration backstop (last resort).
        if self.iterations >= self.config.max_iterations:
            return self._stop(
                StopReason.MAX_ITERATIONS,
                f"Reached max_iterations={self.config.max_iterations}.",
            )

        return self._decision  # still RUNNING

    def check(self) -> StopDecision:
        """Poll the wall-clock and budgets WITHOUT counting an iteration.

        For use before/after a long-running tool call so a run that blows its
        deadline mid-iteration is caught promptly. Never trips iteration-based
        reasons (oscillation, stress, max-iterations); those advance only via
        ``record_iteration``.
        """
        if self._decision.stopped:
            return self._decision
        if self._start_time is None:
            self._start_time = self._now()
        wall = self._wall_decision()
        if wall is not None:
            return wall
        budget = self._budget_decision()
        if budget is not None:
            return budget
        return self._decision

    # -- terminal-condition helpers -----------------------------------------

    def _wall_decision(self) -> Optional[StopDecision]:
        limit = self.config.max_wall_seconds
        if limit is None or self._start_time is None:
            return None
        elapsed = self._now() - self._start_time
        if elapsed > limit:
            return self._stop(
                StopReason.WALL_TIMEOUT,
                f"Wall-clock {elapsed:.1f}s exceeded max_wall_seconds={limit}.",
            )
        return None

    def _budget_decision(self) -> Optional[StopDecision]:
        cfg = self.config
        if cfg.max_tokens is not None and self.tokens_spent > cfg.max_tokens:
            return self._stop(
                StopReason.BUDGET_EXHAUSTED,
                f"Token budget exhausted: {self.tokens_spent} > {cfg.max_tokens}.",
            )
        if cfg.max_usd is not None and self.usd_spent > cfg.max_usd:
            return self._stop(
                StopReason.BUDGET_EXHAUSTED,
                f"USD budget exhausted: {self.usd_spent:.4f} > {cfg.max_usd}.",
            )
        if cfg.max_tool_calls is not None and self.tool_calls > cfg.max_tool_calls:
            return self._stop(
                StopReason.BUDGET_EXHAUSTED,
                f"Tool-call budget exhausted: {self.tool_calls} > {cfg.max_tool_calls}.",
            )
        return None

    def _tail_oscillating(self) -> bool:
        """Detect a period-2 ping-pong (A-B-A-B...) over the recent-state window.

        This catches a bounded cycle that never lets any single state exceed the
        recurrence cap: A and B each recur only slowly, but the loop is plainly
        stuck alternating between them.
        """
        window_size = self.config.oscillation_window
        recent = self._recent_hashes
        if len(recent) < window_size:
            return False
        window = recent[-window_size:]
        # Alternating: the two most recent states differ, and every state equals
        # the one two steps before it across the whole window.
        if window[0] == window[1]:
            return False
        return all(window[i] == window[i - 2] for i in range(2, window_size))

    def _stop(self, reason: StopReason, detail: str) -> StopDecision:
        self._decision = StopDecision(
            stopped=True,
            reason=reason,
            detail=detail,
            should_flag_contested=reason is not StopReason.DONE,
        )
        return self._decision

    # -- diagnostics ---------------------------------------------------------

    def trace(self) -> dict:
        """A JSON-serializable snapshot dumped alongside a tripped run.

        Gives an examiner the full picture of why the loop stopped: the typed
        reason, every counter, and the state-recurrence profile.
        """
        max_recurrence = max(self._state_counts.values(), default=0)
        return {
            "stop_reason": self._decision.reason.value,
            "stopped": self._decision.stopped,
            "detail": self._decision.detail,
            "should_flag_contested": self._decision.should_flag_contested,
            "iterations": self.iterations,
            "consecutive_stressed": self.consecutive_stressed,
            "tokens_spent": self.tokens_spent,
            "usd_spent": round(self.usd_spent, 6),
            "tool_calls": self.tool_calls,
            "distinct_states": len(self._state_counts),
            "max_state_recurrence": max_recurrence,
        }
