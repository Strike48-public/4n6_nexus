"""Cognitive-bias / process-integrity meta-verifier.

Audits an investigative process for confirmation bias and tunnel vision,
grounded in Richards Heuer's Analysis of Competing Hypotheses (ACH) and the
Sunde-Dror work on cognitive and human factors in forensic decision-making.

The core insight from ACH is that a rigorous analyst does not merely accumulate
evidence that *confirms* a leading hypothesis; they actively seek evidence that
would *disprove* competing hypotheses, and they keep multiple hypotheses alive
until the data forces a conclusion. A process that only ever confirms one
hypothesis is exhibiting the classic confirmation-bias failure mode.

This module inspects a sequence of tool calls (each tagged with the hypothesis
it tests and whether it was a disconfirming check) and reports on the
methodological health of the investigation, emitting concrete correctives when
the process shows signs of bias.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Minimum number of actions before an audit is statistically meaningful. Below
# this we cannot distinguish bias from an investigation that has simply not
# gathered enough evidence yet.
MIN_ACTIONS: int = 5

# Minimum fraction of actions that should be disconfirming checks. ACH treats
# disconfirmation as the primary engine of analysis, so a healthy process keeps
# a meaningful share of its effort aimed at falsification.
MIN_DISCONFIRMATION: float = 0.20

# Minimum number of distinct hypotheses that should be tested. ACH requires a
# genuine field of competing hypotheses, not a single favored explanation.
MIN_DIVERSITY: int = 2

STATUS_INSUFFICIENT: str = "insufficient_actions"
STATUS_HEALTHY: str = "healthy"
STATUS_BIASED: str = "biased"


@dataclass(frozen=True)
class MethodologyReport:
    """Result of auditing an investigative process for cognitive bias.

    Attributes:
        status: One of "insufficient_actions", "healthy", or "biased".
        confirmation_ratio: Fraction of actions that confirm rather than
            disconfirm their hypothesis (0.0 to 1.0).
        diversity: Count of distinct hypothesis ids tested.
        disconfirmation_ratio: Fraction of actions that were disconfirming
            checks (0.0 to 1.0).
        correctives: Concrete, ACH-grounded advice for repairing the process.
    """

    status: str
    confirmation_ratio: float
    diversity: int
    disconfirmation_ratio: float
    correctives: list[str] = field(default_factory=list)


def audit_process(tool_calls: list[dict]) -> MethodologyReport:
    """Audit a sequence of investigative tool calls for cognitive bias.

    Args:
        tool_calls: Ordered list of action records. Each record is a dict with
            keys "tool" (str), "hypothesis_id" (str), and "disconfirming"
            (bool). The input is never mutated.

    Returns:
        A MethodologyReport describing the methodological health of the process
        and any correctives. If fewer than MIN_ACTIONS actions were taken, the
        status is "insufficient_actions" and metrics are reported as zero.
    """
    total = len(tool_calls)

    if total < MIN_ACTIONS:
        return MethodologyReport(
            status=STATUS_INSUFFICIENT,
            confirmation_ratio=0.0,
            diversity=0,
            disconfirmation_ratio=0.0,
            correctives=[],
        )

    disconfirming = sum(1 for call in tool_calls if call.get("disconfirming"))
    confirming = total - disconfirming
    distinct_hypotheses = {
        call.get("hypothesis_id") for call in tool_calls if call.get("hypothesis_id")
    }

    confirmation_ratio = confirming / total
    disconfirmation_ratio = disconfirming / total
    diversity = len(distinct_hypotheses)

    correctives = _build_correctives(
        diversity=diversity, disconfirmation_ratio=disconfirmation_ratio
    )
    status = STATUS_BIASED if correctives else STATUS_HEALTHY

    return MethodologyReport(
        status=status,
        confirmation_ratio=confirmation_ratio,
        diversity=diversity,
        disconfirmation_ratio=disconfirmation_ratio,
        correctives=correctives,
    )


def _build_correctives(*, diversity: int, disconfirmation_ratio: float) -> list[str]:
    """Assemble ACH-grounded correctives for the observed process metrics.

    Args:
        diversity: Count of distinct hypotheses tested.
        disconfirmation_ratio: Fraction of actions that were disconfirming.

    Returns:
        List of concrete advice strings; empty when the process is healthy.
    """
    correctives: list[str] = []

    if disconfirmation_ratio < MIN_DISCONFIRMATION:
        correctives.append(
            "Run a tool that could DISPROVE the leading hypothesis; per Heuer ACH, "
            "seek evidence that falsifies rather than merely confirms."
        )

    if diversity < MIN_DIVERSITY:
        correctives.append(
            "Enumerate and test at least one competing hypothesis; a single "
            "hypothesis under investigation is a hallmark of confirmation bias "
            "(Heuer ACH / Sunde-Dror)."
        )

    return correctives
