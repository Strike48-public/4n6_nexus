"""Mechanically-verified proven negatives (SFE-rylr, gallery idea #17).

A detector that runs clean usually says nothing -- and silence is indistinguishable
from a detector that never ran. A *proven negative* is the opposite: a first-class
finding asserting "tool X ran and found zero Y" that is INDEPENDENTLY re-verified
by re-reading the tool's captured output, so it is grounded and replay-able rather
than a bare claim.

Two verification modes (a finding may assert either or both -- both must hold):

  * pattern-mode -- none of the indicator tokens physically appear in the output.
    Matching is case-insensitive with a TRAILING word-boundary: a ".crypt"
    negative is not refuted by ".crypt14" (a benign WhatsApp DB suffix), but IS
    refuted by "report.docx.crypt". Trailing-only (not both-side) is deliberate:
    a suffix-embedded indicator like "mimikatz" inside "xmimikatz" must still
    refute -- refuting (withholding the clean claim) is always the safe direction.
  * metric-mode -- a parsed count is exactly 0 (e.g. malfind returned 0 rows).

Three guards keep a negative honest, all mapping to ``UNPROVEN`` (not proven):

  * empty / whitespace-only output proves nothing (the tool may have failed);
  * a negative needs a real cited ``tool_call_id`` -- it cannot be proven without
    a run that actually happened;
  * a finding that asserts nothing to check cannot be verified.

The verifier is pure and deterministic: same inputs always yield the same report,
and it never mutates its inputs. Mirrors ``findings/entailment.py`` (which
re-derives POSITIVE asserted values) for the negative case.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Optional, Sequence

from .categories import FindingCategory
from .finding import Finding

if TYPE_CHECKING:
    pass

# Continuation class for the trailing word boundary. An indicator token only
# "appears" when it is not immediately followed by one of these characters, so a
# longer token of the same family (".crypt14") does not refute a shorter negative
# (".crypt"). No leading boundary: a suffix-embedded indicator must still refute.
_TRAILING_CONTINUATION = r"A-Za-z0-9"


class AbsenceStatus(str, Enum):
    """Outcome of mechanically re-verifying an asserted negative."""

    PROVEN = "proven"  # the tool ran and the indicator is genuinely absent
    REFUTED = "refuted"  # an indicator IS present / the metric is non-zero
    UNPROVEN = "unproven"  # cannot verify: empty output, no run, or nothing asserted


@dataclass(frozen=True)
class AbsenceReport:
    """The verifier's ruling on one asserted negative.

    Attributes:
        status: PROVEN / REFUTED / UNPROVEN.
        reason: Human-readable explanation (audit + report line).
        refuting_tokens: Every indicator token found present (pattern-mode), in
            the order the patterns were given. Empty unless REFUTED by a pattern.
    """

    status: AbsenceStatus
    reason: str
    refuting_tokens: tuple[str, ...] = field(default_factory=tuple)


def _token_present(indicator: str, observed_text: str) -> bool:
    """True if ``indicator`` appears with a trailing word boundary (case-insensitive)."""
    if not indicator:
        return False
    pattern = rf"{re.escape(indicator)}(?![{_TRAILING_CONTINUATION}])"
    return re.search(pattern, observed_text, re.IGNORECASE) is not None


def verify_absence(
    tool_call_id: str,
    observed_text: str,
    pattern: Optional[Sequence[str]] = None,
    metric: Optional[int] = None,
) -> AbsenceReport:
    """Mechanically verify an asserted negative against captured tool output.

    Args:
        tool_call_id: The cited tool invocation that produced ``observed_text``.
            A negative cannot be proven without a real run, so an empty id is
            always UNPROVEN.
        observed_text: The tool's captured output, re-read here.
        pattern: Indicator tokens whose ABSENCE is asserted. Any present token
            (trailing-boundary, case-insensitive) refutes the negative.
        metric: A parsed count asserted to be 0. A non-zero value refutes.

    Returns:
        An AbsenceReport. Both asserted modes must hold to be PROVEN.
    """
    if not tool_call_id:
        return AbsenceReport(
            AbsenceStatus.UNPROVEN,
            "No cited tool_call_id: a negative cannot be proven without a run.",
        )

    if not observed_text or not observed_text.strip():
        return AbsenceReport(
            AbsenceStatus.UNPROVEN,
            "Captured output is empty; an empty result proves nothing.",
        )

    has_pattern = bool(pattern)
    has_metric = metric is not None
    if not has_pattern and not has_metric:
        return AbsenceReport(
            AbsenceStatus.UNPROVEN,
            "Nothing asserted to verify (no pattern and no metric).",
        )

    # metric-mode: a non-zero count refutes the negative outright.
    if has_metric and metric != 0:
        return AbsenceReport(
            AbsenceStatus.REFUTED,
            f"Asserted metric is {metric} (!= 0); the negative is refuted.",
        )

    # pattern-mode: any indicator physically present refutes the negative.
    refuting = tuple(
        tok for tok in (pattern or []) if _token_present(tok, observed_text)
    )
    if refuting:
        return AbsenceReport(
            AbsenceStatus.REFUTED,
            "Indicator token(s) present in output: " + ", ".join(refuting),
            refuting_tokens=refuting,
        )

    checked = []
    if has_pattern:
        checked.append(f"{len(pattern)} indicator pattern(s) absent")
    if has_metric:
        checked.append("metric == 0")
    return AbsenceReport(
        AbsenceStatus.PROVEN,
        "Re-read cited output: " + " and ".join(checked) + ".",
    )


def check_absence(finding: "Finding", observed_text: str) -> AbsenceReport:
    """Verify a Finding that asserts a negative against its cited tool output.

    Reads the finding's proven-negative fields (``asserts_absence``,
    ``absence_pattern``, ``absence_metric``) and the cited ``tool_call_id`` from
    ``finding.evidence``. A finding that does not assert absence is UNPROVEN --
    there is no negative to prove.

    Args:
        finding: The finding to verify. Not mutated.
        observed_text: The cited tool's captured output.

    Returns:
        An AbsenceReport for the finding's asserted negative.
    """
    if not getattr(finding, "asserts_absence", False):
        return AbsenceReport(
            AbsenceStatus.UNPROVEN,
            "Finding is not an absence assertion.",
        )
    return verify_absence(
        tool_call_id=str(finding.evidence.get("tool_call_id", "")),
        observed_text=observed_text,
        pattern=finding.absence_pattern or None,
        metric=finding.absence_metric,
    )


def make_absence_finding(
    title: str,
    description: str,
    category: FindingCategory,
    tool_call_id: str,
    pattern: Optional[Sequence[str]] = None,
    metric: Optional[int] = None,
    artifact_sources: Optional[Sequence[str]] = None,
) -> Finding:
    """Build a proven-negative Finding ready for ``check_absence`` re-verification.

    The finding is tagged ``finding_type="negative"`` and ``severity="info"`` (a
    clean result is not an attacker behavior), carries the cited ``tool_call_id``
    in evidence, and records the asserted pattern/metric so a verifier -- or a
    judge, offline -- can independently re-read the output and confirm it.

    Args:
        title: Short negative claim, e.g. "No ransomware extensions on disk".
        description: What ran and what it looked for.
        category: The domain the clean check covers (e.g. PROCESS_INJECTION).
        tool_call_id: The audited tool invocation whose output backs the claim.
        pattern: Indicator tokens asserted absent (pattern-mode).
        metric: A count asserted to be 0 (metric-mode).
        artifact_sources: Sources the check covered (e.g. ["memory"]).

    Returns:
        A Finding with the proven-negative fields populated.
    """
    return Finding(
        title=title,
        description=description,
        finding_type="negative",
        severity="info",
        category=category,
        evidence={"tool_call_id": tool_call_id},
        confidence=1.0,
        confidence_label="Very High",
        artifact_sources=list(artifact_sources or []),
        asserts_absence=True,
        absence_pattern=list(pattern or []),
        absence_metric=metric,
    )
