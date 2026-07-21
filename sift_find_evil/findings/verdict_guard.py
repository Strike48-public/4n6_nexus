"""Verdict rank clamp - a structural severity ceiling (gallery idea #10).

The single cheapest hallucination firewall in the mined field: the analyst LLM
may narrate freely, but a finding's *severity* is structurally re-derived from
the deterministic detector output. Any analyst prose claiming a severity higher
than the evidence supports is clamped down at a single chokepoint, and a
single-source finding cannot reach the top tier until an independent artifact
corroborates it (mandatory corroboration pivot).

The model narrates; deterministic code decides. No LLM is involved here, so the
guard is fully CI-testable against synthetic findings.

Independently built by: logflip-sift-agent, Glass Box, TLVB, MR. Robot
Adversarial, APEX Forensics.
"""

from __future__ import annotations

from dataclasses import replace

from .finding import Finding

# Ordered severity ladder. Higher rank = more severe. A claimed severity may
# never exceed the engine-derived ceiling.
SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# The tier a single-source (uncorroborated) finding may not exceed. A lone
# artifact is suggestive, not conclusive; the top tier requires >=2 distinct
# artifact sources.
_SINGLE_SOURCE_CEILING = "high"


class VerdictClampError(ValueError):
    """Raised when a severity label is not a recognized rank."""


def _rank(severity: str) -> int:
    try:
        return SEVERITY_RANK[severity]
    except KeyError as exc:
        raise VerdictClampError(
            f"unknown severity {severity!r}; expected one of {sorted(SEVERITY_RANK)}"
        ) from exc


def clamp_severity(claimed: str, engine_ceiling: str) -> str:
    """Return the claimed severity, clamped so it never exceeds the ceiling.

    Args:
        claimed: The severity the analyst/LLM asserts.
        engine_ceiling: The highest severity the deterministic detector output
            supports.

    Returns:
        ``claimed`` if it is at or below the ceiling, otherwise ``engine_ceiling``.
        We only ever clamp DOWN - a conservative claim is left untouched.
    """
    if _rank(claimed) > _rank(engine_ceiling):
        return engine_ceiling
    return claimed


def _distinct_sources(finding: Finding) -> int:
    return len({s for s in finding.artifact_sources if s})


def guard_finding(finding: Finding, engine_ceiling: str) -> Finding:
    """Return a new Finding with a structurally defensible severity.

    Applies two clamps and records each in the reasoning chain:
    1. Severity may not exceed ``engine_ceiling`` (what the detector supports).
    2. A single-source finding may not exceed ``_SINGLE_SOURCE_CEILING`` until a
       second distinct artifact corroborates it.

    The input finding is never mutated; a copy is returned.
    """
    new_severity = clamp_severity(finding.severity, engine_ceiling)
    notes: list[str] = []

    if new_severity != finding.severity:
        notes.append(
            f"Verdict clamp: severity {finding.severity} -> {new_severity} "
            f"(detector output supports at most {engine_ceiling})."
        )

    if _distinct_sources(finding) < 2 and _rank(new_severity) > _rank(
        _SINGLE_SOURCE_CEILING
    ):
        capped = _SINGLE_SOURCE_CEILING
        notes.append(
            f"Verdict clamp: single-source finding capped {new_severity} -> "
            f"{capped} pending independent corroboration (corroboration pivot)."
        )
        new_severity = capped

    if new_severity == finding.severity:
        return finding

    return replace(
        finding,
        severity=new_severity,
        reasoning_chain=[*finding.reasoning_chain, *notes],
    )
