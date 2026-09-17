"""Kill-chain coherence: protect a member of a coherent multi-phase chain.

Gallery idea from Mulder's counter-analyst (SFE-fibx.5). The classic failure
mode of naive adversarial review is dismissing five correlated indicators ONE AT
A TIME -- each looks weak alone, so each is refuted in isolation, and a genuine
attack is talked away finding-by-finding. Mulder's rule defends against it: map
every finding to its kill-chain phase FIRST, and require STRONGER counter-evidence
to dismiss a finding that is a member of a coherent 3+-phase chain, because the
convergent chain corroborates it.

This module is the pure, model-free substrate for that rule:

  * ``TACTIC_PHASE_ORDER`` -- the missing piece: a canonical kill-chain ordinal
    for every MITRE tactic the technique catalog can emit. The technique->tactic
    map itself is NOT duplicated here; it is read from the single source of truth,
    ``reporting.mitre_guardrail.CATALOG``, so a technique added there flows through
    without a second edit (and the drift guard test fails loudly if a new tactic
    lacks an ordinal).
  * ``finding_tactics`` -- the distinct kill-chain tactics one finding occupies,
    via its ``mitre_techniques()`` (or a ``to_dict()``-shaped dict).
  * ``assess_chain`` -- classifies a set of findings as a coherent chain when the
    tactics they collectively occupy span ``MIN_CHAIN_PHASES`` (default 3)
    distinct kill-chain phases.
  * ``is_protected`` -- whether one finding is a member of a coherent chain (and
    therefore deserves the "harder to dismiss" treatment the gate applies).

Depends only on the Python standard library plus the technique catalog. It never
mutates a finding and produces no verdict -- it only reports chain membership. The
verdict adjustment that consumes it lives in the blocking gate (PR-D), mirroring
how ``seats.py``/``loop_control.py`` are pure primitives the orchestrator wraps.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..reporting.mitre_guardrail import CATALOG, _finding_techniques

# Minimum distinct kill-chain phases a set of findings must span to count as a
# coherent chain. Three phases (Mulder's threshold): a single indicator is a
# point, two can be coincidence, but three phases in sequence is an attack
# narrative that no longer dismisses finding-by-finding.
MIN_CHAIN_PHASES = 3

# Canonical kill-chain ordinal for every MITRE ATT&CK tactic. The ordinal orders
# phases into the attack lifecycle (Reconnaissance early -> Impact late); it is
# the piece the technique catalog lacks (CATALOG carries the tactic NAME per
# technique but no phase order). Values need only be monotonic; gaps are fine.
# Every tactic string that ``reporting.mitre_guardrail.CATALOG`` can emit MUST
# appear here -- the drift-guard test enforces it, so the ordering stays in
# lockstep with the single-source technique->tactic map.
TACTIC_PHASE_ORDER: dict[str, int] = {
    "Reconnaissance": 0,
    "Resource Development": 1,
    "Initial Access": 2,
    "Execution": 3,
    "Persistence": 4,
    "Privilege Escalation": 5,
    "Defense Evasion": 6,
    "Credential Access": 7,
    "Discovery": 8,
    "Lateral Movement": 9,
    "Collection": 10,
    "Command and Control": 11,
    "Exfiltration": 12,
    "Impact": 13,
}


@dataclass(frozen=True)
class ChainAssessment:
    """The kill-chain classification of a set of findings.

    Attributes:
        phases: The distinct kill-chain tactics the findings collectively
            occupy, in canonical kill-chain order.
        phase_count: ``len(phases)``.
        is_coherent: True when ``phase_count >= MIN_CHAIN_PHASES`` -- the set is
            a coherent multi-phase chain whose members are corroborated by their
            convergence and therefore harder to dismiss individually.
    """

    phases: tuple[str, ...]
    phase_count: int
    is_coherent: bool

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the assessment."""
        return {
            "phases": list(self.phases),
            "phase_count": self.phase_count,
            "is_coherent": self.is_coherent,
        }


def _techniques(finding: Any) -> list[str]:
    """Extract technique ids from a Finding object or a to_dict()-shaped dict.

    Accepts both the ``Finding`` object (via its ``mitre_techniques()`` accessor)
    and a plain dict, so the same primitive serves the hardening path (Finding
    objects) and the report path (finding dicts). BOTH shapes must resolve
    techniques identically: the object accessor honors the first-class
    ``techniques`` field then the legacy ``evidence`` keys, so the dict path
    delegates to the SINGLE-SOURCE dict extractor (:func:`mitre_guardrail._finding_techniques`,
    the same one ``confirmed_matrix`` uses) rather than reading ``techniques``
    alone -- otherwise a legacy finding carrying techniques only under
    ``evidence['mitre_attack']`` would silently lose its kill-chain phase when
    passed as a dict but keep it when passed as an object.
    """
    accessor = getattr(finding, "mitre_techniques", None)
    if callable(accessor):
        return list(accessor())
    if isinstance(finding, dict):
        return _finding_techniques(finding)
    return []


def finding_tactics(finding: Any) -> frozenset[str]:
    """The distinct kill-chain tactics one finding occupies.

    Each technique is resolved to its tactic via the single-source technique
    catalog; a technique whose tactic is not a known kill-chain phase (an
    uncatalogued id resolves to "unknown") contributes nothing, so a finding can
    never inject a phantom phase into a chain.

    Args:
        finding: A ``Finding`` object or a to_dict()-shaped finding dict.

    Returns:
        The frozenset of kill-chain tactic names the finding occupies.
    """
    tactics: set[str] = set()
    for technique_id in _techniques(finding):
        meta = CATALOG.get(str(technique_id))
        if meta is None:
            continue
        tactic = meta["tactic"]
        if tactic in TACTIC_PHASE_ORDER:
            tactics.add(tactic)
    return frozenset(tactics)


def assess_chain(findings: list[Any]) -> ChainAssessment:
    """Classify a set of findings as a coherent kill chain or not.

    CALLER CONTRACT (load-bearing): this treats the findings it is GIVEN as one
    candidate chain and only asks whether they span enough phases. It does NOT
    check that the findings are about the same subject/entity/host or fall in one
    time window -- that scoping is the caller's job. Passing a flat, global
    finding set would call three unrelated findings on three unrelated hosts a
    "coherent chain" and over-protect them. The consumer (the PR-D blocking gate)
    MUST therefore group findings by subject (``findings.dedup.canonical_entity``
    / ``hypothesis_ledger.subject_label``) and call this per group, so coherence
    means "one subject exhibits a multi-phase chain", not "the case as a whole
    happens to touch many phases". Kept schema-agnostic here on purpose: coupling
    the primitive to the Finding schema would duplicate the entity-resolution
    logic that already lives in the dedup layer.

    Args:
        findings: The findings of ONE subject group to consider as a candidate
            chain (``Finding`` objects or to_dict()-shaped dicts).

    Returns:
        A ChainAssessment naming the distinct kill-chain phases the findings
        span (in canonical kill-chain order) and whether that span is coherent
        (>= ``MIN_CHAIN_PHASES`` distinct phases). The input is never mutated.
    """
    occupied: set[str] = set()
    for finding in findings:
        occupied |= finding_tactics(finding)
    ordered = tuple(sorted(occupied, key=lambda t: TACTIC_PHASE_ORDER[t]))
    return ChainAssessment(
        phases=ordered,
        phase_count=len(ordered),
        is_coherent=len(ordered) >= MIN_CHAIN_PHASES,
    )


def is_protected(finding: Any, assessment: ChainAssessment) -> bool:
    """Return True if ``finding`` is a member of a coherent kill chain.

    A protected finding is one the gate must require STRONGER counter-evidence to
    dismiss: the chain is coherent AND this finding actually occupies one of its
    phases. A finding carrying no kill-chain tactic is never protected -- it
    contributes nothing to the chain, so the chain's coherence does not vouch
    for it.

    Args:
        finding: The finding to test for chain membership.
        assessment: The ``assess_chain`` result for the finding's chain.

    Returns:
        True when the chain is coherent and the finding occupies a chain phase.
    """
    if not assessment.is_coherent:
        return False
    return bool(finding_tactics(finding))
