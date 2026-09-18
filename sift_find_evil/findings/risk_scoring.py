"""Weak-signal additive risk scoring per subject (SFE-kh4h).

The engine scores confidence PER finding, but a real incident is often a PILE of
individually-weak signals on ONE subject: an off-hours login alone is noise;
off-hours login + mass-download + external-comms on the same host is an incident.
This module groups findings by their canonical entity (the same subject key the
cross-source correlation join uses) and accumulates gated, weighted, and
trust-discounted contributions into a banded subject-level risk score.

It is a PURE, deterministic, read-only OVERLAY over already-emitted findings, in
the same family as :mod:`sift_find_evil.findings.dedup` and the correlation
overlays: nothing here runs on the detection scoring path (findings still score
off ``evidence['executable']`` in the harness), so F1 is provably unaffected.

The score for a subject is::

    score = min(1.0, sum over contributing findings of
                 confidence * weight[category] * (1 - spoofability[category]) * trust)

where ``trust`` rises with the number of DISTINCT artifact sources backing the
subject (a corroborated subject is trusted more than a lone signal). The top
band (:attr:`RiskBand.CRITICAL`) is GATED: it additionally requires >=2 distinct
artifact-type corroborators, so a single easily-spoofed signal -- however
confident -- can never escalate a subject to CRITICAL on its own. That gate is
the whole point: it accumulates weak evidence without letting one loud, spoofable
artifact manufacture a top-tier verdict.

Weights/spoofability are per-CATEGORY (not per-detector) so the mechanism is
stable as detectors are added; a new detector inherits its category's profile.
Ported from the gallery's insider-threat scorers (Paladin, VIGIA, SIFT-AEGIS) but
mapped to host forensics: the compounding patterns are DFIR ones (credential
theft + anti-forensics + C2 on one host), not the originals' HR signals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .categories import FindingCategory
from .dedup import canonical_entity

# Per-category weight: how much a confirmed finding of this category contributes
# to subject risk. High-severity attacker objectives (credential theft, C2,
# ransomware-adjacent anti-forensics) weigh more than enumeration/execution
# primitives that are common in benign activity too. Unknown categories fall back
# to _DEFAULT_WEIGHT so a new category still contributes without a code change.
_CATEGORY_WEIGHT: dict[FindingCategory, float] = {
    FindingCategory.CREDENTIAL_THEFT: 0.9,
    FindingCategory.CREDENTIAL_ACCESS: 0.9,
    FindingCategory.COMMAND_AND_CONTROL: 0.85,
    FindingCategory.DATA_EXFILTRATION: 0.85,
    FindingCategory.PROCESS_INJECTION: 0.8,
    FindingCategory.ANTI_FORENSICS: 0.8,
    FindingCategory.TIMELINE_TAMPERING: 0.75,
    FindingCategory.LATERAL_MOVEMENT: 0.75,
    FindingCategory.MALWARE_CLASSIFICATION: 0.7,
    FindingCategory.PERSISTENCE: 0.7,
    FindingCategory.EXECUTION: 0.5,
    FindingCategory.RECONNAISSANCE: 0.4,
    # ANALYSIS_GAP / UNKNOWN are not attacker behavior -> zero risk weight.
    FindingCategory.ANALYSIS_GAP: 0.0,
    FindingCategory.UNKNOWN: 0.0,
}
_DEFAULT_WEIGHT = 0.5

# Per-category spoofability: how easily this signal can be forged/planted, so a
# spoofable signal contributes proportionally LESS (the (1 - spoofability)
# discount). Timestamps are trivially stompable; a YARA content match or a memory
# injection artifact is hard to fake. 0 = not spoofable, 1 = fully spoofable.
_CATEGORY_SPOOFABILITY: dict[FindingCategory, float] = {
    FindingCategory.TIMELINE_TAMPERING: 0.6,  # timestamps are the easiest to forge
    FindingCategory.ANTI_FORENSICS: 0.3,
    FindingCategory.PERSISTENCE: 0.3,  # registry/task entries are writable
    FindingCategory.RECONNAISSANCE: 0.4,
    FindingCategory.EXECUTION: 0.2,
    FindingCategory.LATERAL_MOVEMENT: 0.2,
    FindingCategory.COMMAND_AND_CONTROL: 0.15,
    FindingCategory.DATA_EXFILTRATION: 0.15,
    FindingCategory.CREDENTIAL_THEFT: 0.1,
    FindingCategory.CREDENTIAL_ACCESS: 0.1,
    FindingCategory.PROCESS_INJECTION: 0.1,
    FindingCategory.MALWARE_CLASSIFICATION: 0.1,  # content signature, hard to fake
    # Not attacker behavior (weight 0.0 above, so spoofability is inert); listed
    # explicitly to keep this table symmetric with _CATEGORY_WEIGHT, so a future
    # weight bump can't silently inherit _DEFAULT_SPOOFABILITY.
    FindingCategory.ANALYSIS_GAP: 0.0,
    FindingCategory.UNKNOWN: 0.0,
}
_DEFAULT_SPOOFABILITY = 0.2

# Band floors on the clamped [0,1] score. Each constant names the band a score AT
# OR ABOVE it lands in (four bands over four ranges):
#   [0, MEDIUM_FLOOR)          -> LOW
#   [MEDIUM_FLOOR, HIGH_FLOOR) -> MEDIUM
#   [HIGH_FLOOR, TOP_FLOOR)    -> HIGH
#   [TOP_FLOOR, 1]             -> CRITICAL if corroborated (gate below), else HIGH
# Naming the floor for the band it GATES (not the band below) keeps the ladder
# in _band self-evident.
_TOP_FLOOR = 0.7  # CRITICAL-or-HIGH floor (top tier needs the gate too)
_HIGH_FLOOR = 0.4
_MEDIUM_FLOOR = 0.15

# The CRITICAL gate: the top band requires the score to clear _TOP_FLOOR AND the
# subject to be backed by at least this many DISTINCT artifact sources, so one
# spoofable signal cannot reach CRITICAL alone.
_CRITICAL_MIN_DISTINCT_SOURCES = 2

# Scores are reported to this many decimals; a subject whose score rounds to zero
# at this precision carries no reportable signal and is dropped. Tying the drop
# threshold to the display precision keeps "dropped" and "shows as 0.0000" from
# diverging (a score like 5e-5 would otherwise survive the drop yet display 0).
_SCORE_DECIMALS = 4
_SCORE_EPSILON = 0.5 * 10**-_SCORE_DECIMALS  # rounds-to-zero boundary at 4dp


class RiskBand(StrEnum):
    """Qualitative subject-risk band (lowercase for clean JSON round-trip)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class SubjectRisk:
    """Accumulated risk for one subject (canonical entity).

    Attributes:
        subject: The canonical entity value (process/ip/hash/relationship/title).
        subject_kind: The entity kind (``"process"``/``"ip"``/.../``"title"``).
        score: Clamped [0,1] additive risk.
        band: The qualitative :class:`RiskBand` (CRITICAL is gated, see module doc).
        distinct_sources: Count of distinct artifact-source types backing it.
        contributors: Per-finding contribution breakdown (title, category,
            adjusted contribution) for report transparency.
    """

    subject: str
    subject_kind: str
    score: float
    band: RiskBand
    distinct_sources: int
    contributors: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "subject_kind": self.subject_kind,
            "score": round(self.score, _SCORE_DECIMALS),
            "band": self.band.value,
            "distinct_sources": self.distinct_sources,
            "contributors": self.contributors,
        }


def _weight(category: Any) -> float:
    try:
        return _CATEGORY_WEIGHT.get(FindingCategory(category), _DEFAULT_WEIGHT)
    except ValueError:
        return _DEFAULT_WEIGHT


def _spoofability(category: Any) -> float:
    try:
        return _CATEGORY_SPOOFABILITY.get(
            FindingCategory(category), _DEFAULT_SPOOFABILITY
        )
    except ValueError:
        return _DEFAULT_SPOOFABILITY


def _trust(distinct_sources: int) -> float:
    """Trust multiplier that rises with distinct-source corroboration.

    One source is taken at 0.75; each additional distinct artifact source adds
    0.125, capped at 1.0 (reached at 3 sources). So a corroborated subject's
    contributions are weighted more heavily than a lone-source subject's, without
    ever exceeding the raw weighted confidence.
    """
    if distinct_sources <= 0:
        return 0.75
    return min(1.0, 0.75 + 0.125 * (distinct_sources - 1))


def _subject_of(finding: Any) -> tuple[str, str]:
    """Return ``(value, kind)`` for a finding's subject, falling back to title.

    A finding with no structured canonical entity is attributed to its title
    (kind ``"title"``) so the overlay never silently drops a scored finding.
    """
    entity = canonical_entity(finding)
    if entity is not None:
        return entity.value, entity.kind
    title = _get(finding, "title", None) or ""
    return title, "title"


def _get(finding: Any, key: str, default: Any) -> Any:
    """Read ``key`` from a Finding dataclass OR its ``to_dict`` mapping.

    :func:`canonical_entity` already accepts both shapes, so this module must too
    -- otherwise a dict-shaped finding (a serialized/round-tripped Finding) would
    have its subject read correctly but its category/confidence/sources silently
    default (scoring 0.0 -> dropped), an inconsistency worse than either shape
    failing outright. Mirrors ``dedup._get_field``: mapping key first, else attr.
    """
    if isinstance(finding, dict):
        return finding.get(key, default)
    return getattr(finding, key, default)


def score_subject_risk(findings: list[Any]) -> list[SubjectRisk]:
    """Accumulate per-subject risk over ``findings`` (pure overlay, F1-safe).

    Groups findings by canonical entity, applies gate-then-weight per contributing
    finding (``confidence * weight * (1 - spoofability) * trust``), clamps the sum
    to [0,1], and assigns a band -- with CRITICAL gated behind >=2 distinct
    artifact sources. Returns one :class:`SubjectRisk` per subject, sorted by
    descending score (ties broken by subject for determinism). Never mutates the
    inputs; reads only confidence/category/artifact_sources/evidence.
    """
    # subject value -> accumulation state.
    groups: dict[str, dict] = {}
    for finding in findings:
        value, kind = _subject_of(finding)
        group = groups.get(value)
        if group is None:
            group = {"kind": kind, "sources": set(), "contributors": [], "raw": 0.0}
            groups[value] = group

        category = _get(finding, "category", FindingCategory.UNKNOWN)
        confidence = float(_get(finding, "confidence", 0.0) or 0.0)
        sources = {s for s in (_get(finding, "artifact_sources", None) or []) if s}
        group["sources"].update(sources)

        weight = _weight(category)
        spoof = _spoofability(category)
        contribution = confidence * weight * (1.0 - spoof)
        group["contributors"].append(
            {
                "title": _get(finding, "title", ""),
                "category": str(category),
                "confidence": round(confidence, 4),
                "weight": weight,
                "spoofability": spoof,
                "pre_trust_contribution": round(contribution, 4),
            }
        )
        group["raw"] += contribution

    subjects: list[SubjectRisk] = []
    for value, group in groups.items():
        distinct = len(group["sources"])
        # Trust is applied from the subject's FULL distinct-source set, so it does
        # not depend on the order findings were iterated.
        trust = _trust(distinct)
        score = min(1.0, group["raw"] * trust)
        # A subject whose contributions are all zero-weight (ANALYSIS_GAP /
        # UNKNOWN -> not attacker behavior) or that rounds to zero at the report's
        # display precision carries no reportable risk signal; omit it rather than
        # clutter the overlay with a 0.0000 row. It was still attributed (no scored
        # finding is dropped) -- it simply adds nothing.
        if score < _SCORE_EPSILON:
            continue
        subjects.append(
            SubjectRisk(
                subject=value,
                subject_kind=group["kind"],
                score=score,
                band=_band(score, distinct),
                distinct_sources=distinct,
                contributors=group["contributors"],
            )
        )

    # Highest-risk subject first; subject value breaks ties for a stable order.
    subjects.sort(key=lambda s: (-s.score, s.subject))
    return subjects


def _band(score: float, distinct_sources: int) -> RiskBand:
    """Map a clamped score to a band; CRITICAL is gated on corroboration.

    A score clearing the HIGH threshold only reaches CRITICAL when the subject is
    backed by >=2 distinct artifact sources -- so a single, possibly-spoofed
    signal caps at HIGH no matter how confident it is.
    """
    if score >= _TOP_FLOOR:
        if distinct_sources >= _CRITICAL_MIN_DISTINCT_SOURCES:
            return RiskBand.CRITICAL
        return RiskBand.HIGH
    if score >= _HIGH_FLOOR:
        return RiskBand.HIGH
    if score >= _MEDIUM_FLOOR:
        return RiskBand.MEDIUM
    return RiskBand.LOW
