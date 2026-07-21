"""Pure-Python Dempster-Shafer evidence fusion over {malicious, benign}.

The frame of discernment is the binary set {M, B} where M = malicious and
B = benign. A Basic Probability Assignment (BPA) is a mapping from
non-empty subsets of the frame to masses summing to 1.0::

    {frozenset({'M'}): m_M,
     frozenset({'B'}): m_B,
     frozenset({'M', 'B'}): m_theta}

``m_theta`` is the ignorance mass assigned to the whole frame.

Each detector contributes a discounted BPA: a raw ``(confidence, rho)``
pair is turned into masses using Shafer discounting, where ``rho`` is the
detector reliability. The remaining ``(1 - rho)`` mass is committed to
ignorance. Multiple BPAs are combined with Dempster's rule of
combination; when the normalized conflict ``K`` grows too large the
combination falls back to Yager's rule, which dumps conflict into
ignorance instead of normalizing it away.
"""

from __future__ import annotations

from dataclasses import dataclass

# Frame of discernment singletons and the full frame (ignorance).
MALICIOUS: frozenset[str] = frozenset({"M"})
BENIGN: frozenset[str] = frozenset({"B"})
THETA: frozenset[str] = frozenset({"M", "B"})

# Conflict threshold above which Dempster's rule is replaced by Yager's.
YAGER_CONFLICT_THRESHOLD: float = 0.7
# Decision-policy thresholds.
CONFIRM_BELIEF_THRESHOLD: float = 0.7
CONFIRM_CONFLICT_CEILING: float = 0.5

BPA = dict[frozenset[str], float]


def _hypothesis_set(hypothesis: str) -> frozenset[str]:
    """Map a hypothesis label to its singleton frame subset.

    Args:
        hypothesis: Either ``"M"`` (malicious) or ``"B"`` (benign).

    Returns:
        The corresponding singleton frozenset.

    Raises:
        ValueError: If the hypothesis is not a known frame element.
    """
    if hypothesis == "M":
        return MALICIOUS
    if hypothesis == "B":
        return BENIGN
    raise ValueError(f"unknown hypothesis {hypothesis!r}; expected 'M' or 'B'")


def detector_bpa(confidence: float, rho: float) -> BPA:
    """Build a Shafer-discounted BPA from a detector output.

    Args:
        confidence: Probability the observation is malicious, in [0, 1].
        rho: Detector reliability (discount factor), in [0, 1]. A value
            of 1.0 fully trusts the detector; 0.0 yields total ignorance.

    Returns:
        A BPA over {M}, {B}, and {M, B} whose masses sum to 1.0.

    Raises:
        ValueError: If ``confidence`` or ``rho`` fall outside [0, 1].
    """
    if not 0.0 <= confidence <= 1.0:
        raise ValueError(f"confidence must be in [0, 1], got {confidence}")
    if not 0.0 <= rho <= 1.0:
        raise ValueError(f"rho must be in [0, 1], got {rho}")

    m_malicious = confidence * rho
    m_benign = (1.0 - confidence) * rho
    m_theta = 1.0 - rho
    return {MALICIOUS: m_malicious, BENIGN: m_benign, THETA: m_theta}


def belief(bpa: BPA, hypothesis: str) -> float:
    """Compute the belief (sum of masses of subsets) for a hypothesis.

    Args:
        bpa: A basic probability assignment.
        hypothesis: ``"M"`` or ``"B"``.

    Returns:
        The belief value Bel(hypothesis) in [0, 1].
    """
    target = _hypothesis_set(hypothesis)
    return sum(mass for subset, mass in bpa.items() if subset and subset <= target)


def plausibility(bpa: BPA, hypothesis: str) -> float:
    """Compute the plausibility for a hypothesis.

    Args:
        bpa: A basic probability assignment.
        hypothesis: ``"M"`` or ``"B"``.

    Returns:
        The plausibility Pl(hypothesis) in [0, 1]. Always >= belief.
    """
    target = _hypothesis_set(hypothesis)
    return sum(mass for subset, mass in bpa.items() if subset and subset & target)


def dempster_combine(bpa1: BPA, bpa2: BPA) -> tuple[BPA, float]:
    """Combine two BPAs, tracking conflict and applying Yager on high K.

    Uses Dempster's rule of combination. The conflict mass ``K`` is the
    total mass assigned to the empty set by the orthogonal sum. When
    ``K <= YAGER_CONFLICT_THRESHOLD`` the result is normalized by
    ``1 - K`` (classic Dempster). When ``K`` exceeds the threshold the
    combination uses Yager's rule instead: conflict is reassigned to
    ignorance (theta) rather than normalized away.

    Args:
        bpa1: First basic probability assignment.
        bpa2: Second basic probability assignment.

    Returns:
        A tuple of the combined BPA and the conflict value ``K``.
    """
    raw: dict[frozenset[str], float] = {
        MALICIOUS: 0.0,
        BENIGN: 0.0,
        THETA: 0.0,
    }
    conflict = 0.0

    for subset1, mass1 in bpa1.items():
        for subset2, mass2 in bpa2.items():
            product = mass1 * mass2
            intersection = subset1 & subset2
            if not intersection:
                conflict += product
            else:
                raw[intersection] = raw.get(intersection, 0.0) + product

    if conflict > YAGER_CONFLICT_THRESHOLD:
        # Yager's rule: conflict flows to ignorance, no normalization.
        combined = dict(raw)
        combined[THETA] = combined.get(THETA, 0.0) + conflict
        return combined, conflict

    denom = 1.0 - conflict
    if denom <= 0.0:
        # Total conflict with K below threshold is not reachable, but
        # guard against division by zero by deferring to Yager.
        combined = dict(raw)
        combined[THETA] = combined.get(THETA, 0.0) + conflict
        return combined, conflict

    combined = {subset: mass / denom for subset, mass in raw.items()}
    return combined, conflict


@dataclass(frozen=True)
class FusionResult:
    """Outcome of fusing a set of detector outputs.

    Attributes:
        bel_malicious: Belief that the frame element is malicious.
        pl_malicious: Plausibility that the frame element is malicious.
        conflict_k: The maximum conflict observed across combinations.
        decision: One of ``"confirm"``, ``"conflict"``, or ``"observe"``.
    """

    bel_malicious: float
    pl_malicious: float
    conflict_k: float
    decision: str


def fuse(detectors: list[tuple[float, float]]) -> FusionResult:
    """Fuse detector (confidence, rho) pairs into a single verdict.

    Detectors are converted to discounted BPAs and combined pairwise with
    :func:`dempster_combine`. The reported conflict is the maximum ``K``
    encountered across the fold, so a single strongly-conflicting pair is
    not diluted by later low-conflict combinations.

    Decision policy:
        - ``confirm`` when belief >= 0.7 and conflict < 0.5
        - ``conflict`` when conflict >= 0.7
        - ``observe`` otherwise

    Args:
        detectors: Non-empty list of ``(confidence, rho)`` pairs.

    Returns:
        A :class:`FusionResult` summarizing the fused evidence.

    Raises:
        ValueError: If ``detectors`` is empty.
    """
    if not detectors:
        raise ValueError("fuse() requires at least one detector")

    confidence, rho = detectors[0]
    combined = detector_bpa(confidence, rho)
    max_conflict = 0.0

    for confidence, rho in detectors[1:]:
        combined, conflict = dempster_combine(combined, detector_bpa(confidence, rho))
        max_conflict = max(max_conflict, conflict)

    bel_malicious = belief(combined, "M")
    pl_malicious = plausibility(combined, "M")
    decision = _decide(bel_malicious, max_conflict)
    return FusionResult(
        bel_malicious=bel_malicious,
        pl_malicious=pl_malicious,
        conflict_k=max_conflict,
        decision=decision,
    )


def _decide(bel_malicious: float, conflict_k: float) -> str:
    """Apply the decision policy to a belief and conflict value.

    Args:
        bel_malicious: Belief that the element is malicious.
        conflict_k: Observed conflict value.

    Returns:
        ``"conflict"``, ``"confirm"``, or ``"observe"``.
    """
    if conflict_k >= YAGER_CONFLICT_THRESHOLD:
        return "conflict"
    if (
        bel_malicious >= CONFIRM_BELIEF_THRESHOLD
        and conflict_k < CONFIRM_CONFLICT_CEILING
    ):
        return "confirm"
    return "observe"
