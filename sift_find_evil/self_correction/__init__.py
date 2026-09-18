"""Self-correction engine for cross-artifact validation."""

from .contradiction_detector import ContradictionDetector, Contradiction
from .confidence_scorer import ConfidenceScorer, Resolution
from .engine import SelfCorrectionEngine
from .hypothesis_ledger import (
    AttachedFinding,
    Hypothesis,
    HypothesisLedger,
    HypothesisStatus,
    SelfCorrection,
    Verdict,
)

# Finding moved to findings module for Community/Enterprise split
from ..findings import Finding

__all__ = [
    "ContradictionDetector",
    "Contradiction",
    "ConfidenceScorer",
    "Resolution",
    "SelfCorrectionEngine",
    "Finding",  # Re-exported for backward compatibility
    # Falsifiable hypothesis ledger (SFE-udkk)
    "HypothesisLedger",
    "Hypothesis",
    "AttachedFinding",
    "SelfCorrection",
    "Verdict",
    "HypothesisStatus",
]
