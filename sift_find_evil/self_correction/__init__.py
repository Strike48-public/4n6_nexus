"""Self-correction engine for cross-artifact validation."""

from .contradiction_detector import ContradictionDetector, Contradiction
from .confidence_scorer import ConfidenceScorer, Resolution
from .engine import SelfCorrectionEngine, Finding

__all__ = [
    "ContradictionDetector",
    "Contradiction",
    "ConfidenceScorer",
    "Resolution",
    "SelfCorrectionEngine",
    "Finding",
]
