"""Confidence Scorer - Calculate and adjust confidence scores based on evidence.

This module provides confidence scoring with adjustments based on
contradictions detected and resolutions applied.
"""

from typing import List
from dataclasses import dataclass

from .contradiction_detector import Contradiction


@dataclass
class Resolution:
    """Represents a resolution of a contradiction."""

    contradiction_type: str
    resolution_method: str
    confidence_recovery: float  # Positive value (how much to recover confidence)
    evidence: dict


class ConfidenceScorer:
    """Calculates confidence scores (0.0-1.0) for forensic findings.

    Confidence starts at a base value and is adjusted based on:
    - Contradictions detected (reduce confidence)
    - Resolutions applied (recover confidence)
    """

    def __init__(self, base_confidence: float = 0.85):
        """Initialize confidence scorer.

        Args:
            base_confidence: Starting confidence (default 0.85)
        """
        if not 0.0 <= base_confidence <= 1.0:
            raise ValueError("base_confidence must be between 0.0 and 1.0")

        self.base_confidence = base_confidence

    def calculate_initial_confidence(
        self, artifact_count: int, artifact_types: List[str]
    ) -> float:
        """Calculate initial confidence based on available artifacts.

        More artifacts and diverse types increase confidence.

        Args:
            artifact_count: Number of artifacts available
            artifact_types: Types of artifacts (e.g., ['MFT', 'Prefetch', 'EventLog'])

        Returns:
            Initial confidence score (0.0-1.0)
        """
        confidence = self.base_confidence

        # Bonus for multiple artifact types (cross-validation)
        unique_types = len(set(artifact_types))
        if unique_types >= 3:
            confidence += 0.10  # Three+ types = strong cross-validation
        elif unique_types == 2:
            confidence += 0.05  # Two types = moderate cross-validation

        # Bonus for artifact count
        if artifact_count >= 5:
            confidence += 0.05

        # Clamp to valid range
        return min(1.0, confidence)

    def apply_contradiction(
        self, confidence: float, contradiction: Contradiction
    ) -> float:
        """Apply a contradiction's confidence impact.

        Args:
            confidence: Current confidence score
            contradiction: Contradiction that was detected

        Returns:
            Adjusted confidence score (0.0-1.0)
        """
        # Contradiction impact is negative
        adjusted = confidence + contradiction.confidence_impact

        # Clamp to valid range
        return max(0.0, min(1.0, adjusted))

    def apply_contradictions(
        self, confidence: float, contradictions: List[Contradiction]
    ) -> float:
        """Apply multiple contradictions sequentially.

        Args:
            confidence: Current confidence score
            contradictions: List of contradictions detected

        Returns:
            Adjusted confidence score (0.0-1.0)
        """
        for contradiction in contradictions:
            confidence = self.apply_contradiction(confidence, contradiction)

        return confidence

    def apply_resolution(self, confidence: float, resolution: Resolution) -> float:
        """Apply a resolution's confidence recovery.

        Args:
            confidence: Current confidence score
            resolution: Resolution that was applied

        Returns:
            Adjusted confidence score (0.0-1.0)
        """
        # Resolution recovery is positive
        adjusted = confidence + resolution.confidence_recovery

        # Clamp to valid range
        return max(0.0, min(1.0, adjusted))

    def apply_resolutions(
        self, confidence: float, resolutions: List[Resolution]
    ) -> float:
        """Apply multiple resolutions sequentially.

        Args:
            confidence: Current confidence score
            resolutions: List of resolutions applied

        Returns:
            Adjusted confidence score (0.0-1.0)
        """
        for resolution in resolutions:
            confidence = self.apply_resolution(confidence, resolution)

        return confidence

    def calculate_final_confidence(
        self,
        artifact_count: int,
        artifact_types: List[str],
        contradictions: List[Contradiction],
        resolutions: List[Resolution],
    ) -> tuple[float, dict]:
        """Calculate final confidence with full audit trail.

        Args:
            artifact_count: Number of artifacts
            artifact_types: Types of artifacts
            contradictions: List of contradictions
            resolutions: List of resolutions

        Returns:
            Tuple of (final_confidence, calculation_details)
        """
        # Start with initial confidence
        initial = self.calculate_initial_confidence(artifact_count, artifact_types)

        # Track each step
        steps = [
            {
                "step": "initial",
                "confidence": initial,
                "reason": f"{artifact_count} artifacts, {len(set(artifact_types))} types",
            }
        ]

        current = initial

        # Apply contradictions
        for contradiction in contradictions:
            before = current
            current = self.apply_contradiction(current, contradiction)
            steps.append(
                {
                    "step": "contradiction",
                    "type": contradiction.type.value,
                    "confidence_before": before,
                    "confidence_after": current,
                    "impact": contradiction.confidence_impact,
                }
            )

        # Apply resolutions
        for resolution in resolutions:
            before = current
            current = self.apply_resolution(current, resolution)
            steps.append(
                {
                    "step": "resolution",
                    "method": resolution.resolution_method,
                    "confidence_before": before,
                    "confidence_after": current,
                    "recovery": resolution.confidence_recovery,
                }
            )

        details = {
            "initial_confidence": initial,
            "final_confidence": current,
            "total_contradictions": len(contradictions),
            "total_resolutions": len(resolutions),
            "calculation_steps": steps,
        }

        return current, details

    def get_confidence_label(self, confidence: float) -> str:
        """Convert confidence score to human-readable label.

        Args:
            confidence: Confidence score (0.0-1.0)

        Returns:
            Label (e.g., "High", "Medium", "Low")
        """
        if confidence >= 0.80:
            return "High"
        elif confidence >= 0.60:
            return "Medium"
        elif confidence >= 0.40:
            return "Low"
        else:
            return "Very Low"
