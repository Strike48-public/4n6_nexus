"""Scene-staging / over-interpretation detector.

Idea #28: 'too obvious = planted'. A forensic scene that is dominated by
cartoonishly obvious bait artifact names ('definitely_evil.exe',
'password.txt', 'mimikatz.txt', ...) is more consistent with a staged or
planted scene than with real attacker tradecraft. Real intrusions rarely
leave signposts this loud.

This is a verifier confidence-adjust signal, not a malice verdict. When it
fires it should prompt an abductive inversion: stop trusting the loud
artifacts at face value and look for what is *not* there (the quiet,
unstaged corroborating evidence a genuine intrusion would leave behind).

Pure stdlib. The staging decision is an INTEGER comparison, not a float
threshold: bait must strictly dominate the scene.
"""

from __future__ import annotations

import re

from sift_find_evil.findings import Finding, FindingCategory

OBVIOUS_BAIT_TERMS: tuple[str, ...] = (
    "hacktool",
    "definitely_evil.exe",
    "totally_not_malware",
    "mimikatz.txt",
    "password.txt",
    "passwords.txt",
    "readme_i_hacked_you",
    "i_am_a_hacker",
    "evil.exe",
    "malware.exe",
    "backdoor.exe",
    "hacked.txt",
    "you_got_pwned",
)


class SceneStagingDetector:
    """Flags forensic scenes dominated by over-obvious 'bait' artifacts."""

    def __init__(self) -> None:
        """Build case-insensitive word-boundary matchers for each bait term."""
        # Underscore counts as a word char under \w, so '_'-joined bait terms
        # (e.g. 'totally_not_malware') match as whole tokens while a bait
        # substring buried inside a larger token (e.g. 'counterhacktoolkit')
        # is correctly rejected by the surrounding-\w lookarounds.
        self._patterns: tuple[re.Pattern[str], ...] = tuple(
            re.compile(r"(?<!\w)" + re.escape(term) + r"(?!\w)", re.IGNORECASE)
            for term in OBVIOUS_BAIT_TERMS
        )

    def _is_bait(self, term: str) -> bool:
        """Return True if term matches any bait pattern on a word boundary."""
        return any(pattern.search(term) for pattern in self._patterns)

    def analyze(self, evidence_terms: list[str]) -> list[Finding]:
        """Detect a scene dominated by obvious bait artifacts.

        Args:
            evidence_terms: Artifact names / strings recovered from the scene.

        Returns:
            A single-element list with a POSSIBLE_SCENE_STAGING finding when
            bait strictly dominates the scene, otherwise an empty list. The
            input is never mutated.
        """
        total = len(evidence_terms)
        bait_hits = sum(1 for term in evidence_terms if self._is_bait(term))

        # Integer decision: bait must strictly dominate. Equivalent to
        # bait_hits / total > 0.5 without any float threshold.
        staged = total > 0 and 2 * bait_hits > total
        if not staged:
            return []

        ratio = bait_hits / total
        return [
            Finding(
                title="POSSIBLE_SCENE_STAGING",
                description=(
                    "The scene is dominated by over-obvious 'bait' artifacts "
                    f"({bait_hits} of {total} terms). A real intrusion rarely "
                    "signposts itself this loudly; this pattern is consistent "
                    "with a staged or planted scene and should lower verifier "
                    "confidence in the loud artifacts."
                ),
                finding_type="behavior",
                severity="medium",
                category=FindingCategory.ANTI_FORENSICS,
                evidence={
                    "bait_hits": bait_hits,
                    "total": total,
                    "ratio": ratio,
                },
                confidence=0.5,
                confidence_label="Medium",
                reasoning_chain=[
                    f"{bait_hits} of {total} evidence terms are cartoonishly "
                    "obvious bait names.",
                    "Bait strictly dominates the scene (2*bait_hits > total).",
                    "Genuine attacker tradecraft avoids self-incriminating "
                    "signposts; loudness this high is suspicious of staging.",
                    "ACTION: INVERT ANALYSIS - distrust the loud artifacts and "
                    "look for what is NOT there (quiet corroborating evidence a "
                    "real intrusion would leave: process lineage, network "
                    "beacons, credential-access traces).",
                ],
                artifact_sources=["scene_inventory"],
            )
        ]
