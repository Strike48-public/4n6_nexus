"""Finding dataclass - Core forensic finding representation.

The Finding class is used by all detectors to represent discovered evidence
of malicious activity. It includes confidence scoring, reasoning chains, and
self-correction metadata (contradictions and resolutions).

This class was moved from self_correction/engine.py to enable clean separation
between Community (core detection) and Enterprise (self-correction) editions.
All detectors emit Finding objects regardless of whether self-correction is used.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, List

from .categories import FindingCategory

if TYPE_CHECKING:
    # Import types only for type checking to avoid circular dependencies
    # These types are only used in self-correction (Enterprise)
    pass


@dataclass
class Finding:
    """Represents a forensic finding with confidence and reasoning."""

    # Core finding information
    title: str
    description: str
    finding_type: str  # indicator, behavior, timeline_event
    severity: str  # critical, high, medium, low, info
    category: FindingCategory  # case-agnostic taxonomy label

    # Evidence
    evidence: dict = field(default_factory=dict)

    # Confidence and reasoning
    confidence: float = 0.85
    confidence_label: str = "High"
    reasoning_chain: List[str] = field(default_factory=list)

    # Self-correction metadata (Enterprise features)
    contradictions: List[Any] = field(default_factory=list)  # List[Contradiction]
    resolutions: List[Any] = field(default_factory=list)  # List[Resolution]
    confidence_calculation: dict = field(default_factory=dict)

    # Metadata
    detected_at: datetime = field(default_factory=lambda: datetime.now())
    artifact_sources: List[str] = field(default_factory=list)

    # First-class MITRE ATT&CK technique ids (SFE-fibx.4). Promoted from three
    # drifting evidence keys (``mitre_attack`` list, ``mitre_technique`` scalar,
    # ``mitre`` scalar) to one field with a single accessor. Detectors populate
    # this; ``mitre_techniques()`` falls back to the legacy evidence keys so no
    # serialized finding or downstream consumer regresses during the migration.
    techniques: List[str] = field(default_factory=list)

    # Provenance (SFE-fibx.4 PR-B). ``source_exec_id`` cites the specific input a
    # finding was derived from. There is no real per-tool-execution id on the
    # deterministic engine path (analyze_artifacts/the connector adapter carry
    # none), so when a caller does not supply one it is DERIVED in __post_init__
    # from the finding's own provenance (the ``source_span`` record when present,
    # else a digest of artifact_sources + evidence). A caller that DOES have a real
    # tool-run id (e.g. an MCP tool execution) may pass it and it is respected.
    # Additive here; PR-C flips construction to fail when it is empty.
    source_exec_id: str = ""
    # Fact-vs-inference split: ``observation`` is what was READ from tool output
    # (a fact); ``interpretation`` is the analytic conclusion drawn from it. Both
    # default empty so no detector is forced to populate them yet.
    observation: str = ""
    interpretation: str = ""

    # Proven-negative metadata (SFE-rylr). A finding with asserts_absence=True
    # claims "tool X ran and found zero Y" and is independently re-verified by
    # re-reading the cited tool output (see findings/absence.py): either none of
    # absence_pattern's indicator tokens physically appear, or absence_metric==0.
    # Default False so every existing positive finding is unaffected.
    asserts_absence: bool = False
    absence_pattern: List[str] = field(default_factory=list)
    absence_metric: "int | None" = None

    def __post_init__(self) -> None:
        """Enforce that every finding carries a non-empty ``source_exec_id``.

        A caller-supplied id is kept verbatim (a real tool-run id); a blank or
        whitespace-only value is treated as UNSET and derived, so a finding can
        never masquerade as provenanced while carring an empty id. Otherwise the
        id is derived from the finding's own provenance (SFE-fibx.4 PR-B): a
        stable ``<artifact>:<digest>`` over the exact consumed record
        (``evidence['source_span']``) when present, else the sorted evidence.

        The invariant is ENFORCED (PR-C): if a supplied id is empty AND derivation
        somehow yields empty, construction RAISES rather than emitting a finding
        with no provenance. Derivation is non-empty by construction today (it
        always falls back to ``unknown:<digest>``), so this rejects no real
        finding — it makes the guarantee un-bypassable against future regressions.
        """
        # Normalize None-valued containers to their empty defaults before the
        # derivation reads them: a caller passing ``evidence=None`` (or legacy
        # JSON with ``"evidence": null`` reaching from_dict) would otherwise crash
        # in ``_derive_source_exec_id`` on ``None.get(...)``. The dataclass default
        # is already ``{}``/``[]``; this only rescues an explicit None.
        if self.evidence is None:
            self.evidence = {}
        if self.artifact_sources is None:
            self.artifact_sources = []
        if not (self.source_exec_id and self.source_exec_id.strip()):
            self.source_exec_id = self._derive_source_exec_id()
        if not (self.source_exec_id and self.source_exec_id.strip()):
            raise ValueError(
                "Finding must carry a non-empty source_exec_id: neither a caller "
                "value nor the derived provenance id was usable. A finding without "
                "a citable source is not admissible."
            )

    @staticmethod
    def _stable_default(obj: Any) -> Any:
        """JSON ``default`` that renders non-JSON types DETERMINISTICALLY.

        A set/frozenset is rendered as its SORTED list, not via ``str()``: a bare
        ``str(set)`` orders elements by hash-seed and so differs across
        interpreter runs, which would make the derived id flaky. No detector
        stores a set in evidence today, but the id feeds a hard construction gate
        (PR-C), so this closes the landmine by construction rather than by
        convention. Anything else falls back to ``str`` as before.
        """
        if isinstance(obj, (set, frozenset)):
            return sorted(obj, key=str)
        return str(obj)

    def _derive_source_exec_id(self) -> str:
        """Compute the artifact-scoped provenance id. See ``__post_init__``."""
        scope = (
            self.artifact_sources[0] if self.artifact_sources else "unknown"
        ).lower()
        span = self.evidence.get("source_span")
        if span:
            seed = (
                span
                if isinstance(span, str)
                else json.dumps(span, sort_keys=True, default=self._stable_default)
            )
        else:
            seed = json.dumps(
                self.evidence, sort_keys=True, default=self._stable_default
            )
        digest = hashlib.sha1(seed.encode("utf-8", "replace")).hexdigest()[:12]
        return f"{scope}:{digest}"

    # Legacy evidence keys that carried techniques before the first-class field,
    # highest-authority first. Kept as the fallback source for findings that
    # predate the migration; never merged across keys (the first present wins).
    _LEGACY_MITRE_KEYS = ("mitre_attack", "mitre_technique", "mitre")

    def mitre_techniques(self) -> List[str]:
        """Return this finding's MITRE technique ids from the single source.

        The first-class ``techniques`` field is authoritative when populated.
        Otherwise falls back to the first present legacy evidence key, accepting
        either a scalar id or a list — so a not-yet-migrated detector and a
        replayed old finding both still surface their techniques.
        """
        if self.techniques:
            return list(self.techniques)
        for key in self._LEGACY_MITRE_KEYS:
            value = self.evidence.get(key)
            if value is None or value == "":
                continue
            return list(value) if isinstance(value, (list, tuple)) else [value]
        return []

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "title": self.title,
            "description": self.description,
            "type": self.finding_type,
            "severity": self.severity,
            "category": self.category.value,
            "evidence": self.evidence,
            "confidence": round(self.confidence, 2),
            "confidence_label": self.confidence_label,
            "reasoning_chain": self.reasoning_chain,
            "contradictions": [c.to_dict() for c in self.contradictions],
            "resolutions": [
                {
                    "type": r.contradiction_type,
                    "method": r.resolution_method,
                    "recovery": r.confidence_recovery,
                    "evidence": r.evidence,
                }
                for r in self.resolutions
            ],
            "confidence_calculation": self.confidence_calculation,
            "detected_at": self.detected_at.isoformat(),
            "artifact_sources": self.artifact_sources,
            "techniques": self.techniques,
            "source_exec_id": self.source_exec_id,
            "observation": self.observation,
            "interpretation": self.interpretation,
            "asserts_absence": self.asserts_absence,
            "absence_pattern": self.absence_pattern,
            "absence_metric": self.absence_metric,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Finding:
        """Create Finding from dictionary (inverse of to_dict)."""
        return cls(
            title=data["title"],
            description=data["description"],
            finding_type=data["type"],
            severity=data["severity"],
            category=FindingCategory(data["category"]),
            evidence=data.get("evidence", {}),
            confidence=data.get("confidence", 0.85),
            confidence_label=data.get("confidence_label", "High"),
            reasoning_chain=data.get("reasoning_chain", []),
            contradictions=[],  # Skip reconstruction for comparison purposes
            resolutions=[],  # Skip reconstruction for comparison purposes
            confidence_calculation=data.get("confidence_calculation", {}),
            detected_at=datetime.fromisoformat(data["detected_at"]),
            artifact_sources=data.get("artifact_sources", []),
            techniques=data.get("techniques", []),
            source_exec_id=data.get("source_exec_id", ""),
            observation=data.get("observation", ""),
            interpretation=data.get("interpretation", ""),
            asserts_absence=data.get("asserts_absence", False),
            absence_pattern=data.get("absence_pattern", []),
            absence_metric=data.get("absence_metric"),
        )
