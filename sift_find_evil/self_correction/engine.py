"""Self-Correction Engine - Orchestrate contradiction detection and resolution.

This is the main orchestrator for the autonomous self-correction system.
"""

from typing import Callable, List, Optional, Any

from .contradiction_detector import (
    ContradictionDetector,
    Contradiction,
    ContradictionType,
)
from .confidence_scorer import ConfidenceScorer, Resolution
from .attack_pattern_detector import AttackPatternDetector, AttackPattern
from ..validators.timestamp_comparator import TimestampComparator
from ..findings import Finding, FindingCategory


# Which finding category a given contradiction type maps to. Every known
# ContradictionType must appear here; unmapped types fall through to UNKNOWN.
_CATEGORY_BY_CONTRADICTION: dict[ContradictionType, FindingCategory] = {
    ContradictionType.CAUSALITY_VIOLATION: FindingCategory.TIMELINE_TAMPERING,
    ContradictionType.TIMESTOMPING: FindingCategory.TIMELINE_TAMPERING,
    ContradictionType.TEMPORAL_MISMATCH: FindingCategory.TIMELINE_TAMPERING,
    ContradictionType.MISSING_ARTIFACT: FindingCategory.ANTI_FORENSICS,
}


def _pick_category(contradictions: List[Contradiction]) -> FindingCategory:
    """Choose the strongest category represented among the contradictions.

    Order of precedence reflects how unambiguous each category is as a signal:
    anti_forensics > timeline_tampering > unknown.
    """
    categories = {
        _CATEGORY_BY_CONTRADICTION.get(c.type, FindingCategory.UNKNOWN)
        for c in contradictions
    }
    if FindingCategory.ANTI_FORENSICS in categories:
        return FindingCategory.ANTI_FORENSICS
    if FindingCategory.TIMELINE_TAMPERING in categories:
        return FindingCategory.TIMELINE_TAMPERING
    return FindingCategory.UNKNOWN


# Finding class moved to findings/finding.py to enable clean Community/Enterprise split.
# It is now imported above from ..findings import Finding

class SelfCorrectionEngine:
    """Main orchestrator for autonomous self-correction.

    Workflow:
    1. Load artifacts (MFT, Prefetch, Event Logs)
    2. Detect contradictions across artifacts
    3. Attempt resolution via Event Log tiebreaker
    4. Calculate confidence with adjustments
    5. Generate findings with reasoning chain
    """

    def __init__(
        self,
        comparator: Optional[TimestampComparator] = None,
        base_confidence: float = 0.85,
    ):
        """Initialize self-correction engine.

        Args:
            comparator: TimestampComparator instance (creates new if None)
            base_confidence: Starting confidence for findings
        """
        self.comparator = comparator or TimestampComparator()
        self.detector = ContradictionDetector(self.comparator)
        self.scorer = ConfidenceScorer(base_confidence)
        self.attack_detector = AttackPatternDetector()

    def analyze(
        self,
        mft_entries: List[Any],
        prefetch_entries: List[Any],
        event_log_entries: List[Any],
        content_reader: Optional[Callable[[Any], bytes]] = None,
        emails: Optional[List[Any]] = None,
    ) -> List[Finding]:
        """Run full self-correction analysis.

        Args:
            mft_entries: List of MFTEntry objects
            prefetch_entries: List of PrefetchEntry objects
            event_log_entries: List of EventLogEntry objects (Event ID 4688)
            content_reader: Optional callable for reading file bytes from disk image.
                           When None (default), existing CSV-only behavior is unchanged.
                           When provided, hash-based detectors (e.g. EXFIL_CORRELATION)
                           can compute on-disk file hashes for correlation.
            emails: Optional list of EmailMessage objects from PST parser. When provided,
                   EXFIL_CORRELATION detector runs to find file-save-then-email patterns.

        Returns:
            List of Finding objects with confidence and reasoning
        """
        findings = []

        # Detect process-execution contradictions (MFT/Prefetch/EventLog)
        contradictions = self.detector.detect_all(
            mft_entries, prefetch_entries, event_log_entries
        )

        # Group contradictions by executable
        contradiction_map = self._group_contradictions_by_executable(contradictions)

        # Generate findings for each executable with contradictions
        for executable, exec_contradictions in contradiction_map.items():
            finding = self._generate_finding(
                executable,
                exec_contradictions,
                mft_entries,
                prefetch_entries,
                event_log_entries,
            )
            findings.append(finding)

        # Detect file-save-then-email exfiltration (EXFIL_CORRELATION)
        if emails:
            exfil_contradictions = self.detector.detect_save_then_exfil(
                mft_entries, emails, content_reader
            )
            for contradiction in exfil_contradictions:
                finding = self._generate_exfil_finding(contradiction)
                findings.append(finding)

        # Detect attack patterns in Event Log command lines
        attack_findings = self._detect_attack_patterns(event_log_entries)
        findings.extend(attack_findings)

        return findings

    def _group_contradictions_by_executable(
        self, contradictions: List[Contradiction]
    ) -> dict:
        """Group contradictions by executable name.

        Args:
            contradictions: List of all contradictions

        Returns:
            Dictionary mapping executable name to list of contradictions
        """
        grouped = {}

        for contradiction in contradictions:
            # Extract executable name from artifacts
            executable = None

            for artifact in contradiction.artifacts:
                if hasattr(artifact, "file_name"):
                    executable = artifact.file_name
                    break
                elif hasattr(artifact, "executable"):
                    executable = artifact.executable
                    break

            if executable:
                if executable not in grouped:
                    grouped[executable] = []
                grouped[executable].append(contradiction)

        return grouped

    def _generate_finding(
        self,
        executable: str,
        contradictions: List[Contradiction],
        mft_entries: List[Any],
        prefetch_entries: List[Any],
        event_log_entries: List[Any],
    ) -> Finding:
        """Generate a finding with self-correction applied.

        Args:
            executable: Executable name
            contradictions: Contradictions for this executable
            mft_entries: All MFT entries
            prefetch_entries: All Prefetch entries
            event_log_entries: All Event Log entries

        Returns:
            Finding with confidence and reasoning
        """
        reasoning_chain = []
        resolutions = []

        # Determine artifact types available
        artifact_types = []
        if any(e.file_name == executable for e in mft_entries):
            artifact_types.append("MFT")
        if any(p.executable.lower() == executable.lower() for p in prefetch_entries):
            artifact_types.append("Prefetch")
        if any(
            e.get_executable_name()
            and e.get_executable_name().lower() == executable.lower()
            for e in event_log_entries
        ):
            artifact_types.append("EventLog")

        artifact_count = len(artifact_types)

        # Start reasoning chain
        reasoning_chain.append(
            f"Found {artifact_count} artifact types for {executable}: {', '.join(artifact_types)}"
        )

        # Calculate initial confidence
        initial_confidence, calc_details = self.scorer.calculate_final_confidence(
            artifact_count, artifact_types, contradictions, resolutions
        )

        reasoning_chain.append(
            f"Initial confidence: {initial_confidence:.2f} "
            f"({artifact_count} artifacts, {len(artifact_types)} types)"
        )

        # Apply contradictions
        for contradiction in contradictions:
            reasoning_chain.append(
                f"Detected {contradiction.type.value}: {contradiction.description} "
                f"(impact: {contradiction.confidence_impact:.2f})"
            )

        # Attempt resolution via Event Log tiebreaker
        for contradiction in contradictions:
            if contradiction.type == ContradictionType.CAUSALITY_VIOLATION:
                resolution = self._resolve_causality_violation(
                    executable, contradiction, prefetch_entries, event_log_entries
                )
                if resolution:
                    resolutions.append(resolution)
                    reasoning_chain.append(
                        f"Resolved via Event Log: {resolution.resolution_method} "
                        f"(recovery: +{resolution.confidence_recovery:.2f})"
                    )

        # Recalculate final confidence with resolutions
        final_confidence, calc_details = self.scorer.calculate_final_confidence(
            artifact_count, artifact_types, contradictions, resolutions
        )

        reasoning_chain.append(
            f"Final confidence: {final_confidence:.2f} "
            f"({self.scorer.get_confidence_label(final_confidence)})"
        )

        # Determine severity based on contradiction types
        severity = self._determine_severity(contradictions)

        # Build evidence
        evidence = {
            "executable": executable,
            "contradictions_detected": len(contradictions),
            "resolutions_applied": len(resolutions),
            "artifact_types": artifact_types,
        }

        # Create finding
        finding = Finding(
            title=f"Suspicious Activity: {executable}",
            description=self._generate_description(
                executable, contradictions, resolutions
            ),
            finding_type="indicator",
            severity=severity,
            category=_pick_category(contradictions),
            evidence=evidence,
            confidence=final_confidence,
            confidence_label=self.scorer.get_confidence_label(final_confidence),
            reasoning_chain=reasoning_chain,
            contradictions=contradictions,
            resolutions=resolutions,
            confidence_calculation=calc_details,
            artifact_sources=artifact_types,
        )

        return finding

    def _generate_exfil_finding(self, contradiction: Contradiction) -> Finding:
        """Generate a standalone finding for EXFIL_CORRELATION (SFE-3).

        These findings have fixed confidence scores based on match type:
        - Hash match: 0.95
        - Size+name fallback: 0.65

        Args:
            contradiction: EXFIL_CORRELATION contradiction with match details.

        Returns:
            Finding with DATA_EXFILTRATION category and appropriate confidence.
        """
        details = contradiction.details
        match_type = details.get("match_type", "unknown")

        # Set confidence based on match type
        if match_type == "hash":
            confidence = 0.95
            confidence_label = "Very High"
        elif match_type == "size_name_fallback":
            confidence = 0.65
            confidence_label = "Medium"
        else:
            confidence = 0.50
            confidence_label = "Low"

        # Build reasoning chain
        reasoning = [
            f"File-save-then-email pattern detected ({match_type} match)",
            f"File: {details.get('file_path', 'unknown')}",
            f"Saved: {details.get('save_time', 'unknown')}",
            f"Emailed: {details.get('send_time', 'unknown')} "
            f"({details.get('delta_seconds', 0):.1f}s later)",
            f"Subject: {details.get('email_subject', 'unknown')}",
            f"Attachment: {details.get('attachment_name', 'unknown')} "
            f"({details.get('attachment_size', 0)} bytes)",
        ]

        if match_type == "hash":
            reasoning.append(
                f"SHA-256 match: {details.get('file_hash', 'unknown')[:16]}... "
                f"(on-disk) == {details.get('attachment_hash', 'unknown')[:16]}... (email)"
            )
            reasoning.append("Cryptographic proof: file bytes are byte-identical")
        else:
            reasoning.append("Filename and size match (no hash verification)")

        # Check for external recipient flag (from transport headers analysis)
        # For now, this is a placeholder — full header parsing would check
        # for external domains, tuckgorge@gmail.com patterns, etc.
        # The Jean case has this; we'll extend the detector in future if needed.

        return Finding(
            title=f"Data exfiltration: {details.get('attachment_name', 'file')} via email",
            description=contradiction.description,
            finding_type="indicator",
            severity="critical",
            category=FindingCategory.DATA_EXFILTRATION,
            evidence=details,
            confidence=confidence,
            confidence_label=confidence_label,
            reasoning_chain=reasoning,
            contradictions=[contradiction],
            resolutions=[],
            confidence_calculation={
                "base": confidence,
                "match_type": match_type,
                "rationale": (
                    "Hash-based match provides cryptographic certainty"
                    if match_type == "hash"
                    else "Size+name match without hash verification"
                ),
            },
            artifact_sources=["MFT", "PST"],
        )

    def _resolve_causality_violation(
        self,
        executable: str,
        contradiction: Contradiction,
        prefetch_entries: List[Any],
        event_log_entries: List[Any],
    ) -> Optional[Resolution]:
        """Attempt to resolve causality violation using Event Log tiebreaker.

        Args:
            executable: Executable name
            contradiction: Causality violation contradiction
            prefetch_entries: All Prefetch entries
            event_log_entries: All Event Log entries

        Returns:
            Resolution if Event Log confirms execution time, None otherwise
        """
        # Find Prefetch entry for this executable
        prefetch_entry = next(
            (p for p in prefetch_entries if p.executable.lower() == executable.lower()),
            None,
        )

        if not prefetch_entry or not prefetch_entry.last_run_time:
            return None

        # Find matching Event Log entries
        matching_events = [
            e
            for e in event_log_entries
            if e.get_executable_name()
            and e.get_executable_name().lower() == executable.lower()
        ]

        if not matching_events:
            return None

        # Check if any Event Log entry matches Prefetch time
        prefetch_time = prefetch_entry.last_run_time
        for event in matching_events:
            comparison = self.comparator.compare(
                event.time_created,
                prefetch_time,
                tolerance_seconds=10,  # Tight tolerance for high confidence
            )

            if comparison == 0:  # Within tolerance
                # Event Log confirms Prefetch time
                return Resolution(
                    contradiction_type="causality_violation",
                    resolution_method="event_log_confirms_prefetch",
                    confidence_recovery=0.30,
                    evidence={
                        "prefetch_time": prefetch_time.isoformat(),
                        "event_log_time": event.time_created.isoformat(),
                        "event_id": event.event_id,
                        "time_delta_seconds": abs(
                            (event.time_created - prefetch_time).total_seconds()
                        ),
                    },
                )

        return None

    def _determine_severity(self, contradictions: List[Contradiction]) -> str:
        """Determine overall severity based on contradictions.

        Args:
            contradictions: List of contradictions

        Returns:
            Severity label (critical, high, medium, low)
        """
        if not contradictions:
            return "info"

        # Use highest severity from contradictions
        severity_order = ["info", "low", "medium", "high", "critical"]
        max_severity = "info"

        for contradiction in contradictions:
            severity_value = contradiction.severity.value
            if severity_order.index(severity_value) > severity_order.index(
                max_severity
            ):
                max_severity = severity_value

        return max_severity

    def _generate_description(
        self,
        executable: str,
        contradictions: List[Contradiction],
        resolutions: List[Resolution],
    ) -> str:
        """Generate human-readable description of finding.

        Args:
            executable: Executable name
            contradictions: Contradictions detected
            resolutions: Resolutions applied

        Returns:
            Description string
        """
        lines = [
            f"Analysis of {executable} detected {len(contradictions)} contradiction(s):"
        ]

        for contradiction in contradictions:
            lines.append(f"- {contradiction.description}")

        if resolutions:
            lines.append(f"\nApplied {len(resolutions)} resolution(s):")
            for resolution in resolutions:
                lines.append(f"- {resolution.resolution_method}")

        return "\n".join(lines)

    def _detect_attack_patterns(self, event_log_entries: List[Any]) -> List[Finding]:
        """Detect attack patterns in Event Log command lines.

        Args:
            event_log_entries: List of EventLogEntry objects (should include 4688)

        Returns:
            List of findings for detected attack patterns
        """
        findings = []

        # Only analyze process creation events (Event ID 4688)
        for event in event_log_entries:
            if (
                not hasattr(event, "is_process_creation")
                or not event.is_process_creation()
            ):
                continue

            # Get command line
            command_line = (
                event.get_command_line() if hasattr(event, "get_command_line") else None
            )
            if not command_line:
                continue

            # Analyze for attack patterns
            patterns = self.attack_detector.analyze_command_line(command_line)
            if not patterns:
                continue

            # Get highest severity pattern
            primary_pattern = self.attack_detector.get_highest_severity_pattern(
                patterns
            )
            if not primary_pattern:
                continue

            # Get executable name
            exe_name = (
                event.get_executable_name()
                if hasattr(event, "get_executable_name")
                else "unknown"
            )

            # Create finding for attack pattern
            finding = Finding(
                title=f"Attack Pattern: {primary_pattern.pattern_name}",
                description=f"Detected {primary_pattern.technique.value} activity in command line:\n{command_line}",
                finding_type="behavior",
                severity=primary_pattern.severity,
                category=self._pattern_to_category(primary_pattern),
                evidence={
                    "executable": exe_name,
                    "command_line": command_line,
                    "technique": primary_pattern.technique.value,
                    "mitre_id": primary_pattern.mitre_id,
                    "pattern_name": primary_pattern.pattern_name,
                    "event_id": event.event_id,
                    "time_created": event.time_created.isoformat(),
                },
                confidence=primary_pattern.confidence,
                confidence_label=self.scorer.get_confidence_label(
                    primary_pattern.confidence
                ),
                reasoning_chain=[
                    f"Event ID {event.event_id} captured process execution",
                    f"Command line matches pattern: {primary_pattern.pattern_name}",
                    f"MITRE ATT&CK Technique: {primary_pattern.mitre_id}",
                    f"Confidence: {primary_pattern.confidence:.2f} (pattern-based detection)",
                ],
                contradictions=[],
                resolutions=[],
                confidence_calculation={
                    "base": primary_pattern.confidence,
                    "method": "pattern_matching",
                    "pattern": primary_pattern.pattern_name,
                },
                artifact_sources=["EventLog"],
            )

            findings.append(finding)

        return findings

    def _pattern_to_category(self, pattern: AttackPattern) -> FindingCategory:
        """Map attack pattern technique to finding category.

        Args:
            pattern: Detected attack pattern

        Returns:
            FindingCategory enum value
        """
        from .attack_pattern_detector import AttackTechnique

        technique_to_category = {
            AttackTechnique.RECONNAISSANCE: FindingCategory.RECONNAISSANCE,
            AttackTechnique.CREDENTIAL_ACCESS: FindingCategory.CREDENTIAL_ACCESS,
            AttackTechnique.LATERAL_MOVEMENT: FindingCategory.LATERAL_MOVEMENT,
            AttackTechnique.PERSISTENCE: FindingCategory.PERSISTENCE,
            AttackTechnique.DEFENSE_EVASION: FindingCategory.ANTI_FORENSICS,
            AttackTechnique.EXFILTRATION: FindingCategory.DATA_EXFILTRATION,
            AttackTechnique.EXECUTION: FindingCategory.EXECUTION,
            AttackTechnique.COMMAND_AND_CONTROL: FindingCategory.COMMAND_AND_CONTROL,
        }

        return technique_to_category.get(pattern.technique, FindingCategory.UNKNOWN)
