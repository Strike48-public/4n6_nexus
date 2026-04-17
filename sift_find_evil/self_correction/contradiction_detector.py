"""
Contradiction Detector - Detect inconsistencies across forensic artifacts.

This is the core of the self-correction mechanism.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Any
from enum import Enum

from ..validators.timestamp_comparator import TimestampComparator


class ContradictionType(Enum):
    """Types of contradictions that can be detected."""
    CAUSALITY_VIOLATION = "causality_violation"
    TIMESTOMPING = "timestomping"
    MISSING_ARTIFACT = "missing_artifact"
    TEMPORAL_MISMATCH = "temporal_mismatch"


class Severity(Enum):
    """Severity levels for contradictions."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Contradiction:
    """
    Represents a detected contradiction between artifacts.
    """
    type: ContradictionType
    severity: Severity
    description: str
    confidence_impact: float  # Negative value (how much to reduce confidence)

    # Artifacts involved
    artifacts: List[Any] = field(default_factory=list)

    # Details specific to contradiction type
    details: dict = field(default_factory=dict)

    # When contradiction was detected
    detected_at: datetime = field(default_factory=lambda: datetime.now())

    def to_dict(self) -> dict:
        """Convert to dictionary for logging/output."""
        return {
            'type': self.type.value,
            'severity': self.severity.value,
            'description': self.description,
            'confidence_impact': self.confidence_impact,
            'details': self.details,
            'detected_at': self.detected_at.isoformat()
        }


class ContradictionDetector:
    """
    Detects contradictions between MFT, Prefetch, and Event Log artifacts.
    """

    def __init__(self, comparator: Optional[TimestampComparator] = None):
        """
        Initialize detector.

        Args:
            comparator: TimestampComparator instance (creates new if None)
        """
        self.comparator = comparator or TimestampComparator()

    def detect_causality_violation(
        self,
        mft_entry: Any,
        prefetch_entry: Any
    ) -> Optional[Contradiction]:
        """
        Detect if file was modified AFTER it was executed (causality violation).

        Args:
            mft_entry: MFTEntry with file timestamps
            prefetch_entry: PrefetchEntry with execution timestamps

        Returns:
            Contradiction if detected, None otherwise
        """
        # Get modification time from MFT (prefer $FN over $SI)
        mft_modified = mft_entry.get_modification_time(prefer_fn=False)  # Use $SI for this check

        # Get last execution time from Prefetch
        prefetch_last_run = prefetch_entry.last_run_time

        if not mft_modified or not prefetch_last_run:
            return None

        # Check for causality violation
        violation_details = self.comparator.detect_causality_violation(
            mft_modified,
            prefetch_last_run,
            tolerance_seconds=300  # 5-minute tolerance
        )

        if violation_details:
            # Determine severity based on time delta
            time_delta = abs(violation_details['time_delta_seconds'])
            if time_delta > 3600:  # > 1 hour
                severity = Severity.CRITICAL
                confidence_impact = -0.60
            elif time_delta > 600:  # > 10 minutes
                severity = Severity.HIGH
                confidence_impact = -0.50
            else:
                severity = Severity.MEDIUM
                confidence_impact = -0.45

            return Contradiction(
                type=ContradictionType.CAUSALITY_VIOLATION,
                severity=severity,
                description=f"File {mft_entry.file_name} modified at {mft_modified} "
                          f"but executed at {prefetch_last_run} (causality violation)",
                confidence_impact=confidence_impact,
                artifacts=[mft_entry, prefetch_entry],
                details={
                    'mft_modified': mft_modified.isoformat(),
                    'prefetch_last_run': prefetch_last_run.isoformat(),
                    'time_delta_seconds': violation_details['time_delta_seconds'],
                    'file_path': mft_entry.file_path
                }
            )

        return None

    def detect_timestomping(
        self,
        mft_entry: Any
    ) -> Optional[Contradiction]:
        """
        Detect timestamp manipulation ($SI vs $FN discrepancy).

        Args:
            mft_entry: MFTEntry with both $SI and $FN timestamps

        Returns:
            Contradiction if detected, None otherwise
        """
        si_modified = mft_entry.si_modified
        fn_modified = mft_entry.fn_modified

        if not si_modified or not fn_modified:
            return None

        # Check for timestomping
        timestomping = self.comparator.detect_timestomping(
            si_modified,
            fn_modified,
            tolerance_seconds=60  # 1-minute tolerance
        )

        if timestomping:
            return Contradiction(
                type=ContradictionType.TIMESTOMPING,
                severity=Severity.CRITICAL,
                description=f"File {mft_entry.file_name} shows timestomping: "
                          f"$SI ({si_modified}) earlier than $FN ({fn_modified})",
                confidence_impact=-0.60,
                artifacts=[mft_entry],
                details={
                    'si_modified': si_modified.isoformat(),
                    'fn_modified': fn_modified.isoformat(),
                    'time_delta_seconds': timestomping['time_delta_seconds'],
                    'file_path': mft_entry.file_path
                }
            )

        return None

    def detect_missing_execution_artifact(
        self,
        mft_entry: Any,
        prefetch_entries: List[Any]
    ) -> Optional[Contradiction]:
        """
        Detect if executable exists in MFT but has no Prefetch evidence.

        This is suspicious for executables that should have Prefetch.

        Args:
            mft_entry: MFTEntry for an executable file
            prefetch_entries: List of all PrefetchEntry objects

        Returns:
            Contradiction if detected, None otherwise
        """
        # Only check .exe files
        if not mft_entry.file_name.lower().endswith('.exe'):
            return None

        # Search for matching Prefetch entry
        exe_name = mft_entry.file_name
        matching_prefetch = [
            pf for pf in prefetch_entries
            if pf.executable.lower() == exe_name.lower()
        ]

        if not matching_prefetch:
            # Executable exists but no Prefetch - suspicious
            return Contradiction(
                type=ContradictionType.MISSING_ARTIFACT,
                severity=Severity.MEDIUM,
                description=f"Executable {exe_name} exists in MFT but has no Prefetch artifact",
                confidence_impact=-0.30,
                artifacts=[mft_entry],
                details={
                    'file_path': mft_entry.file_path,
                    'mft_created': mft_entry.get_creation_time().isoformat() if mft_entry.get_creation_time() else None,
                    'note': 'May indicate Prefetch deletion or disabled Prefetch'
                }
            )

        return None

    def detect_temporal_mismatch(
        self,
        prefetch_entry: Any,
        event_log_entries: List[Any],
        tolerance_seconds: int = 300
    ) -> Optional[Contradiction]:
        """
        Detect if Prefetch execution time doesn't match any Event ID 4688.

        Args:
            prefetch_entry: PrefetchEntry with execution time
            event_log_entries: List of Event ID 4688 entries for this executable
            tolerance_seconds: Time window to search (default 5 minutes)

        Returns:
            Contradiction if detected, None otherwise
        """
        if not event_log_entries:
            # No Event Logs to compare - not necessarily a contradiction
            return None

        prefetch_last_run = prefetch_entry.last_run_time
        if not prefetch_last_run:
            return None

        # Check if any Event Log entry is within tolerance
        matches_found = False
        for event in event_log_entries:
            comparison = self.comparator.compare(
                event.time_created,
                prefetch_last_run,
                tolerance_seconds
            )
            if comparison == 0:  # Within tolerance
                matches_found = True
                break

        if not matches_found:
            # Prefetch time doesn't match any Event Log entry
            event_times = [e.time_created.isoformat() for e in event_log_entries[:3]]

            return Contradiction(
                type=ContradictionType.TEMPORAL_MISMATCH,
                severity=Severity.MEDIUM,
                description=f"Prefetch shows execution at {prefetch_last_run} but no matching "
                          f"Event ID 4688 found within ±{tolerance_seconds}s",
                confidence_impact=-0.35,
                artifacts=[prefetch_entry] + event_log_entries,
                details={
                    'prefetch_last_run': prefetch_last_run.isoformat(),
                    'event_log_times': event_times,
                    'event_count': len(event_log_entries),
                    'executable': prefetch_entry.executable
                }
            )

        return None

    def detect_all(
        self,
        mft_entries: List[Any],
        prefetch_entries: List[Any],
        event_log_entries: List[Any]
    ) -> List[Contradiction]:
        """
        Run all contradiction detection checks.

        Args:
            mft_entries: List of MFTEntry objects
            prefetch_entries: List of PrefetchEntry objects
            event_log_entries: List of EventLogEntry objects (should be Event ID 4688)

        Returns:
            List of detected contradictions
        """
        contradictions = []

        # For each Prefetch entry, try to find matching MFT entry
        for prefetch_entry in prefetch_entries:
            exe_name = prefetch_entry.executable

            # Find matching MFT entry
            matching_mft = [
                mft for mft in mft_entries
                if mft.file_name.lower() == exe_name.lower()
            ]

            if matching_mft:
                mft_entry = matching_mft[0]

                # Check for causality violation
                causality = self.detect_causality_violation(mft_entry, prefetch_entry)
                if causality:
                    contradictions.append(causality)

                # Check for timestomping
                timestomping = self.detect_timestomping(mft_entry)
                if timestomping:
                    contradictions.append(timestomping)

            # Check for temporal mismatch with Event Logs
            matching_events = [
                evt for evt in event_log_entries
                if evt.get_executable_name() and
                   evt.get_executable_name().lower() == exe_name.lower()
            ]

            temporal = self.detect_temporal_mismatch(
                prefetch_entry,
                matching_events
            )
            if temporal:
                contradictions.append(temporal)

        # Check for missing Prefetch artifacts
        for mft_entry in mft_entries:
            if mft_entry.file_name.lower().endswith('.exe'):
                missing = self.detect_missing_execution_artifact(
                    mft_entry,
                    prefetch_entries
                )
                if missing:
                    contradictions.append(missing)

        return contradictions
