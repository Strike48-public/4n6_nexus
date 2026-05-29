"""
Progress tracking system for TUI investigation analysis.

Provides real-time progress updates, system resource monitoring,
phase management, and activity logging for the analysis screen.
"""

import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable


class PhaseStatus(Enum):
    """Phase execution status."""

    PENDING = "pending"
    ACTIVE = "active"
    COMPLETE = "complete"
    ERROR = "error"


class FindingSeverity(Enum):
    """Finding severity levels."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class Phase:
    """Represents a phase in the investigation pipeline."""

    name: str
    display_name: str
    status: PhaseStatus = PhaseStatus.PENDING
    items_total: int = 0
    items_processed: int = 0
    start_time: float | None = None
    end_time: float | None = None

    @property
    def progress_pct(self) -> float:
        """Calculate progress percentage."""
        if self.items_total == 0:
            return 0.0
        return (self.items_processed / self.items_total) * 100

    @property
    def elapsed_seconds(self) -> float:
        """Calculate elapsed time in seconds."""
        if self.start_time is None:
            return 0.0
        end = self.end_time if self.end_time else time.time()
        return end - self.start_time


@dataclass
class Activity:
    """Represents an activity log entry."""

    timestamp: float
    message: str

    @property
    def formatted_time(self) -> str:
        """Format timestamp as HH:MM:SS."""
        elapsed = time.time() - self.timestamp
        hours = int(elapsed // 3600)
        minutes = int((elapsed % 3600) // 60)
        seconds = int(elapsed % 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


@dataclass
class Finding:
    """Represents a detected finding."""

    severity: FindingSeverity
    title: str
    details: str = ""
    timestamp: float = 0.0

    def __post_init__(self):
        """Set timestamp if not provided."""
        if self.timestamp == 0.0:
            self.timestamp = time.time()


@dataclass
class Contradiction:
    """Represents a contradiction event detected and resolved."""

    description: str
    resolution: str
    timestamp: float = 0.0

    def __post_init__(self):
        """Set timestamp if not provided."""
        if self.timestamp == 0.0:
            self.timestamp = time.time()


@dataclass
class SystemResources:
    """Current system resource usage."""

    cpu_percent: float = 0.0
    ram_used_gb: float = 0.0
    ram_total_gb: float = 0.0
    disk_io_mb: float = 0.0

    @property
    def ram_percent(self) -> float:
        """Calculate RAM usage percentage."""
        if self.ram_total_gb == 0:
            return 0.0
        return (self.ram_used_gb / self.ram_total_gb) * 100

    @property
    def has_warning(self) -> bool:
        """Check if any resource exceeds warning threshold."""
        return self.ram_percent > 80 or self.cpu_percent > 90

    @property
    def warning_message(self) -> str | None:
        """Get resource warning message."""
        if self.ram_percent > 80:
            return (
                f"High memory usage ({self.ram_used_gb:.1f}/{self.ram_total_gb:.0f}GB)"
            )
        if self.cpu_percent > 90:
            return f"High CPU usage ({self.cpu_percent:.0f}%)"
        return None


class ProgressTracker:
    """Central progress tracking system for investigations."""

    def __init__(self):
        """Initialize progress tracker."""
        self.phases: list[Phase] = []
        self.current_phase: Phase | None = None
        self.findings_by_severity: dict[FindingSeverity, int] = {
            severity: 0 for severity in FindingSeverity
        }
        self.findings: list[Finding] = []  # Store actual findings, not just counts
        self.contradictions: list[Contradiction] = []  # Store contradiction events
        self.activities: list[Activity] = []
        self.system_resources = SystemResources()
        self.start_time = time.time()
        self.is_running = False
        self.is_canceled = False

        # Callbacks for UI updates
        self._on_progress_update: list[Callable] = []
        self._on_finding_added: list[Callable] = []
        self._on_activity_added: list[Callable] = []
        self._on_phase_changed: list[Callable] = []
        self._on_resources_updated: list[Callable] = []
        self._on_contradiction_added: list[Callable] = []

    def register_phases(self, phases: list[tuple[str, str]]) -> None:
        """Register investigation phases.

        Args:
            phases: List of (name, display_name) tuples
        """
        self.phases = [
            Phase(name=name, display_name=display_name) for name, display_name in phases
        ]

    def start_phase(self, phase_name: str, items_total: int = 0) -> None:
        """Start a new phase.

        Args:
            phase_name: Phase identifier
            items_total: Total number of items to process in this phase
        """
        # Complete current phase if any
        if self.current_phase:
            self.complete_phase()

        # Find and start new phase
        for phase in self.phases:
            if phase.name == phase_name:
                phase.status = PhaseStatus.ACTIVE
                phase.items_total = items_total
                phase.items_processed = 0
                phase.start_time = time.time()
                self.current_phase = phase
                self._notify_phase_changed(phase)
                self.log_activity(f"Started phase: {phase.display_name}")
                break

    def update_progress(self, items_processed: int) -> None:
        """Update progress for current phase.

        Args:
            items_processed: Number of items processed so far
        """
        if self.current_phase:
            self.current_phase.items_processed = items_processed
            self._notify_progress_update()

    def increment_progress(self) -> None:
        """Increment progress by 1 for current phase."""
        if self.current_phase:
            self.current_phase.items_processed += 1
            self._notify_progress_update()

    def complete_phase(self) -> None:
        """Mark current phase as complete."""
        if self.current_phase:
            self.current_phase.status = PhaseStatus.COMPLETE
            self.current_phase.end_time = time.time()
            self.log_activity(f"Completed phase: {self.current_phase.display_name}")
            self._notify_phase_changed(self.current_phase)
            self.current_phase = None

    def add_finding(
        self, severity: FindingSeverity, message: str, details: str = ""
    ) -> None:
        """Record a new finding.

        Args:
            severity: Finding severity level
            message: Finding description
            details: Additional finding details
        """
        finding = Finding(severity=severity, title=message, details=details)
        self.findings.append(finding)
        self.findings_by_severity[severity] += 1
        self.log_activity(f"{severity.value}: {message}")
        self._notify_finding_added(severity)

    def add_contradiction(self, description: str, resolution: str) -> None:
        """Record a contradiction event.

        Args:
            description: Description of the contradiction
            resolution: How the contradiction was resolved
        """
        contradiction = Contradiction(description=description, resolution=resolution)
        self.contradictions.append(contradiction)
        self.log_activity(f"Contradiction resolved: {description}")
        self._notify_contradiction_added(contradiction)

    def log_activity(self, message: str) -> None:
        """Log an activity event.

        Args:
            message: Activity description
        """
        activity = Activity(timestamp=time.time(), message=message)
        self.activities.insert(0, activity)  # Most recent first
        if len(self.activities) > 5:
            self.activities.pop()  # Keep only last 5
        self._notify_activity_added(activity)

    def update_resources(
        self,
        cpu_percent: float,
        ram_used_gb: float,
        ram_total_gb: float,
        disk_io_mb: float,
    ) -> None:
        """Update system resource metrics.

        Args:
            cpu_percent: CPU usage percentage
            ram_used_gb: RAM used in GB
            ram_total_gb: Total RAM in GB
            disk_io_mb: Disk I/O in MB/s
        """
        self.system_resources.cpu_percent = cpu_percent
        self.system_resources.ram_used_gb = ram_used_gb
        self.system_resources.ram_total_gb = ram_total_gb
        self.system_resources.disk_io_mb = disk_io_mb
        self._notify_resources_updated()

    def cancel(self) -> None:
        """Cancel the current investigation."""
        self.is_canceled = True
        self.is_running = False
        self.log_activity("Investigation canceled by user")

    @property
    def elapsed_time(self) -> str:
        """Get formatted elapsed time."""
        elapsed = time.time() - self.start_time
        hours = int(elapsed // 3600)
        minutes = int((elapsed % 3600) // 60)
        seconds = int(elapsed % 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    @property
    def estimated_time_remaining(self) -> str | None:
        """Calculate estimated time remaining."""
        if not self.current_phase or self.current_phase.items_total == 0:
            return None

        items_remaining = (
            self.current_phase.items_total - self.current_phase.items_processed
        )
        if items_remaining <= 0:
            return "00:00:00"

        elapsed = self.current_phase.elapsed_seconds
        if elapsed == 0 or self.current_phase.items_processed == 0:
            return None

        # Calculate velocity (items/second)
        velocity = self.current_phase.items_processed / elapsed
        if velocity == 0:
            return None

        # Estimate remaining time
        eta_seconds = items_remaining / velocity
        hours = int(eta_seconds // 3600)
        minutes = int((eta_seconds % 3600) // 60)
        seconds = int(eta_seconds % 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    # Callback registration methods
    def on_progress_update(self, callback: Callable) -> None:
        """Register callback for progress updates."""
        self._on_progress_update.append(callback)

    def on_finding_added(self, callback: Callable) -> None:
        """Register callback for new findings."""
        self._on_finding_added.append(callback)

    def on_activity_added(self, callback: Callable) -> None:
        """Register callback for new activities."""
        self._on_activity_added.append(callback)

    def on_phase_changed(self, callback: Callable) -> None:
        """Register callback for phase changes."""
        self._on_phase_changed.append(callback)

    def on_resources_updated(self, callback: Callable) -> None:
        """Register callback for resource updates."""
        self._on_resources_updated.append(callback)

    def on_contradiction_added(self, callback: Callable) -> None:
        """Register callback for contradiction events."""
        self._on_contradiction_added.append(callback)

    # Notification methods
    def _notify_progress_update(self) -> None:
        """Notify all progress update callbacks."""
        for callback in self._on_progress_update:
            callback()

    def _notify_finding_added(self, severity: FindingSeverity) -> None:
        """Notify all finding added callbacks."""
        for callback in self._on_finding_added:
            callback(severity)

    def _notify_activity_added(self, activity: Activity) -> None:
        """Notify all activity added callbacks."""
        for callback in self._on_activity_added:
            callback(activity)

    def _notify_phase_changed(self, phase: Phase) -> None:
        """Notify all phase changed callbacks."""
        for callback in self._on_phase_changed:
            callback(phase)

    def _notify_resources_updated(self) -> None:
        """Notify all resource update callbacks."""
        for callback in self._on_resources_updated:
            callback()

    def _notify_contradiction_added(self, contradiction: Contradiction) -> None:
        """Notify all contradiction added callbacks."""
        for callback in self._on_contradiction_added:
            callback(contradiction)
