"""
Tests for progress_tracker.py - Progress tracking system.

Provides comprehensive coverage of phase management, progress tracking,
findings, contradictions, activity logging, callbacks, resource tracking,
and time calculations.
"""

import time
import unittest
from unittest.mock import Mock

from sift_find_evil.progress_tracker import (
    Activity,
    Contradiction,
    Finding,
    FindingSeverity,
    Phase,
    PhaseStatus,
    ProgressTracker,
    SystemResources,
)


class TestPhase(unittest.TestCase):
    """Tests for Phase dataclass."""

    def test_phase_progress_pct_calculates_correctly(self):
        # Arrange
        phase = Phase(
            name="test", display_name="Test", items_total=100, items_processed=25
        )

        # Act
        progress = phase.progress_pct

        # Assert
        self.assertEqual(progress, 25.0)

    def test_phase_progress_pct_returns_zero_when_no_items(self):
        # Arrange
        phase = Phase(
            name="test", display_name="Test", items_total=0, items_processed=0
        )

        # Act
        progress = phase.progress_pct

        # Assert
        self.assertEqual(progress, 0.0)

    def test_phase_elapsed_seconds(self):
        # Arrange
        start_time = time.time() - 5.0
        phase = Phase(name="test", display_name="Test", start_time=start_time)

        # Act
        elapsed = phase.elapsed_seconds

        # Assert
        self.assertGreaterEqual(elapsed, 4.9)
        self.assertLessEqual(elapsed, 5.5)

    def test_phase_elapsed_seconds_handles_no_start_time(self):
        # Arrange
        phase = Phase(name="test", display_name="Test", start_time=None)

        # Act
        elapsed = phase.elapsed_seconds

        # Assert
        self.assertEqual(elapsed, 0.0)

    def test_phase_elapsed_seconds_with_end_time(self):
        # Arrange
        start_time = 1000.0
        end_time = 1010.0
        phase = Phase(
            name="test", display_name="Test", start_time=start_time, end_time=end_time
        )

        # Act
        elapsed = phase.elapsed_seconds

        # Assert
        self.assertEqual(elapsed, 10.0)


class TestActivity(unittest.TestCase):
    """Tests for Activity dataclass."""

    def test_activity_formatted_time(self):
        # Arrange
        timestamp = time.time() - 3665  # 1 hour, 1 minute, 5 seconds ago
        activity = Activity(timestamp=timestamp, message="Test")

        # Act
        formatted = activity.formatted_time

        # Assert
        self.assertRegex(formatted, r"01:01:\d{2}")  # HH:MM:SS format


class TestFinding(unittest.TestCase):
    """Tests for Finding dataclass."""

    def test_finding_auto_timestamp(self):
        # Arrange
        before = time.time()

        # Act
        finding = Finding(
            severity=FindingSeverity.HIGH, title="Test", details="Details"
        )

        # Assert
        after = time.time()
        self.assertGreaterEqual(finding.timestamp, before)
        self.assertLessEqual(finding.timestamp, after)

    def test_finding_with_explicit_timestamp(self):
        # Arrange
        explicit_time = 1234567890.0

        # Act
        finding = Finding(
            severity=FindingSeverity.HIGH,
            title="Test",
            details="Details",
            timestamp=explicit_time,
        )

        # Assert
        self.assertEqual(finding.timestamp, explicit_time)


class TestContradiction(unittest.TestCase):
    """Tests for Contradiction dataclass."""

    def test_contradiction_auto_timestamp(self):
        # Arrange
        before = time.time()

        # Act
        contradiction = Contradiction(description="Test", resolution="Resolved")

        # Assert
        after = time.time()
        self.assertGreaterEqual(contradiction.timestamp, before)
        self.assertLessEqual(contradiction.timestamp, after)

    def test_contradiction_with_explicit_timestamp(self):
        # Arrange
        explicit_time = 1234567890.0

        # Act
        contradiction = Contradiction(
            description="Test", resolution="Resolved", timestamp=explicit_time
        )

        # Assert
        self.assertEqual(contradiction.timestamp, explicit_time)


class TestSystemResources(unittest.TestCase):
    """Tests for SystemResources dataclass."""

    def test_system_resources_ram_percent(self):
        # Arrange
        resources = SystemResources(ram_used_gb=8.0, ram_total_gb=16.0)

        # Act
        ram_pct = resources.ram_percent

        # Assert
        self.assertEqual(ram_pct, 50.0)

    def test_system_resources_ram_percent_zero_total(self):
        # Arrange
        resources = SystemResources(ram_used_gb=8.0, ram_total_gb=0.0)

        # Act
        ram_pct = resources.ram_percent

        # Assert
        self.assertEqual(ram_pct, 0.0)

    def test_system_resources_has_warning_high_ram(self):
        # Arrange
        resources = SystemResources(
            ram_used_gb=17.0, ram_total_gb=20.0, cpu_percent=50.0
        )

        # Act
        has_warning = resources.has_warning

        # Assert
        self.assertTrue(has_warning)

    def test_system_resources_has_warning_high_cpu(self):
        # Arrange
        resources = SystemResources(
            ram_used_gb=8.0, ram_total_gb=16.0, cpu_percent=95.0
        )

        # Act
        has_warning = resources.has_warning

        # Assert
        self.assertTrue(has_warning)

    def test_system_resources_no_warning(self):
        # Arrange
        resources = SystemResources(
            ram_used_gb=8.0, ram_total_gb=16.0, cpu_percent=50.0
        )

        # Act
        has_warning = resources.has_warning

        # Assert
        self.assertFalse(has_warning)

    def test_system_resources_warning_message_ram(self):
        # Arrange
        resources = SystemResources(
            ram_used_gb=17.0, ram_total_gb=20.0, cpu_percent=50.0
        )

        # Act
        message = resources.warning_message

        # Assert
        self.assertIn("High memory usage", message)
        self.assertIn("17.0", message)
        self.assertIn("20", message)

    def test_system_resources_warning_message_cpu(self):
        # Arrange
        resources = SystemResources(
            ram_used_gb=8.0, ram_total_gb=16.0, cpu_percent=95.0
        )

        # Act
        message = resources.warning_message

        # Assert
        self.assertIn("High CPU usage", message)
        self.assertIn("95", message)

    def test_system_resources_no_warning_message(self):
        # Arrange
        resources = SystemResources(
            ram_used_gb=8.0, ram_total_gb=16.0, cpu_percent=50.0
        )

        # Act
        message = resources.warning_message

        # Assert
        self.assertIsNone(message)


class TestProgressTrackerStateManagement(unittest.TestCase):
    """Tests for ProgressTracker state management."""

    def test_register_phases_creates_phase_objects(self):
        # Arrange
        tracker = ProgressTracker()
        phases = [("phase1", "Phase 1"), ("phase2", "Phase 2")]

        # Act
        tracker.register_phases(phases)

        # Assert
        self.assertEqual(len(tracker.phases), 2)
        self.assertEqual(tracker.phases[0].name, "phase1")
        self.assertEqual(tracker.phases[0].display_name, "Phase 1")
        self.assertEqual(tracker.phases[1].name, "phase2")
        self.assertEqual(tracker.phases[1].display_name, "Phase 2")

    def test_start_phase_sets_active_status_and_time(self):
        # Arrange
        tracker = ProgressTracker()
        tracker.register_phases([("phase1", "Phase 1")])
        before = time.time()

        # Act
        tracker.start_phase("phase1", items_total=100)

        # Assert
        phase = tracker.phases[0]
        self.assertEqual(phase.status, PhaseStatus.ACTIVE)
        self.assertEqual(phase.items_total, 100)
        self.assertEqual(phase.items_processed, 0)
        self.assertIsNotNone(phase.start_time)
        self.assertGreaterEqual(phase.start_time, before)
        self.assertEqual(tracker.current_phase, phase)

    def test_start_phase_completes_previous_phase(self):
        # Arrange
        tracker = ProgressTracker()
        tracker.register_phases([("phase1", "Phase 1"), ("phase2", "Phase 2")])
        tracker.start_phase("phase1", items_total=100)
        phase1 = tracker.phases[0]

        # Act
        tracker.start_phase("phase2", items_total=50)

        # Assert
        self.assertEqual(phase1.status, PhaseStatus.COMPLETE)
        self.assertIsNotNone(phase1.end_time)
        self.assertEqual(tracker.current_phase, tracker.phases[1])

    def test_complete_phase_sets_status_and_end_time(self):
        # Arrange
        tracker = ProgressTracker()
        tracker.register_phases([("phase1", "Phase 1")])
        tracker.start_phase("phase1", items_total=100)
        phase = tracker.phases[0]
        before = time.time()

        # Act
        tracker.complete_phase()

        # Assert
        self.assertEqual(phase.status, PhaseStatus.COMPLETE)
        self.assertIsNotNone(phase.end_time)
        self.assertGreaterEqual(phase.end_time, before)
        self.assertIsNone(tracker.current_phase)

    def test_cancel_sets_flags(self):
        # Arrange
        tracker = ProgressTracker()

        # Act
        tracker.cancel()

        # Assert
        self.assertTrue(tracker.is_canceled)
        self.assertFalse(tracker.is_running)


class TestProgressTrackerProgress(unittest.TestCase):
    """Tests for ProgressTracker progress tracking."""

    def test_update_progress_sets_items_processed(self):
        # Arrange
        tracker = ProgressTracker()
        tracker.register_phases([("phase1", "Phase 1")])
        tracker.start_phase("phase1", items_total=100)

        # Act
        tracker.update_progress(25)

        # Assert
        self.assertEqual(tracker.current_phase.items_processed, 25)

    def test_increment_progress_advances_by_one(self):
        # Arrange
        tracker = ProgressTracker()
        tracker.register_phases([("phase1", "Phase 1")])
        tracker.start_phase("phase1", items_total=100)

        # Act
        tracker.increment_progress()
        tracker.increment_progress()

        # Assert
        self.assertEqual(tracker.current_phase.items_processed, 2)


class TestProgressTrackerFindings(unittest.TestCase):
    """Tests for ProgressTracker findings and contradictions."""

    def test_add_finding_increments_severity_counter(self):
        # Arrange
        tracker = ProgressTracker()

        # Act
        tracker.add_finding(FindingSeverity.HIGH, "Test finding", "Details")

        # Assert
        self.assertEqual(tracker.findings_by_severity[FindingSeverity.HIGH], 1)

    def test_add_finding_stores_finding_object(self):
        # Arrange
        tracker = ProgressTracker()

        # Act
        tracker.add_finding(FindingSeverity.HIGH, "Test finding", "Details")

        # Assert
        self.assertEqual(len(tracker.findings), 1)
        finding = tracker.findings[0]
        self.assertEqual(finding.severity, FindingSeverity.HIGH)
        self.assertEqual(finding.title, "Test finding")
        self.assertEqual(finding.details, "Details")

    def test_add_contradiction_stores_event(self):
        # Arrange
        tracker = ProgressTracker()

        # Act
        tracker.add_contradiction("Contradiction detected", "Resolved via method X")

        # Assert
        self.assertEqual(len(tracker.contradictions), 1)
        contradiction = tracker.contradictions[0]
        self.assertEqual(contradiction.description, "Contradiction detected")
        self.assertEqual(contradiction.resolution, "Resolved via method X")


class TestProgressTrackerActivityLog(unittest.TestCase):
    """Tests for ProgressTracker activity logging."""

    def test_log_activity_keeps_last_five(self):
        # Arrange
        tracker = ProgressTracker()

        # Act
        for i in range(10):
            tracker.log_activity(f"Activity {i}")

        # Assert
        self.assertEqual(len(tracker.activities), 5)
        # Most recent should be first
        self.assertEqual(tracker.activities[0].message, "Activity 9")
        self.assertEqual(tracker.activities[4].message, "Activity 5")

    def test_log_activity_auto_timestamps(self):
        # Arrange
        tracker = ProgressTracker()
        before = time.time()

        # Act
        tracker.log_activity("Test activity")

        # Assert
        after = time.time()
        activity = tracker.activities[0]
        self.assertGreaterEqual(activity.timestamp, before)
        self.assertLessEqual(activity.timestamp, after)


class TestProgressTrackerCallbacks(unittest.TestCase):
    """Tests for ProgressTracker callback system."""

    def test_callback_registration_and_notification_on_phase_start(self):
        # Arrange
        tracker = ProgressTracker()
        tracker.register_phases([("phase1", "Phase 1")])
        callback = Mock()
        tracker.on_phase_changed(callback)

        # Act
        tracker.start_phase("phase1", items_total=100)

        # Assert
        callback.assert_called_once()
        self.assertEqual(callback.call_args[0][0], tracker.phases[0])

    def test_callback_registration_and_notification_on_progress(self):
        # Arrange
        tracker = ProgressTracker()
        tracker.register_phases([("phase1", "Phase 1")])
        tracker.start_phase("phase1", items_total=100)
        callback = Mock()
        tracker.on_progress_update(callback)

        # Act
        tracker.update_progress(25)

        # Assert
        callback.assert_called_once()

    def test_callback_registration_and_notification_on_finding(self):
        # Arrange
        tracker = ProgressTracker()
        callback = Mock()
        tracker.on_finding_added(callback)

        # Act
        tracker.add_finding(FindingSeverity.HIGH, "Test finding")

        # Assert
        callback.assert_called_once_with(FindingSeverity.HIGH)

    def test_callback_registration_and_notification_on_contradiction(self):
        # Arrange
        tracker = ProgressTracker()
        callback = Mock()
        tracker.on_contradiction_added(callback)

        # Act
        tracker.add_contradiction("Test", "Resolved")

        # Assert
        callback.assert_called_once()
        self.assertEqual(callback.call_args[0][0].description, "Test")

    def test_callback_registration_and_notification_on_resource_update(self):
        # Arrange
        tracker = ProgressTracker()
        callback = Mock()
        tracker.on_resources_updated(callback)

        # Act
        tracker.update_resources(50.0, 8.0, 16.0, 100.0)

        # Assert
        callback.assert_called_once()

    def test_callback_registration_and_notification_on_activity(self):
        # Arrange
        tracker = ProgressTracker()
        callback = Mock()
        tracker.on_activity_added(callback)

        # Act
        tracker.log_activity("Test")

        # Assert
        callback.assert_called_once()
        self.assertEqual(callback.call_args[0][0].message, "Test")


class TestProgressTrackerResources(unittest.TestCase):
    """Tests for ProgressTracker resource tracking."""

    def test_update_resources_stores_metrics(self):
        # Arrange
        tracker = ProgressTracker()

        # Act
        tracker.update_resources(
            cpu_percent=75.0, ram_used_gb=12.0, ram_total_gb=16.0, disk_io_mb=50.0
        )

        # Assert
        self.assertEqual(tracker.system_resources.cpu_percent, 75.0)
        self.assertEqual(tracker.system_resources.ram_used_gb, 12.0)
        self.assertEqual(tracker.system_resources.ram_total_gb, 16.0)
        self.assertEqual(tracker.system_resources.disk_io_mb, 50.0)


class TestProgressTrackerTimeCalculations(unittest.TestCase):
    """Tests for ProgressTracker time calculations."""

    def test_elapsed_time_formats_correctly(self):
        # Arrange
        tracker = ProgressTracker()
        tracker.start_time = time.time() - 3665  # 1 hour, 1 minute, 5 seconds

        # Act
        elapsed = tracker.elapsed_time

        # Assert
        self.assertRegex(elapsed, r"01:01:\d{2}")

    def test_estimated_time_remaining_computes_eta(self):
        # Arrange
        tracker = ProgressTracker()
        tracker.register_phases([("phase1", "Phase 1")])
        tracker.start_phase("phase1", items_total=100)
        # Simulate 25 items processed in 10 seconds
        tracker.current_phase.start_time = time.time() - 10.0
        tracker.update_progress(25)

        # Act
        eta = tracker.estimated_time_remaining

        # Assert
        # 25 items in 10s = 2.5 items/s
        # 75 items remaining / 2.5 items/s = 30s
        self.assertIsNotNone(eta)
        self.assertRegex(eta, r"00:00:\d{2}")

    def test_estimated_time_remaining_returns_none_when_no_phase(self):
        # Arrange
        tracker = ProgressTracker()

        # Act
        eta = tracker.estimated_time_remaining

        # Assert
        self.assertIsNone(eta)

    def test_estimated_time_remaining_handles_zero_progress(self):
        # Arrange
        tracker = ProgressTracker()
        tracker.register_phases([("phase1", "Phase 1")])
        tracker.start_phase("phase1", items_total=100)
        tracker.current_phase.start_time = time.time()

        # Act
        eta = tracker.estimated_time_remaining

        # Assert
        self.assertIsNone(eta)

    def test_estimated_time_remaining_returns_zero_when_complete(self):
        # Arrange
        tracker = ProgressTracker()
        tracker.register_phases([("phase1", "Phase 1")])
        tracker.start_phase("phase1", items_total=100)
        tracker.current_phase.start_time = time.time() - 10.0
        tracker.update_progress(100)

        # Act
        eta = tracker.estimated_time_remaining

        # Assert
        self.assertEqual(eta, "00:00:00")


if __name__ == "__main__":
    unittest.main()
