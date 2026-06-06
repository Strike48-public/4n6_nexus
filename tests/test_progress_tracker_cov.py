"""
Coverage-focused tests for progress_tracker.py.

Targets the velocity==0 guard in ProgressTracker.estimated_time_remaining
(the branch that returns None when computed velocity collapses to zero),
which is not exercised by the existing suite.
"""

import math
import unittest

from sift_find_evil.progress_tracker import ProgressTracker


class TestEstimatedTimeRemainingZeroVelocity(unittest.TestCase):
    """Drive the velocity==0 guard in estimated_time_remaining."""

    def test_returns_none_when_velocity_rounds_to_zero(self):
        # Arrange: items_processed is positive (so the items_processed==0
        # guard is bypassed) but elapsed is infinite, making the computed
        # velocity (items_processed / elapsed) collapse to exactly 0.0.
        tracker = ProgressTracker()
        tracker.register_phases([("phase1", "Phase 1")])
        tracker.start_phase("phase1", items_total=100)
        # -inf start_time -> elapsed = time.time() - (-inf) = +inf, nonzero.
        tracker.current_phase.start_time = -math.inf
        tracker.update_progress(25)

        # Sanity: this configuration genuinely produces zero velocity.
        elapsed = tracker.current_phase.elapsed_seconds
        self.assertTrue(math.isinf(elapsed))
        self.assertEqual(tracker.current_phase.items_processed / elapsed, 0.0)

        # Act
        eta = tracker.estimated_time_remaining

        # Assert: the velocity==0 branch returns None.
        self.assertIsNone(eta)


if __name__ == "__main__":
    unittest.main()
