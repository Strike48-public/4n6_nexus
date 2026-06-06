"""
Coverage-focused tests for resource_monitor.py.

Targets the psutil ImportError fallback branch (PSUTIL_AVAILABLE = False)
and the non-positive time_delta guard in disk I/O rate calculation.
"""

import builtins
import importlib
import sys
import unittest
from unittest.mock import Mock, patch

from sift_find_evil.resource_monitor import ResourceMonitor


class TestPsutilImportFallback(unittest.TestCase):
    """Drives the `except ImportError` branch (lines 14-15)."""

    def test_import_without_psutil_sets_flag_false(self):
        # Arrange: force `import psutil` to raise ImportError, then reimport
        # the module so the try/except at module scope runs the failure path.
        import sift_find_evil.resource_monitor as rm

        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "psutil":
                raise ImportError("psutil not installed")
            return real_import(name, *args, **kwargs)

        saved_psutil = sys.modules.pop("psutil", None)
        try:
            with patch.object(builtins, "__import__", side_effect=fake_import):
                reloaded = importlib.reload(rm)

            # Assert: the ImportError handler set the availability flag to False.
            self.assertFalse(reloaded.PSUTIL_AVAILABLE)

            # And behavior matches the documented fallback contract.
            monitor = reloaded.ResourceMonitor()
            resources = monitor.get_current_resources()
            self.assertEqual(resources["disk_io_mb"], 0.0)
            self.assertEqual(resources["cpu_percent"], 0.0)
        finally:
            # Restore a clean, real module state for other tests.
            if saved_psutil is not None:
                sys.modules["psutil"] = saved_psutil
            importlib.reload(rm)


class TestDiskIORateNonPositiveDelta(unittest.TestCase):
    """Drives the `time_delta <= 0` guard returning 0.0 (line 104)."""

    @patch("sift_find_evil.resource_monitor.PSUTIL_AVAILABLE", True)
    @patch("sift_find_evil.resource_monitor.psutil")
    @patch("time.time")
    def test_zero_time_delta_returns_zero(self, mock_time, mock_psutil):
        # Arrange: identical timestamps on both samples -> time_delta == 0,
        # so the rate calculation branch is skipped and the guard returns 0.0.
        monitor = ResourceMonitor()

        counters1 = Mock()
        counters1.read_bytes = 1000
        counters1.write_bytes = 2000
        mock_psutil.disk_io_counters.return_value = counters1
        mock_time.return_value = 500.0
        first = monitor._get_disk_io_rate()
        self.assertEqual(first, 0.0)  # first sample primes state

        counters2 = Mock()
        counters2.read_bytes = 1000 + (1024 * 1024)
        counters2.write_bytes = 2000 + (1024 * 1024)
        mock_psutil.disk_io_counters.return_value = counters2
        mock_time.return_value = 500.0  # same time -> delta 0

        # Act
        rate = monitor._get_disk_io_rate()

        # Assert: non-positive delta hits the `return 0.0` guard, not divide.
        self.assertEqual(rate, 0.0)


if __name__ == "__main__":
    unittest.main()
