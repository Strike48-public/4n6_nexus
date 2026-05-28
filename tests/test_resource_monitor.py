"""
Tests for resource_monitor.py - System resource monitoring.

Provides comprehensive coverage of resource retrieval, disk I/O calculation,
async monitoring loop, and error handling.
"""

import asyncio
import time
import unittest
from unittest.mock import Mock, patch

from sift_find_evil.resource_monitor import ResourceMonitor


class TestResourceMonitorBasicRetrieval(unittest.TestCase):
    """Tests for ResourceMonitor basic resource retrieval."""

    @patch("sift_find_evil.resource_monitor.PSUTIL_AVAILABLE", False)
    def test_get_current_resources_without_psutil_returns_fallback(self):
        # Arrange
        monitor = ResourceMonitor()

        # Act
        resources = monitor.get_current_resources()

        # Assert
        self.assertEqual(resources["cpu_percent"], 0.0)
        self.assertEqual(resources["ram_used_gb"], 0.0)
        self.assertEqual(resources["ram_total_gb"], 0.0)
        self.assertEqual(resources["disk_io_mb"], 0.0)

    @patch("sift_find_evil.resource_monitor.PSUTIL_AVAILABLE", True)
    @patch("sift_find_evil.resource_monitor.psutil")
    def test_get_current_resources_with_psutil_returns_real_metrics(self, mock_psutil):
        # Arrange
        monitor = ResourceMonitor()
        mock_psutil.cpu_percent.return_value = 45.5
        mock_memory = Mock()
        mock_memory.used = 8 * (1024**3)  # 8 GB
        mock_memory.total = 16 * (1024**3)  # 16 GB
        mock_psutil.virtual_memory.return_value = mock_memory
        mock_psutil.disk_io_counters.return_value = None  # First call returns None

        # Act
        resources = monitor.get_current_resources()

        # Assert
        self.assertEqual(resources["cpu_percent"], 45.5)
        self.assertEqual(resources["ram_used_gb"], 8.0)
        self.assertEqual(resources["ram_total_gb"], 16.0)
        self.assertEqual(resources["disk_io_mb"], 0.0)  # First sample

    @patch("sift_find_evil.resource_monitor.PSUTIL_AVAILABLE", True)
    @patch("sift_find_evil.resource_monitor.psutil")
    def test_get_current_resources_handles_psutil_exception(self, mock_psutil):
        # Arrange
        monitor = ResourceMonitor()
        mock_psutil.cpu_percent.side_effect = Exception("psutil error")

        # Act & Assert
        with self.assertRaises(Exception):
            monitor.get_current_resources()


class TestResourceMonitorDiskIO(unittest.TestCase):
    """Tests for ResourceMonitor disk I/O rate calculation."""

    @patch("sift_find_evil.resource_monitor.PSUTIL_AVAILABLE", False)
    def test_disk_io_rate_without_psutil_returns_zero(self):
        # Arrange
        monitor = ResourceMonitor()

        # Act
        rate = monitor._get_disk_io_rate()

        # Assert
        self.assertEqual(rate, 0.0)

    @patch("sift_find_evil.resource_monitor.PSUTIL_AVAILABLE", True)
    @patch("sift_find_evil.resource_monitor.psutil")
    def test_disk_io_rate_first_sample_returns_zero(self, mock_psutil):
        # Arrange
        monitor = ResourceMonitor()
        mock_counters = Mock()
        mock_counters.read_bytes = 1000
        mock_counters.write_bytes = 2000
        mock_psutil.disk_io_counters.return_value = mock_counters

        # Act
        rate = monitor._get_disk_io_rate()

        # Assert
        self.assertEqual(rate, 0.0)
        self.assertIsNotNone(monitor._last_disk_counters)

    @patch("sift_find_evil.resource_monitor.PSUTIL_AVAILABLE", True)
    @patch("sift_find_evil.resource_monitor.psutil")
    @patch("time.time")
    def test_disk_io_rate_second_sample_calculates_rate(self, mock_time, mock_psutil):
        # Arrange
        monitor = ResourceMonitor()

        # First sample
        mock_counters1 = Mock()
        mock_counters1.read_bytes = 1000
        mock_counters1.write_bytes = 2000
        mock_psutil.disk_io_counters.return_value = mock_counters1
        mock_time.return_value = 100.0
        monitor._get_disk_io_rate()

        # Second sample (1 second later, 1 MB more data)
        mock_counters2 = Mock()
        mock_counters2.read_bytes = 1000 + (512 * 1024)  # +512 KB
        mock_counters2.write_bytes = 2000 + (512 * 1024)  # +512 KB
        mock_psutil.disk_io_counters.return_value = mock_counters2
        mock_time.return_value = 101.0

        # Act
        rate = monitor._get_disk_io_rate()

        # Assert
        # 1 MB in 1 second = 1 MB/s
        self.assertAlmostEqual(rate, 1.0, places=2)

    @patch("sift_find_evil.resource_monitor.PSUTIL_AVAILABLE", True)
    @patch("sift_find_evil.resource_monitor.psutil")
    def test_disk_io_rate_handles_missing_disk_counters(self, mock_psutil):
        # Arrange
        monitor = ResourceMonitor()
        mock_psutil.disk_io_counters.return_value = None

        # Act
        rate = monitor._get_disk_io_rate()

        # Assert
        self.assertEqual(rate, 0.0)

    @patch("sift_find_evil.resource_monitor.PSUTIL_AVAILABLE", True)
    @patch("sift_find_evil.resource_monitor.psutil")
    def test_disk_io_rate_handles_attribute_error(self, mock_psutil):
        # Arrange
        monitor = ResourceMonitor()
        mock_psutil.disk_io_counters.side_effect = AttributeError("No such attribute")

        # Act
        rate = monitor._get_disk_io_rate()

        # Assert
        self.assertEqual(rate, 0.0)

    @patch("sift_find_evil.resource_monitor.PSUTIL_AVAILABLE", True)
    @patch("sift_find_evil.resource_monitor.psutil")
    def test_disk_io_rate_handles_os_error(self, mock_psutil):
        # Arrange
        monitor = ResourceMonitor()
        mock_psutil.disk_io_counters.side_effect = OSError("Disk error")

        # Act
        rate = monitor._get_disk_io_rate()

        # Assert
        self.assertEqual(rate, 0.0)


class TestResourceMonitorAsyncLoop(unittest.TestCase):
    """Tests for ResourceMonitor async monitoring loop."""

    @patch("sift_find_evil.resource_monitor.PSUTIL_AVAILABLE", True)
    @patch("sift_find_evil.resource_monitor.psutil")
    def test_monitor_loop_calls_callback_with_metrics(self, mock_psutil):
        # Arrange
        monitor = ResourceMonitor(interval=0.1)
        mock_psutil.cpu_percent.return_value = 50.0
        mock_memory = Mock()
        mock_memory.used = 8 * (1024**3)
        mock_memory.total = 16 * (1024**3)
        mock_psutil.virtual_memory.return_value = mock_memory
        mock_psutil.disk_io_counters.return_value = None

        callback = Mock()
        call_count = 0

        def stop_after_two_calls(resources):
            nonlocal call_count
            call_count += 1
            callback(resources)
            if call_count >= 2:
                monitor.stop()

        # Act
        asyncio.run(monitor.monitor_loop(stop_after_two_calls))

        # Assert
        self.assertEqual(callback.call_count, 2)
        self.assertEqual(callback.call_args[0][0]["cpu_percent"], 50.0)
        self.assertEqual(callback.call_args[0][0]["ram_used_gb"], 8.0)

    @patch("sift_find_evil.resource_monitor.PSUTIL_AVAILABLE", True)
    @patch("sift_find_evil.resource_monitor.psutil")
    def test_monitor_loop_respects_interval(self, mock_psutil):
        # Arrange
        monitor = ResourceMonitor(interval=0.2)
        mock_psutil.cpu_percent.return_value = 50.0
        mock_memory = Mock()
        mock_memory.used = 8 * (1024**3)
        mock_memory.total = 16 * (1024**3)
        mock_psutil.virtual_memory.return_value = mock_memory
        mock_psutil.disk_io_counters.return_value = None

        callback = Mock()
        start_time = time.time()

        def stop_after_one_call(resources):
            callback(resources)
            monitor.stop()

        # Act
        asyncio.run(monitor.monitor_loop(stop_after_one_call))
        elapsed = time.time() - start_time

        # Assert
        # Should have called callback, then slept ~0.2s, then checked is_running
        self.assertGreaterEqual(elapsed, 0.15)

    @patch("sift_find_evil.resource_monitor.PSUTIL_AVAILABLE", True)
    @patch("sift_find_evil.resource_monitor.psutil")
    def test_monitor_loop_handles_callback_exception(self, mock_psutil):
        # Arrange
        monitor = ResourceMonitor(interval=0.1)
        mock_psutil.cpu_percent.return_value = 50.0
        mock_memory = Mock()
        mock_memory.used = 8 * (1024**3)
        mock_memory.total = 16 * (1024**3)
        mock_psutil.virtual_memory.return_value = mock_memory
        mock_psutil.disk_io_counters.return_value = None

        call_count = 0

        def failing_callback(resources):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ValueError("Callback error")
            monitor.stop()

        # Act & Assert
        # The exception should propagate and stop the loop
        with self.assertRaises(ValueError):
            asyncio.run(monitor.monitor_loop(failing_callback))

    def test_stop_sets_is_running_false(self):
        # Arrange
        monitor = ResourceMonitor()
        monitor.is_running = True

        # Act
        monitor.stop()

        # Assert
        self.assertFalse(monitor.is_running)

    @patch("sift_find_evil.resource_monitor.PSUTIL_AVAILABLE", True)
    @patch("sift_find_evil.resource_monitor.psutil")
    def test_stop_cancels_running_loop(self, mock_psutil):
        # Arrange
        monitor = ResourceMonitor(interval=0.1)
        mock_psutil.cpu_percent.return_value = 50.0
        mock_memory = Mock()
        mock_memory.used = 8 * (1024**3)
        mock_memory.total = 16 * (1024**3)
        mock_psutil.virtual_memory.return_value = mock_memory
        mock_psutil.disk_io_counters.return_value = None

        callback = Mock()

        async def run_and_stop():
            # Start monitoring in background
            task = asyncio.create_task(monitor.monitor_loop(callback))
            await asyncio.sleep(0.3)  # Let it run for a bit
            monitor.stop()
            await task

        # Act
        asyncio.run(run_and_stop())

        # Assert
        # Callback should have been called at least once
        self.assertGreaterEqual(callback.call_count, 1)
        self.assertFalse(monitor.is_running)


if __name__ == "__main__":
    unittest.main()
