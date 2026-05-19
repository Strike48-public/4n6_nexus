"""
System resource monitoring for TUI progress tracking.

Monitors CPU, RAM, and disk I/O metrics at regular intervals.
"""

import time
from typing import Callable

try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class ResourceMonitor:
    """Monitors system resource usage."""

    def __init__(self, interval: float = 5.0):
        """Initialize resource monitor.

        Args:
            interval: Sampling interval in seconds (default: 5.0)
        """
        self.interval = interval
        self.is_running = False
        self._last_disk_counters = None
        self._last_disk_time = None

    def get_current_resources(self) -> dict:
        """Get current system resource metrics.

        Returns:
            Dictionary with cpu_percent, ram_used_gb, ram_total_gb, disk_io_mb
        """
        if not PSUTIL_AVAILABLE:
            # Return mock data if psutil not available
            return {
                "cpu_percent": 0.0,
                "ram_used_gb": 0.0,
                "ram_total_gb": 0.0,
                "disk_io_mb": 0.0,
            }

        # CPU usage (non-blocking)
        cpu_percent = psutil.cpu_percent(interval=0)

        # Memory usage
        memory = psutil.virtual_memory()
        ram_used_gb = memory.used / (1024**3)
        ram_total_gb = memory.total / (1024**3)

        # Disk I/O
        disk_io_mb = self._get_disk_io_rate()

        return {
            "cpu_percent": cpu_percent,
            "ram_used_gb": ram_used_gb,
            "ram_total_gb": ram_total_gb,
            "disk_io_mb": disk_io_mb,
        }

    def _get_disk_io_rate(self) -> float:
        """Calculate disk I/O rate in MB/s.

        Returns:
            Disk I/O rate in MB/s
        """
        if not PSUTIL_AVAILABLE:
            return 0.0

        try:
            current_counters = psutil.disk_io_counters()
            current_time = time.time()

            if self._last_disk_counters is None:
                # First sample - no rate available yet
                self._last_disk_counters = current_counters
                self._last_disk_time = current_time
                return 0.0

            # Calculate bytes read/written since last sample
            bytes_read = (
                current_counters.read_bytes - self._last_disk_counters.read_bytes
            )
            bytes_written = (
                current_counters.write_bytes - self._last_disk_counters.write_bytes
            )
            total_bytes = bytes_read + bytes_written

            # Calculate time delta
            time_delta = current_time - self._last_disk_time

            # Update last sample
            self._last_disk_counters = current_counters
            self._last_disk_time = current_time

            # Convert to MB/s
            if time_delta > 0:
                mb_per_second = (total_bytes / time_delta) / (1024**2)
                return mb_per_second
            return 0.0

        except (AttributeError, OSError):
            # Disk counters not available on this system
            return 0.0

    async def monitor_loop(self, callback: Callable) -> None:
        """Run monitoring loop that calls callback with resource updates.

        Args:
            callback: Function to call with resource dict
        """
        import asyncio

        self.is_running = True
        while self.is_running:
            resources = self.get_current_resources()
            callback(resources)
            await asyncio.sleep(self.interval)

    def stop(self) -> None:
        """Stop monitoring loop."""
        self.is_running = False
