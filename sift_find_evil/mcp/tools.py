"""MCP tool wrappers for forensic applications."""

from pathlib import Path
from typing import Optional

from .client import MCPClient, MCPToolResult


class VolatilityTool:
    """Wrapper for Volatility 3 memory analysis."""

    def __init__(self, mcp_client: MCPClient, vol_path: str = "vol.py"):
        """Initialize Volatility wrapper.

        Args:
            mcp_client: MCP client instance
            vol_path: Path to vol.py (default: "vol.py")
        """
        self.mcp = mcp_client
        self.vol_path = vol_path

    def pslist(self, memory_file: Path, output_format: str = "json") -> MCPToolResult:
        """Run windows.pslist plugin.

        Args:
            memory_file: Path to memory dump
            output_format: Output format (json, csv)

        Returns:
            MCPToolResult with process list
        """
        command = [
            self.vol_path,
            "-f",
            str(memory_file),
            "-r",
            output_format,
            "windows.pslist",
        ]
        return self.mcp.execute_tool("volatility", command)

    def netscan(self, memory_file: Path, output_format: str = "json") -> MCPToolResult:
        """Run windows.netscan plugin.

        Args:
            memory_file: Path to memory dump
            output_format: Output format (json, csv)

        Returns:
            MCPToolResult with network connections
        """
        command = [
            self.vol_path,
            "-f",
            str(memory_file),
            "-r",
            output_format,
            "windows.netscan",
        ]
        return self.mcp.execute_tool("volatility", command)

    def malfind(self, memory_file: Path, output_format: str = "json") -> MCPToolResult:
        """Run windows.malfind plugin.

        Args:
            memory_file: Path to memory dump
            output_format: Output format (json, csv)

        Returns:
            MCPToolResult with injected code detections
        """
        command = [
            self.vol_path,
            "-f",
            str(memory_file),
            "-r",
            output_format,
            "windows.malfind",
        ]
        return self.mcp.execute_tool("volatility", command)

    def cmdline(self, memory_file: Path, output_format: str = "json") -> MCPToolResult:
        """Run windows.cmdline plugin.

        Args:
            memory_file: Path to memory dump
            output_format: Output format (json, csv)

        Returns:
            MCPToolResult with command lines
        """
        command = [
            self.vol_path,
            "-f",
            str(memory_file),
            "-r",
            output_format,
            "windows.cmdline",
        ]
        return self.mcp.execute_tool("volatility", command)


class SleuthKitTool:
    """Wrapper for Sleuth Kit filesystem analysis."""

    def __init__(self, mcp_client: MCPClient):
        """Initialize Sleuth Kit wrapper.

        Args:
            mcp_client: MCP client instance
        """
        self.mcp = mcp_client

    def fls(
        self,
        image_file: Path,
        partition_offset: Optional[int] = None,
        recursive: bool = True,
    ) -> MCPToolResult:
        """List files in filesystem.

        Args:
            image_file: Path to disk image
            partition_offset: Byte offset to partition (optional)
            recursive: Recursive listing

        Returns:
            MCPToolResult with file listing
        """
        command = ["fls"]
        if recursive:
            command.append("-r")
        if partition_offset:
            command.extend(["-o", str(partition_offset)])
        command.append(str(image_file))

        return self.mcp.execute_tool("sleuthkit", command)

    def icat(
        self, image_file: Path, inode: int, partition_offset: Optional[int] = None
    ) -> MCPToolResult:
        """Extract file contents by inode.

        Args:
            image_file: Path to disk image
            inode: Inode number
            partition_offset: Byte offset to partition (optional)

        Returns:
            MCPToolResult with file contents
        """
        command = ["icat"]
        if partition_offset:
            command.extend(["-o", str(partition_offset)])
        command.extend([str(image_file), str(inode)])

        return self.mcp.execute_tool("sleuthkit", command)

    def mmls(self, image_file: Path) -> MCPToolResult:
        """Display partition layout.

        Args:
            image_file: Path to disk image

        Returns:
            MCPToolResult with partition table
        """
        command = ["mmls", str(image_file)]
        return self.mcp.execute_tool("sleuthkit", command)

    def mactime(
        self, body_file: Path, date_format: str = "%Y-%m-%d %H:%M:%S"
    ) -> MCPToolResult:
        """Generate timeline from body file.

        Args:
            body_file: Path to body file (from fls -m)
            date_format: strftime format string

        Returns:
            MCPToolResult with timeline
        """
        command = ["mactime", "-b", str(body_file), "-d", "-z", "UTC"]
        return self.mcp.execute_tool("sleuthkit", command)


class EZToolsTool:
    """Wrapper for Eric Zimmerman's forensic tools."""

    def __init__(
        self,
        mcp_client: MCPClient,
        mftecmd_path: str = "mftecmd",
        pecmd_path: str = "pecmd",
        evtxecmd_path: str = "evtxecmd",
        recmd_path: str = "recmd",
    ):
        """Initialize EZ Tools wrapper.

        Args:
            mcp_client: MCP client instance
            mftecmd_path: Path to MFTECmd (default: "mftecmd")
            pecmd_path: Path to PECmd (default: "pecmd")
            evtxecmd_path: Path to EvtxECmd (default: "evtxecmd")
            recmd_path: Path to RECmd (default: "recmd")
        """
        self.mcp = mcp_client
        self.mftecmd_path = mftecmd_path
        self.pecmd_path = pecmd_path
        self.evtxecmd_path = evtxecmd_path
        self.recmd_path = recmd_path

    def mftecmd(self, mft_file: Path, output_dir: Path) -> MCPToolResult:
        """Parse MFT with MFTECmd.

        Args:
            mft_file: Path to $MFT file
            output_dir: Output directory for CSV

        Returns:
            MCPToolResult with CSV path
        """
        command = [
            self.mftecmd_path,
            "-f",
            str(mft_file),
            "--csv",
            str(output_dir),
        ]
        return self.mcp.execute_tool("mftecmd", command)

    def pecmd(self, prefetch_dir: Path, output_dir: Path) -> MCPToolResult:
        """Parse Prefetch with PECmd.

        Args:
            prefetch_dir: Path to Prefetch directory
            output_dir: Output directory for CSV

        Returns:
            MCPToolResult with CSV path
        """
        command = [
            self.pecmd_path,
            "-d",
            str(prefetch_dir),
            "--csv",
            str(output_dir),
        ]
        return self.mcp.execute_tool("pecmd", command)

    def evtxecmd(self, evtx_file: Path, output_dir: Path) -> MCPToolResult:
        """Parse EVTX with EvtxECmd.

        Args:
            evtx_file: Path to .evtx file
            output_dir: Output directory for CSV

        Returns:
            MCPToolResult with CSV path
        """
        command = [
            self.evtxecmd_path,
            "-f",
            str(evtx_file),
            "--csv",
            str(output_dir),
        ]
        return self.mcp.execute_tool("evtxecmd", command)

    def recmd(self, registry_hive: Path, output_dir: Path) -> MCPToolResult:
        """Parse Registry hive with RECmd.

        Args:
            registry_hive: Path to Registry hive file (SAM, SYSTEM, SOFTWARE, etc.)
            output_dir: Output directory for CSV

        Returns:
            MCPToolResult with CSV path
        """
        command = [
            self.recmd_path,
            "-f",
            str(registry_hive),
            "--csv",
            str(output_dir),
        ]
        return self.mcp.execute_tool("recmd", command)


class PlasoTool:
    """Wrapper for Plaso timeline analysis."""

    def __init__(
        self,
        mcp_client: MCPClient,
        log2timeline_path: str = "log2timeline.py",
        psort_path: str = "psort.py",
    ):
        """Initialize Plaso wrapper.

        Args:
            mcp_client: MCP client instance
            log2timeline_path: Path to log2timeline.py
            psort_path: Path to psort.py
        """
        self.mcp = mcp_client
        self.log2timeline_path = log2timeline_path
        self.psort_path = psort_path

    def log2timeline(
        self, image_file: Path, plaso_file: Path, timezone: str = "UTC"
    ) -> MCPToolResult:
        """Create Plaso storage file from evidence.

        Args:
            image_file: Path to disk image
            plaso_file: Output Plaso storage file
            timezone: Timezone for timestamps

        Returns:
            MCPToolResult with Plaso file path
        """
        command = [
            self.log2timeline_path,
            "--timezone",
            timezone,
            str(plaso_file),
            str(image_file),
        ]
        return self.mcp.execute_tool("plaso", command)

    def psort(
        self, plaso_file: Path, output_file: Path, output_format: str = "l2tcsv"
    ) -> MCPToolResult:
        """Sort and filter Plaso timeline.

        Args:
            plaso_file: Input Plaso storage file
            output_file: Output timeline file
            output_format: Output format (l2tcsv, json, etc.)

        Returns:
            MCPToolResult with timeline file path
        """
        command = [
            self.psort_path,
            "-o",
            output_format,
            "-w",
            str(output_file),
            str(plaso_file),
        ]
        return self.mcp.execute_tool("plaso", command)
