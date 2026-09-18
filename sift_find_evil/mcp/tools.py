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
    """Wrapper for the Sleuth Kit read-only file listing (``fls``).

    Only ``fls`` is exposed: the ToolGuard ``sleuthkit`` policy resolves to the
    ``fls`` binary (see ``tool_binary``), which is the single read-only
    capability the boundary offers. ``mmls``/``icat``/``mactime`` were retired
    (SFE-kek8) -- they do not map to the ``sleuthkit`` key's binary and had no
    consumers; expose them as their own guarded capabilities if ever needed.
    """

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
