"""Example: Integrating MCP tools with detection engine.

This demonstrates how to wire detectors to use real forensic tools
via MCP instead of parsing pre-generated CSV fixtures.
"""

from pathlib import Path
from typing import Optional

from ..audit.logger import AuditLogger
from ..parsers.mft_parser import MFTParser
from ..parsers.prefetch_parser import PrefetchParser
from ..parsers.evtx_parser import EvtxParser
from .client import MCPClient
from .tools import EZToolsTool, VolatilityTool


class MCPDetectionPipeline:
    """Detection pipeline using MCP for tool execution.

    Instead of:
        parser.parse_csv("pre-generated-mft.csv")

    Use:
        mcp_pipeline.analyze_mft("$MFT", output_dir)
    """

    def __init__(
        self,
        case_id: str,
        audit_log_path: Optional[Path] = None,
        timeout_seconds: int = 300,
    ):
        """Initialize MCP detection pipeline.

        Args:
            case_id: Case identifier for audit logging
            audit_log_path: Path to audit log file
            timeout_seconds: Tool timeout (default 5 minutes)
        """
        self.case_id = case_id

        # Initialize audit logger
        self.audit_logger = None
        if audit_log_path:
            self.audit_logger = AuditLogger(audit_log_path)

        # Initialize MCP client with safety guards
        self.mcp = MCPClient(
            audit_logger=self.audit_logger,
            timeout_seconds=timeout_seconds,
            max_failures=3,
        )

        # Initialize tool wrappers
        self.ez_tools = EZToolsTool(self.mcp)
        self.volatility = VolatilityTool(self.mcp)

        # Initialize parsers (for processing tool output)
        self.mft_parser = MFTParser()
        self.prefetch_parser = PrefetchParser()
        self.evtx_parser = EvtxParser()

    def analyze_mft(self, mft_file: Path, output_dir: Path) -> list:
        """Analyze MFT using MFTECmd via MCP.

        Args:
            mft_file: Path to $MFT file
            output_dir: Directory for MFTECmd CSV output

        Returns:
            List of MFT entries (parsed from CSV)

        Raises:
            RuntimeError: If tool execution fails
        """
        # Execute MFTECmd via MCP
        result = self.ez_tools.mftecmd(mft_file, output_dir)

        if not result.success:
            raise RuntimeError(
                f"MFTECmd failed (exit {result.exit_code}): {result.stderr}"
            )

        # Parse generated CSV
        csv_file = output_dir / "MFT.csv"  # MFTECmd default output name
        if not csv_file.exists():
            raise FileNotFoundError(f"MFTECmd CSV not found: {csv_file}")

        return self.mft_parser.parse_csv(csv_file)

    def analyze_prefetch(self, prefetch_dir: Path, output_dir: Path) -> list:
        """Analyze Prefetch using PECmd via MCP.

        Args:
            prefetch_dir: Directory containing .pf files
            output_dir: Directory for PECmd CSV output

        Returns:
            List of Prefetch entries (parsed from CSV)

        Raises:
            RuntimeError: If tool execution fails
        """
        # Execute PECmd via MCP
        result = self.ez_tools.pecmd(prefetch_dir, output_dir)

        if not result.success:
            raise RuntimeError(
                f"PECmd failed (exit {result.exit_code}): {result.stderr}"
            )

        # Parse generated CSV
        csv_file = output_dir / "Prefetch.csv"  # PECmd default output name
        if not csv_file.exists():
            raise FileNotFoundError(f"PECmd CSV not found: {csv_file}")

        return self.prefetch_parser.parse_csv(csv_file)

    def analyze_evtx(self, evtx_file: Path, output_dir: Path) -> list:
        """Analyze Event Logs using EvtxECmd via MCP.

        Args:
            evtx_file: Path to .evtx file
            output_dir: Directory for EvtxECmd CSV output

        Returns:
            List of Event Log entries (parsed from CSV)

        Raises:
            RuntimeError: If tool execution fails
        """
        # Execute EvtxECmd via MCP
        result = self.ez_tools.evtxecmd(evtx_file, output_dir)

        if not result.success:
            raise RuntimeError(
                f"EvtxECmd failed (exit {result.exit_code}): {result.stderr}"
            )

        # Parse generated CSV
        csv_file = output_dir / "EventLog.csv"  # EvtxECmd default output name
        if not csv_file.exists():
            raise FileNotFoundError(f"EvtxECmd CSV not found: {csv_file}")

        return self.evtx_parser.parse_csv(csv_file)

    def analyze_memory(self, memory_file: Path, output_dir: Path) -> dict:
        """Analyze memory dump using Volatility 3 via MCP.

        Args:
            memory_file: Path to memory dump (.raw, .mem, .dmp)
            output_dir: Directory for JSON output

        Returns:
            Dictionary with analysis results (pslist, netscan, etc.)

        Raises:
            RuntimeError: If tool execution fails
        """
        results = {}

        # Run pslist
        pslist_result = self.volatility.pslist(memory_file, output_format="json")
        if pslist_result.success:
            results["pslist"] = pslist_result.stdout
        else:
            results["pslist_error"] = pslist_result.stderr

        # Run netscan
        netscan_result = self.volatility.netscan(memory_file, output_format="json")
        if netscan_result.success:
            results["netscan"] = netscan_result.stdout
        else:
            results["netscan_error"] = netscan_result.stderr

        # Run malfind
        malfind_result = self.volatility.malfind(memory_file, output_format="json")
        if malfind_result.success:
            results["malfind"] = malfind_result.stdout
        else:
            results["malfind_error"] = malfind_result.stderr

        # Run cmdline
        cmdline_result = self.volatility.cmdline(memory_file, output_format="json")
        if cmdline_result.success:
            results["cmdline"] = cmdline_result.stdout
        else:
            results["cmdline_error"] = cmdline_result.stderr

        return results


# Usage example
def example_usage():
    """Example: Using MCP pipeline for case analysis."""
    from ..self_correction.engine import SelfCorrectionEngine

    # Initialize MCP pipeline
    pipeline = MCPDetectionPipeline(
        case_id="INC-2026-001",
        audit_log_path=Path("/cases/INC-2026-001/audit.jsonl"),
    )

    # Define evidence paths
    mft_file = Path("/evidence/disk.E01/C/$MFT")
    prefetch_dir = Path("/evidence/disk.E01/C/Windows/Prefetch")
    evtx_file = Path("/evidence/disk.E01/C/Windows/System32/winevt/Logs/Security.evtx")

    # Define output directory for tool CSVs
    output_dir = Path("/cases/INC-2026-001/analysis")
    output_dir.mkdir(exist_ok=True)

    # Run tools via MCP (automatically logged)
    mft_entries = pipeline.analyze_mft(mft_file, output_dir)
    prefetch_entries = pipeline.analyze_prefetch(prefetch_dir, output_dir)
    evtx_entries = pipeline.analyze_evtx(evtx_file, output_dir)

    # Run self-correction engine on parsed artifacts
    engine = SelfCorrectionEngine()
    findings = engine.analyze(
        mft_entries=mft_entries,
        prefetch_entries=prefetch_entries,
        evtx_entries=evtx_entries,
    )

    return findings
