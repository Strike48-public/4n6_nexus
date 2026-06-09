"""Custom MCP server exposing SIFT forensic tools behind architectural guardrails.

This is the single boundary every agent tool call crosses. Each call is:
  1. validated by ``ToolGuard`` (allowlist + path containment + circuit breaker),
  2. executed (subprocess) only if it passed,
  3. recorded in the A2A audit log with the acting agent + correlation id.

Because the guardrails live here -- not in an agent prompt -- they are
architectural: an agent cannot reach a forensic tool except through this chokepoint.

``EvidenceMCPServer`` holds the transport-independent dispatch core (unit-tested in
tests/test_mcp_server.py). ``build_fastmcp`` registers that core as real MCP tools
over the official SDK for live agent use.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Optional

from ..audit.logger import AuditLogger
from .guardrails import CircuitBreakerOpen, GuardrailViolation, ToolGuard, ToolPolicy


def default_policies() -> dict[str, ToolPolicy]:
    """Read-only policies for the bundled forensic tool wrappers (deny-by-default).

    Each tool may only run with the flags listed. No write/modify flag is listed
    anywhere, so write operations are structurally impossible at this boundary.
    """
    return {
        "volatility": ToolPolicy(
            allowed_flags={
                "-f",
                "-r",
                "windows.pslist",
                "windows.netscan",
                "windows.malfind",
                "windows.cmdline",
            },
            path_flags={"-f"},
            value_flags={"-r"},
        ),
        "mftecmd": ToolPolicy(
            allowed_flags={"-f", "--csv"},
            path_flags={"-f"},
            value_flags={"--csv"},
        ),
        "pecmd": ToolPolicy(
            allowed_flags={"-d", "--csv"},
            path_flags={"-d"},
            value_flags={"--csv"},
        ),
        "evtxecmd": ToolPolicy(
            allowed_flags={"-f", "--csv"},
            path_flags={"-f"},
            value_flags={"--csv"},
        ),
        "recmd": ToolPolicy(
            allowed_flags={"-f", "--csv"},
            path_flags={"-f"},
            value_flags={"--csv"},
        ),
        "sleuthkit": ToolPolicy(
            allowed_flags={"-r", "-o"},
            path_flags=set(),
            value_flags={"-o"},
        ),
        # Network capture analysis (read-only). -r reads an input capture; the
        # field/format flags below only shape output. The capture-WRITE flag
        # (-w) is deliberately absent, so tshark cannot create or alter a capture
        # at this boundary -- read-only by construction, like every tool here.
        "tshark": ToolPolicy(
            allowed_flags={"-r", "-Y", "-T", "-e", "-E", "-q", "-z", "fields"},
            path_flags={"-r"},
            value_flags={"-Y", "-T", "-e", "-E", "-z"},
        ),
    }


class EvidenceMCPServer:
    """Transport-independent MCP dispatch core with architectural guardrails."""

    def __init__(
        self,
        case_id: str,
        evidence_root: Path,
        audit_path: Path,
        examiner: Optional[str] = None,
        policies: Optional[dict[str, ToolPolicy]] = None,
        max_consecutive_failures: int = 3,
        timeout_seconds: int = 300,
    ):
        self.case_id = case_id
        self.evidence_root = Path(evidence_root)
        self.audit_logger = AuditLogger(audit_path, examiner=examiner)
        self.guard = ToolGuard(
            policies=policies or default_policies(),
            evidence_root=self.evidence_root,
            max_consecutive_failures=max_consecutive_failures,
        )
        self.timeout_seconds = timeout_seconds

    def run_tool(
        self,
        tool: str,
        args: list[str],
        agent: str,
        correlation_id: str,
    ) -> dict:
        """Validate, execute, and audit a forensic tool invocation.

        Raises:
            GuardrailViolation: the call violates an architectural guardrail.
            CircuitBreakerOpen: too many consecutive failures.

        Returns:
            dict with success/stdout/stderr/exit_code/duration_ms and the audit
            ``entry_id`` (the traceable handle a finding cites).
        """
        # 1. Boundary check. A denial is itself an auditable event.
        try:
            self.guard.check(tool, args)
        except (GuardrailViolation, CircuitBreakerOpen) as exc:
            # Record the denial as a single append-only entry carrying the A2A
            # identity, so the blocked event stays on the same correlated thread
            # as the rest of the investigation. (SFE-eol: never rewrite the log.)
            self.audit_logger.log_action(
                action="tool_blocked",
                details={
                    "tool": tool,
                    "args": args,
                    "reason": type(exc).__name__,
                    "message": str(exc),
                },
                correlation_id=correlation_id,
                agent=agent,
            )
            raise

        # 2. Execute (only reached if the guardrail passed).
        result = self._execute(tool, args)

        # 3. Update circuit-breaker state.
        if result["success"]:
            self.guard.record_success()
        else:
            self.guard.record_failure()

        # 4. Audit, returning the traceable entry_id.
        entry_id = self.audit_logger.log_tool_invocation(
            tool=tool,
            command=f"{tool} {' '.join(args)}",
            exit_code=result["exit_code"],
            duration_ms=result["duration_ms"],
            output=result["stdout"],
            stderr=result["stderr"],
            correlation_id=correlation_id,
            agent=agent,
        )
        result["entry_id"] = entry_id
        return result

    def _execute(self, tool: str, args: list[str]) -> dict:
        """Run the tool as a subprocess (overridable/stubbable in tests)."""
        start = time.time()
        try:
            proc = subprocess.run(
                [tool, *args],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
            return {
                "success": proc.returncode == 0,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "exit_code": proc.returncode,
                "duration_ms": int((time.time() - start) * 1000),
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Tool {tool} exceeded timeout of {self.timeout_seconds}s",
                "exit_code": -1,
                "duration_ms": int((time.time() - start) * 1000),
            }
        except FileNotFoundError:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Tool not found: {tool}",
                "exit_code": -1,
                "duration_ms": int((time.time() - start) * 1000),
            }


def build_fastmcp(server: EvidenceMCPServer):
    """Register the dispatch core as real MCP tools over the official SDK.

    Imported lazily so the unit-testable core has no hard dependency on the
    transport stack (starlette/uvicorn). Each MCP tool simply delegates to
    ``server.run_tool`` -- the guardrails and audit logging are unavoidable.

    Every tool with a read-only policy in ``default_policies`` is exposed here,
    so an analyst agent never references a forensic tool the boundary does not
    expose. The argument shapes mirror each tool's ``ToolPolicy`` (only the
    flags it declares are reachable; anything else is rejected by ``ToolGuard``).
    """
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("sift-find-evil")

    @mcp.tool()
    def volatility(
        plugin: str,
        memory_file: str,
        correlation_id: str,
        agent: str = "memory_analyst",
        output_format: str = "json",
    ) -> dict:
        """Run a read-only Volatility 3 plugin against a memory image."""
        return server.run_tool(
            "volatility",
            ["-f", memory_file, "-r", output_format, plugin],
            agent=agent,
            correlation_id=correlation_id,
        )

    @mcp.tool()
    def mftecmd(
        mft_file: str, output_dir: str, correlation_id: str, agent: str = "disk_analyst"
    ) -> dict:
        """Parse an $MFT to CSV with MFTECmd (read-only on evidence)."""
        return server.run_tool(
            "mftecmd",
            ["-f", mft_file, "--csv", output_dir],
            agent=agent,
            correlation_id=correlation_id,
        )

    @mcp.tool()
    def pecmd(
        prefetch_dir: str,
        output_dir: str,
        correlation_id: str,
        agent: str = "disk_analyst",
    ) -> dict:
        """Parse a Prefetch directory to CSV with PECmd (read-only on evidence)."""
        return server.run_tool(
            "pecmd",
            ["-d", prefetch_dir, "--csv", output_dir],
            agent=agent,
            correlation_id=correlation_id,
        )

    @mcp.tool()
    def evtxecmd(
        evtx_file: str,
        output_dir: str,
        correlation_id: str,
        agent: str = "disk_analyst",
    ) -> dict:
        """Parse a Windows Event Log to CSV with EvtxECmd (read-only on evidence)."""
        return server.run_tool(
            "evtxecmd",
            ["-f", evtx_file, "--csv", output_dir],
            agent=agent,
            correlation_id=correlation_id,
        )

    @mcp.tool()
    def recmd(
        hive_file: str,
        output_dir: str,
        correlation_id: str,
        agent: str = "disk_analyst",
    ) -> dict:
        """Parse a registry hive to CSV with RECmd (read-only on evidence)."""
        return server.run_tool(
            "recmd",
            ["-f", hive_file, "--csv", output_dir],
            agent=agent,
            correlation_id=correlation_id,
        )

    @mcp.tool()
    def sleuthkit(
        offset: str,
        correlation_id: str,
        recurse: bool = True,
        agent: str = "disk_analyst",
    ) -> dict:
        """Run a read-only Sleuth Kit listing at a partition offset.

        Only the read-only flags declared in the tool policy (``-r`` recurse,
        ``-o`` offset) are reachable; the guardrail rejects anything else.
        """
        args = ["-o", offset]
        if recurse:
            args.insert(0, "-r")
        return server.run_tool(
            "sleuthkit",
            args,
            agent=agent,
            correlation_id=correlation_id,
        )

    @mcp.tool()
    def tshark(
        pcap_file: str,
        correlation_id: str,
        display_filter: str = "",
        agent: str = "network_analyst",
    ) -> dict:
        """Extract read-only fields from a PCAP with tshark (no capture write).

        Reads ``pcap_file`` (must resolve inside the evidence root) and emits
        field output; the capture-write flag is not reachable at the boundary.
        """
        args = ["-r", pcap_file]
        if display_filter:
            args += ["-Y", display_filter]
        args += ["-T", "fields", "-e", "ip.src", "-e", "ip.dst"]
        return server.run_tool(
            "tshark",
            args,
            agent=agent,
            correlation_id=correlation_id,
        )

    return mcp
