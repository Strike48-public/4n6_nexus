"""MCP client for forensic tool execution with safety guards."""

import platform
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..audit.logger import AuditLogger
from .guardrails import ToolGuard, tool_binary, tool_supported_on_platform


@dataclass
class MCPToolResult:
    """Result from MCP tool execution."""

    success: bool
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    tool: str
    command: str


class MCPClient:
    """Client for executing forensic tools, routed through ToolGuard (SFE-fibx.14).

    Every ``execute_tool`` call is validated by the SAME ``ToolGuard`` the
    shipping ``EvidenceMCPServer`` (server.py) uses: the read-only allowlist AND
    input/output evidence-path containment. Historically this client enforced
    only a best-effort write-flag denylist and ran ``subprocess.run`` directly --
    a ToolGuard bypass reachable through the exported ``EZToolsTool`` wrapper and
    the documented ``cli_mcp`` entrypoint. That bypass is now closed at the choke
    point: ``evidence_root`` is REQUIRED (containment is meaningless without one),
    so there is no ungated fallback.

    Provides:
    - Read-only enforcement via ToolGuard (allowlist + path/output containment)
    - Platform gate: a tool that cannot produce output here is refused before
      spawning (SFE-ybki), rather than exiting 0 while silently doing nothing
    - Timeout guards (default 5 minutes)
    - Circuit breaker for tool failures
    - Audit logging for all invocations
    """

    def __init__(
        self,
        evidence_root: Path,
        audit_logger: Optional[AuditLogger] = None,
        timeout_seconds: int = 300,
        max_failures: int = 3,
    ):
        """Initialize MCP client.

        Args:
            evidence_root: The case evidence directory. REQUIRED -- the ToolGuard
                path-containment check is meaningless without a root, so this
                path has no default and there is no unguarded mode.
            audit_logger: Optional audit logger instance
            timeout_seconds: Command timeout (default 5 minutes)
            max_failures: Max consecutive failures before circuit break
        """
        self.evidence_root = Path(evidence_root)
        self.audit_logger = audit_logger
        self.timeout_seconds = timeout_seconds
        self.max_failures = max_failures
        self.failure_count = 0
        self.last_failure_time: Optional[datetime] = None
        # Route through the shipping server's read-only policies. Local import
        # keeps this off the module-load path (client is imported at package
        # import time via mcp/__init__.py; server pulls heavier deps).
        from .server import default_policies

        self.guard = ToolGuard(
            policies=default_policies(),
            evidence_root=self.evidence_root,
        )

    def execute_tool(
        self,
        tool: str,
        command: list[str],
        working_dir: Optional[Path] = None,
    ) -> MCPToolResult:
        """Execute forensic tool with safety guards.

        Args:
            tool: Tool name (e.g., "volatility", "mftecmd")
            command: Command and arguments as list
            working_dir: Optional working directory

        Returns:
            MCPToolResult with execution details

        Raises:
            RuntimeError: If circuit breaker is open, or if ``tool`` cannot do
                work on this platform (SFE-ybki)
            TimeoutError: If command exceeds timeout
        """
        # Check circuit breaker
        if self.failure_count >= self.max_failures:
            raise RuntimeError(
                f"Circuit breaker open: {self.failure_count} consecutive failures. "
                f"Last failure: {self.last_failure_time}"
            )

        # Architectural boundary: the read-only allowlist AND input/output path
        # containment, enforced by the same ToolGuard the shipping server uses
        # (SFE-fibx.14). ``command[0]`` is the executable; the guard vets the
        # argument vector, matching server.run_tool's ``check(tool, args)``
        # contract where ``args`` excludes the binary. A write flag, an unknown
        # tool/flag, an input path outside evidence, or an output path inside it
        # raises GuardrailViolation here -- before anything is spawned.
        self.guard.check(tool, command[1:])

        # Resolve the binary from the logical ``tool`` key -- NEVER trust the
        # caller's ``command[0]``. The guard validates args against ``tool``'s
        # policy, so spawning whatever binary sat in ``command[0]`` would decouple
        # "what was validated" from "what runs": a caller could pass tool="tshark"
        # (a permissive policy) with command=["sh", ...] and the guard would wave
        # the args through while ``sh`` spawned. Mirroring server._execute's
        # ``[tool_binary(tool), *args]`` makes the spawned binary a pure function
        # of the guard-checked key.
        resolved_command = [tool_binary(tool), *command[1:]]

        start_time = time.time()

        # Platform gate, mirroring server._execute and jobs_worker (SFE-ybki).
        # This is the legacy path and not the architectural boundary, but
        # EZToolsTool is exported from this package, so ``EZToolsTool(...).pecmd()``
        # reaches subprocess here. PECmd on Linux refuses to work and exits 0, and
        # ``success`` below is derived from the return code, so an ungated call
        # would report success for a run that produced nothing -- the same silent
        # failure being closed at the other doorways.
        #
        # RAISE rather than return a failed result, for two reasons. (1) This
        # class already signals every cannot-run condition by raising (circuit
        # breaker -> RuntimeError, timeout -> TimeoutError) and every RETURNED
        # result carries a real integer ``returncode``; a None exit_code here
        # would break that contract. (2) cli_mcp.analyze_prefetch already has a
        # ``except RuntimeError`` handler for precisely this case, which was dead
        # code until now because PECmd's exit-0 never raised anything.
        #
        # ``failure_count`` is deliberately NOT incremented: the tool never ran,
        # so this is an environment condition and must not trip the breaker.
        if not tool_supported_on_platform(tool):
            raise RuntimeError(
                f"Tool {tool} is not supported on this platform "
                f"({platform.system()}): it cannot produce output here. "
                "Refused before execution."
            )

        try:
            # Execute the resolved command with timeout. ``resolved_command`` uses
            # the key-derived binary, so the caller's command[0] cannot influence
            # what is spawned.
            result = subprocess.run(
                resolved_command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                cwd=working_dir,
            )

            duration_ms = int((time.time() - start_time) * 1000)

            tool_result = MCPToolResult(
                success=result.returncode == 0,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
                duration_ms=duration_ms,
                tool=tool,
                command=" ".join(resolved_command),
            )

            # Reset failure count on success
            if tool_result.success:
                self.failure_count = 0
            else:
                self.failure_count += 1
                self.last_failure_time = datetime.now(timezone.utc)

            # Log to audit trail
            if self.audit_logger:
                self.audit_logger.log_tool_invocation(
                    tool=tool,
                    command=" ".join(resolved_command),
                    exit_code=result.returncode,
                    duration_ms=duration_ms,
                    output=result.stdout[:1024],  # First 1KB
                    stderr=result.stderr[:1024] if result.stderr else None,
                    working_dir=str(working_dir) if working_dir else None,
                )

            return tool_result

        except subprocess.TimeoutExpired:
            self.failure_count += 1
            self.last_failure_time = datetime.now(timezone.utc)
            raise TimeoutError(
                f"Tool {tool} exceeded timeout of {self.timeout_seconds}s"
            )

        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = datetime.now(timezone.utc)
            raise RuntimeError(f"Tool {tool} execution failed: {e}")

    def reset_circuit_breaker(self) -> None:
        """Manually reset circuit breaker after addressing failures."""
        self.failure_count = 0
        self.last_failure_time = None
