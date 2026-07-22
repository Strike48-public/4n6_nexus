"""MCP client for forensic tool execution with safety guards."""

import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..audit.logger import AuditLogger


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


# Flags that would let a tool mutate evidence. Matched as whole tokens
# (optionally with an attached =value), so a write flag at any position --
# including the final argument -- is caught, while read flags that merely
# contain these letters (e.g. --password, --forward) are not. (SFE-0dq)
#
# Scoped to evidence-MUTATION flags. Derived-output flags like --csv <outdir>
# are deliberately NOT blocked: writing analysis output to a separate directory
# is the normal read-only workflow and is allowed by the server's ToolGuard
# policy too. The real boundary (path containment) is ToolGuard, not this list.
_WRITE_FLAG_TOKENS = frozenset({"-w", "-W", "--write", "--modify", "--delete"})


def _is_write_flag(token: str) -> bool:
    """True if a single argv token requests a write/mutation."""
    base = token.split("=", 1)[
        0
    ]  # strip attached value: --write-out=... -> --write-out
    if base in _WRITE_FLAG_TOKENS:
        return True
    # Catch long-form spellings like --write-out / --writeable without
    # false-positiving on unrelated flags.
    return base.startswith("--write")


class MCPClient:
    """Legacy client for executing forensic tools with best-effort safety guards.

    WARNING: This client is NOT the architectural security boundary. It performs
    a best-effort write-flag rejection but has NO path-containment enforcement --
    it runs ``subprocess.run`` on the command directly. For real forensic
    investigations, drive tools through ``EvidenceMCPServer`` (server.py), where
    ``ToolGuard`` enforces the read-only allowlist AND evidence-path containment
    on every call. See SFE-0dq.

    Provides:
    - Best-effort read-only enforcement (write-flag rejection; see warning above)
    - Timeout guards (default 5 minutes)
    - Circuit breaker for tool failures
    - Audit logging for all invocations
    """

    def __init__(
        self,
        audit_logger: Optional[AuditLogger] = None,
        timeout_seconds: int = 300,
        max_failures: int = 3,
    ):
        """Initialize MCP client.

        Args:
            audit_logger: Optional audit logger instance
            timeout_seconds: Command timeout (default 5 minutes)
            max_failures: Max consecutive failures before circuit break
        """
        self.audit_logger = audit_logger
        self.timeout_seconds = timeout_seconds
        self.max_failures = max_failures
        self.failure_count = 0
        self.last_failure_time: Optional[datetime] = None

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
            RuntimeError: If circuit breaker is open
            TimeoutError: If command exceeds timeout
        """
        # Check circuit breaker
        if self.failure_count >= self.max_failures:
            raise RuntimeError(
                f"Circuit breaker open: {self.failure_count} consecutive failures. "
                f"Last failure: {self.last_failure_time}"
            )

        # Best-effort read-only enforcement: reject any whole-token write flag,
        # at any position (the real boundary is ToolGuard; see class docstring).
        if any(_is_write_flag(token) for token in command):
            raise ValueError(
                f"Write operations not allowed in read-only mode: {' '.join(command)}"
            )

        start_time = time.time()

        try:
            # Execute command with timeout
            result = subprocess.run(
                command,
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
                command=" ".join(command),
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
                    command=" ".join(command),
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
