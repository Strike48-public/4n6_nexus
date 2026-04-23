"""Audit logger for forensic tool invocations."""

import json
import subprocess
import time
from pathlib import Path
from typing import Optional

from .models import AuditEntry, ToolInvocation, calculate_output_hash


class AuditLogger:
    """Append-only audit logger for forensic investigations."""

    def __init__(self, audit_path: Path, examiner: Optional[str] = None):
        """Initialize audit logger.

        Args:
            audit_path: Path to audit.jsonl file
            examiner: Name of examiner (optional)
        """
        self.audit_path = audit_path
        self.examiner = examiner

        # Create audit file if it doesn't exist
        if not audit_path.exists():
            audit_path.parent.mkdir(parents=True, exist_ok=True)
            audit_path.touch()

    def log_entry(self, entry: AuditEntry) -> None:
        """Append audit entry to log.

        Args:
            entry: AuditEntry to append
        """
        with open(self.audit_path, "a") as f:
            f.write(json.dumps(entry.to_dict(), default=str) + "\n")

    def log_action(self, action: str, details: Optional[dict] = None) -> None:
        """Log a generic action.

        Args:
            action: Action description
            details: Optional action details
        """
        entry = AuditEntry(
            action=action,
            examiner=self.examiner,
            details=details,
        )
        self.log_entry(entry)

    def log_tool_invocation(
        self,
        tool: str,
        command: str,
        exit_code: Optional[int] = None,
        duration_ms: Optional[int] = None,
        output: Optional[str] = None,
        stderr: Optional[str] = None,
        working_dir: Optional[str] = None,
    ) -> None:
        """Log a forensic tool invocation.

        Args:
            tool: Tool name (e.g., "volatility", "mftecmd")
            command: Full command executed
            exit_code: Tool exit code
            duration_ms: Execution duration in milliseconds
            output: Tool stdout
            stderr: Tool stderr
            working_dir: Working directory
        """
        output_hash = calculate_output_hash(output) if output else None

        invocation = ToolInvocation(
            tool=tool,
            command=command,
            exit_code=exit_code,
            duration_ms=duration_ms,
            output_hash=output_hash,
            examiner=self.examiner,
            working_dir=working_dir,
            stdout=output[:1000] if output else None,  # First 1KB for reference
            stderr=stderr[:1000] if stderr else None,  # First 1KB for reference
        )

        # Log as AuditEntry
        entry = AuditEntry(
            action="tool_invocation",
            examiner=self.examiner,
            details=invocation.to_dict(),
        )
        self.log_entry(entry)

    def run_tool(
        self,
        tool: str,
        args: list[str],
        working_dir: Optional[Path] = None,
    ) -> tuple[int, str, str]:
        """Run a forensic tool with automatic audit logging.

        Args:
            tool: Tool name (e.g., "vol.py", "mftecmd")
            args: Command-line arguments
            working_dir: Working directory (optional)

        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        command = f"{tool} {' '.join(args)}"
        start_time = time.time()

        try:
            result = subprocess.run(
                [tool] + args,
                cwd=working_dir,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )
            exit_code = result.returncode
            stdout = result.stdout
            stderr = result.stderr
        except subprocess.TimeoutExpired:
            exit_code = -1
            stdout = ""
            stderr = "Tool execution timed out after 300 seconds"
        except FileNotFoundError:
            exit_code = -1
            stdout = ""
            stderr = f"Tool not found: {tool}"
        except Exception as exc:
            exit_code = -1
            stdout = ""
            stderr = f"Tool execution failed: {exc}"

        duration_ms = int((time.time() - start_time) * 1000)

        self.log_tool_invocation(
            tool=tool,
            command=command,
            exit_code=exit_code,
            duration_ms=duration_ms,
            output=stdout,
            stderr=stderr,
            working_dir=str(working_dir) if working_dir else None,
        )

        return exit_code, stdout, stderr

    def get_recent(self, limit: int = 20) -> list[AuditEntry]:
        """Get most recent audit entries.

        Args:
            limit: Maximum number of entries to return

        Returns:
            List of AuditEntry objects (most recent first)
        """
        entries = []
        with open(self.audit_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                entries.append(AuditEntry.from_dict(data))

        return entries[-limit:][::-1]  # Reverse to get most recent first

    def get_statistics(self) -> dict:
        """Get audit log statistics.

        Returns:
            Dictionary with statistics
        """
        total = 0
        tools = set()
        actions = {}
        examiners = set()

        with open(self.audit_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                total += 1

                action = data.get("action", "unknown")
                actions[action] = actions.get(action, 0) + 1

                examiner = data.get("examiner")
                if examiner:
                    examiners.add(examiner)

                details = data.get("details")
                if details and isinstance(details, dict):
                    tool = details.get("tool")
                    if tool:
                        tools.add(tool)

        return {
            "total_entries": total,
            "unique_tools": len(tools),
            "tools": sorted(tools),
            "actions": actions,
            "examiners": sorted(examiners),
        }
