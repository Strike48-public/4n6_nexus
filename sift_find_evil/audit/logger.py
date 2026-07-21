"""Audit logger for forensic tool invocations."""

import json
import subprocess
import time
from pathlib import Path
from typing import Optional

from .models import (
    GENESIS_HASH,
    AgentMessage,
    AuditEntry,
    FindingEmitted,
    ToolInvocation,
    Verification,
    calculate_output_hash,
    compute_entry_hash,
)


class AuditLogger:
    """Append-only audit logger for forensic investigations.

    Extended for the multi-agent (A2A) log per analysis/A2A_MESSAGE_SCHEMA.md:
    every entry receives a monotonic ``entry_id`` and may carry a
    ``correlation_id`` (investigative thread) and acting ``agent`` identity.
    ``trace(finding_id)`` reconstructs the full thread behind a finding.
    """

    def __init__(self, audit_path: Path, examiner: Optional[str] = None):
        """Initialize audit logger.

        Args:
            audit_path: Path to audit.jsonl file
            examiner: Name of examiner (optional)
        """
        # Accept str or Path for ergonomics — the documented trace command
        # (AuditLogger("path/to/audit.jsonl").trace(...)) passes a string.
        self.audit_path = Path(audit_path)
        self.examiner = examiner

        # Create audit file if it doesn't exist
        if not self.audit_path.exists():
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            self.audit_path.touch()

        # Seed the entry-id counter from any existing log so ids never collide
        # across logger instances appending to the same file.
        self._next_seq = self._scan_max_seq() + 1

        # Seed the hash-chain tail from any existing log so a fresh logger over
        # the same file continues the chain rather than restarting it. The first
        # real entry commits to GENESIS_HASH when the log is empty.
        self._tail_hash = self._scan_tail_hash()

    def _scan_max_seq(self) -> int:
        """Return the highest evt-NNNNNN sequence already present in the log."""
        max_seq = -1
        try:
            with open(self.audit_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    entry_id = data.get("entry_id")
                    if entry_id and entry_id.startswith("evt-"):
                        try:
                            max_seq = max(max_seq, int(entry_id.split("-")[1]))
                        except (IndexError, ValueError):
                            continue
        except FileNotFoundError:
            pass
        return max_seq

    def _allocate_entry_id(self) -> str:
        """Allocate the next monotonic entry id (evt-NNNNNN)."""
        entry_id = f"evt-{self._next_seq:06d}"
        self._next_seq += 1
        return entry_id

    def _scan_tail_hash(self) -> str:
        """Return the ``entry_hash`` of the last chained entry, or GENESIS.

        Reads the log tail so a new logger instance continues the existing
        chain. Legacy logs whose final entry predates chaining have no
        ``entry_hash``; in that case we anchor the next entry at GENESIS so a
        chain still forms going forward (older unchained entries are simply not
        covered, which ``verify_chain`` reports rather than silently trusting).
        """
        tail = GENESIS_HASH
        try:
            with open(self.audit_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    tail = data.get("entry_hash", tail)
        except FileNotFoundError:
            pass
        return tail

    def log_entry(self, entry: AuditEntry) -> str:
        """Append audit entry to log, assigning an entry_id and chain hashes.

        Links the entry into the tamper-evident hash chain: ``prev_hash`` is the
        prior entry's digest (or GENESIS for the first), and ``entry_hash`` is
        the SHA-256 over this entry's canonical body. The write critical section
        assigns both, appends, then advances the in-memory tail so concurrent
        appends within one process stay ordered.

        Args:
            entry: AuditEntry to append

        Returns:
            The entry_id assigned to (or already on) the entry.
        """
        if entry.entry_id is None:
            entry.entry_id = self._allocate_entry_id()
        # Chain: commit to the current tail, then digest the canonical body.
        entry.prev_hash = self._tail_hash
        entry.entry_hash = compute_entry_hash(entry.chain_body())
        with open(self.audit_path, "a") as f:
            f.write(json.dumps(entry.to_dict(), default=str) + "\n")
        self._tail_hash = entry.entry_hash
        return entry.entry_id

    def verify_chain(self) -> tuple[bool, Optional[int], Optional[str]]:
        """Re-verify the tamper-evident hash chain end to end.

        Walks the log in file order, recomputing each entry's digest and
        confirming it links to the prior entry. Detects in-line edits (a
        recomputed ``entry_hash`` no longer matches the stored one), deletions
        and reordering (a ``prev_hash`` that does not equal the actual prior
        digest), and appended forgeries (a tail entry that does not chain).

        Returns:
            ``(ok, broken_at_seq, reason)``. ``ok`` is True for a pristine (or
            empty) chain, with ``broken_at_seq``/``reason`` None. On failure,
            ``broken_at_seq`` is the 0-based index of the first bad entry and
            ``reason`` names the break (content vs. link).
        """
        expected_prev = GENESIS_HASH
        index = 0
        try:
            with open(self.audit_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        return (False, index, f"entry {index}: malformed JSON")

                    stored_hash = data.get("entry_hash")
                    if stored_hash is None:
                        return (
                            False,
                            index,
                            f"entry {index}: missing entry_hash (unchained/legacy entry)",
                        )

                    # Link check: this entry must commit to the prior digest.
                    if data.get("prev_hash") != expected_prev:
                        return (
                            False,
                            index,
                            f"entry {index}: prev_hash link mismatch "
                            "(deletion, reordering, or truncation)",
                        )

                    # Content check: recomputed digest must match the stored one.
                    body = {k: v for k, v in data.items() if k != "entry_hash"}
                    recomputed = compute_entry_hash(body)
                    if recomputed != stored_hash:
                        return (
                            False,
                            index,
                            f"entry {index}: entry_hash content mismatch "
                            "(in-line edit)",
                        )

                    expected_prev = stored_hash
                    index += 1
        except FileNotFoundError:
            return (True, None, None)

        return (True, None, None)

    def log_action(
        self,
        action: str,
        details: Optional[dict] = None,
        correlation_id: Optional[str] = None,
        agent: Optional[str] = None,
    ) -> str:
        """Log a generic action.

        Args:
            action: Action description
            details: Optional action details
            correlation_id: Investigative thread this action belongs to (A2A)
            agent: Acting agent identity (A2A)

        Returns:
            The assigned entry_id.
        """
        entry = AuditEntry(
            action=action,
            examiner=self.examiner,
            details=details,
            correlation_id=correlation_id,
            agent=agent,
        )
        return self.log_entry(entry)

    def log_tool_invocation(
        self,
        tool: str,
        command: str,
        exit_code: Optional[int] = None,
        duration_ms: Optional[int] = None,
        output: Optional[str] = None,
        stderr: Optional[str] = None,
        working_dir: Optional[str] = None,
        correlation_id: Optional[str] = None,
        agent: Optional[str] = None,
    ) -> str:
        """Log a forensic tool invocation.

        Args:
            tool: Tool name (e.g., "volatility", "mftecmd")
            command: Full command executed
            exit_code: Tool exit code
            duration_ms: Execution duration in milliseconds
            output: Tool stdout
            stderr: Tool stderr
            working_dir: Working directory
            correlation_id: Investigative thread this invocation belongs to (A2A)
            agent: Acting agent identity (A2A)

        Returns:
            The assigned entry_id (used as the traceable handle for findings).
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
            correlation_id=correlation_id,
            agent=agent,
        )
        return self.log_entry(entry)

    def log_agent_message(
        self,
        message: AgentMessage,
        correlation_id: Optional[str] = None,
        agent: Optional[str] = None,
    ) -> str:
        """Log an agent-to-agent message (A2A deliverable #8).

        Returns:
            The assigned entry_id.
        """
        entry = AuditEntry(
            action="agent_message",
            examiner=self.examiner,
            details=message.to_dict(),
            correlation_id=correlation_id,
            agent=agent or message.sender,
        )
        return self.log_entry(entry)

    def log_finding(
        self,
        finding: FindingEmitted,
        correlation_id: Optional[str] = None,
        agent: Optional[str] = None,
    ) -> str:
        """Log an emitted finding with its source tool-invocation links.

        Returns:
            The assigned entry_id.
        """
        entry = AuditEntry(
            action="finding_emitted",
            examiner=self.examiner,
            details=finding.to_dict(),
            correlation_id=correlation_id,
            agent=agent or finding.produced_by,
        )
        return self.log_entry(entry)

    def log_verification(
        self,
        verification: Verification,
        correlation_id: Optional[str] = None,
        agent: Optional[str] = None,
    ) -> str:
        """Log a verifier's challenge/resolution of a finding (self-correction).

        Returns:
            The assigned entry_id.
        """
        entry = AuditEntry(
            action="verification",
            examiner=self.examiner,
            details=verification.to_dict(),
            correlation_id=correlation_id,
            agent=agent or verification.verifier,
        )
        return self.log_entry(entry)

    def _read_all(self) -> list[AuditEntry]:
        """Read every audit entry in file order."""
        entries: list[AuditEntry] = []
        with open(self.audit_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entries.append(AuditEntry.from_dict(json.loads(line)))
        return entries

    def trace(self, finding_id: str) -> list[AuditEntry]:
        """Reconstruct the full investigative thread behind a finding.

        Follows the Audit Trail Quality criterion: returns the finding entry, the
        tool invocations that produced it, any verification of it, and the rest of
        the correlated thread -- so a judge can trace a finding to the specific
        tool executions that produced it.

        Returns an empty list if the finding is unknown.
        """
        entries = self._read_all()

        # Locate the finding and any verification entries referencing it.
        finding_entry: Optional[AuditEntry] = None
        related_tool_ids: set[str] = set()
        verification_entries: list[AuditEntry] = []

        related_message_ids: set[str] = set()
        for e in entries:
            details = e.details or {}
            if (
                e.action == "finding_emitted"
                and details.get("finding_id") == finding_id
            ):
                finding_entry = e
                related_tool_ids.update(details.get("source_tool_invocations", []))
                if details.get("source_message_id"):
                    related_message_ids.add(details["source_message_id"])
            elif e.action == "verification" and details.get("finding_id") == finding_id:
                verification_entries.append(e)
                related_tool_ids.update(details.get("tiebreaker_tool_invocations", []))
                if details.get("challenge_message_id"):
                    related_message_ids.add(details["challenge_message_id"])

        if finding_entry is None:
            return []

        # Gather ONLY the entries that belong to THIS finding's lineage: the
        # finding itself, the exact tool invocations it cites, its verification(s)
        # and their tiebreaker tools, and the messages that produced/challenged it.
        # We deliberately do NOT return every entry sharing the correlation_id --
        # that would dump the whole investigation and defeat "trace ANY finding to
        # the specific tool execution that produced IT" when a case has several
        # findings on one thread.
        thread: list[AuditEntry] = []
        for e in entries:
            include = (
                e is finding_entry
                or e in verification_entries
                or (e.entry_id is not None and e.entry_id in related_tool_ids)
                or (e.entry_id is not None and e.entry_id in related_message_ids)
            )
            if include:
                thread.append(e)
        return thread

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
