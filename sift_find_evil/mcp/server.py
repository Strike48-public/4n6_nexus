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

import platform
import subprocess
import time
from pathlib import Path
from typing import Optional

from ..audit.logger import AuditLogger
from ..injection_defense import scan_and_wrap
from .guardrails import (
    CircuitBreakerOpen,
    GuardrailViolation,
    ToolGuard,
    ToolPolicy,
    is_dispatch_role,
    tool_binary,
    tool_supported_on_platform,
)
from .jobs import NEVER_RAN_EXIT_CODE, JobRunner, JobState


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
            output_flags={"--csv"},
        ),
        "pecmd": ToolPolicy(
            allowed_flags={"-d", "--csv"},
            path_flags={"-d"},
            output_flags={"--csv"},
        ),
        "evtxecmd": ToolPolicy(
            allowed_flags={"-f", "--csv"},
            path_flags={"-f"},
            output_flags={"--csv"},
        ),
        "recmd": ToolPolicy(
            allowed_flags={"-f", "--csv"},
            path_flags={"-f"},
            output_flags={"--csv"},
        ),
        # The Sleuth Kit read-only file listing: ``fls -r -o <offset> <image>``
        # (SFE-qdlk). ``-o`` consumes a numeric partition offset (not a path).
        # The image is a POSITIONAL evidence target (fls has no -f flag), so
        # positional_path contains it inside the evidence root. No write flag is
        # listed, so this boundary can only list -- never modify -- a filesystem.
        "sleuthkit": ToolPolicy(
            allowed_flags={"-r", "-o"},
            value_flags={"-o"},
            positional_path=True,
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
        job_runner: Optional[JobRunner] = None,
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
        # Detached background-job runner (SFE-dup8). Defaults to a real JobRunner
        # writing under exports/jobs/; injectable so a test can stub the spawn.
        self.job_runner = job_runner if job_runner is not None else JobRunner()

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
        # 1. Boundary check. A denial is itself an auditable event. The caller's
        # ``agent`` identity IS its analyst role (the FastMCP endpoints default
        # each tool's agent to the role that owns it), so role-scoped tool
        # authorization (SFE-l7mp) is enforced here alongside the arg allowlist.
        try:
            self.guard.check(tool, args, role=agent)
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

        # 3. Update circuit-breaker state. An environment failure (never ran ->
        # exit_code < 0, e.g. timeout / tool-not-found) does not count; only a
        # genuine tool outcome moves the breaker (SFE-zydh).
        self._record_breaker_outcome(result["exit_code"])

        # 4. Audit, returning the traceable entry_id. The RAW stdout is hashed
        # (tamper-evidence needs the real bytes an analyst would otherwise see).
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

        # 5. Injection defense at the tool-output boundary. Tool stdout is hostile
        # input: an attacker who knows an LLM reads it can plant role-token
        # injection, BIDI reordering, or forged verdict JSON. Sanitize + sentinel-
        # wrap it into ``sanitized_stdout`` (what an analyst should consume);
        # preserve raw ``stdout`` (already hashed above). Any detected attempt is
        # surfaced on the result AND logged as its own auditable event -
        # counts-only, so the raw hostile payload is never re-emitted.
        scan = scan_and_wrap(result["stdout"])
        result["sanitized_stdout"] = scan.wrapped_text
        result["injection_meta"] = scan.findings_meta
        result["injection_detected"] = bool(scan.findings_meta)
        if scan.findings_meta:
            self.audit_logger.log_action(
                action="prompt_injection_attempt",
                details={
                    "tool": tool,
                    "source_entry_id": entry_id,
                    # Counts-only: never the raw payload (injection-defense contract).
                    "indicators": scan.findings_meta,
                },
                correlation_id=correlation_id,
                agent=agent,
            )
        return result

    def _record_breaker_outcome(self, exit_code: Optional[int]) -> None:
        """Fold a tool outcome into the circuit breaker (SFE-zydh).

        The breaker exists to halt on TOOL misbehavior, not on environment/config
        issues. Classification, keyed on the exit code:

        * ``None`` (``NEVER_RAN_EXIT_CODE``) -- an ENVIRONMENT failure the tool
          never ran through (timeout, tool-not-found, spawn/payload failure on the
          detached path). Does NOT count: otherwise a few unrelated config issues
          (a missing binary) would spuriously open the breaker and halt the
          investigation even though the guardrail passed. Still AUDITED by the
          caller; it just does not move the breaker.
        * ``0`` -- success, resets the consecutive-failure count.
        * any integer != 0, INCLUDING a signal-death negative -- the tool RAN and
          failed. A signal death (SIGHUP -> -1, SIGSEGV -> -11, SIGKILL -> -9) is
          tool misbehavior a repeatedly-crashing tool should trip the breaker on.
          Keying "never ran" on the ABSENCE of a code (None) rather than a magic
          negative is what makes this collision-proof: -1 is also SIGHUP.
        """
        if exit_code is None:
            return  # environment failure: never ran -> do not penalize the breaker
        if exit_code == 0:
            self.guard.record_success()
        else:
            self.guard.record_failure()

    def _execute(self, tool: str, args: list[str]) -> dict:
        """Run the tool as a subprocess (overridable/stubbable in tests)."""
        start = time.time()
        # Translate the logical tool key to its real executable at the exec
        # boundary only: the guardrail + audit keep keying on ``tool`` (e.g.
        # "volatility"), while the process spawns the actual binary (e.g. "vol").
        binary = tool_binary(tool)
        # A resolvable binary is not a runnable tool. PECmd installs on Linux and
        # its wrapper resolves, but it refuses to work and EXITS 0 -- so the
        # ``returncode == 0`` success test below would score a no-op run as a
        # success and hand back an empty result (SFE-ybki). Refuse before
        # spawning. The advertised-capability gate normally prevents this call,
        # but a caller can name a tool key directly (Matrix Mode A routes on the
        # request's tool, not the capability id), so the exec doorway needs its
        # own check rather than trusting the advertisement.
        #
        # NEVER_RAN, not a failure code: the tool never executed, so this is an
        # environment condition and must not move the circuit breaker.
        if not tool_supported_on_platform(tool):
            return {
                "success": False,
                "stdout": "",
                "stderr": (
                    f"Tool {tool} is not supported on this platform "
                    f"({platform.system()}): it cannot produce output here. "
                    "Refused before execution."
                ),
                "exit_code": NEVER_RAN_EXIT_CODE,
                "duration_ms": int((time.time() - start) * 1000),
            }
        try:
            proc = subprocess.run(
                [binary, *args],
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
                "exit_code": NEVER_RAN_EXIT_CODE,
                "duration_ms": int((time.time() - start) * 1000),
            }
        except FileNotFoundError:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Tool not found: {tool}",
                "exit_code": NEVER_RAN_EXIT_CODE,
                "duration_ms": int((time.time() - start) * 1000),
            }

    # -- detached background jobs (SFE-dup8) ---------------------------------
    #
    # A long-running tool (Volatility on 4GB, Plaso, Chainsaw) is run DETACHED so
    # the interactive tool call never hits the transport timeout. The security
    # boundary stays here in the server (option B): the guard vets the PAYLOAD
    # before staging (the args are off the command line, so vetting the argv is
    # not enough), and the run is audited exactly once when the server first sees
    # a terminal state. The detached worker itself stays a dumb executor.

    def start_job(
        self, tool: str, args: list[str], agent: str, correlation_id: str
    ) -> dict:
        """Guard, then stage + spawn a detached job. Returns ``{job_id, state}``.

        The guardrail runs on ``(tool, args)`` BEFORE the payload is staged, so a
        denied call never writes a job dir and is audited as ``tool_blocked`` --
        identical to the synchronous ``run_tool`` boundary.

        Raises:
            GuardrailViolation / CircuitBreakerOpen: the call is refused (audited).
        """
        try:
            # Role-scoped authorization (SFE-l7mp) on the staged payload. start_job
            # is the detached sibling of run_tool, so an ANALYST must not use it to
            # stage a tool outside its remit -- a network_analyst cannot background
            # a volatility job any more than it can run one synchronously.
            #
            # A DISPATCH role (orchestrator/lead/triage), however, owns no forensic
            # tool by design yet its whole function is to manage the job queue on
            # behalf of the analysts -- so it may stage any tool. This is not a
            # bypass: the payload's args stay fully guarded (path containment + arg
            # allowlist) regardless of role, and an analyst staging out-of-remit is
            # still refused. Passing role=None for a dispatch caller applies exactly
            # controls 1-3 to the payload (SFE-l7mp review finding #1).
            gate_role = None if is_dispatch_role(agent) else agent
            self.guard.check(tool, args, role=gate_role)
        except (GuardrailViolation, CircuitBreakerOpen) as exc:
            self.audit_logger.log_action(
                action="tool_blocked",
                details={
                    "tool": tool,
                    "args": args,
                    "reason": type(exc).__name__,
                    "message": str(exc),
                    "detached": True,
                },
                correlation_id=correlation_id,
                agent=agent,
            )
            raise

        job_id = self.job_runner.start_job(tool, args)
        self.audit_logger.log_action(
            action="job_started",
            details={"job_id": job_id, "tool": tool, "detached": True},
            correlation_id=correlation_id,
            agent=agent,
        )
        record = self.job_runner.poll_job(job_id)
        return {"job_id": job_id, "state": record.state.value}

    def poll_job(self, job_id: str, agent: str, correlation_id: str) -> dict:
        """Return a job's current state, reconciling its result if terminal.

        The first time the server observes a COMPLETE/FAILED job it reconciles
        (audits the invocation + runs the injection scan); subsequent polls are
        read-only. The returned dict mirrors the job record and, once reconciled,
        also carries ``sanitized_stdout`` / ``injection_detected``.
        """
        record = self.job_runner.poll_job(job_id)
        out = record.to_dict()
        if record.state in (JobState.COMPLETE, JobState.FAILED):
            # Overlay wins over any same-named record key (explicit merge, not a
            # positional update, so a future JobRecord field can't shadow it).
            overlay = self._reconcile_terminal(record, agent, correlation_id)
            out = {**out, **overlay}
        return out

    def load_results(self, job_id: str, agent: str, correlation_id: str) -> dict:
        """Return a COMPLETE job's result payload (with the injection overlay).

        A terminal job (COMPLETE or FAILED) is reconciled once here if a poll has
        not already done so, so the audit lands regardless of which call first
        observes the terminal state. Only a COMPLETE job returns results; a FAILED
        one raises with its recorded reason. The returned dict carries the
        injection-scan overlay (``sanitized_stdout`` / ``injection_detected``), so
        a load-without-poll caller still gets the sanitized output rather than the
        raw tool stdout.

        Raises:
            ValueError: the job has not completed (still running/staging) or
                failed (no results to return).
            KeyError: unknown job id.
        """
        record = self.job_runner.poll_job(job_id)
        overlay: dict = {}
        if record.state in (JobState.COMPLETE, JobState.FAILED):
            overlay = self._reconcile_terminal(record, agent, correlation_id)
        if record.state is JobState.FAILED:
            raise ValueError(
                f"job {job_id} failed (exit {record.exit_code}): "
                f"{record.error or 'no error recorded'}"
            )
        results = self.job_runner.load_results(job_id)
        return {**results, **overlay}

    def _reconcile_terminal(self, record, agent: str, correlation_id: str) -> dict:
        """Audit + injection-scan a terminal job's result, then mark it reconciled.

        Returns the injection-scan overlay (``sanitized_stdout`` etc.) so the
        caller can attach it to the record; an already-reconciled job returns the
        overlay without re-logging.

        Ordering is deliberately AUDIT-THEN-MARK, not mark-then-audit. For a
        forensic trail, never-losing an audit entry outranks strict
        exactly-once: the marker is written only AFTER the ``tool_invocation`` is
        durably logged, so a crash mid-reconcile leaves the job UNMARKED and a
        later poll re-audits it (a duplicate, benign append-only entry keyed by
        job_id) rather than silently dropping the record forever. The server is
        single-threaded per the module contract, and this method has no ``await``,
        so within one process the check-log-mark sequence is atomic -> exactly
        once in normal operation; only a process crash + re-poll can duplicate,
        which is the safe direction.
        """
        result = record.result or {}
        stdout = result.get("stdout", "") or ""
        # A job that never ran (spawn failure, missing tool, unreadable payload)
        # carries no result -- only ``record.error``. Surface that as the audited
        # stderr so the record states WHY it failed, matching the synchronous path
        # (which records e.g. "Tool not found: X" as stderr) rather than logging a
        # misleading empty output for a tool that produced none.
        stderr = result.get("stderr", "") or (record.error or "")
        scan = scan_and_wrap(stdout)
        overlay = {
            "sanitized_stdout": scan.wrapped_text,
            "injection_meta": scan.findings_meta,
            "injection_detected": bool(scan.findings_meta),
        }
        store = self.job_runner.store
        if store.is_reconciled(record.job_id):
            return overlay

        # First terminal observation: fold the detached outcome into the circuit
        # breaker exactly as a synchronous run does (SFE-zydh) -- an environment
        # failure (never ran -> exit_code < 0, e.g. spawn/not-found) does not
        # count, only a genuine tool exit does -- then audit it identically.
        self._record_breaker_outcome(record.exit_code)

        self.audit_logger.log_tool_invocation(
            tool=record.command,
            command=f"{record.command} {' '.join(record.args)}",
            exit_code=record.exit_code,
            output=stdout,
            stderr=stderr,
            correlation_id=correlation_id,
            agent=agent,
        )
        if scan.findings_meta:
            self.audit_logger.log_action(
                action="prompt_injection_attempt",
                details={
                    "job_id": record.job_id,
                    "tool": record.command,
                    # Counts-only: never the raw payload (injection-defense contract).
                    "indicators": scan.findings_meta,
                    "detached": True,
                },
                correlation_id=correlation_id,
                agent=agent,
            )
        # Mark ONLY after the audit is durably written, so a crash before this
        # point re-audits on the next poll instead of losing the record.
        store.mark_reconciled(record.job_id)
        return overlay


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

    mcp = FastMCP("forensics_nexus")

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
        image_file: str,
        offset: str,
        correlation_id: str,
        recurse: bool = True,
        agent: str = "disk_analyst",
    ) -> dict:
        """Run a read-only Sleuth Kit file listing (``fls``) on a disk image.

        Builds ``fls [-r] -o <offset> <image_file>``. Only the read-only flags in
        the tool policy (``-r`` recurse, ``-o`` offset) are reachable and the
        image is a positional evidence path the guardrail contains; anything else
        is rejected. ``image_file`` must resolve inside the evidence root.
        """
        args = ["-o", offset, image_file]
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

    # -- detached background jobs (SFE-dup8) ---------------------------------
    # A slow tool run detached so the interactive call never times out. The guard
    # vets the payload at start_job; the run is audited when a poll/load first
    # sees it terminal. `tool`/`args` mirror the synchronous wrappers' contract,
    # so an out-of-root path or unknown tool is rejected here too.

    @mcp.tool()
    def start_job(
        tool: str,
        args: list[str],
        correlation_id: str,
        agent: str = "orchestrator",
    ) -> dict:
        """Start a long-running forensic tool as a DETACHED background job.

        Returns ``{job_id, state}`` immediately (never blocks on the tool). The
        payload is guardrail-checked before staging; a denied call raises and is
        audited, exactly like a synchronous tool call.
        """
        return server.start_job(tool, args, agent=agent, correlation_id=correlation_id)

    @mcp.tool()
    def poll_job(job_id: str, correlation_id: str, agent: str = "orchestrator") -> dict:
        """Return a detached job's current state (reconciles + audits if done)."""
        return server.poll_job(job_id, agent=agent, correlation_id=correlation_id)

    @mcp.tool()
    def load_job_results(
        job_id: str, correlation_id: str, agent: str = "orchestrator"
    ) -> dict:
        """Return a COMPLETE detached job's result payload (raises if not done)."""
        return server.load_results(job_id, agent=agent, correlation_id=correlation_id)

    return mcp
