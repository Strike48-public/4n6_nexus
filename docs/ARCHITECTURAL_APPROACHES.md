# Architectural Approaches

**How SIFT Find Evil maps to the FIND EVIL! supported architectural approaches**

The competition names four supported architectural approaches and is explicit that
the platform matters less than *how the architecture enforces evidence integrity and
enables genuine self-correction*. SIFT Find Evil implements **two** of the four, and
deliberately the two the competition calls the most architecturally sound:

- **#2 - Custom MCP Server**
- **#3 - Multi-Agent Framework**

This document states each approach in the competition's own words, then shows exactly
where in the code we implement it. Every claim below points at a file you can read.

---

## Why these two

The competition rules describe the trade-offs (quoted verbatim):

> **#2 Custom MCP Server.** "Build a purpose-built MCP server that exposes structured
> functions instead of generic shell commands [...] The agent physically cannot run
> destructive commands because the server doesn't have those tools. The MCP server
> handles raw tool output natively and can parse it before returning to the LLM,
> preventing context window overload from massive text dumps. **(This is the most
> sound architecture in the evaluation. It's also the most work.)**"

> **#3 Multi-Agent Frameworks.** "Decompose the analysis into specialized,
> communicating agents [...] No single model holds all raw data in its context window
> [...] Agent-to-agent communication is logged programmatically with timestamps [...]
> **Warning:** agent loops can get stuck in infinite conversational spirals without
> careful termination conditions. Build in max-iteration caps and graceful
> degradation."

We chose these two because together they put **both** evidence-integrity guardrails
*and* context-management where the competition rewards them: enforced at a boundary in
code, not asserted in a prompt. Approaches #1 (Direct Agent Extension) and #4
(Alternative Agentic IDEs) both "rely on prompt adherence for evidence protection, not
architectural enforcement" - the exact property our design avoids.

---

## Approach #2: Custom MCP Server

### What the competition asked for

A purpose-built MCP server exposing typed, structured functions instead of a generic
shell, such that the agent *physically cannot* run destructive commands, and that
parses raw tool output before it reaches the model.

### How we implement it

**The single tool boundary: `sift_find_evil/mcp/server.py`**

`EvidenceMCPServer.run_tool()` is the only path from any agent to any forensic tool.
Every call is (1) validated by `ToolGuard`, (2) executed only if it passed, and (3)
recorded in the A2A audit log with the acting agent and correlation id:

```python
# sift_find_evil/mcp/server.py
def run_tool(self, tool, args, agent, correlation_id) -> dict:
    # 1. Boundary check. A denial is itself an auditable event.
    try:
        self.guard.check(tool, args)
    except (GuardrailViolation, CircuitBreakerOpen) as exc:
        self.audit_logger.log_action(action="tool_blocked", details={...})
        self._stamp_last_entry(agent=agent, correlation_id=correlation_id)
        raise
    # 2. Execute (only reached if the guardrail passed).
    result = self._execute(tool, args)
    # 4. Audit, returning the traceable entry_id a finding cites.
    entry_id = self.audit_logger.log_tool_invocation(...)
    result["entry_id"] = entry_id
    return result
```

**Typed functions, not a shell: `build_fastmcp()`**

When run live over the official MCP SDK, the server exposes *named, typed* tools
(`volatility(plugin, memory_file, ...)`, `mftecmd(mft_file, output_dir, ...)`) - not
`execute_shell_cmd`. Each delegates to `run_tool`, so the guardrails and audit logging
are unavoidable:

```python
# sift_find_evil/mcp/server.py
@mcp.tool()
def volatility(plugin, memory_file, correlation_id, agent="memory_analyst", ...):
    """Run a read-only Volatility 3 plugin against a memory image."""
    return server.run_tool("volatility", ["-f", memory_file, "-r", ..., plugin], ...)
```

**The agent physically cannot run destructive commands: `sift_find_evil/mcp/guardrails.py`**

`ToolGuard` enforces three deny-by-default controls in code, not in a prompt:

1. **Per-tool argument allowlist.** A tool may only run with the flags it explicitly
   declares (`ToolPolicy.allowed_flags`). Every tool's policy in `default_policies()`
   lists only read flags; no write/modify flag is listed anywhere, so write operations
   are structurally impossible at this boundary. This is strictly stronger than a
   write-flag *denylist* (you cannot forget to deny a flag you never allowed).
2. **Evidence-path containment.** Arguments naming input paths are canonicalised and
   must resolve inside the configured evidence root; traversal escapes and absolute
   paths outside the root are rejected (`_check_path_contained`).
3. **Circuit breaker.** N consecutive failures opens the boundary so a misbehaving loop
   cannot hammer the system.

```python
# sift_find_evil/mcp/guardrails.py
def check(self, tool, args) -> None:
    if self.circuit_open:
        raise CircuitBreakerOpen(...)
    policy = self.policies.get(tool)
    if policy is None:
        raise GuardrailViolation(f"Tool '{tool}' is not on the allowlist (deny-by-default)")
    self._check_args(tool, args, policy)
```

**Parses output before the model sees it.** The server captures stdout/stderr and the
detectors/parsers turn raw tool output into structured findings rather than dumping
multi-megabyte text into the model context.

### Proof it holds

- Unit tests for the dispatch core: `tests/test_mcp_server.py`
- Guardrail bypass tests (allowlist, traversal, circuit breaker):
  `tests/test_mcp_guardrails.py`
- Live demonstration of a blocked out-of-bounds read:

  ```bash
  PYTHONPATH=. python3 -m sift_find_evil.orchestration --bypass-demo \
    --output-dir analysis/bypass_run
  grep tool_blocked analysis/bypass_run/audit.jsonl
  ```

  The agent attempts `volatility -f /etc/shadow ...`; the path-containment guardrail
  rejects it and the denial is recorded as a `tool_blocked` audit event on the same
  correlation thread.

---

## Approach #3: Multi-Agent Framework

### What the competition asked for

Decompose analysis into specialized, communicating agents so no single model holds all
raw data; log agent-to-agent communication with timestamps; and include termination
conditions (max-iteration caps, graceful degradation) so loops cannot spiral.

### How we implement it

**The agent topology: `sift_find_evil/orchestration.py`**

`InvestigationOrchestrator.run_demo_investigation()` drives the full flow:

```
Orchestrator
  ├─ dispatch → Triage          (enumerate artifacts, scope domains)
  ├─ dispatch → Disk Analyst    (MFT / Prefetch / Event Log)
  ├─ dispatch → Memory Analyst  (pslist / psscan / netscan)
  ├─ dispatch → Network Analyst (PCAP conversations + DNS)
  └─ dispatch → Verifier        (challenge every finding; resolve contradictions)
```

Each domain analyst runs only its own tools (through the MCP boundary) and emits
candidate findings. No single agent parses every artifact type - the disk analyst
never sees memory rows, the memory analyst never sees PCAP - which is precisely the
"no single model holds all raw data" property the competition describes.

**Two runtimes, one agent design.** The same agent decomposition exists as Claude Code
subagents (`.claude/agents/dfir-orchestrator.md`, `dfir-triage.md`,
`dfir-disk-analyst.md`, `dfir-memory-analyst.md`, `dfir-network-analyst.md`,
`dfir-verifier.md`) for interactive use on a Protocol SIFT host, and as the in-process
`orchestration.py` harness for a deterministic, judge-reproducible run. Both write the
same correlated A2A log over the same MCP server. See
[DUAL_PATH_STRATEGY.md](DUAL_PATH_STRATEGY.md).

**Agent-to-agent communication is logged with timestamps.** Every dispatch, result,
challenge, finding, and verification is an append-only JSONL `AuditEntry` carrying a
`correlation_id`, the acting `agent`, and a UTC timestamp. The schema is documented in
[../analysis/A2A_MESSAGE_SCHEMA.md](../analysis/A2A_MESSAGE_SCHEMA.md) and implemented in
`sift_find_evil/audit/`:

```python
# sift_find_evil/orchestration.py
def _dispatch(self, sender, recipient, task, **body) -> str:
    return self.server.audit_logger.log_agent_message(
        AgentMessage(sender=sender, recipient=recipient,
                     message_type="dispatch", body={"task": task, **body}),
        correlation_id=self.correlation_id, agent=sender)
```

**Findings are traceable by construction.** Each `FindingEmitted` record carries
`source_tool_invocations` (the `entry_id`s returned by `run_tool`), so a judge can trace
any finding back to the exact tool executions that produced it:

```bash
PYTHONPATH=. python3 -c "from sift_find_evil.audit.logger import AuditLogger; \
[print(e.entry_id, e.action) for e in AuditLogger('analysis/demo_run/audit.jsonl').trace('F-005')]"
```

**Termination / graceful degradation.** The harness is bounded by construction: the
orchestrator dispatches a fixed, finite set of analysts and a single verification pass
(no open-ended conversational loop). The MCP circuit breaker (`max_consecutive_failures`)
opens the tool boundary on repeated failure, and analysts degrade gracefully - the
memory and network analysts return zero findings (and run no tools) when their fixtures
are absent, rather than erroring, so the disk-only path is unaffected.

### Self-correction (the cross-cutting demonstration)

The verifier challenges every finding through the `SelfCorrectionEngine`
(`sift_find_evil/self_correction/engine.py`): it detects contradictions across
artifacts (e.g. a file executed *before* it was modified - a causality violation),
reduces confidence, queries a tiebreaker (Event Log 4688, psscan, etc.), and either
resolves the contradiction (confidence recovery) or leaves it flagged. Every step is in
the reasoning chain and the A2A log. See [SELF_CORRECTION.md](SELF_CORRECTION.md).

### Proof it holds

- Orchestration end-to-end test: `tests/test_orchestration.py`
- A2A audit trail test: `tests/test_audit_a2a.py`
- Live run:

  ```bash
  PYTHONPATH=. python3 -m sift_find_evil.orchestration --output-dir analysis/demo_run
  ```

---

## Where the security boundary is enforced (architectural vs prompt-based)

The competition requires that prompt-based and architectural guardrails be clearly
distinguished. In this system:

| Control | Enforced where | Architectural or prompt-based |
|---------|----------------|-------------------------------|
| No destructive/write tool flags | `ToolGuard` allowlist (code) | **Architectural** |
| Reads confined to evidence root | `ToolGuard` path containment (code) | **Architectural** |
| Runaway-loop protection | `ToolGuard` circuit breaker (code) | **Architectural** |
| No tool access except via MCP | Agent `tools:` allowlists grant no `Bash`/`Write`/`Edit` -- only `mcp__sift-find-evil__*` (+ read-only `Read`/`Grep`/`Glob`); standalone agents are Python classes with no shell | **Architectural** |
| Tool *selection* / analytic strategy | Agent definitions / prompts | Prompt-based (does not affect evidence integrity) |

The integrity-critical controls are all architectural: an agent cannot reach a forensic
tool except through `EvidenceMCPServer.run_tool`, and that chokepoint rejects anything
outside the allowlist or the evidence root before execution. Prompts shape *how the
agent reasons*, never *what it is physically able to do to the evidence*.

See [ARCHITECTURE_DIAGRAM.md](ARCHITECTURE_DIAGRAM.md) for the visual, and
[../analysis/FIND_EVIL_REQUIREMENTS.md](../analysis/FIND_EVIL_REQUIREMENTS.md) for the
full competition criteria these approaches satisfy.
