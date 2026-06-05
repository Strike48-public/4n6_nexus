# Written Project Description (Devpost Story)

> FIND EVIL! Deliverable #4. The Devpost submission narrative. Sections follow
> Devpost's prompts: What it does · How we built it · Challenges · What we
> learned · What's next. Every metric here is reproducible — see
> [TRY_IT_OUT.md](TRY_IT_OUT.md), [ACCURACY_REPORT.md](ACCURACY_REPORT.md), and
> [ARCHITECTURE_DIAGRAM.md](ARCHITECTURE_DIAGRAM.md).

## Inspiration

A DFIR analyst triaging a disk image does the same thing a hundred times: run a
tool, read its output, form a hypothesis, then run a *second* tool to check
whether the first one lied. Timestamps get backdated. Processes unlink
themselves from the active list but keep their sockets. Malware hardcodes a C2
IP to skip DNS. The skill isn't running the tools — it's noticing when two
artifacts disagree and resolving the contradiction before writing it into a
report.

That "notice the contradiction, resolve it, then report" loop is exactly what a
language model does badly if you just ask it nicely, and exactly what an
*agentic system with the right architecture* can do reliably. We wanted to build
the second thing — and to make its safety guarantees real, not promised.

## What it does

The hackathon's goal is to *make Protocol SIFT a fully autonomous incident
response agent*. 4n6 Nexus does that by teaching the agent how a **senior analyst
thinks** — not just how to run tools. A senior analyst sequences their approach
(triage first, scope the domains, then go deep where the evidence is), recognizes
when something doesn't add up (two artifacts disagree), and adjusts (pull a third
source, lower confidence, or hold the finding). Our system encodes that loop: the
orchestrator sequences, the analysts go deep per domain, and the verifier is the
"that doesn't add up" instinct made architectural — it challenges every finding
and resolves or holds it before anything is reported.

**4n6 Nexus** (submitted as *SIFT Find Evil*) is an autonomous multi-agent DFIR
system that extends Protocol SIFT. A lead orchestrator opens a case, dispatches a
triage agent and three domain analysts (disk/timeline, memory, network), and a
verifier
challenges every finding. It runs on the SANS SIFT Workstation / a Linux
terminal using Claude Code subagents.

It delivers the three demonstrations the hackathon asks for:

- **Self-correction across three domains.** Every analyst finding is challenged
  by the verifier through a `SelfCorrectionEngine` that detects cross-artifact
  contradictions and resolves them with a second source. One reproducible
  command produces six findings in a single correlated log:
  - **Disk/timeline** — a binary modified *after* it executed (causality
    violation); resolved via the Event Log 4688 tiebreaker (`0.95 → 0.75`).
  - **Memory** — a process present in `psscan` but missing from `pslist` while
    owning a live socket (a DKOM hidden-process signal); resolved via the
    `psscan` tiebreaker (`0.95 → 0.75`).
  - **Network** — a conversation to a hardcoded external IP with no preceding
    DNS resolution. One such finding **stays detected** (`0.90 → 0.45`, a real
    C2 signal) right next to a benign public-DNS hit that **resolves**
    (`0.90 → 0.75`). The verifier does not blanket-approve — it keeps the
    genuine contradiction flagged.

- **Accuracy you can trace.** Every finding records the exact tool invocations
  that produced it (`source_tool_invocations`). A judge picks any finding and
  reconstructs the full thread — agent messages → tool calls → finding →
  challenge → verification — with one call to `AuditLogger.trace()`.

- **Analytical reasoning, not a log dump.** Each finding carries a `finding_type`
  (indicator / behavior / timeline_event), a confidence with a label, and a
  `reasoning_chain` that states the observation first and the inference second —
  so a reviewer sees exactly where evidence ends and interpretation begins.

On the validation harness it holds **F1 = 1.00 across 14 synthetic scenarios
(57 findings, 0 false positives, 0 false negatives)**, backed by 1,035 tests at
~94% coverage. Against real evidence it has verified runs on the CIRCL wiped-disk
image (1 CRITICAL finding) and the Digital Corpora M57-Jean and Nitroba cases.

## How we built it

**Architecture: a Multi-Agent Framework over a Custom MCP Server.** The agent
layer (six Claude Code subagent definitions in `.claude/agents/dfir-*.md`) is the
execution engine; a Custom MCP server (`EvidenceMCPServer`) is the single
chokepoint every forensic-tool call crosses. This split is the whole point of
the design, because it lets the safety controls be **architectural** rather than
prompt-based:

- The MCP `ToolGuard` enforces three controls in code — a **per-tool argument
  allowlist** (deny-by-default, so write/modify flags are *unreachable*, not just
  discouraged), **evidence-path containment** (no reads outside the evidence
  root, traversal rejected), and a **circuit breaker**.
- An agent holds no tool binaries and no write path to evidence. Its only route
  to a forensic tool is `EvidenceMCPServer.run_tool()`, which calls
  `ToolGuard.check()` before any subprocess runs. There is no prompt an agent can
  emit that reaches a tool without crossing that check. Prompt-based rules
  ("never call binaries directly", "never fabricate an artifact") exist too — but
  as defense-in-depth *on top of* the code boundary, never as the primary
  control.

**Detection + self-correction engine.** Underneath the agents sits a
deterministic Python engine: parsers normalize tool output into typed rows;
detectors emit findings with MITRE ATT&CK mappings; and the `SelfCorrectionEngine`
implements the three cross-domain contradiction types with their tiebreakers.

**Audit trail.** A single append-only JSONL log carries every agent message,
tool invocation, finding, verification, and *blocked* tool attempt, all keyed by
one `correlation_id` per investigation — UTC, monotonic, never mutated.

**Reproducibility.** Because a recorded demo isn't repeatable, we built an
in-process orchestration harness (`python -m sift_find_evil.orchestration`) that
drives the same agent flow deterministically and emits an identical-every-time
audit log. The live Claude Code subagents and this harness share the same MCP
server and engine.

**Stack:** Python 3.12, the official MCP SDK, court-vetted forensic tools
(MFTECmd, PECmd, EvtxECmd, RECmd, Volatility 3, Sleuth Kit) behind read-only
policies, YARA, pytest. Synthetic JSON/CSV fixtures mirror real tool output so
the detection logic is validated deterministically in CI without multi-GB
evidence.

## Challenges we ran into

- **Making guardrails provable, not promised.** A denylist of write flags is
  brittle — there's always another spelling. We inverted it to a deny-by-default
  *allowlist*: a tool may run only with the exact flags it declares, so write
  operations are structurally impossible at the boundary. We then wrote a bypass
  test that makes an agent try to read `/etc/shadow` and proves the boundary
  blocks it and records the attempt as `tool_blocked`.

- **Protecting an accuracy invariant while adding features.** The synthetic
  harness must stay at F1 = 1.00. Adding the memory and network contradiction
  types risked perturbing scenario counts. We kept them safe *by construction*:
  the regression harness only scores fixtures declared in each `scenario.yaml`,
  so new demo evidence is invisible to it and consumed only by the orchestration
  harness. F1 = 1.00 held through every Phase B change.

- **A false IP-range assumption.** Our first network detector treated any
  non-RFC1918 address as "external," which leaked carrier-grade NAT (100.64/10)
  and reserved ranges as fake C2 signals. Code review caught it; we switched to
  the standard-library `is_global` predicate (with a documented exception for the
  TEST-NET ranges our fixtures use) and added tests for every reserved block.

- **Bugs hide where you don't run the code.** While *verifying* the judge
  quickstart end-to-end, the documented `AuditLogger.trace()` command crashed —
  it passed a string where a `Path` was expected. The fix was one line, but it
  only surfaced because we actually ran what we documented.

## What we learned

The biggest lesson was about **our own honesty under deadline pressure.** Midway
through, we found that a "1,071 findings / 7.7 GB / 11-minute" result for an
insider-threat dataset had propagated into 13+ documents — including the README
and a "Measured Performance" benchmark table — but it was *not reproducible from
any run artifact*. Our own methodology doc had even flagged the runtime as an
estimate. We treated this the way the engine treats a forensic finding: if it
can't be traced to evidence, it doesn't get asserted. We purged the number
everywhere, wrote an authoritative correction in the Accuracy Report, and added
"DO NOT NARRATE UNVERIFIED NUMBERS" banners to the demo scripts so it could never
reach the submission video. The accuracy report is now built on results that have
run artifacts, full stop.

That experience made the technical thesis concrete: **the same discipline that
makes a guardrail architectural instead of aspirational is what makes a finding
credible instead of plausible.** An agent that can fabricate a clean-sounding
metric is the same failure mode as an agent that can quietly write to evidence —
both are prevented by structure, not by good intentions.

## What's next

- **Wire the live Claude Code subagents end-to-end against the in-process harness
  artifact** for the recorded demo (the deterministic harness already guarantees
  the artifact).
- **Broaden real-evidence coverage.** We have the Narcos/CCleaner disk + memory,
  M57-Patents, National Gallery, and a large multi-system APT corpus staged; the immediate
  work is generating the EZ Tools / Volatility CSVs on Windows so the full
  USB/cloud/timeline triage runs against them, not just the disk-image wipe path.
- **N-way adversarial verification.** Today the verifier makes one
  self-correction pass per finding; a panel of independent skeptics would catch
  failure modes a single pass misses.
- **IPv6 network policy** and **DLL-only timestomping**, the two detection gaps
  the Accuracy Report names honestly.

After the hackathon the project continues under its product name, **4n6 Nexus**.
