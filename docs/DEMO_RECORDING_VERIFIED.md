# FIND EVIL! Demo - Verified Recording Script

> **Every command and every number in this script was executed live on the SIFT
> Workstation (`sift-dfir`, Claude Code 2.1.165 on AWS Bedrock) on 2026-06-05.**
> Nothing here is a projection. This is the single authoritative recording script;
> earlier demo drafts that carried unverified projections have been removed.
> Record against THIS document.

**Duration target:** 5 minutes. **Format:** live terminal screencast + narration.
**Host:** SIFT Workstation VM, Claude Code → Bedrock, our Custom MCP server.

---

## Pre-flight (do BEFORE recording — not on camera)

```bash
# On the VM (ssh sansforensics@<vm-ip>):
export AWS_PROFILE=bedrock CLAUDE_CODE_USE_BEDROCK=1
export PATH="$HOME/.local/bin:$PATH"
aws sso login --profile bedrock          # if the 12h SSO session expired
cd ~/sift_find_evil && source venv/bin/activate

# Confirm everything is live:
claude -p "Reply with exactly: BEDROCK_OK"        # -> BEDROCK_OK
claude mcp list                                    # -> sift-find-evil: ✓ Connected
sha256sum scenarios/real/circl-2023-wiped/evidence/wiped_disk.E01
#   c4a8145bcbfd5485cd7b36a0603bdec68674c2f27e6c2dcf3ef25aa7a4f4ef15  (authentic CIRCL TR-80)
```

Clear the scrollback, set a legible font size, and start the screen recorder.

---

## Timing breakdown

> **Why the timing has slack:** the commands themselves complete in seconds — the
> minutes are *narration*. Each segment has a "talking points" block below; lean
> on them so the screen has time to breathe and you're never racing the terminal.
> The two **[OPTIONAL]** beats (nitroba second source, adversarial framing) are
> stretch — include them if comfortably under time, cut first if not.

| Segment | Time | Content |
|---------|------|---------|
| 1. Problem | 0:00-0:40 | Adversary speed vs. manual IR; why autonomy + integrity |
| 2. The system | 0:40-1:20 | Extension of Protocol SIFT; Claude Code + Custom MCP; no-shell agents |
| 3. Real evidence | 1:20-2:30 | Agent analyzes a REAL CIRCL wiped disk → CRITICAL (+ optional nitroba) |
| 4. Multi-agent + self-correction | 2:30-3:40 | Orchestrator → analysts → verifier; contradiction resolved, one held |
| 5. Architectural guardrail | 3:40-4:20 | Live agent BLOCKED on out-of-bounds read; `tool_blocked` audited |
| 6. Traceability + accuracy | 4:20-4:40 | Trace any finding to its tools; F1=1.00 |
| 7. The report | 4:40-5:00 | The synthesized investigation report — Mermaid A2A + finding-flow diagrams |

---

## SEGMENT 1 - The problem (0:00-0:30)

**[Screen: SIFT terminal, project README visible]**

> "In November 2025, attackers drove Claude Code to run an intrusion at 80-90%
> autonomy - machine speed. Defenders still look up command-line flags during
> active incidents. This is SIFT Find Evil: an autonomous DFIR agent that extends
> Protocol SIFT, built to investigate at that pace - without sacrificing evidence
> integrity."

---

## SEGMENT 2 - The system (0:30-1:00)

**[Screen: run these, let output show]**

```bash
claude mcp list
```
**Expected (real):** `sift-find-evil: python -m sift_find_evil.mcp - ✓ Connected`

> "It runs on the SIFT Workstation itself. Claude Code is the agent runtime;
> backed by Bedrock. But the agents never touch a forensic tool directly - every
> tool call crosses our Custom MCP server, where the guardrails live in code."

```bash
# Show the agent only has MCP tools + read-only nav, NO shell:
grep -A1 '^tools:' .claude/agents/dfir-disk-analyst.md
```
**Expected (real):** `tools: ["Read", "Grep", "Glob", "mcp__sift-find-evil__*"]`

> "No Bash. No write tools. The only path to a forensic binary is the MCP server."

---

## SEGMENT 3 - Real evidence (1:00-2:15)

**[Screen: analyze the authentic CIRCL wiped disk]**

```bash
python -m sift_find_evil.cli analyze \
  --image scenarios/real/circl-2023-wiped/evidence/wiped_disk.E01 \
  --output analysis/circl-2023-wiped/findings.json
```

**Expected (real, exit 0): one CRITICAL finding.** Show the finding:

```bash
python3 -c "import json; f=json.load(open('analysis/circl-2023-wiped/findings.json'))['findings'][0]['finding']; print(f['severity'].upper(), '-', f['title'])"
```
**Expected (real):**
`CRITICAL - Partition table wiped (primary GPT zeroed, secondary GPT intact)`

> "This is real evidence - the CIRCL TR-80 wiped disk, hash-verified. The agent
> reads the raw E01, finds the primary GPT header zeroed while the backup GPT is
> intact - an asymmetry no normal OS action produces. A deliberate anti-forensic
> wipe. Confidence 0.95, and every byte it cites is in the evidence."

**[OPTIONAL second source - include if pacing allows (~20s). Different domain:
network. Keeps the demo from looking single-trick.]**

```bash
python -m sift_find_evil.cli analyze \
  --pcap scenarios/real/nitroba/evidence/nitroba.pcap \
  --output analysis/nitroba/findings.json
```

**Expected (real, exit 0):** a HIGH beaconing finding to `image.weather.com` from
`192.168.15.4`, confidence 0.7, with the reasoning chain:
`7 events, mean interval 899.5s, coefficient of variation 0.0016 (below 0.15) ->
uniform cadence consistent with automated/beaconing traffic`.

> "Different evidence, different domain - the Nitroba network capture, also
> hash-verified. Same agent finds command-and-control beaconing: seven callbacks
> at a near-perfect 15-minute cadence - a coefficient of variation of essentially
> zero. It doesn't just flag it; it shows the math behind the call."

---

## SEGMENT 4 - Multi-agent + self-correction (2:15-3:45)

**[Screen: the full orchestrated investigation]**

```bash
PYTHONPATH=. python3 -m sift_find_evil.orchestration --output-dir analysis/demo_run
```

**Expected (real, identical every run):**
```
Case INC-2026-001 -- 6 findings
  F-001 [disk_timeline] ransom_note.exe    contradiction_resolved   confidence 0.95 -> 0.75
  F-002 [disk_timeline] crypt_engine.exe   contradiction_resolved   confidence 0.95 -> 0.75
  F-003 [disk_timeline] persist.exe        contradiction_resolved   confidence 0.95 -> 0.75
  F-004 [memory       ] crypt_engine.exe   contradiction_resolved   confidence 0.95 -> 0.75
  F-005 [network      ] 203.0.113.66       contradiction_detected   confidence 0.9 -> 0.45
  F-006 [network      ] 1.1.1.1            contradiction_resolved   confidence 0.9 -> 0.75
```

> "Now the multi-agent investigation. An orchestrator dispatches a triage agent
> and three domain analysts - disk, memory, network. No single agent holds all
> the evidence. Then a verifier challenges every finding.
>
> Look at F-001: the disk timeline says a file executed BEFORE it was created - a
> causality violation. The verifier catches it, drops confidence from 0.95, queries
> the Event Log as a tiebreaker, and resolves it to 0.75. That's autonomous
> self-correction - the agent fixing its own reasoning, on the record.
>
> And F-005 - a hardcoded-IP C2 beacon with no DNS - it canNOT resolve, so it stays
> flagged at 0.45. The agent is honest about what it can't confirm."

---

## SEGMENT 5 - The architectural guardrail (3:45-4:30)

**[Screen: ask the live Claude agent to read something out of bounds]**

```bash
claude -p "Use the mcp__sift-find-evil__mftecmd tool to parse the MFT at path /etc/shadow with output_dir /tmp/out and correlation_id corr-demo. Report exactly what the tool returned." \
  --allowedTools "mcp__sift-find-evil__*"
```

**Expected (real):** the agent reports the tool returned an error:
`Path '/etc/shadow' resolves outside the evidence root ... (read-only containment)`

> "Here's the difference between 'the agent shouldn't' and 'the agent can't.' I'm
> telling a live agent to read /etc/shadow - outside the evidence. It physically
> cannot. The MCP server rejects it in code, before any tool runs."

```bash
grep tool_blocked analysis/live_demo/audit.jsonl | tail -1 | python3 -m json.tool
```

> "And the blocked attempt is logged - which agent, what it tried, why it was
> denied. A bypass attempt isn't just stopped; it's evidence."

**[OPTIONAL — adversarial framing, ~15s. Say it over the audit JSON if pacing
allows; it elevates the block from a feature to a threat-model answer. Cut first
if over time.]**

> "This matters because the evidence is attacker-controlled input. A sophisticated
> adversary - the kind this competition was built around - can target the
> responder's agent: poison it with a crafted artifact, or bury it in a giant file
> to exhaust its context. Our answer is architectural. Even if a prompt injection
> hidden in the evidence convinces the agent to *try* something, it still can't
> reach a destructive tool - the boundary rejects it in code. We don't claim to
> solve prompt injection; nobody has. But we decouple the injection from the
> impact. The agent can be fooled in what it says - it cannot act against the
> evidence."

---

## SEGMENT 6 - Close (4:30-5:00)

```bash
# Traceability: any finding back to the exact tool executions
python3 -c "from sift_find_evil.audit.logger import AuditLogger; [print(e.entry_id, e.action) for e in AuditLogger('analysis/demo_run/audit.jsonl').trace('F-001')]"

# And the deterministic regression gate:
PYTHONPATH=. python3 tests/scenario_harness.py | grep TOTAL
```
**Expected (real):** `TOTAL  62  0  0  1.00  1.00  1.00`

> "Every finding traces to the tool execution that produced it. The detection
> engine holds F1 of 1.00 across 15 scenarios - zero false positives, zero false
> negatives."

---

## SEGMENT 7 - The report (4:40-5:00)

**[Screen: generate the investigation report and open it — ideally rendered on
GitHub or a Markdown preview so the Mermaid diagrams display as graphics.]**

Pre-staged ONCE before recording (a 6-finding case so the report carries BOTH
diagrams — the single-finding CIRCL case shows only the sequence diagram):

```bash
# (pre-flight, off camera) build the multi-finding demo case once:
CR=~/demo_cases
python -m sift_find_evil.cli case init --case-id DEMO-MULTI \
  --name "Multi-Agent Investigation" --examiner "Jonathan Tomek" --case-root $CR
PYTHONPATH=. python3 scripts/prep-demo-case.py --case-id DEMO-MULTI --case-root $CR
```

On camera — generate and show the report:

```bash
python -m sift_find_evil.cli report --case-id DEMO-MULTI \
  --output $CR/DEMO-MULTI/report.md --format markdown --all-findings --case-root $CR
```

Then open `report.md` rendered (MarkText, or GitHub / VS Code preview) so the
Mermaid displays as graphics:

> "And this is what the analyst actually receives - a court-style investigation
> report the agent wrote itself. An executive summary with stated confidence, each
> finding mapped to MITRE ATT&CK with its supporting evidence, chain of custody,
> and a methodology section. But look at the visuals: this agent-to-agent sequence
> diagram is the *real execution record* - orchestrator dispatching triage and the
> three analysts, the verifier challenging every finding - reconstructed straight
> from the audit log. And the findings-at-a-glance flow: five contradictions
> resolved in green, one held in red - the C2 beacon the agent refused to dismiss.
> Nothing here is hand-drawn; the system generated all of it from the investigation
> it just ran. That's autonomous DFIR you can hand to a court."

**Expected (real):** a Markdown report following DFIR conventions whose visuals
include a `sequenceDiagram` (orchestrator → triage → disk/memory/network analysts
→ verifier) and a colour-coded `flowchart` of the 6 findings (5 green resolved,
F-005 red/held). Verified live on the VM 2026-06-05.

---

## Real numbers used in this script

> **Verification provenance:** the reproducible segments (3 real-evidence
> analyses, 4 orchestration + self-correction, 6 traceability, 7 report, and the
> scenario harness) were RE-VERIFIED on current `main` on 2026-06-10. The live VM
> beats (Segments 2 and 5: `claude` → MCP enumeration, and the `tool_blocked`
> guardrail) were verified on the SIFT VM on 2026-06-05 and run only on the VM.

| Claim | Verified value |
|-------|----------------|
| CIRCL E01 SHA-256 | `c4a8145b...4f4ef15` (matches pinned hash) |
| CIRCL analysis result | 1 CRITICAL, exit 0, wiped primary GPT |
| nitroba PCAP SHA-256 | `2b77a9ea...53ec2fb` (matches pinned hash) |
| nitroba analysis result | HIGH beaconing to image.weather.com, conf 0.7, CoV 0.0016 over 7 events |
| Orchestration | 6 findings; F-005 stays detected (0.9→0.45), rest resolved (→0.75) |
| Audit log (demo_run) | 37 entries: 16 agent_message, 8 tool_invocation, 6 finding_emitted, 6 verification, 1 tool_blocked |
| Guardrail block | mftecmd /etc/shadow → GuardrailViolation, logged tool_blocked |
| Scenario harness | 62 findings across 15 synthetic scenarios, F1=1.00 (0 FP / 0 FN) |

## Recording tips

- Run each block once off-camera first (warms Bedrock latency; the first live
  `claude -p` call is the slowest).
- The orchestration + harness outputs are deterministic - safe to re-take.
- The live `claude` calls vary in wording; the BLOCK and the audit entry are the
  invariants - if narration drifts, the on-screen error + JSON carry the point.
- Keep the audit JSON on screen during Segment 5; it's the strongest single frame.
