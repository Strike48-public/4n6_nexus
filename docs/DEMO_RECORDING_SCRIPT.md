# Demo Recording Script (5-Minute Walkthrough)

> FIND EVIL! Deliverable #2 prep. A command-by-command script for the live
> screencast, with narration beats and the exact expected output. **Every
> command here was dry-run verified** (see [TRY_IT_OUT.md](TRY_IT_OUT.md)); the
> numbers below are real, not placeholders.
>
> ⚠️ Do NOT narrate any unverified metric. The only numbers spoken on camera are
> the ones these commands actually print. (See SFE-3sc for why this matters.)

## Pre-flight (do BEFORE you hit record)

```bash
cd ~/Code/sift_find_evil
source .venv/bin/activate                    # or: pip install -r requirements.txt
rm -rf analysis/demo_run analysis/bypass_run # clean slate so the log is fresh
clear
```

Terminal: large font, dark theme, wide enough that the orchestration table
doesn't wrap. Target length **≤ 5:00**; judges aren't required to watch past 10.

---

## Beat 1 — The problem (0:00–0:30, talking head or title card)

> "A DFIR analyst's real skill isn't running tools — it's noticing when two
> artifacts disagree, and resolving that contradiction before it goes in the
> report. Timestamps get backdated. Hidden processes keep their sockets. Malware
> hardcodes a C2 IP to skip DNS. We built an autonomous multi-agent system that
> does that contradiction-resolution loop itself, on SIFT, with safety enforced
> in the architecture — not just asked for in a prompt."

No terminal yet. State the three demonstrations you're about to show:
**self-correction, traceable accuracy, architectural guardrails.**

---

## Beat 2 — Self-correction smoke test (0:30–1:10)

```bash
PYTHONPATH=. python3 -m sift_find_evil.cli demo
```

Expected (real output):

```
  Confidence: 0.75 (Medium)
  Contradictions Detected: 1
    [PASS] Contradiction detected
    [PASS] Resolution applied via Event Log
    [PASS] Confidence in expected range: 0.75
    [PASS] Comprehensive reasoning chain (5 steps)
  Demo completed successfully!
```

> "Thirty-second sanity check. The engine planted a causality contradiction — a
> file modified *after* it executed — detected it, resolved it using Event Log
> evidence, and dropped its confidence from 0.95 to 0.75. That's one domain.
> Now the full multi-agent investigation."

---

## Beat 3 — The multi-agent investigation (1:10–2:40) — CENTERPIECE

```bash
PYTHONPATH=. python3 -m sift_find_evil.orchestration --output-dir analysis/demo_run
```

Expected (real output):

```
Case INC-2026-001 -- 6 findings
  F-001 [disk_timeline] ransom_note.exe    contradiction_resolved   confidence 0.95 -> 0.75
  F-002 [disk_timeline] crypt_engine.exe   contradiction_resolved   confidence 0.95 -> 0.75
  F-003 [disk_timeline] persist.exe        contradiction_resolved   confidence 0.95 -> 0.75
  F-004 [memory       ] crypt_engine.exe   contradiction_resolved   confidence 0.95 -> 0.75
  F-005 [network      ] 203.0.113.66       contradiction_detected   confidence 0.9 -> 0.45
  F-006 [network      ] 1.1.1.1            contradiction_resolved   confidence 0.9 -> 0.75

A2A audit log:  analysis/demo_run/audit.jsonl
Report:         analysis/demo_run/report.json
```

Narration — walk the table, top to bottom:

> "One command drives the whole agent team: an orchestrator dispatches a triage
> agent and three domain analysts — disk, memory, network — and a verifier
> challenges every finding. Six findings, three domains, one investigation."
>
> "Disk: three timestomped binaries, each resolved via the Event Log tiebreaker.
> Memory: a process that shows up in psscan but *not* pslist while holding a live
> socket — a classic hidden-process rootkit signal — resolved by the psscan
> tiebreaker."
>
> **(Point at F-005 and F-006 — this is the money shot.)**
> "Now watch the network domain. F-005 is a connection to a hardcoded IP with no
> DNS lookup — a C2 signal. The verifier challenges it, finds no benign
> explanation, and it **stays flagged** — confidence drops to 0.45. But F-006,
> right below it, is traffic to 1.1.1.1 — Cloudflare DNS, also no hostname
> lookup, but legitimately so. The verifier **resolves that one** up to 0.75.
> Same surface signal, opposite verdicts. The agent isn't rubber-stamping — it's
> reasoning about each case."

---

## Beat 4 — Traceable accuracy (2:40–3:30)

> "Every finding traces back to the exact tool execution that produced it. Pick
> the network finding."

```bash
PYTHONPATH=. python3 -c "from sift_find_evil.audit.logger import AuditLogger; \
[print(e.entry_id, e.action) for e in AuditLogger('analysis/demo_run/audit.jsonl').trace('F-005')]"
```

Expected (real output — finding-specific, NOT the whole case):

```
evt-000017 tool_invocation
evt-000018 tool_invocation
evt-000019 finding_emitted
evt-000031 agent_message
evt-000032 verification
```

> "F-005's lineage and nothing else: the two `tshark` tool calls that produced
> it, the finding itself, the verifier's challenge message, and the verification
> verdict. A judge can do this for any of the six findings and get *that*
> finding's evidence chain — not a dump of the whole case. Single correlated
> JSONL log, UTC, append-only."

Optional: `cat analysis/demo_run/audit.jsonl | head -3` to show the raw envelope.

---

## Beat 5 — Architectural guardrails (3:30–4:20)

> "The safety controls are architectural, not prompt-based. Every tool call
> crosses a Custom MCP server with a deny-by-default allowlist. Let's make an
> agent try to read something outside the evidence — `/etc/shadow`."

```bash
PYTHONPATH=. python3 -m sift_find_evil.orchestration --bypass-demo --output-dir analysis/bypass_run
grep tool_blocked analysis/bypass_run/audit.jsonl
```

Expected: the run still completes its 6 findings, and:

```
... "action": "tool_blocked" ... "reason": "GuardrailViolation" ...
"message": "Path '/etc/shadow' resolves outside the evidence root ... (read-only containment)"
```

> "Blocked at the MCP boundary before any subprocess ran — and the *attempt* is
> itself recorded in the audit log. There's no prompt an agent can write that
> reaches a tool without crossing this check. Write operations aren't
> denylisted; they're unreachable. The investigation still finished normally —
> the guardrail blocks abuse without breaking legitimate work."

---

## Beat 6 — Accuracy at scale + close (4:20–5:00)

```bash
PYTHONPATH=. python3 tests/scenario_harness.py | tail -3
```

Expected (real output):

```
TOTAL                       57   0   0    1.00    1.00    1.00
```

> "Across fourteen scenarios — 57 findings, zero false positives, zero false
> negatives, F1 of 1.00 — backed by over a thousand tests. On real evidence we
> have verified runs on the CIRCL wiped-disk image and the M57 and Nitroba
> cases, documented honestly in our accuracy report, including what we *didn't*
> find."
>
> "Self-correction across three domains, every finding traceable to its tool
> execution, guardrails enforced in code. That's SIFT Find Evil."

---

## Timing summary

| Beat | Content | Target |
|------|---------|--------|
| 1 | Problem statement | 0:30 |
| 2 | Self-correction smoke test | 0:40 |
| 3 | Multi-agent investigation (centerpiece) | 1:30 |
| 4 | Traceable accuracy | 0:50 |
| 5 | Architectural guardrail bypass | 0:50 |
| 6 | Accuracy at scale + close | 0:40 |
| | **Total** | **~5:00** |

## Honest scoping notes (so nothing said on camera is unverifiable)

- **The memory/network evidence in the demo is synthetic fixtures** shaped like
  real Volatility / tshark output (`scenarios/synthetic/02_ransomware/`). Say
  "synthetic fixtures that mirror tool output" if asked — do not imply a live
  Volatility run produced F-004.
- **Live Volatility on the real Narcos memory image was attempted and is an
  environment limitation, not a product one.** The E01 exports cleanly and the
  engine shells out correctly, but this offline SIFT box has no bundled Windows
  kernel symbols and no network to fetch them, so Vol3 can't symbolize the
  image. The synthetic memory fixtures exercise the same `MemoryDetector` +
  self-correction code path. Don't show a failed Vol run on camera.
- **Real-evidence disk run:** the CIRCL wiped-disk E01 is the strongest live
  real-evidence moment if you want one (`cli analyze --image ...` → one CRITICAL
  finding). It needs the evidence downloaded first; keep it as an optional B-roll
  segment, not part of the 5-minute core.
- Every confidence number, finding count, and the F1 line above are the actual
  current outputs as of this script. Re-run Beat 3 and Beat 6 right before
  recording to confirm they still match.
