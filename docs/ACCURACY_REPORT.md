# Accuracy Report

> FIND EVIL! Deliverable #6. Self-assessment of finding accuracy for the
> multi-agent DFIR system: false positives, missed artifacts, hallucination
> controls, confirmed-vs-inferred separation, and an evidence-integrity /
> guardrail bypass test. **Honesty is valued over perfection** — this report
> documents what was measured, what is synthetic, and what is not yet wired.

**See also:** [ARCHITECTURE_DIAGRAM.md](ARCHITECTURE_DIAGRAM.md) for the
guardrail taxonomy, [PERFORMANCE_BENCHMARK.md](PERFORMANCE_BENCHMARK.md) for speed.

## How to reproduce

```bash
# Detection accuracy across all scenarios (writes analysis/scenario_report.json)
PYTHONPATH=. python tests/scenario_harness.py

# Guardrail bypass test (architectural evidence-integrity proof)
PYTHONPATH=. python -m pytest tests/test_mcp_guardrails.py tests/test_mcp_server.py -q

# Live bypass demo: attempt an out-of-bounds read through the MCP boundary
PYTHONPATH=. python -m sift_find_evil.orchestration --bypass-demo
```

---

## 1. Detection accuracy (measured)

Scenario harness run, all figures from the live run that writes
`analysis/scenario_report.json`. These are synthetic fixtures (see Caveats).

| Scenario | TP | FP | FN | Precision | Recall | F1 | Avg conf |
|---|---|---|---|---|---|---|---|
| 01_clean_baseline | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.00 |
| 02_ransomware | 3 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.75 |
| 03_timestomping | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.35 |
| 04_edge_cases | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.72 |
| 05_missing_prefetch | 3 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.80 |
| 06_webmail_exfiltration | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.80 |
| 07_cloud_upload | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.80 |
| 08_persistence_run_keys | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.75 |
| 09_shimcache_only | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.62 |
| 10_timestomping_with_bam | 3 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.48 |
| 11_yara_malware | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.95 |
| 12_memory_intrusion | 27 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.73 |
| 16_powershell_obfuscated | 5 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.82 |
| 19_credential_dumping | 5 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.72 |
| **TOTAL** | **57** | **0** | **0** | **1.00** | **1.00** | **1.00** | — |

14 scenarios, 57 true-positive findings, **0 false positives, 0 false
negatives** (micro-averaged F1 = 1.00). The full unit + integration suite is
**1030 tests** at 95% line coverage.

### Real evidence

Two real datasets were run end-to-end through the engine (artifacts in
`analysis/`):

| Dataset | Tier | Findings | FP | FN | Notes |
|---|---|---|---|---|---|
| `circl-2023-wiped` | real | 1 | 0 | 0 | Anti-forensics / wiped disk; one high-confidence finding (0.95). |
| `m57-jean` | real | 0 | 0 | 0 | Ran clean against the engine's current detector scope. |

These two are the *only* real datasets with verified run artifacts. Other
datasets named in `scenarios/` (e.g. `insider_threat_2022`, `nitroba`,
`apt_attack_2015`) are **downloaded/staged but not yet validated** — they appear
as unchecked items in `scenarios/VALIDATION.md` and have no run output. We do not
report numbers for them.

> **Correction (authoritative).** Earlier docs across this repo — including the
> top-level README and `PERFORMANCE_BENCHMARK.md` — cite a "1,071 findings /
> 7.7 GB / 155,452 MFT entries / 11 minutes" `insider_threat_2022` result. **That
> figure is not reproducible from any run artifact** and the dataset directory is
> empty; `PROOF_METHODOLOGY.md` itself marks the "11 minutes / 155K entries"
> number as an *estimate, not a measurement*. This Accuracy Report supersedes
> those numbers: treat the 1,071-finding result as unverified until a real run
> artifact exists. Cleanup of the stale citations across the other docs is
> tracked as follow-up (SFE-3sc).

---

## 2. False positives and missed artifacts

- **False positives across the scenario corpus: 0.** The clean-baseline scenario
  (legitimate activity only) produces zero findings, confirming the engine does
  not raise alarms on benign input.
- **Known detection gaps (true false-negative surface, by design today):**
  - **DLL-only timestomping** is not detected — timestomping currently fires only
    when a matching Prefetch entry exists.
  - **IPv6 network destinations** are deliberately skipped by the netscan and
    network-contradiction detectors (no tuned policy / fixtures yet).
  - **Memory and network self-correction** (contradiction types
    `MEMORY_PRESENCE_MISMATCH`, `NETWORK_PRESENCE_MISMATCH`) are implemented in
    the engine and unit-tested, but the end-to-end orchestration harness
    currently drives only the disk/timeline domain. A real investigation today
    exercises disk/timeline self-correction live; memory/network run via the
    detectors and unit tests, not yet the harnessed agent loop.
- **F1 = 1.00 is on synthetic fixtures**, not a claim of real-world infallibility.
  It means the implemented detection logic matches its ground truth with no drift;
  it does not measure performance against adversarial real-world noise.

---

## 3. Hallucination controls (no fabricated artifacts)

The system is built so an analyst agent cannot assert an artifact it did not
observe in tool output:

- **Findings cite their tool executions.** Every finding carries
  `source_tool_invocations` — the audit `entry_id`s of the MCP tool calls whose
  output produced it (A2A schema). A judge can trace any finding back to the
  exact tool execution; a claim with no backing tool invocation is structurally
  visible as ungrounded.
- **Analyst prompt rule.** Each `.claude/agents/dfir-*.md` analyst is instructed:
  "Emit a finding ONLY when grounded in tool output … Never assert an artifact
  you did not observe." This is a prompt-based control layered on top of the
  architectural audit trail (see ARCHITECTURE_DIAGRAM.md guardrail taxonomy).
- **The verifier challenges every finding.** The `dfir-verifier` runs each
  finding through the `SelfCorrectionEngine`, which can lower or recover
  confidence and is recorded as an A2A `verification` entry. In the demo
  investigation all three findings move `0.95 → 0.75` (contradiction detected
  then resolved via the Event Log tiebreaker) — visible self-correction, not a
  silent pass.

No hallucinated findings were observed in testing. The honest framing: with
synthetic fixtures the inputs are known-good, so this measures that the controls
*work*, not that they have been stress-tested against a model actively trying to
fabricate.

---

## 4. Confirmed observations vs inferences

Every finding separates what was *observed* from what was *concluded*:

- `finding_type` — `indicator` / `behavior` / `timeline_event`.
- `confidence` + `confidence_label` — e.g. timestomping lands at **0.35** (a
  critical red flag with no Event Log tiebreaker path), while a hash-matched
  exfil correlation lands at **0.95**. Low confidence is reported, not suppressed.
- `reasoning_chain` — an ordered, human-readable list that states the observation
  first ("MFT $SI time precedes $FN time by 3 days") and the inference second
  ("therefore likely timestomped"), so a reviewer sees exactly where evidence
  ends and interpretation begins.

The analyst agents are explicitly instructed to "distinguish a confirmed
observation from an inference," and the confidence score is the machine-readable
expression of that distinction.

---

## 5. Evidence-integrity / guardrail bypass test

This is the criterion-#4 proof: the read-only / evidence-containment guarantees
are **architectural** (enforced in code at the MCP boundary), so they hold even
when an agent ignores its prompt. We test that the boundary actually blocks
abuse.

### Automated bypass tests (17 passing)

`tests/test_mcp_guardrails.py` + `tests/test_mcp_server.py` exercise each
rejection path of `ToolGuard` / `EvidenceMCPServer`:

| Attempted bypass | Result |
|---|---|
| Write/modify flag (incl. novel spellings not on the allowlist) | **Rejected** — `GuardrailViolation` (deny-by-default arg allowlist) |
| Unknown tool not in policy set | **Rejected** — `GuardrailViolation` |
| Volatility plugin not on the allowlist | **Rejected** |
| Input path outside the evidence root | **Rejected** — path containment |
| Path-traversal escape (`../`) | **Rejected** — canonicalised then contained |
| Repeated failures | **Circuit breaker opens** after N consecutive failures |
| Known read-only invocation inside the root | **Allowed** (control case) |

### Live bypass demo (recorded in the audit log)

`python -m sift_find_evil.orchestration --bypass-demo` makes the disk analyst
attempt an out-of-bounds read — `volatility -f /etc/shadow -r json
windows.pslist` — through the MCP boundary. Result:

```text
action: tool_blocked   agent: disk_analyst   entry_id: evt-000003
reason: GuardrailViolation
message: Path '/etc/shadow' resolves outside the evidence root '…' (read-only containment)
```

The attempt is **denied before any subprocess runs**, and the denial is itself an
audited A2A entry on the same correlation thread as the investigation — an
attempted bypass is part of the permanent record, not silently dropped. The
investigation still completes (3 findings, all self-corrected `0.95 → 0.75`),
demonstrating the boundary blocks abuse without breaking legitimate work.

### Why this is architectural, not prompt-based

Agents hold no tool binaries and no write path to evidence; the *only* route to a
forensic tool is `EvidenceMCPServer.run_tool()`, which calls `ToolGuard.check()`
first. There is no prompt an agent can emit that reaches a tool without crossing
this check. Write operations are not denylisted — they are **unreachable**,
because anything not on the per-tool allowlist is rejected.

---

## Caveats (honest limitations)

- **Synthetic fixtures.** Scenarios are hand-authored CSV/JSON that mirror real
  forensic tool output. They validate detection logic deterministically in CI but
  do not measure performance on adversarial real-world noise.
- **Real-evidence coverage is thin.** Only two real datasets have verified run
  artifacts (`circl-2023-wiped`, `m57-jean`); broader real-evidence validation is
  open work.
- **Single-vote verification.** The verifier currently applies one
  self-correction pass per finding (engine tiebreaker), not an N-way adversarial
  panel. Multi-vote verification is a future enhancement.
- **Memory/network self-correction is engine + unit-test only**, not yet wired
  into the end-to-end orchestration harness (the harness drives disk/timeline).
- **Executable-level scoring.** The harness scores findings at the
  executable/category level; per-contradiction scoring is future work.
