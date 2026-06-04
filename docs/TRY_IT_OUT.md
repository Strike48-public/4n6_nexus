# Try It Out — Judge Quickstart

> FIND EVIL! Deliverable #7. Step-by-step instructions to run the agent locally
> against provided evidence and produce findings plus an agent-to-agent (A2A)
> audit log. **Every command below was executed end-to-end from this repository
> before publishing** — see the "Verified" note under each step. No live
> deployment URL is required; this runs entirely on a local SIFT / Linux
> terminal.

## Requirements

| Need | Detail |
|---|---|
| OS | Linux terminal / SANS SIFT Workstation (developed on Ubuntu; macOS works too) |
| Python | **3.12** (the version CI runs and the engine is tested against) |
| Disk | ~500 MB for the repo + synthetic fixtures (real-evidence images are larger and optional) |
| Network | Only to `pip install` dependencies and (optionally) download real evidence |

No native build toolchain or external forensic binaries are required for the
core demo and validation — `requirements.txt` is pure-Python plus prebuilt
wheels (including `yara-python`).

## 1. Clone and install

```bash
git clone https://github.com/Strike48/sift_find_evil.git
cd sift_find_evil

python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

> **Verified:** all core dependencies (`pyyaml`, `pydantic`, `rich`, `textual`,
> `psutil`, `pandas`, `numpy`, `yara-python`, `mcp`, `python-dateutil`, `pytz`)
> import cleanly on Python 3.12 from `requirements.txt` alone.

For processing **real** disk/memory/PST evidence (not needed for the demo or
validation), also install the native extras:

```bash
pip install -r requirements-forensic.txt   # pyewf, pytsk3, pypff, etc.
```

## 2. Thirty-second smoke test (self-correction demo)

The fastest proof the engine works — runs on bundled synthetic data, no
arguments:

```bash
PYTHONPATH=. python3 -m sift_find_evil.cli demo
```

Expected: a planted contradiction is **detected**, **resolved via Event Log
evidence**, and confidence is adjusted to **0.75**, ending with:

```
  Validation checks:
    [PASS] Contradiction detected
    [PASS] Resolution applied via Event Log
    [PASS] Confidence in expected range: 0.75
    [PASS] Comprehensive reasoning chain (5 steps)
  Demo completed successfully!
```

> **Verified:** runs to `Demo completed successfully!`, exit code 0.

## 3. Run the multi-agent investigation (findings + A2A audit log)

This is the agentic deliverable: an orchestrator dispatches a triage agent and
a disk analyst (tools called through the Custom MCP boundary), then a verifier
challenges the findings and resolves contradictions — emitting **one correlated
A2A audit log**.

```bash
PYTHONPATH=. python3 -m sift_find_evil.orchestration --output-dir ./analysis/demo_run
```

Expected output:

```
Case INC-2026-001 -- 3 findings
  F-001 ransom_note.exe    contradiction_resolved   confidence 0.95 -> 0.75
  F-002 crypt_engine.exe   contradiction_resolved   confidence 0.95 -> 0.75
  F-003 persist.exe        contradiction_resolved   confidence 0.95 -> 0.75

A2A audit log:  ./analysis/demo_run/audit.jsonl
Report:         ./analysis/demo_run/report.json
```

> **Verified:** produces 3 findings, each self-corrected 0.95 → 0.75, and writes
> `audit.jsonl` + `report.json`.

### Trace any finding back to its tool executions

The audit-trail requirement ("trace any finding back to the specific tool
execution that produced it") is satisfied by `AuditLogger.trace`:

```bash
PYTHONPATH=. python3 -c "from sift_find_evil.audit.logger import AuditLogger; \
[print(e.entry_id, e.action) for e in AuditLogger('analysis/demo_run/audit.jsonl').trace('F-001')]"
```

Expected: the full correlated thread for `F-001` — agent dispatch messages →
`tool_invocation` entries → `finding_emitted` → `challenge` → `verification`.

> **Verified:** reconstructs the 18-entry A2A thread for F-001.

## 4. See the architectural guardrail block a bypass attempt

Demonstrates that read-only / evidence-containment is enforced **at the MCP
boundary, not by prompt**. The disk analyst attempts an out-of-bounds read
(`/etc/shadow`); the boundary denies it and records the denial.

```bash
PYTHONPATH=. python3 -m sift_find_evil.orchestration --bypass-demo --output-dir ./analysis/bypass_run
```

Confirm the denial was audited:

```bash
grep tool_blocked ./analysis/bypass_run/audit.jsonl
```

Expected: a `tool_blocked` entry with
`reason: GuardrailViolation` and a message that `/etc/shadow` resolves outside
the evidence root. The investigation still completes its 3 findings — the
boundary blocks abuse without breaking legitimate work.

> **Verified:** `tool_blocked` / `GuardrailViolation` entry present;
> investigation completes normally.

## 5. Reproduce the accuracy result (validation harness)

The headline F1 = 1.00 across all scenarios:

```bash
PYTHONPATH=. python3 tests/scenario_harness.py
```

Expected final line:

```
TOTAL                       57   0   0    1.00    1.00    1.00
```

(14 scenarios, 57 findings, 0 false positives, 0 false negatives. A
machine-readable copy is written to `analysis/scenario_report.json`.)

> **Verified:** prints `TOTAL  57  0  0  1.00  1.00  1.00`.

Run the full test suite too, if you want:

```bash
PYTHONPATH=. python3 -m pytest -q          # 1030 tests
```

## 6. (Optional) Run against real evidence

Real images are not bundled (they are multi-GB). Each lives under
`scenarios/real/<name>/` with a `scenario.yaml` that pins the source URL and
SHA-256, and a `download.sh` / documented fetch step. Provenance and expected
findings for every dataset are in
[EVIDENCE_DATASETS.md](EVIDENCE_DATASETS.md). Example (CIRCL wiped disk):

```bash
# After downloading evidence into scenarios/real/circl-2023-wiped/evidence/
python3 -m sift_find_evil.cli analyze \
    --image scenarios/real/circl-2023-wiped/evidence/wiped_disk.E01 \
    --output analysis/circl-2023-wiped/findings.json
```

Expected: one CRITICAL finding (wiped GPT partition table, confidence 0.95).

## Command reference

| Goal | Command |
|---|---|
| Self-correction smoke test | `python3 -m sift_find_evil.cli demo` |
| Multi-agent run + A2A log | `python3 -m sift_find_evil.orchestration --output-dir DIR` |
| Guardrail bypass proof | `python3 -m sift_find_evil.orchestration --bypass-demo --output-dir DIR` |
| Accuracy harness (F1=1.00) | `python3 tests/scenario_harness.py` |
| Full test suite | `python3 -m pytest -q` |
| CLI help (all subcommands) | `python3 -m sift_find_evil.cli --help` |

All commands are run from the repository root with `PYTHONPATH=.` (or after
`pip install -e .`). See [ARCHITECTURE_DIAGRAM.md](ARCHITECTURE_DIAGRAM.md) for
how the pieces connect, [ACCURACY_REPORT.md](ACCURACY_REPORT.md) for the
accuracy self-assessment, and [EVIDENCE_DATASETS.md](EVIDENCE_DATASETS.md) for
what was tested and found.
