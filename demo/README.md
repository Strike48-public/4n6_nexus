# Demo Folder

Supporting artifacts for the 5-minute competition demo.

> **The recording script is [`docs/DEMO_RECORDING_VERIFIED.md`](../docs/DEMO_RECORDING_VERIFIED.md)** -
> the single authoritative script, with every command and number verified live on
> the SIFT Workstation. Record against that. This folder holds the committed
> sample artifacts a judge can inspect without running anything.

## Contents

| File | Purpose |
|------|---------|
| `run-demo.sh` | **Interactive step-through** of the verified recording commands. Run on the SIFT VM (`./demo/run-demo.sh`); it pauses at each segment so you narrate, then runs the command on Enter. `--preflight` runs only the checks; `--auto` runs without pauses (rehearsal). Mirrors `docs/DEMO_RECORDING_VERIFIED.md` exactly — that doc stays the narrative source of truth. |
| `a2a_investigation_log.jsonl` | **Deliverable #8 sample.** Full multi-agent A2A log from a real run (37 entries: `agent_message`, `tool_invocation`, `finding_emitted`, `verification`, `tool_blocked`). Trace any finding to its tool executions: `AuditLogger('demo/a2a_investigation_log.jsonl').trace('F-001')`. |
| `findings_sample.json` | A sample findings file (structure reference / live-failure backup). |
| `audit_sample.jsonl` | A single real `tool_invocation` entry (raw MFTECmd output example). |

## Reproducing the demo artifacts

The recording script drives these live; to regenerate the committed samples:

```bash
cd ~/sift_find_evil && source venv/bin/activate

# Multi-agent A2A log (deterministic) -> a2a_investigation_log.jsonl source
PYTHONPATH=. python3 -m sift_find_evil.orchestration --bypass-demo \
  --output-dir analysis/demo_run

# Real-evidence analysis (CIRCL wiped disk) -> a real CRITICAL finding
python -m sift_find_evil.cli analyze \
  --image scenarios/real/circl-2023-wiped/evidence/wiped_disk.E01 \
  --output analysis/circl-2023-wiped/findings.json
```

See [`../docs/DEMO_RECORDING_VERIFIED.md`](../docs/DEMO_RECORDING_VERIFIED.md) for
the full beat-by-beat script (pre-flight, segments, expected output, real numbers)
and [`../docs/TRY_IT_OUT.md`](../docs/TRY_IT_OUT.md) for the judge run-it-yourself path.
