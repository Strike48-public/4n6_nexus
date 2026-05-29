# Demo Guide

A 5-minute live demo of SIFT Find Evil. Every command here is verified to work
from a clean core install (no forensic extras, no evidence files).

## Setup (once, before the demo)

```bash
cd ~/Code/sift_find_evil
source venv/bin/activate
```

If `venv/` does not exist yet:

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

> Rehearse the full demo on the actual demo machine beforehand. The commands are
> verified here, but a fresh box or the SIFT workstation should get one dry run.

---

## The 3-beat demo

### Beat 1 — Self-correction (the differentiator, ~90s)

```bash
python -m sift_find_evil demo
```

**Say:** "Most tools report conflicting timestamps and leave the examiner to
reconcile them. Watch what this does instead."

**Point at:** `malware.exe` executed at 14:25 but the MFT says it was modified at
14:40 - a causality violation (a file cannot run before it exists). The engine:

1. Detects the contradiction
2. Drops confidence 0.95 -> 0.45 (contradiction penalty)
3. Queries Event Log 4688 (process creation) as a tiebreaker
4. Recovers to 0.75 once the Event Log confirms the 14:25 execution
5. Logs the full reasoning chain

The reasoning chain is the money shot: an **auditable decision**, not a black box.

### Beat 2 — Validation (the proof, ~90s)

```bash
PYTHONPATH=. python tests/scenario_harness.py
```

**Say:** "Twelve attack scenarios - ransomware, timestomping, persistence, memory
injection, data exfiltration - each validated against hand-authored ground truth."

**Point at:** the `TOTAL` line - **47 findings, F1=1.00, 0 false positives,
0 false negatives.** For a forensic audience, *zero false positives* is the number
that matters: no wild-goose chases. This runs in CI on every commit.

### Beat 3 — The TUI (it's a product, ~60s, optional)

```bash
python demo_tui.py
```

Interactive terminal UI: evidence selection, live progress, findings panel.
Use as a finale if you have a screen; skip if short on time. Press `q` to quit.

---

## Questions you will get

**"Does it work on real evidence?"**
Yes. `pip install -r requirements-forensic.txt` adds the Volatility 3, Sleuth Kit,
libewf, and libpff bindings, and the same detection logic runs against real E01
images and memory dumps. The synthetic fixtures exist so the detection *logic* is
CI-validated without shipping multi-GB evidence files.

**"How do I know the detections are correct?"**
Each of the 12 scenarios ships a `manifest.json` (`scenario.yaml`) of expected
findings. The harness compares engine output to that ground truth and computes
precision/recall. CI runs the whole thing at F1=1.00 on every commit.

**"What makes this different from an LLM wrapper?"**
The self-correction engine is deterministic code, not a prompt. It cross-checks
artifacts (MFT vs Prefetch vs Event Log), detects contradictions, and adjusts
confidence with a logged reasoning chain. No hallucination surface.

---

## Fallback

If anything misbehaves live, run the canned recording instead:

```bash
./scripts/demo-recording.sh
```

It runs the same three beats with paced output and section headers, so you can
narrate over it without typing.

---

## One-line cheat sheet

```
source venv/bin/activate
python -m sift_find_evil demo                      # self-correction
PYTHONPATH=. python tests/scenario_harness.py      # 12 scenarios, F1=1.00
python demo_tui.py                                 # interactive TUI (q to quit)
```
