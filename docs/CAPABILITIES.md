# 4n6 Nexus - Capabilities & How to Drive It

**Audience:** a new user, evaluator, or judge who wants one page that answers
"what can this system do, and how do I run each part?" - then points to the
deeper doc for each area.

This is a **map, not a duplicate**: every capability below links to the
authoritative deep-dive. For the narrative pitch see the top-level
[`README.md`](../README.md); for worked end-to-end investigations see
[`EXAMPLES.md`](EXAMPLES.md); for the full internal doc catalog see
[`DOCUMENTATION_INDEX.md`](DOCUMENTATION_INDEX.md).

> **What it is.** An autonomous DFIR agent that turns forensic artifacts into
> grounded, court-defensible findings, with architectural self-correction and a
> trust pipeline that is *independently verifiable offline*. Detection is 100%
> deterministic Python (no LLM in the finding path); F1 = 1.00 across all 16
> validation scenarios.

## The 60-second tour

```bash
# 1. See it work on synthetic data (no evidence download needed)
python -m sift_find_evil.cli demo --output findings.json

# 2. Prove the detection accuracy claim yourself
PYTHONPATH=. python3 tests/scenario_harness.py     # expect F1=1.00, 0 FP, 0 FN

# 3. Analyze real parsed artifacts, with the trust pipeline engaged
python -m sift_find_evil.cli analyze --mft mft.csv --prefetch pf.csv \
  --evtx evtx.csv --harden --output report.json

# 4. Independently verify the run - no engine install required
python3 tools/verify_chain.py        /cases/<id>/audit.jsonl   # audit chain
python3 tools/verify_receipts.py     report.json               # finding receipts
python3 tools/verify_verification.py report.json               # verification verdicts
```

## Capability map

| Capability | Drive it with | Deep dive |
|---|---|---|
| **Detection engine** (MFT/Prefetch/EVTX/registry/LNK/PCAP/PST/browser + memory + YARA) | `cli analyze ...` / `cli run --scenario ...` | [`ARCHITECTURE.md`](ARCHITECTURE.md), [`DETECTION_TAXONOMY.md`](DETECTION_TAXONOMY.md) |
| **Detection accuracy** (16 scenarios @ F1=1.00) | `tests/scenario_harness.py` | [`ACCURACY_REPORT.md`](ACCURACY_REPORT.md) |
| **Architectural self-correction** (adversarial verify/remand loop) | runs inline in `analyze`/`run` | README "Core Innovation" |
| **Human-in-the-loop approval** (findings start DRAFT) | `cli approve` / `reject` / `list` | [`CLI_USAGE.md`](CLI_USAGE.md) |
| **Case management** (custody dirs, evidence registry) | `cli case ...` | [`CLI_USAGE.md`](CLI_USAGE.md) |
| **Chain-of-custody audit log** (hash-chained) | `cli audit ...` | README "Audit Logging" |
| **Custody / trust pipeline** (receipts + Merkle anchor) | `analyze --harden` | README "Trust and Verification" |
| **Injection defense** (see below) | automatic on every parsed string | README "Prompt injection / hostile-log-as-data" |
| **Report generation** (Markdown / HTML) | `cli report ...` | [`CLI_USAGE.md`](CLI_USAGE.md) |
| **Multi-agent orchestration** (triage + domain analysts + verifier) | `.claude/agents/dfir-*` | [`ARCHITECTURE.md`](ARCHITECTURE.md) |

## Trust & verifiability (the differentiator)

Three standalone verifiers each re-implement their contract from the Python
standard library and **import nothing from the engine**, so a third party can
re-run them without trusting or installing our code (a Daubert-friendly
property). Any drift between our writer and the verifier surfaces as a failure.

| Verifier | Proves | Exit codes |
|---|---|---|
| `tools/verify_chain.py <audit.jsonl>` | The audit hash-chain is intact (no altered/deleted/reordered entry) | 0 valid / non-0 with reason |
| `tools/verify_receipts.py <report.json> [pubkey.pem]` | Every finding's Ed25519 receipt + the set-level Merkle anchor verify (no shared secret; a pinned key proves provenance) | 0 / 1 broken / 2 env / 3 HMAC-only |
| `tools/verify_verification.py <report.json>` | Every adversarial-verification verdict re-derives from the recorded evidence (catches a tampered or drifted ruling) | 0 / 1 broken / 2 file error |

## Injection defense (hostile-log-as-data)

Forensic evidence is attacker-controlled text. Every parsed string crosses a
sanitizer boundary before it can reach a prompt:

- **Strip + neutralize + sentinel-wrap** - invisible/BIDI/zero-width codepoints
  stripped, role/system tokens and forged verdict/tool JSON neutralized to inert
  markers, content wrapped in a nonce-keyed untrusted sentinel; the attempt is
  surfaced as a counts-only finding (payload never re-emitted).
- **Trojan-Source confusable folding** - a homoglyph-disguised control token
  (`ѕуѕtem:` reading as `system:`) is folded to ASCII and caught, surgically, so
  benign non-Latin evidence is never transliterated.
- **Tamper-evident injection ledger** - a genesis-anchored hash chain of attempts
  on the scored path, counts-only and deterministic.
- **Self-attack corpus** - a static battery the sanitizer is proven against
  (load-bearing in the benchmark ablation), with benign controls proving zero
  false positives.

## Validation & current status

Detection accuracy: **F1 = 1.00** across all 16 recall scenarios with 0 false
positives and 0 false negatives - reproducible locally with
`PYTHONPATH=. python3 tests/scenario_harness.py`. Full methodology, held-out
and tamper benchmarks, and the accuracy history live in
[`ACCURACY_REPORT.md`](ACCURACY_REPORT.md).
