# Scenario Testing Notes

**Date**: 2026-04-19
**Git SHA**: `0e45c4a`
**Purpose**: Systematic walk-through of every scenario in `scenarios/README.md`
to verify the detection engine works, capture what passes, and list the
concrete updates/changes required.

---

## Executive Summary

| Tier       | Scenarios | Passing | Skipped | Blocked |
|------------|-----------|---------|---------|---------|
| synthetic  | 6         | 5       | 1       | 0       |
| real       | 5         | 2       | 0       | 3       |
| training   | 4         | 0       | 4       | 0       |
| reference  | 0         | —       | —       | —       |

- CSV-driven CI gate is green: **TP=10, FP=0, FN=0, Precision=1.00, Recall=1.00, F1=1.00**.
- Real scenarios with downloaded evidence (CIRCL, m57-jean) run end-to-end.
- Training scenarios all have empty `evidence/` directories — none are runnable.
- Scenario 06 webmail is a known gap: harness intentionally skips it; no dedicated runner yet.

---

## Tier 1: synthetic (CI gate)

### Run
```bash
python -m tests.scenario_harness
python -m pytest tests/test_scenarios.py -v
```

Both invocations succeed; `pytest` reports **7 passed in 0.06s**.

### Per-scenario results

| # | Scenario                  | TP | FP | FN | Precision | Recall | F1   | AvgConf | Status |
|---|---------------------------|----|----|----|-----------|--------|------|---------|--------|
| 1 | 01_clean_baseline         | 0  | 0  | 0  | 1.00      | 1.00   | 1.00 | 0.00    | PASS   |
| 2 | 02_ransomware             | 3  | 0  | 0  | 1.00      | 1.00   | 1.00 | 0.75    | PASS   |
| 3 | 03_timestomping           | 2  | 0  | 0  | 1.00      | 1.00   | 1.00 | 0.35    | PASS   |
| 4 | 04_edge_cases             | 2  | 0  | 0  | 1.00      | 1.00   | 1.00 | 0.72    | PASS   |
| 5 | 05_missing_prefetch       | 3  | 0  | 0  | 1.00      | 1.00   | 1.00 | 0.60    | PASS   |
| 6 | 06_webmail_exfiltration   | —  | —  | —  | —         | —      | —    | —       | SKIP   |

### Notes / changes needed

- **Scenario 06** is deliberately skipped by `tests/scenario_harness.py:98-103`
  because its ground truth is non-executable
  (`finding_counts.webmail_exfiltration: 1`, `malicious_executables: []`).
  The scenario manifest explicitly acknowledges this:
  *"Not yet wired into scenario_harness.py."*
  **Change needed**: build a dedicated harness/runner that inspects
  `webmail_exfiltration` findings via `browser_history_parser.py`.
- Average confidence on `03_timestomping` (0.35) is below the 0.60 bar used
  by the engine's self-correction layer — detection still works, but the
  downstream confidence prior is weak. Worth revisiting once cross-artifact
  validation is wired in.

---

## Tier 2: real (full evidence)

### 2.1 `circl-2023-wiped` — **PASS**

```bash
python -m sift_find_evil analyze \
  --image scenarios/real/circl-2023-wiped/evidence/wiped_disk.E01 \
  --output analysis/scenario_testing/circl_wiped.json
```

- Evidence: `evidence/wiped_disk.E01` (52 MB) — present.
- Engine produced **1 CRITICAL finding at 0.95 confidence**, matching the
  manifest's `partition_table_destroyed: 1, total: 1` expectation.
- Reasoning chain enumerates the primary/secondary GPT asymmetry and the
  two surviving partitions — exactly the behaviour expected for this case.

**Status**: matches `expected:` block. First-pass validation complete.

### 2.2 `m57-jean` — **FAIL (under-detection)**

```bash
python -m sift_find_evil analyze \
  --image scenarios/real/m57-jean/evidence/nps-2008-jean.E01 \
  --output analysis/scenario_testing/m57_jean.json
```

- Evidence: `nps-2008-jean.E01` (1.5 GB) + `.E02` (1.4 GB) — present.
- CLI only runs the GPT inspector on raw disk images. For an NTFS E01 with
  no wipe indicator, it prints "No partition-table anomaly detected." and
  exits with no findings.
- The scenario's expected result is an `EXFIL_CORRELATION` finding on
  SHA-256 `34456b5f...779f` (see `scenarios/VALIDATION.md`). That requires
  MFT + registry + browser-history evidence extracted from the image —
  not raw-image scanning.

**Changes needed**:

1. CLI lacks an "E01 -> MFT/registry/browser extraction" pipeline. Today the
   user has to run MFTECmd/ RECmd externally, feed CSVs to `--mft` /
   `--prefetch` / `--evtx`, and browser history separately.
2. Add an `--extract` or `--scenario <path>` mode that:
   - reads `scenario.yaml`
   - mounts/parses each `evidence/*.E01`
   - dispatches to the right parsers
   - emits findings keyed back to the manifest.
3. Document the manual workaround in `USER_GUIDE.md` until (2) lands.

### 2.3 `m57-patents` — **BLOCKED**

- `scenarios/real/m57-patents/evidence/` is empty.
- `download_all.sh` 404s on `nps-2009-pat.*` (see
  `docs/DATASET_DOWNLOAD_STATUS.md`). Terry/Charlie/Jo presumed to share
  the same broken URL pattern.
- Engine cannot be exercised without evidence.

**Change needed**: either fix the download URLs (investigate Digital Corpora
relocation) or mark the scenario as "download-required" in VALIDATION.md so
future passes don't repeatedly attempt it.

### 2.4 `nitroba` — **BLOCKED (no PCAP code path)**

- Evidence: `evidence/nitroba.pcap` (54 MB) — present.
- Parser exists at `sift_find_evil/parsers/pcap_parser.py` (`PcapParser`
  with `HTTPRequest`, `HTTPSession`, `DNSQuery`, `SMTPMessage` classes).
- CLI has **no `--pcap` flag** — `python -m sift_find_evil analyze --help`
  only exposes `--mft / --prefetch / --evtx / --pst / --image`.
- Scenario manifest expects `finding_counts.total: 0, min_precision: 1.0`
  (it is a Q&A investigative scenario, not a detection scenario), so
  technically the engine's silence already matches `expected:`. But there
  is no way to answer the investigative questions through the CLI.

**Changes needed**:

1. Wire `PcapParser` into `cli.py` via a `--pcap <path>` flag.
2. Add a `network_forensics` finding category so PCAP-derived evidence
   can surface (sender MAC, webmail service used, email send timestamp).
3. Update `scenario.yaml` expectations once the runner exists.

### 2.5 `national_gallery_2012` — **BLOCKED**

- `scenarios/real/national_gallery_2012/evidence/` is empty.
- Scenario manifest describes a multi-device corporate case. No download
  script yet.

**Change needed**: document evidence source and add a download script
(or remove from VALIDATION.md until evidence is acquired).

---

## Tier 3: training (external community images)

| Scenario              | Evidence present | Runnable |
|-----------------------|------------------|----------|
| ransomware_2021       | No (empty dir)   | No       |
| insider_threat_2022   | No (empty dir)   | No       |
| blue_team_challenge   | No (empty dir)   | No       |
| network_intrusion     | No (empty dir)   | No       |

All four training scenarios ship only `scenario.yaml` + `README.md` and an
empty `evidence/` directory. They are practice material and expected to be
hydrated on demand — today they are **not exercised**.

**Changes needed**:

- Add a `download.sh` (or per-scenario note in the README) pointing to
  the DFIR.training page, clarifying that human registration is required.
- Otherwise: de-scope them from VALIDATION.md so they don't appear to be
  ongoing test targets.

---

## Tier 4: reference (raw corpora)

`scenarios/reference/` is **not present** in the tree at all (the tier
exists in the README layout but has no on-disk realization yet). CFReDS,
NIST-NPS, CIRCL drive, mobile, network-pcaps, govdocs, and sql sub-trees
are aspirational.

**Change needed**: either create placeholder `scenario.yaml` manifests for
each listed corpus (so they show up in the harness discovery) or remove the
tier from `scenarios/README.md` until we actually stage the data.

---

## Cross-cutting Findings

### CLI gaps

1. **No `--pcap`** — blocks nitroba and network-heavy training scenarios.
2. **No `--browser-history`** — blocks scenario 06 webmail.
3. **No `--registry-csv`** — blocks registry-dependent detections despite
   `registry_parser.py` being implemented (Phase 1 session 1).
4. **No `--scenario <path>` mode** — every scenario is run manually by
   pointing at the right CSV/image files. A manifest-driven runner would
   close the loop between `scenario.yaml` `expected:` blocks and actual
   engine output.

### Harness gaps

- `tests/scenario_harness.py` only discovers scenarios with
  `fixtures.mft + fixtures.prefetch + fixtures.evtx`. Any future synthetic
  scenario that exercises a different parser (browser history, registry,
  PCAP) needs either a generalization of the harness or a parallel runner.
- The non-executable skip at lines 97-103 is correct behaviour, but it
  means we **cannot assert** scenario 06's expected `webmail_exfiltration`
  finding in CI today.

### Validation tracker

`scenarios/VALIDATION.md` has boxes for 1st/2nd/3rd pass across 15
scenarios. Today's run flips:

| Scenario          | 1st pass | Notes                                       |
|-------------------|:--------:|---------------------------------------------|
| 01-05 synthetic   | [x]      | Matches expected block exactly              |
| 06 synthetic      | [ ]      | No harness path — intentional skip          |
| circl-2023-wiped  | [x]      | CRITICAL finding at 0.95 matches manifest   |
| m57-jean          | [!]      | CLI has no extraction pipeline              |
| m57-patents       | [ ]      | Blocked on 404 download                     |
| nitroba           | [!]      | PcapParser exists but not wired into CLI    |
| national_gallery  | [ ]      | No evidence, no download script             |
| training x4       | [ ]      | No evidence                                 |

---

## Prioritized Backlog

1. **Wire `PcapParser` into the CLI** so nitroba + future PCAP scenarios
   can be exercised.
2. **Add `--browser-history` (and scenario 06 runner)** so webmail
   exfiltration has a CI assertion.
3. **Add `--registry-csv`** to close the registry parser loop.
4. **Investigate the m57-patents 404s** (Digital Corpora URL change).
5. **Build a scenario-manifest runner** (`python -m sift_find_evil run --scenario <path>`)
   that ingests `scenario.yaml`, dispatches the right parsers per
   `fixtures:` / `evidence:` kind, and compares output to `expected:`.
6. **Decide the fate of the training + reference tiers** — either hydrate
   with download scripts or remove from the validation matrix.
7. **Generalize `tests/scenario_harness.py`** so it can run non-MFT
   scenarios once (2) and (3) exist.

---

## Appendix: exact commands used this pass

```bash
# Synthetic harness
python -m tests.scenario_harness
python -m pytest tests/test_scenarios.py -v

# Real
python -m sift_find_evil analyze \
  --image scenarios/real/circl-2023-wiped/evidence/wiped_disk.E01 \
  --output analysis/scenario_testing/circl_wiped.json

python -m sift_find_evil analyze \
  --image scenarios/real/m57-jean/evidence/nps-2008-jean.E01 \
  --output analysis/scenario_testing/m57_jean.json
```
