# Evidence Dataset Documentation

> FIND EVIL! Deliverable #5. For every dataset the agent was tested against,
> this document records **what it is, where it came from (provenance + license),
> and what the agent found**. Numbers here are limited to results with a
> verifiable run artifact; anything not yet run is labeled as such. See
> [ACCURACY_REPORT.md](ACCURACY_REPORT.md) for the precision/recall self-
> assessment and [PERFORMANCE_BENCHMARK.md](PERFORMANCE_BENCHMARK.md) for speed.

## Summary

| Tier | Dataset | Source | Run? | What the agent found |
|---|---|---|---|---|
| Synthetic | 14 scenarios (harness) | Hand-authored | ✅ harness | 57 findings, F1 = 1.00 (0 FP / 0 FN) |
| Real | `circl-2023-wiped` | CIRCL TR-80 (2023) | ✅ CLI | 1 CRITICAL: wiped GPT partition table (0.95) |
| Real | `m57-jean` | Digital Corpora (2008) | ✅ CLI | CRITICAL data-exfiltration (BEC) + supporting artifacts |
| Real | `nitroba` | Digital Corpora (2008) | ✅ CLI | 1 finding: beaconing to image.weather.com (0.95) |
| Real | `apt_attack_2015` | SANS SRL-2015 | ⛔ not run | Evidence on external media, not bundled (see below) |

Two evidence styles are used deliberately:

- **Synthetic CSV/JSON fixtures** mirror forensic-tool output and run in CI,
  deterministically, in seconds — they are the regression gate (F1 = 1.00).
- **Real disk/memory/network images** validate the same detection logic against
  genuine evidence with independent ground truth. They are multi-GB and run
  out-of-band (not in CI).

---

## Synthetic scenarios

**Source / license:** hand-authored in this repository (internal, MIT). Each is a
small set of CSV/JSON fixtures shaped exactly like the real tool's output
(MFTECmd CSV, Volatility `-r json`, etc.) plus a `scenario.yaml` manifest that
declares the ground-truth finding count. The scenario harness
(`tests/scenario_harness.py`) auto-discovers every `scenario.yaml` and scores
findings against that ground truth.

**What was tested and found (14 scenarios actually run, F1 = 1.00):**

| Scenario | What it exercises | Findings |
|---|---|---|
| 01_clean_baseline | Legitimate activity — must stay silent | 0 (no false alarms) |
| 02_ransomware | Causality violations resolved via Event ID 4688 | 3 |
| 03_timestomping | `$SI`/`$FN` discrepancy (critical, unresolved) | 2 |
| 04_edge_cases | Tolerance boundary, null/future timestamps | 2 |
| 05_missing_prefetch | Executable in MFT+EventLog but no Prefetch | 3 |
| 06_webmail_exfiltration | Webmail upload pattern | 1 |
| 07_cloud_upload | Cloud-storage upload pattern | 1 |
| 08_persistence_run_keys | Registry Run-key persistence | 2 |
| 09_shimcache_only | Execution evidence from shimcache alone | 2 |
| 10_timestomping_with_bam | Timestomping corroborated by BAM | 3 |
| 11_yara_malware | YARA signature match | 1 |
| 12_memory_intrusion | Volatility: injection, hidden proc, C2, Linux | 27 |
| 16_powershell_obfuscated | Encoded/obfuscated PowerShell (T1027/T1140) | 5 |
| 19_credential_dumping | LSASS/credential-access patterns | 5 |
| **Total** | | **57 — 0 FP, 0 FN, F1 = 1.00** |

**Honest note on the numbering gap.** Directories `13_browser_tampering`,
`14_usb_device_activity`, `15_scheduled_task_persistence`,
`17_network_share_lateral`, `18_shadow_copy_deletion`, `20_file_slack_hiding`,
and `21_ai_adversarial_evasion` exist as **specification stubs without a
`scenario.yaml`**, so the harness does not run them and they are **not** counted
above. They document intended future coverage, not tested behavior. (A prior
accuracy table listed 13–21 as passing; that was inaccurate and has been
corrected.)

Reproduce:

```bash
PYTHONPATH=. python tests/scenario_harness.py   # writes analysis/scenario_report.json
```

### Cross-domain self-correction demo (`02_ransomware`)

Beyond the regression-scored CSV fixtures, the `02_ransomware` scenario also
carries `memory_fixtures/` and `network_fixtures/` consumed by the reproducible
orchestration harness (not the regression harness). Running
`python -m sift_find_evil.orchestration` over it produces **six findings across
disk/timeline, memory, and network** in one correlated A2A log — including a
hidden process resolved via a psscan tiebreaker and a hardcoded-IP C2 that stays
detected next to a benign direct-IP hit that resolves. See
[ARCHITECTURE_DIAGRAM.md](ARCHITECTURE_DIAGRAM.md) and
[TRY_IT_OUT.md](TRY_IT_OUT.md).

---

## Real evidence

All real images carry a `scenario.yaml` manifest recording the source URL,
publication date, license, and SHA-256 of each evidence file. Evidence is
**read-only**; the engine never modifies it (enforced architecturally at the MCP
boundary — see [ARCHITECTURE_DIAGRAM.md](ARCHITECTURE_DIAGRAM.md)).

### `circl-2023-wiped` — wiped-disk anti-forensics

- **What it is:** A disk where an insider began wiping from LBA 0 outward and was
  interrupted; the primary GPT is zeroed but the secondary GPT at end-of-disk
  survived.
- **Source / provenance:** CIRCL (Computer Incident Response Center Luxembourg),
  technical report **TR-80**, "Recovering data from a wiped disk", published
  2023-01-31. URL: https://www.circl.lu/pub/tr-80/. License: public.
- **Evidence:** `wiped_disk.E01` — 52 MB EWF container (8.18 GB logical),
  SHA-256 `c4a8145b…4f4ef15` (pinned in `scenario.yaml`); plus a 20-slide
  walkthrough PDF.
- **What the agent found:** **1 CRITICAL finding, confidence 0.95** —
  *"Partition table wiped (primary GPT zeroed, secondary GPT intact)."* The
  reasoning chain cites the zeroed protective MBR + primary GPT header, the valid
  `EFI PART` signature in the secondary GPT at LBA 15974399, and the two
  partitions it enumerates (3.52 GiB NTFS + 4.10 GiB LUKS). The asymmetry
  (primary destroyed, secondary valid) cannot arise from normal OS behavior.
  Matches the report's documented ground truth.
- **Reproduce:** `python -m sift_find_evil.cli analyze --image
  scenarios/real/circl-2023-wiped/evidence/wiped_disk.E01 --output
  analysis/circl-2023-wiped/findings.json` (read-only scripts and a full
  forensic report are in `analysis/circl-2023-wiped/`).

### `m57-jean` — data-exfiltration / business email compromise

- **What it is:** The M57.biz scenario: the CFO's (Jean's) laptop is imaged to
  determine whether the confidential spreadsheet `m57biz.xls` (employee names,
  salaries, SSNs) was exfiltrated, and how.
- **Source / provenance:** Digital Corpora, NPS M57-Jean scenario (2008). URL:
  https://digitalcorpora.org/corpora/scenarios/m57-jean/. Academic use.
- **Evidence:** `nps-2008-jean.E01` (1.5 GB) + `.E02` (1.4 GB), 10,737,418,240
  bytes logical.
- **What the agent found:** Running the full CLI analysis pipeline over the E01,
  the engine produced a **CRITICAL `data_exfiltration` finding (confidence
  ≥ 0.90)**: a file saved to disk and emailed ~65 seconds later, proven by a
  **byte-equal SHA-256 across two independent artifacts (MFT on-disk file ↔ PST
  attachment)** with a save-to-send delta under 300s. Analyst reconciliation
  (`scenarios/real/m57-jean/findings.md`) identifies the recipient as
  `tuckgorge@gmail.com` masquerading as `alison@m57.biz` — i.e. Jean is a
  **phishing victim (BEC)**, not an insider threat. The engine's acceptance test
  (`engine_pass.md`) confirms all artifact-centric criteria pass with **no
  case-specific string matching**. The broader pass also surfaced ~856 lower-
  severity engine findings (e.g. missing-Prefetch anti-forensics indicators)
  during full-image triage.
- **Why the regression harness row shows 0.** In the CSV-fixture regression
  harness, `m57-jean`'s manifest declares `finding_counts.total: 0`, so the
  harness (which scores CSV fixtures, not the multi-GB E01) reports 0 findings
  for it — that is the harness scope, not the engine's real-image result. The
  real exfiltration finding above comes from the CLI pipeline against the actual
  E01, documented in `scenarios/real/m57-jean/findings.md` and
  `analysis/m57-jean/engine_findings.json`. Both facts are true and are reported
  side by side to avoid overstating the regression number.
- **Reproduce:** `python -m sift_find_evil.cli analyze --image
  scenarios/real/m57-jean/evidence/nps-2008-jean.E01 --output
  analysis/m57-jean/findings.json`.

### `nitroba` — network-capture harassment attribution

- **What it is:** The Nitroba State University harassment case: harassing emails
  to a student were sent from an open dorm Wi-Fi shared by three roommates; a
  network sniffer captured the traffic, and the task is to attribute the sender.
- **Source / provenance:** Digital Corpora, Nitroba University Harassment
  Scenario (2008). URL:
  https://digitalcorpora.org/corpora/scenarios/nitroba-university-harassment-scenario/.
  Academic use.
- **Evidence:** `nitroba.pcap` — 54 MB packet capture.
- **What the agent found:** the engine's structured output
  (`analysis/nitroba/run_2.json`) is **1 finding, confidence 0.95** — a
  **beaconing detection**: *"Beaconing to image.weather.com from 192.168.15.4 —
  7 events, mean interval 899.5s, stddev 1.40s, coefficient of variation
  0.002 — the cadence is too regular to be human browsing."* The finding cites
  the exact event count, intervals, and first/last-seen timestamps. The
  accompanying analyst write-up (`analysis/nitroba/INVESTIGATION_SUMMARY.md`)
  carries the case attribution to a suspect (a Facebook auth cookie for
  `beth@bethr.org` recovered from the capture) — that is human-analyst
  interpretation layered on top of the engine's beaconing finding, not part of
  the engine's structured output, and is reported as such. The regression
  manifest declares `total: 0` (PCAP not scored by the CSV harness); the
  beaconing finding is from the network-analysis pipeline.

### `apt_attack_2015` — multi-system APT (NOT yet run)

- **What it is:** A multi-system enterprise APT compromise (domain controller,
  file/RDP servers, workstations, DMZ FTP) — a breadth-of-analysis target.
- **Source / provenance:** SANS Security Reinforcement Labs, SRL-2015
  ("Compromised Enterprise Network").
- **Status:** **Not run in this submission.** The evidence (multiple 12 GB+ E01
  images) lives on external media
  (`/media/.../SRL-2015-Compromised_Enterprise_Network/`), is not bundled in the
  repo, and has no verified run artifact. It is documented here as a candidate
  breadth target, not a tested result. No findings are claimed for it.

---

## What is and isn't claimed (honesty statement)

- **Claimed (with run artifacts):** the synthetic harness result (57 findings,
  F1 = 1.00), and the three real-evidence findings above (`circl-2023-wiped`,
  `m57-jean`, `nitroba`).
- **Not claimed:** any result for `apt_attack_2015` (not run), and the spec-stub
  scenarios 13–15/17–18/20–21 (no manifest, not run). A previously circulated
  `insider_threat_2022` "1,071-finding" result was unverifiable and has been
  removed across the docs (tracked in SFE-3sc).
- **Evidence integrity:** every real image is processed read-only; the SHA-256 of
  each evidence file is pinned in its `scenario.yaml` so a judge can verify
  integrity before and after a run.
