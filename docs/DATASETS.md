# Evidence Dataset Documentation

**Last Updated:** 2026-06-15

> FIND EVIL! Deliverable: Evidence Dataset Documentation. For every dataset the
> agent was tested against, this document records **what it is, where it came
> from (provenance + license), and what the agent found**. Numbers here are
> limited to results with a verifiable run artifact in this repository; anything
> not yet run is labeled as such. See [ACCURACY_REPORT.md](ACCURACY_REPORT.md)
> for the precision/recall self-assessment.

---

## Summary

| Tier | Dataset | Source | Run? | What the agent found |
|---|---|---|---|---|
| Synthetic | 15 scenarios (harness) | Hand-authored (this repo) | ✅ harness | 62 findings, F1 = 1.00 (0 FP / 0 FN) |
| Real | `circl-2023-wiped` | CIRCL TR-80 (2023) | ✅ CLI | 1 CRITICAL: wiped GPT partition table (0.95) |
| Real | `m57-jean` | Digital Corpora (2008) | ✅ CLI | 1 CRITICAL data-exfiltration / BEC (0.95) + 856 medium triage findings |
| Real | `nitroba` | Digital Corpora (2008) | ✅ CLI | 1 beaconing finding (cadence-based; confidence capped Medium after FP audit) |
| Real | `apt_attack_2015` | SANS SRL-2015 | ⛔ not run | Evidence not bundled; documented as a breadth candidate only |

Two evidence styles are used deliberately:

- **Synthetic CSV/JSON fixtures** mirror forensic-tool output (MFTECmd CSV,
  Volatility `-r json`, tshark, etc.) and run in CI, deterministically, in
  seconds. They are the regression gate (F1 = 1.00).
- **Real disk/memory/network images** validate the same detection logic against
  genuine evidence with independent ground truth. They are multi-GB and run
  out-of-band (not in CI). Every real image carries a `scenario.yaml` manifest
  pinning the source URL, publication date, license, and SHA-256 of each
  evidence file, so a judge can verify integrity before and after a run.

**Evidence integrity:** every real image is processed **read-only**; the engine
never modifies it. This is enforced architecturally at the MCP boundary, not by
prompt (see [ARCHITECTURE_DIAGRAM.md](ARCHITECTURE_DIAGRAM.md)).

---

## Synthetic scenarios

**Source / license:** hand-authored in this repository (internal, MIT). Each is
a small set of CSV/JSON fixtures shaped exactly like the real tool's output, plus
a `scenario.yaml` manifest that declares the ground-truth finding count. The
scenario harness (`tests/scenario_harness.py`) auto-discovers every
`scenario.yaml` and scores findings against that ground truth.

**What was tested and found (15 scenarios scored, F1 = 1.00):**

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
| 22_lateral_movement_logons | Remote-logon lateral movement (Event ID 4624 type 3/10) | 5 |
| **Total** | | **62 — 0 FP, 0 FN, F1 = 1.00** |

**Honest note on the numbering gap.** Directories `13_browser_tampering`,
`14_usb_device_activity`, `15_scheduled_task_persistence`,
`17_network_share_lateral`, `18_shadow_copy_deletion`, `20_file_slack_hiding`,
and `21_ai_adversarial_evasion` exist as **specification stubs without a
`scenario.yaml`**, so the harness does not run them and they are **not** counted
above. They document intended future coverage, not tested behavior.

Reproduce:

```bash
PYTHONPATH=. python3 tests/scenario_harness.py   # writes analysis/scenario_report.json
# Expected final line: TOTAL  62  0  0  1.00  1.00  1.00
```

### Cross-domain self-correction demo (`02_ransomware`)

Beyond the regression-scored CSV fixtures, the `02_ransomware` scenario also
carries `memory_fixtures/` and `network_fixtures/` consumed by the reproducible
orchestration harness (not the regression harness). Running
`python3 -m sift_find_evil.orchestration` over it produces **six findings across
disk/timeline, memory, and network** in one correlated A2A log — including a
hidden process resolved via a psscan tiebreaker and a hardcoded-IP C2 that stays
detected next to a benign direct-IP hit that resolves. See
[TRY_IT_OUT.md](TRY_IT_OUT.md).

---

## Real evidence

### `circl-2023-wiped` — wiped-disk anti-forensics

- **What it is:** A disk where an insider began wiping from LBA 0 outward and was
  interrupted; the primary GPT is zeroed but the secondary GPT at end-of-disk
  survived.
- **Source / provenance:** CIRCL (Computer Incident Response Center Luxembourg),
  technical report **TR-80**, "Recovering data from a wiped disk", published
  2023-01-31. URL: https://www.circl.lu/pub/tr-80/. License: public.
- **Evidence:** `wiped_disk.E01` (EWF container, ~8.18 GB logical), SHA-256
  `c4a8145bcbfd5485cd7b36a0603bdec68674c2f27e6c2dcf3ef25aa7a4f4ef15` (pinned in
  `scenario.yaml`), plus a walkthrough PDF.
- **What the agent found:** **1 CRITICAL finding, confidence 0.95** —
  *"Partition table wiped (primary GPT zeroed, secondary GPT intact)."* The
  reasoning chain cites the zeroed protective MBR + primary GPT header, the valid
  `EFI PART` signature in the secondary GPT at end-of-disk, and the partitions it
  recovers from the surviving copy. The asymmetry (primary destroyed, secondary
  valid) cannot arise from normal OS behavior. Matches the report's documented
  ground truth. Artifacts: `analysis/circl-2023-wiped/` (read-only inspection
  scripts, `findings.json`, `FORENSICS_REPORT.md`).
- **Reproduce:**
  ```bash
  python3 -m sift_find_evil.cli analyze \
      --image scenarios/real/circl-2023-wiped/evidence/wiped_disk.E01 \
      --output analysis/circl-2023-wiped/findings.json
  ```

### `m57-jean` — data-exfiltration / business email compromise

- **What it is:** The M57.biz scenario: the CFO's (Jean's) laptop is imaged to
  determine whether the confidential spreadsheet `m57biz.xls` (employee names,
  salaries, SSNs) was exfiltrated, and how.
- **Source / provenance:** Digital Corpora, NPS M57-Jean scenario (2008-07-21).
  URL: https://digitalcorpora.org/corpora/scenarios/m57-jean/. License: academic
  use. Evidence: `nps-2008-jean.E01` + `.E02` (~10 GB logical), SHA-256s pinned
  in `scenario.yaml`.
- **What the agent found:** Running the full CLI analysis pipeline over the E01,
  the engine produced a **CRITICAL `data_exfiltration` finding, confidence
  0.95**: *"File m57biz.xls (SHA-256 34456b5f…) saved at 2008-07-20 01:28:03,
  then emailed 44.2s later as an attachment in 'RE: Please send me the
  information now'."* The detection is **artifact-centric, not string-matched** —
  it proves a byte-equal SHA-256 across two independent artifacts (the MFT
  on-disk file and the PST attachment) with a save-to-send delta under the
  threshold. Analyst reconciliation (`scenarios/real/m57-jean/findings.md`)
  identifies the recipient as `tuckgorge@gmail.com` masquerading as
  `alison@m57.biz` — i.e. Jean is a **phishing victim (BEC)**, not an insider
  threat. The same full-image triage also surfaced **856 MEDIUM-severity
  findings** (e.g. missing-Prefetch anti-forensics indicators). Artifacts:
  `analysis/m57-jean/acceptance_test_results.json` (1 critical + 856 medium),
  `analysis/m57-jean/engine_findings.json`, and the analyst write-ups under
  `scenarios/real/m57-jean/`.
- **Why the regression-harness row shows 0.** In the CSV-fixture regression
  harness, `m57-jean`'s manifest declares `finding_counts.total: 0`, so the
  harness (which scores small CSV fixtures, not the multi-GB E01) reports 0 for
  it. That is the harness scope, not the engine's real-image result. The
  CRITICAL exfiltration finding above comes from the CLI pipeline against the
  actual E01. Both facts are true and reported side by side to avoid overstating
  the regression number. (`ACCURACY_REPORT.md`'s "real evidence" row likewise
  reflects the regression-scope figure.)
- **Reproduce:**
  ```bash
  python3 -m sift_find_evil.cli analyze \
      --image scenarios/real/m57-jean/evidence/nps-2008-jean.E01 \
      --output analysis/m57-jean/findings.json
  ```

### `nitroba` — network-capture harassment attribution

- **What it is:** The Nitroba State University harassment case: harassing emails
  were sent from an open dorm Wi-Fi shared by three roommates; a network sniffer
  captured the traffic, and the task is to attribute the sender.
- **Source / provenance:** Digital Corpora, Nitroba University Harassment
  Scenario (2008-07-21). URL:
  https://digitalcorpora.org/corpora/scenarios/nitroba-university-harassment-scenario/.
  License: academic use. Evidence: `nitroba.pcap` (~54 MB), SHA-256 pinned in
  `scenario.yaml`.
- **What the agent found:** the engine's structured output
  (`analysis/nitroba/run_2.json`) is a **beaconing detection**: *"Beaconing to
  image.weather.com from 192.168.15.4 — 7 events, mean interval ~899.5s, very
  low jitter — the cadence is too regular to be human browsing."* The finding
  cites the exact event count, intervals, and first/last-seen timestamps.
- **False-positive hardening (SFE-fqn).** This capture was deliberately run
  through the network detectors as a **false-positive audit**. The
  `image.weather.com` beacon is a benign desktop-widget timer, not C2 — a host
  that is not malicious. Cadence alone cannot distinguish a benign timer from C2,
  so the beaconing detector's confidence is now **capped at Medium (0.70)** for
  cadence-only evidence rather than presented as a high-confidence verdict.
  Separately, `DNSAnomalyDetector` produced **zero** findings on the same capture
  (the longest real DNS label was well under the trigger), so an
  "incomplete-CDN-suppression" hypothesis did not reproduce and nothing was
  changed there. The analyst write-up
  (`analysis/nitroba/INVESTIGATION_SUMMARY.md`) carries the human attribution to
  a suspect (a Facebook auth cookie recovered from the capture) — that is analyst
  interpretation layered on the engine's finding, reported as such, not part of
  the structured output.
- **Reproduce:**
  ```bash
  python3 -m sift_find_evil.cli analyze \
      --pcap scenarios/real/nitroba/evidence/nitroba.pcap \
      --output analysis/nitroba/findings.json
  ```

### `apt_attack_2015` — multi-system APT (NOT run in this submission)

- **What it is:** A multi-system enterprise APT compromise (domain controller,
  file/RDP servers, workstations, DMZ FTP) — a breadth-of-analysis candidate.
- **Source / provenance:** SANS Security Reinforcement Labs, SRL-2015
  ("Compromised Enterprise Network").
- **Status:** **Not run.** The evidence (multiple 12 GB+ E01 images) is **not
  bundled** in the repository and there is no verified run artifact. The
  `scenarios/real/apt_attack_2015/` directory contains only analysis scaffolding
  and notes. It is documented here as a candidate breadth target — **no findings
  are claimed for it.**

---

## What is and isn't claimed (honesty statement)

- **Claimed (with run artifacts in this repo):** the synthetic harness result
  (62 findings, F1 = 1.00, 0 FP / 0 FN); the `circl-2023-wiped` CRITICAL wipe
  finding (0.95); the `m57-jean` CRITICAL data-exfiltration finding (0.95) plus
  856 medium triage findings; and the `nitroba` beaconing finding (confidence
  capped Medium after FP audit).
- **Not claimed:** any result for `apt_attack_2015` (not run, evidence not
  bundled); the spec-stub scenarios `13–15 / 17–18 / 20–21` (no manifest, not
  scored). A previously circulated `insider_threat_2022` "1,071-finding" result
  was unverifiable and has been removed across the docs; do not rely on it.
- **Where the numbers live:** the synthetic figures regenerate from
  `tests/scenario_harness.py` into `analysis/scenario_report.json`; each real
  finding traces to a file under `analysis/<dataset>/`.

---

*Datasets are the foundation of the accuracy claims here: documented,
reproducible, and grounded in run artifacts.*
