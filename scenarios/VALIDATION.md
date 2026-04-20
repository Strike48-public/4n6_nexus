# Scenario Validation Tracker

Run each scenario three times to confirm the engine behaves deterministically
and holds up after engine changes. A **pass** is ticked only when the engine
output matches the scenario's `expected:` block in `scenario.yaml`
(precision, recall, finding counts, and named IOCs).

## How to run

Synthetic (CI harness, runs in <1s):

```bash
python -m pytest tests/test_scenarios.py -v
```

Real / training scenarios (require downloaded evidence):

```bash
python -m sift_find_evil run \
  --scenario scenarios/real/<name> \
  --out analysis/<name>/run_<N>.json
```

Compare `run_<N>.json` against `scenarios/<tier>/<name>/scenario.yaml`'s
`expected:` block. Record the date, git SHA, and any notes per pass.

Pass legend: **[ ]** not run -- **[x]** matches expected -- **[!]** divergence (see notes)

---

## Synthetic (CI gate)

| # | Scenario | 1st pass | 2nd pass | 3rd pass | Notes |
|---|----------|:-:|:-:|:-:|-------|
| 1 | [`01_clean_baseline`](synthetic/01_clean_baseline/) | [x] | [ ] | [ ] | Must produce zero findings. |
| 2 | [`02_ransomware`](synthetic/02_ransomware/) | [x] | [ ] | [ ] | Confidence recovery via event log. |
| 3 | [`03_timestomping`](synthetic/03_timestomping/) | [x] | [ ] | [ ] | $STANDARD vs $FILE_NAME divergence. |
| 4 | [`04_edge_cases`](synthetic/04_edge_cases/) | [x] | [ ] | [ ] | Boundary precision check. |
| 5 | [`05_missing_prefetch`](synthetic/05_missing_prefetch/) | [x] | [ ] | [ ] | MFT-only path. |
| 6 | [`06_webmail_exfiltration`](synthetic/06_webmail_exfiltration/) | [ ] | [ ] | [ ] | Non-exec ground truth; harness skips by default. |

## Real (downloaded evidence)

| # | Scenario | 1st pass | 2nd pass | 3rd pass | Notes |
|---|----------|:-:|:-:|:-:|-------|
| 1 | [`circl-2023-wiped`](real/circl-2023-wiped/) | [x] | [x] | [ ] | CRITICAL partition-wipe finding at 0.95 confidence. Pass 2 reproduces exactly. |
| 2 | [`m57-jean`](real/m57-jean/) | [!] | [ ] | [ ] | CLI has no E01->MFT/registry/browser extraction pipeline. |
| 3 | [`m57-patents`](real/m57-patents/) | [ ] | [ ] | [ ] | Evidence downloaded (~42 GB, 6 E01s, sha256 pinned). No CLI path yet. |
| 4 | [`nitroba`](real/nitroba/) | [!] | [!] | [ ] | PCAP path is now wired (`--pcap`); yields 1 FP (weather.com widget beaconing, CoV 0.002). Expected total=0. |
| 5 | [`national_gallery_2012`](real/national_gallery_2012/) | [ ] | [ ] | [ ] | Evidence downloaded (~27 GB, 9 items, sha256 pinned). No CLI path yet. |

## Training (external community images)

| # | Scenario | 1st pass | 2nd pass | 3rd pass | Notes |
|---|----------|:-:|:-:|:-:|-------|
| 1 | [`ransomware_2021`](training/ransomware_2021/) | [ ] | [ ] | [ ] | dfir.training ransomware corpus. |
| 2 | [`insider_threat_2022`](training/insider_threat_2022/) | [ ] | [ ] | [ ] | dfir.training insider threat. |
| 3 | [`blue_team_challenge`](training/blue_team_challenge/) | [ ] | [ ] | [ ] | Memory + disk; advanced. |
| 4 | [`network_intrusion`](training/network_intrusion/) | [!] | [ ] | [ ] | Evidence present + hashes match; no CLI path for PCAP/memory. See analysis/scenario_testing/network_intrusion/. |

---

## Pass log

Append one block per pass across the matrix. Keep it terse.

### Pass 1 -- 2026-04-19 -- git `0e45c4a`

- Environment: SANS SIFT Ubuntu Workstation, Python 3.12.2, pytest 9.0.2
- Observations:
  - Synthetic 01-05 all pass: TP=10, FP=0, FN=0, Precision=1.00, Recall=1.00, F1=1.00
  - circl-2023-wiped produces the expected CRITICAL finding at 0.95 confidence
- Divergences:
  - Scenario 06 webmail: harness intentionally skips non-exec ground truth
  - m57-jean: CLI only scans for wipe indicators on raw E01, no MFT/registry/browser pipeline
  - nitroba: PcapParser exists but CLI lacks `--pcap` flag
  - m57-patents + national_gallery_2012: evidence missing, 404 on Digital Corpora URLs
  - All 4 training scenarios have empty evidence/ directories
- See full notes: `docs/SCENARIO_TESTING_NOTES.md`

### Pass 2 -- 2026-04-19 -- git `bdf6176`

- Environment: SANS SIFT Ubuntu Workstation, Python 3.12.2
- Scope: re-ran `circl-2023-wiped` and `nitroba` per user request
- Observations:
  - `circl-2023-wiped` reproduces 1 CRITICAL partition-wipe finding at 0.95 (matches expected total=1)
  - `nitroba` CLI now has `--pcap`; PcapParser extracts 4850 HTTP / 1488 DNS / 2021 TCP conversations
  - `nitroba` NetworkDetector flags 1 beaconing finding to `image.weather.com` (192.168.15.4, mean 899.5s, CoV 0.002)
- Divergences:
  - `nitroba` expected total=0; got 1 FP — Weather.com's embedded widget polls every 15 minutes, which trips the beaconing detector. Either (a) add a known-benign allowlist for well-known widget hosts, or (b) raise the minimum event count past 7, or (c) accept this as a documented FP for pcaps containing weather widgets.
  - Did not touch m57-jean / m57-patents / national_gallery_2012 / training scenarios this pass.
- Artifacts: `analysis/circl-2023-wiped/run_2.json`, `analysis/nitroba/run_2.json`

### Pass 3 -- YYYY-MM-DD -- git `<sha>`

- Environment:
- Observations:
- Divergences:
