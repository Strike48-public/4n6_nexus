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
| 1 | [`01_clean_baseline`](synthetic/01_clean_baseline/) | [ ] | [ ] | [ ] | Must produce zero findings. |
| 2 | [`02_ransomware`](synthetic/02_ransomware/) | [ ] | [ ] | [ ] | Confidence recovery via event log. |
| 3 | [`03_timestomping`](synthetic/03_timestomping/) | [ ] | [ ] | [ ] | $STANDARD vs $FILE_NAME divergence. |
| 4 | [`04_edge_cases`](synthetic/04_edge_cases/) | [ ] | [ ] | [ ] | Boundary precision check. |
| 5 | [`05_missing_prefetch`](synthetic/05_missing_prefetch/) | [ ] | [ ] | [ ] | MFT-only path. |
| 6 | [`06_webmail_exfiltration`](synthetic/06_webmail_exfiltration/) | [ ] | [ ] | [ ] | Non-exec ground truth; harness skips by default. |

## Real (downloaded evidence)

| # | Scenario | 1st pass | 2nd pass | 3rd pass | Notes |
|---|----------|:-:|:-:|:-:|-------|
| 1 | [`circl-2023-wiped`](real/circl-2023-wiped/) | [ ] | [ ] | [ ] | CRITICAL partition-wipe finding at 0.95 confidence. |
| 2 | [`m57-jean`](real/m57-jean/) | [ ] | [ ] | [ ] | EXFIL_CORRELATION on SHA-256 `34456b5f...779f`. |
| 3 | [`m57-patents`](real/m57-patents/) | [ ] | [ ] | [ ] | Multi-custodian case; engine must correlate across images. |
| 4 | [`nitroba`](real/nitroba/) | [ ] | [ ] | [ ] | PCAP-driven harassment investigation. |
| 5 | [`national_gallery_2012`](real/national_gallery_2012/) | [ ] | [ ] | [ ] | Multi-device corporate case. |

## Training (external community images)

| # | Scenario | 1st pass | 2nd pass | 3rd pass | Notes |
|---|----------|:-:|:-:|:-:|-------|
| 1 | [`ransomware_2021`](training/ransomware_2021/) | [ ] | [ ] | [ ] | dfir.training ransomware corpus. |
| 2 | [`insider_threat_2022`](training/insider_threat_2022/) | [ ] | [ ] | [ ] | dfir.training insider threat. |
| 3 | [`blue_team_challenge`](training/blue_team_challenge/) | [ ] | [ ] | [ ] | Memory + disk; advanced. |
| 4 | [`network_intrusion`](training/network_intrusion/) | [ ] | [ ] | [ ] | PCAP + memory. |

---

## Pass log

Append one block per pass across the matrix. Keep it terse.

### Pass 1 -- YYYY-MM-DD -- git `<sha>`

- Environment:
- Observations:
- Divergences:

### Pass 2 -- YYYY-MM-DD -- git `<sha>`

- Environment:
- Observations:
- Divergences:

### Pass 3 -- YYYY-MM-DD -- git `<sha>`

- Environment:
- Observations:
- Divergences:
