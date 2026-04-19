# M57-Jean (2008)

Jean is CFO of M57.biz. Early in the scenario, the company's confidential spreadsheet `m57plan.xlsx` leaks. Jean's laptop is imaged to determine whether she exfiltrated it, and if so how.

See [`scenario.yaml`](scenario.yaml) for the manifest. Published at https://digitalcorpora.org/corpora/scenarios/m57-jean/.

## Evidence

| File | Size |
|---|---|
| `evidence/nps-2008-jean.E01` | 1.5 GB |
| `evidence/nps-2008-jean.E02` | 1.4 GB |

Logical media: 10 737 418 240 bytes. Download: run phase 1 fetcher (see top-level `scenarios/README.md`).

## Case artifacts in this folder

| File | Purpose |
|---|---|
| [`case_brief.md`](case_brief.md) | Background, null hypothesis, scope |
| [`inventory.md`](inventory.md) | What artifacts we extract and why |
| [`findings.md`](findings.md) | Full engine output and analyst interpretation |
| [`engine_pass.md`](engine_pass.md) | Acceptance-test run results |
| [`grading.md`](grading.md) | How we score the case |
| [`validator_notes.md`](validator_notes.md) | Adversarial review of our findings |
| [`references/M57-Jean-exercise-slides.pdf`](references/) | Original exercise slides |

## Reproduction

```bash
python -m sift_find_evil.cli analyze \
    --image scenarios/real/m57-jean/evidence/nps-2008-jean.E01 \
    --output analysis/m57-jean/findings.json
```

Derived CSVs and extracted artifacts land in `analysis/m57-jean/` (gitignored).
