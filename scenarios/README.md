# DFIR Scenarios

This directory is the single home for every scenario used to exercise the
detection engine. Each scenario owns a folder with a `scenario.yaml` manifest
that describes source, evidence, fixtures, ground truth, and expected metrics.

Binary evidence under `**/evidence/` is git-ignored. Manifests and small
synthetic fixtures are tracked.

## Layout

```text
scenarios/
├── _schemas/                    # Reference schema and README
│   ├── README.md
│   └── scenario.yaml            # canonical schema example
├── synthetic/                   # CSV fixture scenarios (CI gate)
│   ├── 01_clean_baseline/
│   ├── 02_ransomware/
│   ├── 03_timestomping/
│   ├── 04_edge_cases/
│   ├── 05_missing_prefetch/
│   └── 06_webmail_exfiltration/
├── real/                        # Full evidence scenarios (downloaded)
│   ├── nitroba/                 # Nitroba University (PCAP)
│   ├── m57-jean/                # M57 Jean (E01/E02)
│   ├── m57-patents/             # Full M57 corporate case
│   ├── circl-2023-wiped/        # CIRCL wiped disk challenge
│   └── national_gallery_2012/   # NGDC multi-device corporate case
├── training/                    # DFIR.training community images
│   ├── ransomware_2021/
│   ├── insider_threat_2022/
│   ├── blue_team_challenge/
│   └── network_intrusion/
└── reference/                   # Raw corpora used as test inputs
    ├── cfreds/                  # NIST CFReDS datasets
    ├── nist-nps/                # NPS test disk images
    ├── circl-drives/            # CIRCL drive corpus
    ├── mobile/{android,ios,legacy}
    ├── network-pcaps/           # Generic network corpora
    ├── govdocs/                 # Govdocs1 subsets
    └── sql/                     # SQLite forensic corpus
```

## Tiers

| Tier       | Run in CI | Evidence tracked | Purpose |
|------------|-----------|------------------|---------|
| synthetic  | yes       | yes (small CSVs) | Deterministic precision/recall gates |
| real       | no (opt.) | no (downloaded)  | End-to-end validation on public cases |
| training   | no        | no (external)    | Practice material for human analysts |
| reference  | no        | no               | Raw corpora used as inputs to parsers |

The CI harness (`tests/scenario_harness.py`) discovers scenarios by globbing
`scenarios/**/scenario.yaml` and only runs those that declare CSV `fixtures`.

## Adding a scenario

1. Create `scenarios/<tier>/<name>/scenario.yaml` following
   `scenarios/_schemas/scenario.yaml`.
2. Place any fixtures alongside the manifest (CSV) or in `./evidence/`
   (binary, git-ignored).
3. Record SHA-256 hashes in the manifest once the evidence is downloaded.
4. Update the relevant README only if the new scenario materially changes
   the catalogue.

## Downloading evidence

Use the orchestration scripts under `scripts/download-corpora/`:

```bash
scripts/download-corpora/download-phase1-critical.sh
scripts/download-corpora/download-phase2-high.sh
scripts/download-corpora/download-phase3-selective.sh
scripts/download-corpora/verify-downloads.sh
```

Per-scenario scripts (where they exist) live beside the manifest:

```bash
scenarios/real/nitroba/download_all.sh
scenarios/real/m57-patents/download_all.sh
```

## Validating the engine

Use [`VALIDATION.md`](VALIDATION.md) to track 1st/2nd/3rd-pass engine runs
against every scenario's `expected:` block. Tick a box only when the
actual output matches the manifest.

## Resources

- Digital Corpora: https://digitalcorpora.org/
- CFReDS: https://cfreds.nist.gov/
- DFIR.training: https://www.dfir.training/
