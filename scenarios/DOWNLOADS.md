# Scenario Evidence Downloads

Concrete list of files each scenario needs to run the engine end-to-end.
Authoritative URLs and sizes live in each scenario's `scenario.yaml` — this
file is the human-readable summary so you know what is pending.

Legend:
- **[present]** file already on disk under `evidence/`
- **[missing]** not downloaded yet; URL in `scenario.yaml`
- **[tbd]** placeholder URL in `scenario.yaml` — needs real source first

---

## Real scenarios

### circl-2023-wiped — populated
- [present] `evidence/wiped_disk.E01` (~1 GB)
- [present] `evidence/wiped_disk.pdf` (exercise brief)

### m57-jean — populated (required evidence)
- [present] `evidence/nps-2008-jean.E01` (~1.5 GB, sha256 verified)
- [present] `evidence/nps-2008-jean.E02` (~1.4 GB, sha256 verified)

Source: `https://downloads.digitalcorpora.org/corpora/drives/nps-2008-m57-jean/`

### nitroba — populated
- [present] `evidence/nitroba.pcap`

### m57-patents — missing (~45 GB total, all `required: false`)
Source: `https://downloads.digitalcorpora.org/corpora/scenarios/2009-m57-patents/drives-redacted/`

| File | Size |
|------|------|
| `evidence/pat/pat-2009-12-11.E01` | 6.4 GB |
| `evidence/terry/terry-2009-12-11-001.E01` | 11.1 GB |
| `evidence/terry/terry-2009-12-11-002.E01` | 11.1 GB |
| `evidence/charlie/charlie-2009-12-11.E01` | 4.1 GB |
| `evidence/jo/jo-2009-12-11-001.E01` | 6.2 GB |
| `evidence/jo/jo-2009-12-11-002.E01` | 6.2 GB |

Cherry-pick by custodian to cut volume. The 50-snapshot series lives under
the same prefix — see the scenario's `DOWNLOAD_URLS.txt` for the full set.

### national_gallery_2012 — missing (~12 GB final-day subset)
Source: `https://downloads.digitalcorpora.org/corpora/scenarios/2012-ngdc/`

| File | Size |
|------|------|
| `evidence/tracy-home/tracy-home-2012-07-16-final.E01` | 4.3 GB |
| `evidence/tracy-home/tracy-home-2012-07-16-final.E02` | 1.5 GB |
| `evidence/tracy-external/tracy-external-2012-07-16-final.E01` | 3.8 GB |
| `evidence/tracy-phone/tracy-phone-2012-07-15-final.E01` | 788 MB |
| `evidence/carry-phone/carry-phone-2012-07-15-final.zip` | 200 MB |
| `evidence/carry-tablet/carry-tablet-2012-07-16-final.E01` | 1.2 GB |
| `evidence/net/ngdc-exterior-2012-07-10.pcap` | 38 MB |
| `evidence/email.zip` | 16 KB |
| `evidence/answers.zip` | 8.5 MB |

Full 9-snapshot corpus (~100+ GB) sits under the same prefix — see scenario
notes. Final-day images are enough for end-to-end validation.

---

## Training scenarios

All four training scenarios were originally authored with placeholder
URLs pointing at `dfir.training/downloads/test-images` (an aggregator
page, not a download). The manifests now point at verified Digital
Corpora corpora; the downloader works against them directly.

### ransomware_2021 — missing (~14.7 GB)
Source: `https://downloads.digitalcorpora.org/corpora/scenarios/2018-lonewolf/`
- `evidence/Forensic_Image_Files.zip` (14.7 GB, LoneWolf curated image bundle)

### insider_threat_2022 — missing (~9 GB)
Source: `https://downloads.digitalcorpora.org/corpora/scenarios/2019-narcos/`
- `evidence/Narcos-CCleaner.E01` (7.6 GB, disk)
- `evidence/Narcos-Mem-CCleaner.E01` (1.4 GB, memory)

### blue_team_challenge — missing (~8.7 GB)
Source: `https://downloads.digitalcorpora.org/corpora/scenarios/2020-linux-threat-analysis/`
- `evidence/alison_ws.7z` (8.0 GB, Stage 3 workstation)
- `evidence/aamemend.7z` (0.8 GB, Stage 5 memory)

### network_intrusion — missing (~1.4 GB)
Source: `https://downloads.digitalcorpora.org/corpora/scenarios/2020-linux-threat-analysis/Stage1/`
- `evidence/Day_1_Capture.7z` (0.86 GB, PCAP)
- `evidence/ggmemday1.7z` (0.51 GB, memory)

---

## How to fetch

The generic scenario downloader reads `scenario.yaml` and fetches every
`download_url` in its `evidence:` block. It resumes partial downloads,
skips files already on disk, and verifies `sha256` when the manifest
has one (and logs the computed hash when it doesn't, so it can be
pinned back into the manifest).

```bash
# Preview what would be downloaded, no network writes
scripts/download-corpora/download-scenario.sh scenarios/real/m57-patents --dry-run

# Fetch every evidence file
scripts/download-corpora/download-scenario.sh scenarios/real/m57-patents
scripts/download-corpora/download-scenario.sh scenarios/real/national_gallery_2012

# Only required evidence (skips entries marked required: false)
scripts/download-corpora/download-scenario.sh scenarios/real/m57-jean --required-only
```

Per-scenario convenience wrappers exist where useful and delegate to
the generic downloader:

```bash
scenarios/real/m57-patents/download_all.sh
scenarios/real/national_gallery_2012/download_all.sh
scenarios/real/nitroba/download_all.sh   # pre-generic; still works
```

Broader orchestration scripts (multi-scenario phases, reference corpora)
live under `scripts/download-corpora/`:

```bash
scripts/download-corpora/download-phase1-critical.sh
scripts/download-corpora/download-phase2-high.sh
scripts/download-corpora/download-phase3-selective.sh
scripts/download-corpora/verify-downloads.sh
```

After the first successful download, populate the `sha256:` field in
the scenario manifest so future runs can verify integrity.
