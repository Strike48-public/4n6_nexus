# Case: NPS M57-Jean (2008)

## Source

Digital Corpora "M57-Jean" scenario, part of the Real Data Corpus.

- Landing page: https://digitalcorpora.org/corpora/scenarios/m57-jean/
- Image: `practice_images/nps-2008-jean.E01` + `.E02` (~3.0 GB compressed, 10 GB logical)
- Exercise slides: `references/M57-Jean-exercise-slides.pdf`

### EWF header (from `pyewf.get_header_values`)

| Field | Value |
|-------|-------|
| description | Jean's hard drive from the first M57 project |
| examiner_name | Donny |
| evidence_number | 2008-M57-Jean |
| acquiry_date | Mon Jan 31 16:38:29 2011 |
| acquiry_operating_system | Darwin |
| acquiry_software_version | 20101104 |

### Hashes

| File | SHA-256 |
|------|---------|
| nps-2008-jean.E01 | df3a995c7a594e0ba6d95b9aae735a444313fae435a87e7536f9dad3db2769ce |
| nps-2008-jean.E02 | 07f1f78c857d5b5809ac7a68e1467d36872fa74f047ee2c799d37b18aad4f5aa |

Logical media: 10 737 418 240 bytes = 20 971 520 sectors of 512 bytes.

## Scenario

Jean is CFO of M57.Biz, a small startup. Early in the scenario, the company's confidential spreadsheet `m57plan.xlsx` (the cap table / financial plan) leaks outside the company. Jean's laptop is imaged to determine whether she exfiltrated the file, and if so how.

The published exercise deliberately does not tell you the answer up front; the student is expected to derive it from the image. The canonical "solution" is password-gated (SANS / instructor materials). For our purposes we use two independent oracles:

1. The public exercise slides (`references/M57-Jean-exercise-slides.pdf`) which enumerate the concrete questions.
2. A second, independent Agent instance (see `../../../docs/architecture/three_agent_validation.md` once written) given only the findings artifact and the public slides, tasked with challenging our conclusions.

## Null hypothesis

Jean did not exfiltrate `m57plan.xlsx`. Evidence to the contrary must be:

- Timestamped (MFT/USN/Prefetch/EVTX), not just present-on-disk.
- Cross-validated across at least two artifacts.
- Survive an adversarial pass by the validator agent.

## What we are proving

- The pipeline that handled the CIRCL wiped-disk case (partition-table layer) also handles a healthy, populated NTFS image end-to-end.
- The self-correction engine, given real MFT / Prefetch / EVTX output from EZ Tools, produces findings that match what a SIFT analyst would produce manually.
- The adversarial validator catches overreach (for example, claiming intent from a single "file existed on disk" signal).

## Non-goals

- Memory forensics: this is a disk-only capture, no RAM image was published.
- Network reconstruction: `nps-2008-jean` is a disk image only. Network indicators come from artifacts (browser history, email client state) not from a pcap.

## Expected Windows generation

The image predates Vista SP2 on typical M57 lab configurations; confirm by reading the `CurrentVersion` subkey from the SOFTWARE hive during Phase 2 inventory. If this is XP/2003, process-creation events live in Security Event ID **592**, not 4688, and the Event Log parser must read `.evt` (not `.evtx`).
