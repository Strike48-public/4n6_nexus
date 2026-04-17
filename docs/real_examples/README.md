# Real Examples

End-to-end case studies run against public / practice forensic images. Each sub-directory documents one case and ties the outcome back to the self-correction engine where applicable.

Unlike `test_data/scenarios/` (small synthetic CSVs for unit-style regression), these cases run the full pipeline: disk image -> artifact extraction -> parser -> engine -> findings.

| Case | Image | Source | Purpose | Outcome |
|------|-------|--------|---------|---------|
| [wiped_disk](wiped_disk/) | `practice_images/wiped_disk.E01` (52 MB) | CIRCL "Recovering data from a wiped disk" (2023-01-31) | Insider wiped primary GPT; recover via backup GPT, then analyze the NTFS partition. | CRITICAL finding at partition-table layer (0.95 confidence). Partition NTFS metadata is also destroyed and partition 2 is LUKS, so no MFT/Prefetch/EVTX findings are produced. |
| [nps-2008-jean](nps-2008-jean/) | `practice_images/nps-2008-jean.E01`+`.E02` (3.0 GB) | Digital Corpora M57-Jean scenario | Determine whether CFO Jean exfiltrated `m57biz.xls` from her Windows XP SP3 laptop. | Solved (hash-identical exfil via phishing). `Desktop\m57biz.xls` SHA-256 `34456b5f...779f` is byte-identical to the attachment in Jean's Sent Items reply submitted 44 s after save. Attacker impersonated `alison@m57.biz` from `tuckgorge@gmail.com`. See [findings.md](nps-2008-jean/findings.md), [validator_notes.md](nps-2008-jean/validator_notes.md), [grading.md](nps-2008-jean/grading.md). |

## Reproducibility

Every case directory contains:

- `case_brief.md` - what the image is, where it came from, what we are proving.
- `reproduction.md` - exact commands and their output (pasted verbatim).
- `findings.md` - what the engine reported and how that maps to the ground truth.
- Any extracted CSV artifacts live under `analysis/real_examples/<case>/` so evidence directories stay read-only.

## Ground rules

- Never mutate the original `.E01` / `.dd` files. Mount read-only, or operate on a copy.
- Every command recorded with its absolute invocation so reviewers can re-run it.
- Report the negative: if a scenario produced no findings, say so plainly.
