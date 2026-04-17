# Case: CIRCL "Wiped Disk"

## Source

CIRCL (Computer Incident Response Center Luxembourg), "Recovering data from a wiped disk - A manual approach", 2023-01-31, TLP:CLEAR. Distributed as:

- `practice_images/wiped_disk.E01` (52 MB EWF container, 8.18 GB logical image)
- `practice_images/wiped_disk.pdf` (20-slide walkthrough)

## Scenario

Insider threat. The user discovered they were about to be caught and began wiping the disk from LBA 0 outward. They were interrupted before they finished, so the front of the disk (MBR, primary GPT header, primary partition table) is zeroed but the data partitions and the secondary GPT at the end of the disk survived.

## What the walkthrough proves

1. The primary GPT region (LBA 0 through LBA 33) is wiped.
2. The secondary GPT at the end of the disk is intact (EFI PART signature visible).
3. The primary GPT can be rebuilt from the secondary GPT copy.
4. After repair, two partitions appear: NTFS1 (3.5 GB unencrypted) and NTFS2 (4.1 GB behind LUKS).

## What we are proving

- Our pipeline can ingest a real EWF image (via `pyewf`) and enumerate partitions (via `pytsk3`) without SleuthKit CLI tools.
- When a partition table is wiped, we recognize the condition, recover from the secondary GPT, then continue analysis.
- Artifacts extracted from the recovered NTFS partition feed the existing self-correction engine unchanged.
