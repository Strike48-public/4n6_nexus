# Findings: CIRCL Wiped Disk

## Headline

CRITICAL | confidence 0.95 | "Partition table wiped (primary GPT zeroed, secondary GPT intact)"

## Raw output

See `analysis/real_examples/wiped_disk/findings.json` for the machine-readable finding. It is produced directly by:

```bash
python -m sift_find_evil.cli analyze --image practice_images/wiped_disk.E01 \
    --output analysis/real_examples/wiped_disk/findings.json
```

## Evidence summary

| Evidence | Value |
|---|---|
| Total sectors | 15,974,400 (8.18 GB logical) |
| Sector 0 (protective MBR) | all zeros |
| Sector 1 (primary GPT header) | all zeros |
| Secondary GPT @ LBA 15,974,399 | signature `EFI PART`, revision 0x00010000 |
| Disk GUID (from secondary) | `d4d2aac6-7159-422f-b5bc-520ac650ece1` |
| Secondary entry array @ LBA 15,974,367 | 128 entries x 128 bytes |
| Partition 1 | `disk1`, LBA 2048-7,383,039 (3.52 GiB), type GUID `ebd0a0a2-...-b72699c7` (Microsoft Basic Data) |
| Partition 2 | `disk2`, LBA 7,383,040-15,972,351 (4.10 GiB), same type GUID |

These values match the CIRCL walkthrough exactly (same GUIDs, same LBAs), which validates both our parser and the detector's use of the secondary GPT as a ground-truth recovery source.

## Reasoning chain (from the finding)

1. Sector 0 (protective MBR): all zeros
2. Sector 1 (primary GPT header): all zeros
3. Secondary GPT header at LBA 15974399 has valid EFI PART signature
4. Secondary GPT enumerates 2 partition(s)
5. Partition 1: LBA 2048-7383039 (3.52 GiB) type ebd0a0a2-... name 'disk1'
6. Partition 2: LBA 7383040-15972351 (4.10 GiB) type ebd0a0a2-... name 'disk2'
7. Asymmetry (primary wiped, secondary valid) cannot be produced by normal OS behavior; it is the expected outcome of a front-of-disk wipe.

## Why this is high-confidence

GPT specifies a redundant layout: the primary header/table sits at LBAs 1-33 and the secondary copy sits at the last 33 LBAs. Healthy operating-system behavior either keeps both in sync or tears both down together. There is no benign workflow that selectively zeroes the primary region while leaving the secondary structurally valid - not partitioning, not formatting, not filesystem repair, not disk imaging. The CIRCL scenario explicitly models an interrupted `dd if=/dev/zero of=/dev/sdX bs=1M count=N` as the cause, and that is exactly the signature we are observing.

## Why the engine does not produce per-file findings for this case

- Partition 1 NTFS metadata is additionally destroyed (zero NTFS boot sector hits, zero MFT FILE records across 7,380,992 sectors). There is no artifact surface to parse.
- Partition 2 is a LUKS1 volume; the decryption passphrase is not distributed with the practice image.

The partition-table asymmetry is therefore the highest-fidelity forensic evidence available in this image, and it is surfaced as a first-class finding.

## Chain of custody

- Evidence read via `pyewf.handle` in read-only mode.
- No writes to `practice_images/`, `/cases/`, `/mnt/`, or `/media/`.
- All generated artifacts live in `analysis/real_examples/wiped_disk/` and `docs/real_examples/wiped_disk/`.
- Timestamps in the JSON output are UTC.
