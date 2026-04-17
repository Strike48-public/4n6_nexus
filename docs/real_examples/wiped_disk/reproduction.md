# Reproduction: CIRCL Wiped Disk

## Prerequisites

- `practice_images/wiped_disk.E01` present in the repo
- Python dependencies: `libewf-python` (pyewf). Install with `pip install libewf-python`.

## One-shot reproduction

From the repository root:

```bash
python -m sift_find_evil.cli analyze \
    --image practice_images/wiped_disk.E01 \
    --output analysis/real_examples/wiped_disk/findings.json
```

Expected exit code: 0. Expected stdout: one CRITICAL finding titled *"Partition table wiped (primary GPT zeroed, secondary GPT intact)"* with confidence 0.95.

The full JSON output is saved to `analysis/real_examples/wiped_disk/findings.json` and committed as the canonical artifact for this case.

## Step-by-step walkthrough

The following scripts under `analysis/real_examples/wiped_disk/` were used to work out the case and are kept for audit/reviewer reproduction. Each is read-only with respect to the image.

| Script | Purpose | Key finding |
|---|---|---|
| `01_inspect_gpt.py` | Dump LBA 0/1/2/33 and the three trailing sectors | Primary sectors all zero, secondary sector has EFI PART |
| `02_parse_secondary_gpt.py` | Parse the secondary GPT header and entry array | Disk GUID `d4d2aac6-...`, 2 partitions |
| `03_fingerprint_partitions.py` | Read the first sector of each partition | Partition 1 starts zeroed; partition 2 is LUKS1 |
| `04_scan_partition1.py` | Sweep the 3.52 GiB NTFS1 region for any non-zero content | 3595 zero-MiB chunks, first non-zero at offset 562,036,736 |
| `05_read_nonzero.py` | Hex-dump the surviving non-zero region | Sparse, no file-system metadata |
| `06_scan_ntfs_signatures.py` | Per-sector scan for NTFS/MFT/INDX/FILE/RSTR/RCRD signatures | Zero hits across 7.38M sectors |

Outputs from each script are captured alongside the script as `.out` files for the reviewer.

## Why we stopped at the GPT layer

Conclusions from the walkthrough scripts:

- NTFS1 (partition 1) is not merely table-wiped; its NTFS metadata has also been destroyed - no boot sector, no MFT FILE records, no INDX blocks. There is nothing left to parse with MFTECmd/PECmd/EvtxECmd.
- NTFS2 (partition 2) is a LUKS1 volume. The CIRCL workshop discloses the passphrase only in the live classroom; we do not have it.

Because neither partition yields MFT/Prefetch/EVTX artifacts, the self-correction engine (which reasons across those three artifact classes) cannot run here. The detectable anti-forensic evidence lives *at the partition-table layer*, so we encoded that observation directly as a detector and stopped there.

## Resetting between runs

The detector is pure - it only reads the image. No state is written back to the image and no local state needs to be reset between runs.

## Integrity of the image

```bash
python - <<'PY'
import hashlib, pathlib
data = pathlib.Path('practice_images/wiped_disk.E01').read_bytes()
print(hashlib.sha256(data).hexdigest())
PY
```

The image hash should remain constant across all runs of the detector.
