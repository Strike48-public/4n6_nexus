# CIRCL Wiped Disk (2023-01-31)

Insider threat: user began wiping the disk from LBA 0 outward, was interrupted. Primary GPT is zeroed; secondary GPT at the end of the disk survived. Recovery requires rebuilding the primary GPT from the secondary copy.

See [`scenario.yaml`](scenario.yaml) for the manifest.

## Evidence

| File | Size | Purpose |
|---|---|---|
| `evidence/wiped_disk.E01` | 52 MB (8.18 GB logical) | EWF image |
| `evidence/wiped_disk.pdf` | 240 KB | 20-slide walkthrough |

Download: `./download.sh` (fetches into `evidence/`). Integrity verified via SHA-256 in `scenario.yaml`.

## What the walkthrough proves

1. Primary GPT region (LBA 0-33) is wiped
2. Secondary GPT at the end of the disk is intact (EFI PART signature visible)
3. Primary GPT can be rebuilt from the secondary copy
4. After repair: NTFS1 (3.5 GB unencrypted) and NTFS2 (4.1 GB LUKS)

## What our engine detects

CRITICAL finding, confidence 0.95: *"Partition table wiped (primary GPT zeroed, secondary GPT intact)"*

Reasoning:

1. Sector 0 (protective MBR): all zeros
2. Sector 1 (primary GPT header): all zeros
3. Secondary GPT header at LBA 15974399 has valid `EFI PART` signature
4. Secondary enumerates 2 partitions
5. Partition 1: LBA 2048-7383039 (3.52 GiB) `disk1`
6. Partition 2: LBA 7383040-15972351 (4.10 GiB) `disk2`
7. Asymmetry (primary wiped, secondary valid) cannot be produced by normal OS behavior

## Reproduction

```bash
python -m sift_find_evil.cli analyze \
    --image scenarios/real/circl-2023-wiped/evidence/wiped_disk.E01 \
    --output analysis/circl-2023-wiped/findings.json
```

Expected exit code: 0. Expected stdout: one CRITICAL finding.

### Step-by-step walkthrough scripts

Read-only scripts in `analysis/circl-2023-wiped/`:

| Script | Purpose | Key finding |
|---|---|---|
| `01_inspect_gpt.py` | Dump LBA 0/1/2/33 + trailing sectors | Primary zero, secondary has EFI PART |
| `02_parse_secondary_gpt.py` | Parse secondary GPT header | Disk GUID, 2 partitions |
| `03_fingerprint_partitions.py` | Read first sector of each partition | P1 zeroed, P2 is LUKS1 |
| `04_scan_partition1.py` | Sweep NTFS1 region for non-zero content | 3595 zero-MiB chunks |
| `05_read_nonzero.py` | Hex-dump surviving non-zero region | Sparse, no FS metadata |
| `06_scan_ntfs_signatures.py` | Per-sector signature scan | Zero hits across 7.38M sectors |

## Why no per-file findings

- Partition 1 NTFS metadata is destroyed (zero MFT FILE records). Nothing to parse.
- Partition 2 is LUKS1; passphrase not distributed.

The partition-table asymmetry is the highest-fidelity evidence available. We surface it as a first-class finding and stop.

## Chain of custody

- Image read via `pyewf.handle` in read-only mode
- No writes to `scenarios/`, `/cases/`, `/mnt/`, or `/media/`
- All derived artifacts land in `analysis/`
- Timestamps in JSON output are UTC
