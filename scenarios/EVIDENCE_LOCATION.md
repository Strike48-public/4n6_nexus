# Evidence Storage Location

## USB-C Drive Storage (Large Files)

Large evidence files moved to USB-C drive (TESLADRIVE) to free local disk space for SIFT VM operations:

**Location:** `/media/jtomek/TESLADRIVE/sift_evidence/`

### Moved Evidence:

- `mobile/` (50GB) - Mobile forensics reference corpus
- `m57-patents/` (41GB) - M57 Patents multi-custodian case
- `ransomware_2021/` (15GB) - LoneWolf ransomware training scenario
- `insider_threat_2022/` (9.1GB) - Narcos memory dump
- `blue_team_challenge/` (8.8GB) - Linux threat analysis
- `national_gallery_2012/` (11GB) - Insider threat

**Total space freed:** ~135GB

### Accessing Evidence

Evidence files can be accessed directly from USB-C drive mount:

```bash
# USB-C mount point
ls /media/jtomek/TESLADRIVE/sift_evidence/

# Create symlinks for convenience (when needed)
ln -s /media/jtomek/TESLADRIVE/sift_evidence/mobile scenarios/reference/mobile
ln -s /media/jtomek/TESLADRIVE/sift_evidence/m57-patents scenarios/real/m57-patents  
ln -s /media/jtomek/TESLADRIVE/sift_evidence/ransomware_2021 scenarios/training/ransomware_2021
```

### Local Evidence (Still on Disk)

Critical evidence for testing remains local:
- `scenarios/real/m57-jean/` (2.9GB) - Primary demo case
- `scenarios/real/circl-2023-wiped/` (53MB) - Wiped disk case
- `scenarios/training/network_intrusion/` (6.6GB) - Network intrusion + memory
- All synthetic scenarios (< 50KB each)

## TrueNAS Backup (Secondary)

Some evidence was also copied to TrueNAS during earlier transfer attempts:

**Server:** 10.0.4.10 (TrueNAS)  
**Mount:** `/tmp/nfs_personal` → `10.0.4.10:/mnt/Whale/personal`  
**Location:** `/tmp/nfs_personal/git/sift_evidence/`
**Capacity:** 81TB (1% used, 547GB)  
**Protocol:** NFSv4.2

Files on TrueNAS:
- `mobile/` (10GB partial)
- `m57-patents/` (26MB partial)
- `ransomware_2021/` (646MB partial)

**Note:** TrueNAS transfers were slow/incomplete. USB-C drive is the primary storage location.

## Rationale

**Problem:** Local disk 100% full (887GB used / 935GB capacity)  
**Solution:** Move large, infrequently-accessed evidence to USB-C drive  
**Benefit:** Freed 135GB space for SIFT VM conversion (needs ~20GB for qcow2 conversion)
**Result:** Disk now at 91% (804GB used / 935GB capacity, 84GB free)

## Recovery

If USB-C drive becomes unavailable, evidence can be re-downloaded via:

```bash
scripts/download-corpora/download-scenario.sh scenarios/reference/mobile
scripts/download-corpora/download-scenario.sh scenarios/real/m57-patents
scripts/download-corpora/download-scenario.sh scenarios/training/ransomware_2021
scripts/download-corpora/download-scenario.sh scenarios/training/insider_threat_2022
scripts/download-corpora/download-scenario.sh scenarios/training/blue_team_challenge
scripts/download-corpora/download-scenario.sh scenarios/real/national_gallery_2012
```

See `scenarios/DOWNLOADS.md` for source URLs.
