# Dataset Download Status

**Last Updated**: 2026-04-22
**Purpose**: Track available forensic datasets and download attempts

---

## Summary

| Dataset | Status | Size | Location | Notes |
|---------|--------|------|----------|-------|
| M57 Jean laptop | Downloaded | 2.9 GB | scenarios/real/m57-jean/evidence/ | E01, E02 segments |
| M57 Jean USB | Not Downloaded | ~500 MB | - | USB drive missing |
| M57 Pat | URLs Verified | 5.72 GB | - | HEAD 200 via S3 redirect |
| M57 Terry (2 parts) | URLs Verified | 19.72 GB | - | HEAD 200 via S3 redirect |
| M57 Charlie | URLs Verified | 3.61 GB | - | HEAD 200 via S3 redirect |
| M57 Jo (2 parts) | URLs Verified | 11.07 GB | - | HEAD 200 via S3 redirect |
| M57 Network | Not Attempted | Variable | - | PCAP files |
| M57 Memory | Not Attempted | 20-80 GB | - | RAM dumps |
| Nitroba PCAP | Downloaded | 54 MB | scenarios/real/nitroba/evidence/ | Network capture |
| CIRCL Wiped | Downloaded | 52 MB | scenarios/circl-2023-wiped/ | Disk wipe challenge |
| CFReDS data_leakage | Not Available | - | - | HTML stubs only |

**Total Downloaded**: ~3 GB
**Total Available (verified fetchable)**: ~43 GB (Jean + Pat + Terry + Charlie + Jo redacted)
**Resolved (was 404)**: M57 redacted disks — new URL format confirmed live on 2026-04-22

---

## Verified Downloads

### 1. M57 Jean's Laptop
```
Location: scenarios/real/m57-jean/evidence/
Files:
  - nps-2008-jean.E01 (1.5 GB)
  - nps-2008-jean.E02 (1.4 GB)
Status: COMPLETE
Purpose: Primary suspect in corporate espionage scenario
```

### 2. Nitroba Network Capture
```
Location: scenarios/real/nitroba/evidence/
Files:
  - nitroba.pcap (53.6 MB)
Status: COMPLETE
Purpose: Network traffic analysis scenario
```

### 3. CIRCL Wiped Disk Challenge
```
Location: scenarios/circl-2023-wiped/
Files:
  - wiped_disk.E01 (52 MB)
  - wiped_disk.pdf (235 KB)
Status: COMPLETE
Purpose: Advanced data recovery challenge
```

---

## Resolved Failures

### M57 Redacted Disks (Pat / Terry / Charlie / Jo)
**Resolved**: 2026-04-22 (SFE-c73)
**Prior status**: 404 against `nps-2009-pat/nps-2009-pat.E01` style URLs

**Root cause**: Digital Corpora renamed the M57 scenario path. The
`m57-patents/nps-2009-*` layout was replaced by
`2009-m57-patents/drives-redacted/<name>-2009-12-11.E01`.

**Current URLs** (all return HTTP 200 via 302 redirect to
`digitalcorpora.s3.amazonaws.com`; sizes match `scenario.yaml` exactly):

| File | Size | Status |
|------|------|--------|
| pat-2009-12-11.E01 | 6,146,409,989 B (5.72 GB) | 200 |
| terry-2009-12-11-001.E01 | 10,593,607,311 B (9.87 GB) | 200 |
| terry-2009-12-11-002.E01 | 10,576,418,278 B (9.85 GB) | 200 |
| charlie-2009-12-11.E01 | 3,874,203,396 B (3.61 GB) | 200 |
| jo-2009-12-11-001.E01 | 5,945,571,099 B (5.54 GB) | 200 |
| jo-2009-12-11-002.E01 | 5,939,239,364 B (5.53 GB) | 200 |

Manifest (`scenarios/real/m57-patents/scenario.yaml`) already carries the
updated URLs and SHA-256 hashes — no code change required to fetch them.
Running `./scenarios/real/m57-patents/download_all.sh` should now
succeed. Disks are marked `required: false`, so nothing blocks CI if the
operator opts not to fetch the ~43 GB redacted subset.

### M57 Network Traffic
- **Location**: https://downloads.digitalcorpora.org/corpora/scenarios/m57-patents/net/
- **Format**: PCAP files (directory listing required)
- **Size**: Variable
- **Status**: Not attempted

### M57 Memory Dumps
- **Location**: https://downloads.digitalcorpora.org/corpora/scenarios/m57-patents/ram/
- **Format**: Raw memory images
- **Size**: 20-80 GB estimated
- **Status**: Not attempted

---

## Unavailable Datasets

### CFReDS Data Leakage
**Status**: NOT AVAILABLE  
**Issue**: Downloaded files are 1.4KB HTML stubs, not actual forensic images  
**Files**:
- data-leakage-case.dd.zip (1.4 KB HTML)
- data-leakage-case.sha1 (1.4 KB HTML)

**Error when attempting extraction**:
```
End-of-central-directory signature not found.  Either this file is not
a zipfile, or it constitutes one disk of a multi-part archive.
```

**Resolution**: CFReDS data requires download from official portal (not direct URLs)

---

## Storage Analysis

### Current Usage
```bash
scenarios/
├── m57-patents/     2.9 GB (Jean only)
├── nitroba/         54 MB
├── scenarios/       empty placeholders
├── mobile/          empty placeholders
├── disk_images/     empty placeholders
└── cfreds/          1.4 KB HTML stubs

Total: ~3 GB actual data
```

### Projected Full Download
```
M57 Complete:        50-100 GB
  - 5 characters:    ~20 GB (4 GB each)
  - Network:         ~5 GB estimated
  - Memory:          20-80 GB estimated
  
Additional Scenarios:
  - CIRCL:           52 MB (already downloaded)
  - Nitroba:         54 MB (already downloaded)
  
Total Projected:   53-103 GB
```

---

## Next Steps

### Immediate (Priority 1)
1. **Work with available datasets**
   - M57 Jean (2.9 GB) - PRIMARY FOCUS
   - Nitroba (54 MB) - Network analysis
   - CIRCL Wiped (52 MB) - Data recovery

2. **Complete Phase 1 Implementation**
   - Registry parser tests (20+ tests)
   - Scenarios 07-10 creation
   - NSRL integration
   - Use Jean's evidence for testing

### Short-Term (Priority 2)
3. **Fetch the M57 redacted disks as needed**
   - URL format resolved 2026-04-22; manifest is current
   - Opt-in via `./scenarios/real/m57-patents/download_all.sh <char>`
   - ~43 GB total for all 5 custodians' redacted subsets

4. **Expand testing coverage**
   - Additional scenarios from available data
   - Cross-reference with other datasets
   - Verify detection capabilities

### Long-Term (Priority 3)
6. **Download complete M57 scenario**
   - Once URL issues resolved
   - All 5 characters
   - Network captures
   - Memory dumps (if disk space permits)

7. **Expand dataset library**
   - Additional CFReDS scenarios
   - NIST datasets
   - Community-contributed images
   - Custom synthetic scenarios

---

## Download Commands Reference

### M57 Patents
```bash
cd scenarios/real/m57-patents

# Individual characters (URLs verified live 2026-04-22)
./download_all.sh           # Pulls every evidence row in scenario.yaml
# Jean's laptop lives in scenarios/real/m57-jean (already downloaded)

# Special categories (URLs not yet verified)
./download_all.sh network   # Network captures
./download_all.sh memory    # Memory dumps
./download_all.sh docs      # Teaching materials
./download_all.sh all       # Everything (50-100 GB)
```

### Nitroba
```bash
cd scenarios/nitroba
./download_all.sh           # Already downloaded
```

### Verification
```bash
cd scenarios/m57-patents
./verify_files.sh           # Verify checksums against manifest
```

---

## Checksums

### M57 Jean
```
nps-2008-jean.E01: TBD (calculate with md5sum)
nps-2008-jean.E02: TBD (calculate with md5sum)
```

### Nitroba
```
nitroba.pcap: TBD (calculate with md5sum)
```

### CIRCL Wiped
```
wiped_disk.E01: TBD (calculate with md5sum)
```

**Action**: Generate checksums for chain of custody

---

## Recommendations

1. **Focus on available datasets first**
   - M57 Jean has sufficient evidence for Phase 1 testing
   - CIRCL wiped disk is excellent for advanced features
   - Nitroba PCAP covers network analysis

2. **Defer large downloads**
   - Complete Phase 1 implementation
   - Validate tool functionality
   - Then expand to additional M57 characters

3. **Investigate 404 errors**
   - Digital Corpora may have reorganized
   - May require institutional access
   - Consider alternative sources

4. **Document all downloads**
   - Checksums for chain of custody
   - Download dates and sources
   - Verification status

---

**Status**: 3 datasets downloaded (3 GB). M57 redacted subset (~43 GB, 5
custodians) is URL-verified and fetchable on demand.

**Last Updated**: 2026-04-22
