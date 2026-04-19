# Dataset Download Status

**Last Updated**: 2026-04-18
**Purpose**: Track available forensic datasets and download attempts

---

## Summary

| Dataset | Status | Size | Location | Notes |
|---------|--------|------|----------|-------|
| M57 Jean laptop | Downloaded | 2.9 GB | practice_images/m57-patents/jean/ | E01, E02 segments |
| M57 Jean USB | Not Downloaded | ~500 MB | - | USB drive missing |
| M57 Pat | Failed (404) | ~4 GB | - | URLs return 404 errors |
| M57 Terry | Not Attempted | ~4 GB | - | - |
| M57 Charlie | Not Attempted | ~4 GB | - | - |
| M57 Jo | Not Attempted | ~4 GB | - | - |
| M57 Network | Not Attempted | Variable | - | PCAP files |
| M57 Memory | Not Attempted | 20-80 GB | - | RAM dumps |
| Nitroba PCAP | Downloaded | 54 MB | practice_images/nitroba/ | Network capture |
| CIRCL Wiped | Downloaded | 52 MB | scenarios/circl-2023-wiped/ | Disk wipe challenge |
| CFReDS data_leakage | Not Available | - | - | HTML stubs only |

**Total Downloaded**: ~3 GB  
**Total Available**: ~3 GB  
**Attempted but Failed**: ~4 GB (Pat - 404 errors)

---

## Verified Downloads

### 1. M57 Jean's Laptop
```
Location: practice_images/m57-patents/jean/
Files:
  - nps-2008-jean.E01 (1.5 GB)
  - nps-2008-jean.E02 (1.4 GB)
Status: COMPLETE
Purpose: Primary suspect in corporate espionage scenario
```

### 2. Nitroba Network Capture
```
Location: practice_images/nitroba/
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

## Download Failures

### M57 Pat's Desktop
**Attempted**: 2026-04-18  
**Method**: `./download_all.sh pat`  
**Error**: HTTP 404 - The requested URL returned error: 404

**URLs Attempted**:
- https://downloads.digitalcorpora.org/corpora/scenarios/m57-patents/nps-2009-pat/nps-2009-pat.E01
- https://downloads.digitalcorpora.org/corpora/scenarios/m57-patents/nps-2009-pat/nps-2009-pat.E02
- https://downloads.digitalcorpora.org/corpora/scenarios/m57-patents/usb-drives/pat-usb-2009-12-11.E01

**Root Cause**: Files not available at Digital Corpora URLs

**Possible Solutions**:
1. Check Digital Corpora website for updated URLs
2. Contact Digital Corpora for access
3. Verify if files have been relocated
4. Check if account/permission is required

---

## Not Yet Attempted

### M57 Additional Characters
- **Terry's laptop**: nps-2009-terry (2 E01 segments + USB)
- **Charlie's laptop**: nps-2009-charlie (2 E01 segments + USB)
- **Jo's laptop**: nps-2009-jo (2 E01 segments + USB)

**Reason for deferral**: Pat download failed with 404, suggesting all nps-2009-* files may be unavailable

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
practice_images/
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
1. **Investigate M57 404 errors**
   - Check Digital Corpora website for updated URLs
   - Verify if authentication is required
   - Contact support if necessary

2. **Work with available datasets**
   - M57 Jean (2.9 GB) - PRIMARY FOCUS
   - Nitroba (54 MB) - Network analysis
   - CIRCL Wiped (52 MB) - Data recovery

3. **Complete Phase 1 Implementation**
   - Registry parser tests (20+ tests)
   - Scenarios 07-10 creation
   - NSRL integration
   - Use Jean's evidence for testing

### Short-Term (Priority 2)
4. **Resolve M57 download issues**
   - Alternative download sources
   - Direct contact with Digital Corpora
   - Academic/institutional access

5. **Expand testing coverage**
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
cd scenarios/m57-patents

# Individual characters
./download_all.sh jean      # Already downloaded
./download_all.sh pat       # FAILED - 404 errors
./download_all.sh terry     # Not attempted
./download_all.sh charlie   # Not attempted
./download_all.sh jo        # Not attempted

# Special categories
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

**Status**: 3 datasets available (3 GB), sufficient for Phase 1 testing and development

**Last Updated**: 2026-04-18
