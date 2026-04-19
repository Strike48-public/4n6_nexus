# Digital Corpora Download Scripts

Automated download scripts for acquiring comprehensive DFIR training datasets from [Digital Corpora](https://digitalcorpora.org/).

## Quick Start

```bash
# Phase 1: Essential datasets (~140 GB)
./download-phase1-critical.sh

# Verify downloads
./verify-downloads.sh

# Phase 2: Additional important datasets (~100 GB)
./download-phase2-high.sh

# Phase 3: Selective large/specialized datasets (variable)
./download-phase3-selective.sh
```

## Download Phases

### Phase 1: Critical (~140 GB)

**Essential foundation for DFIR training**

- **Mobile:** Android 10-12, iOS 13.x (~80 GB)
- **Disk Images:** NPS test images, CIRCL exercises (~25 GB)
- **Scenarios:** Nitroba, M57-Jean, M57-Patents, National Gallery (~23 GB)
- **Files:** Govdocs1 development subsets (~2.5 GB)
- **Network:** 5 GB TCP test file (~5 GB)
- **SQL:** SQLite forensic corpus (~500 MB)

**Run Time:** 2-6 hours depending on connection speed

### Phase 2: High (~100 GB)

**Additional important training material**

- **Mobile:** Android 13, 8, 9 (~49 GB)
- **Scenarios:** 2018-2019 cases (Lone Wolf, Narcos, Owl, Tuck) (~29 GB)
- **Files:** Govdocs1 JPEG subset (~20 GB)
- **Language:** NPS Language Drives (~2 GB)

**Run Time:** 1-4 hours

### Phase 3: Selective (Variable)

**Specialized/large datasets - download on demand**

- Android 7 (~3 GB)
- Legacy mobile devices (~560 MB)
- Full Govdocs1 corpus (~250 GB)
- DEFCON 20 CTF (~50 GB)
- SAFEDOCS PDF corpus (~500 GB)
- UNSAFE-DOCS malicious PDFs (~50 GB)

**Run Time:** Varies significantly (1 hour - 2 days)

## Storage Requirements

| Configuration | Size | Description |
|---------------|------|-------------|
| **Minimum** | ~140 GB | Phase 1 only - core training |
| **Recommended** | ~240 GB | Phase 1 + 2 - comprehensive |
| **Maximum** | ~800 GB | All phases - research-grade |

## Scripts

### download-phase1-critical.sh

Downloads essential DFIR training datasets.

**Features:**
- Resume support (wget -c)
- Progress tracking
- Error handling
- Directory structure creation

**Usage:**
```bash
./download-phase1-critical.sh
```

### download-phase2-high.sh

Downloads additional important datasets.

**Prerequisites:** Phase 1 should be completed first

**Usage:**
```bash
./download-phase2-high.sh
```

### download-phase3-selective.sh

Interactive menu for selective large dataset downloads.

**Features:**
- Size warnings for large downloads
- Double confirmation for >50 GB datasets
- Individual dataset selection
- Can run multiple times

**Usage:**
```bash
./download-phase3-selective.sh
```

### verify-downloads.sh

Verifies file integrity using MD5/SHA1/SHA256 checksums.

**Features:**
- Automatic hash file detection
- Per-directory verification
- Global summary report
- Missing file detection

**Usage:**
```bash
./verify-downloads.sh
```

## Directory Structure

Downloads are organized under the consolidated `scenarios/` tree:

```
scenarios/
├── real/                              # Downloaded evidence for public cases
│   ├── nitroba/evidence/
│   ├── m57-jean/evidence/
│   ├── m57-patents/evidence/
│   ├── national_gallery_2012/evidence/
│   ├── circl-2023-wiped/evidence/
│   ├── lone_wolf_2018/evidence/
│   ├── narcos_2019/evidence/
│   ├── owl_2019/evidence/
│   ├── tuck_2019/evidence/
│   └── nps_language_2011/evidence/
└── reference/                         # Raw corpora for parser input
    ├── mobile/
    │   ├── android/
    │   │   ├── android_10/
    │   │   ├── android_11.zip
    │   │   ├── android_12.zip
    │   │   └── android_13/
    │   ├── ios/
    │   │   ├── ios_13_3_1/
    │   │   └── ios_13_4_1/
    │   └── legacy/
    ├── nist-nps/
    │   ├── canon2/
    │   ├── casper-rw/
    │   ├── hfsjtest1/
    │   ├── ntfs1/
    │   └── domexusers/
    ├── circl-drives/
    ├── network-pcaps/
    ├── govdocs/
    │   └── subsets/
    └── sql/
        └── sqlite_corpus/
```

## Troubleshooting

### Downloads Interrupted

All scripts use `wget -c` (resume support). Simply re-run the script and it will continue from where it left off.

### Disk Space Issues

Check available space before starting:

```bash
df -h $(pwd)
```

If running low:
- Complete Phase 1 first, then clean up before Phase 2
- Use Phase 3 selectively - avoid full Govdocs1/SAFEDOCS unless needed
- Consider external storage or network mount

### Hash Verification Failures

If `verify-downloads.sh` reports failures:

1. Check disk space: `df -h`
2. Check filesystem health: `dmesg | tail`
3. Re-download failed files
4. Verify network stability during download

### Slow Downloads

Digital Corpora is hosted on AWS S3 with generally good bandwidth. If downloads are slow:

1. Check your internet connection speed
2. Try at off-peak hours
3. Consider using `aria2c` for parallel downloads (see Advanced Usage)

### Permission Errors

If you get permission denied errors:

```bash
chmod +x *.sh
```

## Advanced Usage

### Parallel Downloads with aria2c

For faster downloads on high-bandwidth connections:

```bash
# Install aria2c
sudo apt-get install aria2

# Example: Download with 4 parallel connections
aria2c -x 4 -s 4 https://downloads.digitalcorpora.org/corpora/mobile/android_12.zip
```

### Custom Destination

Modify scripts to use different destination:

```bash
# Edit script and change SCENARIOS_DIR / REAL_DIR / REF_DIR
SCENARIOS_DIR="/mnt/external/forensics/scenarios"
REAL_DIR="$SCENARIOS_DIR/real"
REF_DIR="$SCENARIOS_DIR/reference"
```

### Selective Scenario Downloads

To download only specific scenarios, extract the relevant `download_directory` calls from the scripts:

```bash
BASE_URL="https://downloads.digitalcorpora.org/corpora"
REAL_DIR="./scenarios/real"

# Just Nitroba
wget -r -np -nH --cut-dirs=3 -R "index.html*" \
  "$BASE_URL/scenarios/2008-nitroba/" -P "$REAL_DIR/nitroba/evidence/"
```

## Post-Download Steps

1. **Verify integrity:**
   ```bash
   ./verify-downloads.sh
   ```

2. **Extract archives:**
   ```bash
   # ZIP files
   cd scenarios/reference/mobile/android
   unzip android_12.zip

   # TAR.GZ files
   tar -xzf android_9.tar.gz
   ```

3. **Review scenario documentation:**
   - Visit https://digitalcorpora.org/corpora/scenarios/
   - Read narrative files included in downloads
   - Check for solution requests

4. **Start analyzing:**
   - Begin with Nitroba (smallest, focused)
   - Progress to M57-Jean (single disk)
   - Tackle M57-Patents (multi-evidence)

## Resources

- **Digital Corpora Website:** https://digitalcorpora.org/
- **Comprehensive Catalog:** See `docs/digitalcorpora-comprehensive-catalog.md`
- **S3 Information:** https://digitalcorpora.org/about-digitalcorpora/s3-information/
- **Scenario Solutions:** https://digitalcorpora.org/corpora/scenarios/obtaining-solutions/

## Citation

When using Digital Corpora in research:

**Garfinkel, Farrell, Roussev and Dinolt,** *Bringing Science to Digital Forensics with Standardized Forensic Corpora*, **DFRWS 2009, Montreal, Canada**

## Support

For issues with Digital Corpora datasets:
- Email: corpus@digitalcorpora.org
- Website: https://digitalcorpora.org/about-digitalcorpora/contact/

For issues with these download scripts:
- Check troubleshooting section above
- Review script output for error messages
- Verify network connectivity and disk space

---

**Last Updated:** 2026-04-17  
**Version:** 1.0
