# Digital Corpora - Comprehensive DFIR Training Dataset Catalog

**Research Date:** 2026-04-17  
**Source:** https://digitalcorpora.org/  
**Status:** Active - Hosted on AWS Open Data Program

---

## Executive Summary

Digital Corpora provides forensically sound, freely redistributable datasets for DFIR training and research. All data is hosted on AWS S3 with stable URLs and hash verification available.

**Total Storage Estimate:** ~200-300 GB for comprehensive coverage (excluding Real Data Corpus which requires IRB approval)

**Key Strengths:**
- Court-vetted forensic scenarios with documented narratives
- Multiple OS versions and file systems
- Real-world complexity (not synthetic data)
- Freely redistributable (mostly public domain)
- Active maintenance and new additions

---

## Category 1: Cell Phones / Mobile Forensics

### Available Datasets

#### **Android Images (Modern Versions)**

| Dataset | Size | Format | URL |
|---------|------|--------|-----|
| Android 13 | ~40 GB | ZIP/E01 | https://downloads.digitalcorpora.org/corpora/mobile/ |
| Android 12 | 41.9 GB | ZIP | https://downloads.digitalcorpora.org/corpora/mobile/android_12.zip |
| Android 11 | 10.9 GB | ZIP | https://downloads.digitalcorpora.org/corpora/mobile/android_11.zip |
| Android 10 | ~8 GB | ZIP | https://downloads.digitalcorpora.org/corpora/mobile/android_10/ |
| Android 9 | ~5 GB | tar.gz | https://downloads.digitalcorpora.org/corpora/mobile/android_9.tar.gz |
| Android 8 | ~4 GB | tar.gz | https://downloads.digitalcorpora.org/corpora/mobile/android_8.tar.gz |
| Android 7 | ~3 GB | tar.gz | https://downloads.digitalcorpora.org/corpora/mobile/android_7.tar.gz |

**Total Android:** ~115 GB

#### **iOS Images**

| Dataset | Size | Format | URL |
|---------|------|--------|-----|
| iOS 13.3.1 | ~10 GB | ZIP/TAR | https://downloads.digitalcorpora.org/corpora/mobile/ios_13_3_1/ |
| iOS 13.4.1 | ~10 GB | ZIP/TAR | https://downloads.digitalcorpora.org/corpora/mobile/ios_13_4_1/ |

**Total iOS:** ~20 GB

#### **Legacy Mobile Devices (Norwegian University)**

| Dataset | Description | Size | URL |
|---------|-------------|------|-----|
| Nokia 6230 | Early 2000s feature phone | ~50 MB | https://downloads.digitalcorpora.org/corpora/mobile/Nokia_6230.zip |
| Sony Ericsson P800 | Symbian smartphone | ~80 MB | https://downloads.digitalcorpora.org/corpora/mobile/SE_P800.zip |
| Sony Ericsson T68i | GSM phone | ~30 MB | https://downloads.digitalcorpora.org/corpora/mobile/SE_T68i.zip |
| Sony Ericsson T630 (with images) | Phone with digital photos | ~200 MB | https://downloads.digitalcorpora.org/corpora/mobile/SE_T630.zip |
| Sony Ericsson T630 (deleted) | Same phone after image deletion | ~200 MB | https://downloads.digitalcorpora.org/corpora/mobile/SE_T630.zip |

**Total Legacy:** ~560 MB

### Forensic Value

**Skills Taught:**
- Mobile acquisition and imaging (Cellebrite formats)
- Android file system analysis (versions 7-13)
- iOS file system analysis
- App data extraction
- SQLite database forensics
- Deleted file recovery on mobile
- Mobile timeline analysis
- Communication artifact recovery (SMS, calls, contacts)

**Use Cases:**
- Mobile forensics tool testing
- Android/iOS version comparison
- App behavior analysis
- Mobile malware investigation
- Photo/media recovery
- Deleted artifact recovery

**Difficulty:** Beginner to Advanced
- Legacy phones: Beginner (simple file systems)
- Modern Android/iOS: Intermediate to Advanced (complex file systems, encryption)

**Industry Relevance:** HIGH - Mobile forensics is critical in modern investigations

**Priority:** CRITICAL (Phase 1)
- Android 10, 11, 12: Essential for modern investigation skills
- iOS 13.x: Essential for Apple device investigations
- Legacy devices: MEDIUM (Phase 3) - Historical/educational value only

---

## Category 2: Disk Images

### NPS Test Disk Images

Court-vetted, PII-free images designed for tool testing.

| Dataset | Description | Size | URL |
|---------|-------------|------|-----|
| **nps-2009-canon2** | Canon camera SD card - file recovery, carving, fragmentation | ~500 MB | https://downloads.digitalcorpora.org/corpora/drives/nps-2009-canon2/ |
| **nps-2009-casper-rw** | Ubuntu 8.10 bootable USB (ext3) - web browsing artifacts | ~2 GB | https://downloads.digitalcorpora.org/corpora/drives/nps-2009-casper-rw/ |
| **nps-2009-hfsjtest1** | HFS+ journaled - journal recovery | ~1 GB | https://downloads.digitalcorpora.org/corpora/drives/nps-2009-hfsjtest1/ |
| **nps-2009-ntfs1** | NTFS with fragmented/compressed/encrypted files | ~2 GB | https://downloads.digitalcorpora.org/corpora/drives/nps-2009-ntfs1/ |
| **nps-2009-ubnist1** | FAT32 source for casper-rw | ~2 GB | https://downloads.digitalcorpora.org/corpora/drives/nps-2009-ubnist1/ |
| **nps-2009-domexusers** | Windows XP SP3 with IM/email between users | ~8 GB | https://downloads.digitalcorpora.org/corpora/drives/nps-2009-domexusers/ |
| **nps-2009-domexusers-redacted** | Same, Windows executables redacted | ~6 GB | https://downloads.digitalcorpora.org/corpora/drives/nps-2009-domexusers-redacted/ |
| **nps-2010-emails** | 30 email formats/encodings test | ~500 MB | https://digitalcorpora.org/corpora/disk-images/nps-2010-emails/ |
| **nps-2014-usb-nondeterministic** | USB device with inconsistent reads (firmware issue) | ~2 GB | https://digitalcorpora.org/corpora/disk-images/nps-2014-usb-nondeterministic/ |

**Total NPS Images:** ~24 GB

### CIRCL Forensics Exercises

| Dataset | Description | Size | URL |
|---------|-------------|------|-----|
| **Wiped Disk Image** | Data recovery challenge | ~1 GB | https://downloads.digitalcorpora.org/corpora/drives/circl-2023-wiped/ |

**Total CIRCL:** ~1 GB

### Scenarios (See Category 5 for details)

Major multi-disk scenarios with narratives:
- **M57-Jean** (~3 GB) - Corporate espionage, single laptop
- **M57-Patents** (~15 GB) - Complex multi-drive, multi-actor scenario
- **Nitroba** (53 MB PCAP) - Network harassment
- **2012 National Gallery DC Attack** - Web server compromise
- **2018 Lone Wolf** - Terrorism investigation
- **2019 Narcos, Owl, Tuck** - Various criminal scenarios

**Total Scenarios:** ~25-30 GB

### Real Data Corpus (IRB Required)

**NOTE:** No longer publicly available. Requires IRB approval and formal request.

Previously included:
- 1,289 hard drive images (500 MB - 80 GB each)
- 643 flash memory images (128 MB - 4 GB each)

This represents REAL data from REAL people and contains genuine PII. Not recommended for routine training due to ethical/legal constraints.

### Forensic Value

**Skills Taught:**
- Disk imaging and acquisition
- File system analysis (NTFS, FAT32, ext3, HFS+)
- Deleted file recovery
- File carving and fragmentation reassembly
- Journal forensics
- Encryption key recovery
- Windows artifacts (Registry, MFT, VSS, Prefetch, etc.)
- Linux artifacts (bash history, logs, etc.)
- Email forensics
- Timeline analysis

**Use Cases:**
- Tool validation (Autopsy, FTK, EnCase, X-Ways)
- File system research
- File carving algorithm testing
- Anti-forensics detection
- Data recovery techniques
- Cross-platform forensics

**Difficulty:** Beginner to Advanced

**Industry Relevance:** CRITICAL - Disk forensics is foundational

**Priority:** 
- NPS Test Images: CRITICAL (Phase 1) - Essential skill development
- CIRCL Exercises: HIGH (Phase 2) - Good practical challenges
- Real Data Corpus: N/A - Not available without IRB

---

## Category 3: Files / File Corpora

### Govdocs1 - Nearly 1 Million Government Files

**Description:** 1 million (now ~986,278 after removal of CA over-collection) freely redistributable files downloaded from .gov domains. Includes malware specimens found in mailing list archives.

| Delivery Method | Count | Size | URL |
|-----------------|-------|------|-----|
| **Individual directories** | 1000 dirs x 1000 files | ~250 GB | https://downloads.digitalcorpora.org/corpora/files/govdocs1/ |
| **ZIP files** | 1000 ZIPs x 1000 files | ~250 GB | https://downloads.digitalcorpora.org/corpora/files/govdocs1/zipfiles/ |
| **JPEG subset** | 109,282 images | ~20 GB | https://downloads.digitalcorpora.org/corpora/files/govdocs1/by_type/files.jpeg.tar |
| **Development subsets** | 10 subsets x 1000 files | ~2.5 GB | https://downloads.digitalcorpora.org/corpora/files/govdocs1/threads/ |

**Metadata Available:**
- Source URL for each file
- Download date/time
- MD5/SHA1 hashes
- Malware scan results (MetascanClientLog_201306281214.txt)

**File Types Include:**
- Office documents (DOC, XLS, PPT, PDF)
- Images (JPG, PNG, GIF, TIFF)
- Web formats (HTML, XML, CSS, JS)
- Archives (ZIP, TAR, RAR)
- Executables (EXE, DLL) - some contain malware
- Email formats (MSG, EML, MBOX)
- Database files
- Media files (AVI, MP3, etc.)

### SAFEDOCS Corpus (CC-MAIN-2021-31-PDF-UNTRUNCATED)

**Description:** Large-scale PDF corpus from Common Crawl for document security research

**Size:** ~500 GB (estimated)
**URL:** https://digitalcorpora.org/corpora/file-corpora/cc-main-2021-31-pdf-untruncated/

### UNSAFE-DOCS (CC-MAIN-2021-31-UNSAFE)

**Description:** Malformed/malicious PDF specimens

**Size:** ~50 GB (estimated)
**URL:** https://digitalcorpora.org/corpora/file-corpora/unsafe-docs-cc-main-2021-31-unsafe/

### Forensic Value

**Skills Taught:**
- File type identification (magic bytes vs extensions)
- Bulk file analysis
- Malware triage
- Document metadata extraction
- File carving validation
- Hash-based deduplication
- Whitelist/blacklist generation
- File signature analysis

**Use Cases:**
- File classification tool testing
- Bulk_extractor validation
- Malware detection algorithm training
- Document forensics
- File format research
- Hash database generation (NSRL-style)

**Difficulty:** Beginner to Intermediate

**Industry Relevance:** HIGH - File analysis is core to most investigations

**Priority:**
- Govdocs1 development subsets (10 x 1000 files): CRITICAL (Phase 1) - ~2.5 GB
- Govdocs1 JPEG subset: HIGH (Phase 2) - ~20 GB for image forensics
- Full Govdocs1: MEDIUM (Phase 3) - ~250 GB, useful but massive
- SAFEDOCS/UNSAFE-DOCS: LOW (Phase 3) - Specialized PDF security research

---

## Category 4: Network Packet Dumps

### Available Datasets

| Dataset | Description | Size | URL |
|---------|-------------|------|-----|
| **Nitroba Harassment** | Dorm room network capture (see Scenarios) | 53 MB | https://downloads.digitalcorpora.org/corpora/scenarios/nitroba/ |
| **M57-Patents Network** | Daily PCAPs from corporate scenario | ~2 GB | https://downloads.digitalcorpora.org/corpora/scenarios/ |
| **DEFCON 20 CTF** | 2000+ PCAPs from Capture The Flag | ~50 GB | https://downloads.digitalcorpora.org/corpora/packets/2012-defcon/ |
| **5 GB TCP Connection** | Single large TCP stream for reassembly testing | 5 GB | https://downloads.digitalcorpora.org/corpora/packets/5gb-tcp-connection.pcap.gz |

**External Reference:**
- MIT Lincoln Lab DARPA Intrusion Detection Dataset (not hosted by Digital Corpora)

### Forensic Value

**Skills Taught:**
- Packet analysis (Wireshark, tcpdump, tshark)
- Protocol analysis (HTTP, SMTP, FTP, DNS, etc.)
- Network timeline reconstruction
- TCP stream reassembly
- Traffic baselining
- Intrusion detection
- Malware network behavior analysis
- Data exfiltration detection

**Use Cases:**
- Network forensics training
- IDS/IPS testing
- Protocol analysis tool validation
- Malware C2 detection
- Data leakage investigations
- Network-based timeline analysis

**Difficulty:** Intermediate to Advanced

**Industry Relevance:** HIGH - Network forensics is essential for incident response

**Priority:**
- Nitroba PCAP: CRITICAL (Phase 1) - Small, focused, well-documented
- M57-Patents PCAPs: HIGH (Phase 2) - Part of comprehensive scenario
- 5 GB TCP Connection: MEDIUM (Phase 2) - Good for reassembly testing
- DEFCON CTF: LOW (Phase 3) - Large, specialized, CTF-focused

---

## Category 5: Scenarios (Cross-Domain)

Comprehensive multi-evidence scenarios with narratives and expected findings.

| Scenario | Year | Description | Components | Size | URL |
|----------|------|-------------|------------|------|-----|
| **Nitroba Harassment** | 2008 | University harassment via network | PCAP only | 53 MB | https://digitalcorpora.org/corpora/scenarios/nitroba-university-harassment-scenario/ |
| **M57-Jean** | 2009 | Corporate espionage - document exfiltration | 1 laptop disk image | ~3 GB | https://digitalcorpora.org/corpora/scenarios/m57-jean/ |
| **M57-Patents** | 2009 | Complex corporate IP theft | Multiple disks, daily network, memory | ~15 GB | https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/ |
| **NPS Language Drives** | 2011 | Foreign language file systems | USB drives | ~2 GB | https://digitalcorpora.org/corpora/scenarios/2011-nps-language-drives/ |
| **National Gallery DC Attack** | 2012 | Web server compromise | Server image, logs, network | ~5 GB | https://digitalcorpora.org/corpora/scenarios/national-gallery-dc-2012-attack/ |
| **Lone Wolf** | 2018 | Terrorism investigation | Disk, mobile, network | ~8 GB | https://digitalcorpora.org/corpora/scenarios/2018-lone-wolf-scenario/ |
| **Narcos** | 2019 | Drug trafficking | Mobile, disk | ~6 GB | https://digitalcorpora.org/corpora/scenarios/2019-narcos/ |
| **Owl** | 2019 | Complex multi-evidence | Disk, mobile, network | ~10 GB | https://digitalcorpora.org/corpora/scenarios/2019-owl/ |
| **Tuck** | 2019 | Investigation scenario | Mobile, disk | ~5 GB | https://digitalcorpora.org/corpora/scenarios/2019-tuck/ |

**Total Scenarios:** ~55 GB

**Solutions:** Available by request through https://digitalcorpora.org/corpora/scenarios/obtaining-solutions/

### Forensic Value

**Skills Taught:**
- End-to-end investigation workflow
- Multi-source correlation (disk + network + mobile)
- Timeline pivoting
- Hypothesis testing
- Report writing
- Evidence preservation
- Chain of custody
- Courtroom testimony preparation

**Use Cases:**
- Capstone projects
- SANS FOR500/FOR508 practice
- Team training exercises
- Tool capability comparison
- Academic research
- CTF preparation
- Expert witness training

**Difficulty:** Intermediate to Advanced

**Industry Relevance:** CRITICAL - Realistic scenarios mirror actual cases

**Priority:** CRITICAL (Phase 1)
- Nitroba: Start here (small, focused, solvable)
- M57-Jean: Core single-disk scenario
- M57-Patents: Comprehensive multi-evidence training
- 2012 National Gallery: Web compromise investigation
- Others: HIGH (Phase 2) - Modern, diverse scenarios

---

## Category 6: SQL / Database Forensics

### SQLite Forensic Corpus

**Description:** Collection of SQLite databases from various sources for parser testing and artifact recovery

**Size:** ~500 MB (estimated)
**URL:** https://digitalcorpora.org/corpora/sql/sqlite-forensic-corpus/

### Forensic Value

**Skills Taught:**
- SQLite parsing and analysis
- Database recovery (deleted records, WAL files, journals)
- Browser artifact recovery (Chrome, Firefox, Safari use SQLite)
- App data extraction (iOS/Android apps use SQLite)
- Transaction log analysis

**Use Cases:**
- Browser forensics
- Mobile app forensics
- Database recovery tool testing
- Artifact parsing validation

**Difficulty:** Intermediate

**Industry Relevance:** HIGH - SQLite is ubiquitous in modern systems

**Priority:** HIGH (Phase 2) - Essential for modern forensics

---

## Download Strategy & Organization

### Recommended Directory Structure

```
/home/jtomek/Code/sift_find_evil/
├── practice_images/
│   ├── mobile/
│   │   ├── android/
│   │   │   ├── android_10/
│   │   │   ├── android_11/
│   │   │   ├── android_12/
│   │   │   └── android_13/
│   │   ├── ios/
│   │   │   ├── ios_13_3_1/
│   │   │   └── ios_13_4_1/
│   │   └── legacy/
│   │       ├── nokia_6230/
│   │       └── sony_ericsson/
│   ├── disk_images/
│   │   ├── nps_test_images/
│   │   │   ├── canon2/
│   │   │   ├── casper-rw/
│   │   │   ├── hfsjtest1/
│   │   │   ├── ntfs1/
│   │   │   └── domexusers/
│   │   └── circl/
│   ├── files/
│   │   ├── govdocs1/
│   │   │   ├── subsets/  # 10 development threads
│   │   │   └── jpeg/     # JPEG subset
│   │   └── safedocs/     # If needed
│   ├── network/
│   │   ├── pcaps/
│   │   │   ├── 5gb_tcp/
│   │   │   └── defcon_ctf/  # If downloaded
│   │   └── scenarios/  # Linked from scenarios
│   ├── scenarios/
│   │   ├── nitroba/
│   │   ├── m57-jean/
│   │   ├── m57-patents/
│   │   ├── national_gallery_2012/
│   │   ├── lone_wolf_2018/
│   │   ├── narcos_2019/
│   │   ├── owl_2019/
│   │   └── tuck_2019/
│   └── sql/
│       └── sqlite_corpus/
└── analysis/
    └── real_examples/  # Existing structure
```

### Phased Download Plan

#### **Phase 1: Critical - Essential Training Foundation (~50 GB)**

**Priority:** Must-have for comprehensive DFIR training

**Mobile:**
- Android 10, 11, 12 (61 GB)
- iOS 13.3.1 and 13.4.1 (20 GB)

**Disk Images:**
- All NPS test images (24 GB)
- CIRCL wiped disk (1 GB)

**Scenarios:**
- Nitroba (53 MB)
- M57-Jean (3 GB)
- M57-Patents (15 GB)
- 2012 National Gallery (5 GB)

**Files:**
- Govdocs1 development subsets (2.5 GB)

**Network:**
- 5 GB TCP connection (5 GB)

**SQL:**
- SQLite corpus (500 MB)

**Phase 1 Total:** ~137 GB

#### **Phase 2: High - Important Skill Coverage (~80 GB)**

**Mobile:**
- Android 13 (40 GB)
- Android 8, 9 (9 GB)

**Scenarios:**
- Lone Wolf 2018 (8 GB)
- Narcos 2019 (6 GB)
- Owl 2019 (10 GB)
- Tuck 2019 (5 GB)
- NPS Language Drives (2 GB)

**Files:**
- Govdocs1 JPEG subset (20 GB)

**Phase 2 Total:** ~100 GB

#### **Phase 3: Medium - Nice to Have, Specialized (~200+ GB)**

**Mobile:**
- Android 7 (3 GB)
- Legacy Nokia/Sony Ericsson (560 MB)

**Files:**
- Full Govdocs1 (250 GB) - Only if needed for research
- SAFEDOCS corpus (~500 GB) - Only for PDF security research

**Network:**
- DEFCON 20 CTF (50 GB) - Only if doing CTF training

**Phase 3 Total:** ~300-800 GB (depending on selection)

### Total Storage Requirements

**Minimum (Phase 1):** ~140 GB  
**Recommended (Phase 1 + 2):** ~240 GB  
**Comprehensive (All Phases):** ~500-800 GB

---

## Download Scripts

### Phase 1 Critical Download Script

```bash
#!/usr/bin/env bash
# download-phase1-critical.sh
# Downloads essential DFIR training datasets (~140 GB)

set -euo pipefail

BASE_URL="https://downloads.digitalcorpora.org/corpora"
DEST_DIR="/home/jtomek/Code/sift_find_evil/practice_images"

mkdir -p "$DEST_DIR"/{mobile/{android,ios},disk_images/nps_test_images,scenarios,files/govdocs1/subsets,network/pcaps,sql}

echo "=== Phase 1: Critical Datasets ==="
echo "Total size: ~140 GB"
echo "This will take several hours depending on connection speed"
echo ""

# Mobile - Android
echo "[1/15] Downloading Android 10..."
wget -c "$BASE_URL/mobile/android_10.zip" -P "$DEST_DIR/mobile/android/"

echo "[2/15] Downloading Android 11..."
wget -c "$BASE_URL/mobile/android_11.zip" -P "$DEST_DIR/mobile/android/"

echo "[3/15] Downloading Android 12..."
wget -c "$BASE_URL/mobile/android_12.zip" -P "$DEST_DIR/mobile/android/"

# Mobile - iOS
echo "[4/15] Downloading iOS 13.3.1..."
wget -r -np -nH --cut-dirs=3 -R "index.html*" \
  "$BASE_URL/mobile/ios_13_3_1/" -P "$DEST_DIR/mobile/ios/ios_13_3_1/"

echo "[5/15] Downloading iOS 13.4.1..."
wget -r -np -nH --cut-dirs=3 -R "index.html*" \
  "$BASE_URL/mobile/ios_13_4_1/" -P "$DEST_DIR/mobile/ios/ios_13_4_1/"

# Disk Images - NPS
echo "[6/15] Downloading NPS test images..."
for img in canon2 casper-rw hfsjtest1 ntfs1 ubnist1 domexusers domexusers-redacted; do
  wget -r -np -nH --cut-dirs=3 -R "index.html*" \
    "$BASE_URL/drives/nps-2009-$img/" -P "$DEST_DIR/disk_images/nps_test_images/$img/"
done

# Scenarios
echo "[7/15] Downloading Nitroba scenario..."
wget -r -np -nH --cut-dirs=3 -R "index.html*" \
  "$BASE_URL/scenarios/nitroba/" -P "$DEST_DIR/scenarios/nitroba/"

echo "[8/15] Downloading M57-Jean scenario..."
wget -r -np -nH --cut-dirs=3 -R "index.html*" \
  "$BASE_URL/scenarios/2009-m57-jean/" -P "$DEST_DIR/scenarios/m57-jean/"

echo "[9/15] Downloading M57-Patents scenario..."
wget -r -np -nH --cut-dirs=3 -R "index.html*" \
  "$BASE_URL/scenarios/2009-m57-patents/" -P "$DEST_DIR/scenarios/m57-patents/"

echo "[10/15] Downloading National Gallery 2012 scenario..."
wget -r -np -nH --cut-dirs=3 -R "index.html*" \
  "$BASE_URL/scenarios/2012-ngdc/" -P "$DEST_DIR/scenarios/national_gallery_2012/"

# Files - Govdocs1 subsets
echo "[11/15] Downloading Govdocs1 development subsets..."
for i in {0..9}; do
  wget -c "$BASE_URL/files/govdocs1/threads/subset$i.zip" \
    -P "$DEST_DIR/files/govdocs1/subsets/"
done

# Network
echo "[12/15] Downloading 5 GB TCP connection..."
wget -c "$BASE_URL/packets/5gb-tcp-connection.pcap.gz" \
  -P "$DEST_DIR/network/pcaps/"

# SQL
echo "[13/15] Downloading SQLite forensic corpus..."
wget -r -np -nH --cut-dirs=3 -R "index.html*" \
  "$BASE_URL/sql/sqlite-forensic-corpus/" -P "$DEST_DIR/sql/sqlite_corpus/"

# CIRCL
echo "[14/15] Downloading CIRCL wiped disk..."
wget -r -np -nH --cut-dirs=3 -R "index.html*" \
  "$BASE_URL/drives/circl-2023-wiped/" -P "$DEST_DIR/disk_images/circl/"

# NPS emails
echo "[15/15] Downloading NPS emails test..."
wget -r -np -nH --cut-dirs=3 -R "index.html*" \
  "$BASE_URL/drives/nps-2010-emails/" -P "$DEST_DIR/disk_images/nps_test_images/emails/"

echo ""
echo "Phase 1 download complete!"
echo "Total downloaded to: $DEST_DIR"
echo ""
echo "Next steps:"
echo "1. Verify checksums (see *-md5.txt / *-sha1.txt files)"
echo "2. Extract archives as needed"
echo "3. Review scenario narratives at https://digitalcorpora.org/corpora/scenarios/"
echo "4. Run download-phase2-high.sh for additional datasets"
```

### Phase 2 High Priority Script

```bash
#!/usr/bin/env bash
# download-phase2-high.sh
# Downloads additional important DFIR training datasets (~100 GB)

set -euo pipefail

BASE_URL="https://downloads.digitalcorpora.org/corpora"
DEST_DIR="/home/jtomek/Code/sift_find_evil/practice_images"

echo "=== Phase 2: High Priority Datasets ==="
echo "Total size: ~100 GB"
echo ""

# Mobile - Android 13
echo "[1/10] Downloading Android 13..."
wget -r -np -nH --cut-dirs=3 -R "index.html*" \
  "$BASE_URL/mobile/android_13/" -P "$DEST_DIR/mobile/android/android_13/"

# Mobile - Android 8, 9
echo "[2/10] Downloading Android 8..."
wget -c "$BASE_URL/mobile/android_8.tar.gz" -P "$DEST_DIR/mobile/android/"

echo "[3/10] Downloading Android 9..."
wget -c "$BASE_URL/mobile/android_9.tar.gz" -P "$DEST_DIR/mobile/android/"

# Scenarios - 2018-2019
echo "[4/10] Downloading Lone Wolf 2018..."
wget -r -np -nH --cut-dirs=3 -R "index.html*" \
  "$BASE_URL/scenarios/2018-lone-wolf/" -P "$DEST_DIR/scenarios/lone_wolf_2018/"

echo "[5/10] Downloading Narcos 2019..."
wget -r -np -nH --cut-dirs=3 -R "index.html*" \
  "$BASE_URL/scenarios/2019-narcos/" -P "$DEST_DIR/scenarios/narcos_2019/"

echo "[6/10] Downloading Owl 2019..."
wget -r -np -nH --cut-dirs=3 -R "index.html*" \
  "$BASE_URL/scenarios/2019-owl/" -P "$DEST_DIR/scenarios/owl_2019/"

echo "[7/10] Downloading Tuck 2019..."
wget -r -np -nH --cut-dirs=3 -R "index.html*" \
  "$BASE_URL/scenarios/2019-tuck/" -P "$DEST_DIR/scenarios/tuck_2019/"

echo "[8/10] Downloading NPS Language Drives..."
wget -r -np -nH --cut-dirs=3 -R "index.html*" \
  "$BASE_URL/scenarios/2011-nps-language-drives/" -P "$DEST_DIR/scenarios/nps_language_2011/"

# Files - Govdocs1 JPEG subset
echo "[9/10] Downloading Govdocs1 JPEG subset..."
wget -c "$BASE_URL/files/govdocs1/by_type/files.jpeg.tar" \
  -P "$DEST_DIR/files/govdocs1/"

echo "[10/10] Phase 2 complete!"
```

### Phase 3 Selective Script

```bash
#!/usr/bin/env bash
# download-phase3-selective.sh
# Downloads specialized/large datasets on demand

set -euo pipefail

BASE_URL="https://downloads.digitalcorpora.org/corpora"
DEST_DIR="/home/jtomek/Code/sift_find_evil/practice_images"

echo "=== Phase 3: Selective Download ==="
echo "This script allows selective download of large/specialized datasets"
echo ""

PS3="Select dataset to download (or 0 to exit): "
options=(
  "Android 7 (~3 GB)"
  "Legacy Nokia/Sony Ericsson phones (~560 MB)"
  "Full Govdocs1 (WARNING: ~250 GB)"
  "DEFCON 20 CTF PCAPs (WARNING: ~50 GB)"
  "SAFEDOCS PDF corpus (WARNING: ~500 GB)"
  "Quit"
)

select opt in "${options[@]}"; do
  case $REPLY in
    1)
      echo "Downloading Android 7..."
      wget -c "$BASE_URL/mobile/android_7.tar.gz" -P "$DEST_DIR/mobile/android/"
      ;;
    2)
      echo "Downloading legacy mobile devices..."
      mkdir -p "$DEST_DIR/mobile/legacy"
      for device in Nokia_6230 SE_P800 SE_T68i SE_T630; do
        wget -c "$BASE_URL/mobile/$device.zip" -P "$DEST_DIR/mobile/legacy/"
      done
      ;;
    3)
      read -p "Full Govdocs1 is ~250 GB. Continue? (yes/no): " confirm
      if [[ "$confirm" == "yes" ]]; then
        echo "Downloading full Govdocs1..."
        wget -r -np -nH --cut-dirs=3 -R "index.html*" \
          "$BASE_URL/files/govdocs1/" -P "$DEST_DIR/files/govdocs1/full/"
      fi
      ;;
    4)
      read -p "DEFCON CTF is ~50 GB. Continue? (yes/no): " confirm
      if [[ "$confirm" == "yes" ]]; then
        echo "Downloading DEFCON 20 CTF..."
        wget -r -np -nH --cut-dirs=3 -R "index.html*" \
          "$BASE_URL/packets/2012-defcon/" -P "$DEST_DIR/network/pcaps/defcon_ctf/"
      fi
      ;;
    5)
      read -p "SAFEDOCS is ~500 GB. Continue? (yes/no): " confirm
      if [[ "$confirm" == "yes" ]]; then
        echo "Downloading SAFEDOCS..."
        wget -r -np -nH --cut-dirs=3 -R "index.html*" \
          "$BASE_URL/files/cc-main-2021-31-pdf-untruncated/" \
          -P "$DEST_DIR/files/safedocs/"
      fi
      ;;
    6)
      echo "Exiting."
      break
      ;;
    *)
      echo "Invalid option"
      ;;
  esac
done
```

### Verification Script

```bash
#!/usr/bin/env bash
# verify-downloads.sh
# Verifies checksums of downloaded files

set -euo pipefail

DEST_DIR="/home/jtomek/Code/sift_find_evil/practice_images"

echo "=== Verifying Downloads ==="
echo ""

# Find all *-md5.txt and *-sha1.txt files
find "$DEST_DIR" -type f \( -name "*-md5.txt" -o -name "*-sha1.txt" \) | while read hashfile; do
  hashtype=$(echo "$hashfile" | grep -o "md5\|sha1")
  dir=$(dirname "$hashfile")
  
  echo "Verifying in $dir using $hashtype..."
  cd "$dir"
  
  if [[ "$hashtype" == "md5" ]]; then
    md5sum -c "$(basename "$hashfile")" 2>&1 | grep -v "OK$" || echo "  All files OK"
  else
    sha1sum -c "$(basename "$hashfile")" 2>&1 | grep -v "OK$" || echo "  All files OK"
  fi
  
  echo ""
done

echo "Verification complete."
```

---

## Usage Guidelines

### Getting Started

1. **Start Small:** Begin with Nitroba scenario (53 MB) to validate your workflow
2. **Progress Logically:** Move to M57-Jean (single disk) before M57-Patents (complex)
3. **Validate Tools:** Use NPS test images to ensure your tools work correctly
4. **Document Findings:** Keep notes on each analysis for future reference

### Best Practices

- **Always verify checksums** after download
- **Keep original evidence pristine** - work on copies
- **Document your chain of custody** even in training
- **Use write-blockers** when appropriate
- **Practice report writing** for each scenario
- **Time yourself** on scenarios to improve efficiency

### Integration with SIFT Workstation

All datasets are compatible with SIFT Workstation tools:
- **Sleuth Kit** (fls, icat, mactime) for disk images
- **Autopsy** GUI for comprehensive analysis
- **bulk_extractor** for artifact extraction
- **Volatility** for memory forensics (M57-Patents has memory dumps)
- **Wireshark/tshark** for network analysis
- **EZ Tools** for Windows artifacts

### Scenario Solutions

Solutions are available by request:
https://digitalcorpora.org/corpora/scenarios/obtaining-solutions/

Request via email to corpus@digitalcorpora.org

---

## Citation

When using Digital Corpora in research or publications:

**Garfinkel, Farrell, Roussev and Dinolt,** *Bringing Science to Digital Forensics with Standardized Forensic Corpora*, **DFRWS 2009, Montreal, Canada**

PDF: https://www.simson.net/clips/academic/2009.DFRWS.Corpora.pdf

---

## Support & Community

- **Website:** https://digitalcorpora.org/
- **Contact:** corpus@digitalcorpora.org
- **S3 Info:** https://digitalcorpora.org/about-digitalcorpora/s3-information/
- **Terms of Use:** https://digitalcorpora.org/about-digitalcorpora/terms-of-use/
- **Hashes:** https://digitalcorpora.org/about-digitalcorpora/hashes/

---

## Change Log

**2026-04-17:** Initial comprehensive catalog created  
**2023-05-05:** CIRCL forensics exercises added  
**2022-12-24:** Android 13 image added  
**2022-09-06:** Android 11 and 12 images added  
**2022-07-24:** 19 new scenarios added  

---

## Next Steps

1. **Review this catalog** and prioritize datasets based on training goals
2. **Run Phase 1 download script** to acquire essential training data (~140 GB)
3. **Verify all downloads** using checksums
4. **Start with Nitroba** scenario for initial practice
5. **Progress through scenarios** in order of complexity
6. **Document findings** and maintain analysis notes
7. **Run Phase 2 script** when ready for additional datasets

---

**Document Maintained By:** DFIR Team  
**Last Updated:** 2026-04-17  
**Version:** 1.0
