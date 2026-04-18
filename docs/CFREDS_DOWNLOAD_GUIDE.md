# CFReDS Download Guide

**Last Updated:** 2026-04-17  
**Source:** https://cfreds.nist.gov/  
**Status:** Active (archive mode, no new datasets)

---

## Overview

CFReDS (Computer Forensics Reference Data Sets) is maintained by NIST and provides forensic reference datasets for tool validation and training. The site is in archive mode with no new additions since ~2015, but existing datasets remain available.

## Known Issue: URL Structure Changes

Like other NIST resources (NSRL), CFReDS download URLs may change due to:
- Server migrations
- CDN updates
- Access policy changes
- S3 bucket restructuring

**Symptom:** wget/curl downloads receive HTML error pages instead of actual files.

---

## Manual Download Process

### Step 1: Navigate to CFReDS Site

Visit: https://cfreds.nist.gov/

### Step 2: Browse Available Datasets

Common dataset categories:
- **Data Leakage Case:** `/data_leakage_case/`
- **Hacking Case:** `/Hacking_Case/`
- **USB Testing:** `/usb/`
- **Memory Analysis:** `/mem/`
- **Browser Artifacts:** `/browsers/`

### Step 3: Locate Direct Download Links

Each dataset page typically provides:
- Direct download link (ZIP or dd image)
- Checksum file (SHA1/MD5)
- Documentation/README

### Step 4: Download and Verify

```bash
# Example for Data Leakage Case
cd /cases/cfreds/data_leakage
wget <actual-download-url>
wget <actual-checksum-url>

# Verify integrity
sha1sum -c *.sha1
```

---

## Automated Download Approach

### Current Script Status

The script at `scripts/download-cfreds.sh` uses hardcoded URLs that may need updating.

### Verification Steps

Before running the automated script, verify URLs are current:

```bash
# Test URL accessibility
wget --spider "https://cfreds.nist.gov/data_leakage_case/data-leakage-case.dd.zip"

# Check response headers
curl -I "https://cfreds.nist.gov/data_leakage_case/data-leakage-case.dd.zip"
```

Expected response: `HTTP/1.1 200 OK` with `Content-Type: application/zip`

If you receive HTML content or 404/403 errors, URLs need updating.

---

## Priority Datasets

### 1. Data Leakage Case (CRITICAL)

**Scenario:** Sensitive document exfiltration  
**Size:** ~600 MB (compressed)  
**Format:** dd (raw disk image)

**Files:**
- `data-leakage-case.dd.zip`
- `data-leakage-case.sha1`

**Training Value:**
- File recovery techniques
- Deleted file analysis
- Anti-forensics detection
- Timeline analysis

### 2. Hacking Case - SCHARDT (HIGH)

**Scenario:** Linux system compromise with rootkit  
**Size:** ~1.5 GB (compressed)  
**Format:** dd (raw disk image)

**Files:**
- `SCHARDT.zip`
- `SCHARDT.sha1`

**Training Value:**
- Linux forensics
- Rootkit detection
- File system analysis
- Log correlation

### 3. Memory Analysis Images (MEDIUM)

**Purpose:** Volatility training and validation  
**Size:** 1-4 GB per image  
**Format:** Raw memory dumps

**OS Coverage:**
- Windows XP (dated but good for learning)
- Windows 7 (more relevant)

**Training Value:**
- Process analysis
- Memory artifact extraction
- Volatility plugin validation

---

## URL Update Procedure

If automated download fails:

### 1. Inspect Current Site Structure

```bash
# Use browser or curl to inspect site
curl -s "https://cfreds.nist.gov/" | grep -i "data_leakage\|hacking"
```

### 2. Find New Download URLs

Navigate to dataset pages and locate direct download links.

### 3. Update Script URLs

Edit `scripts/download-cfreds.sh` and update the `CFREDS_BASE` variable or individual URLs:

```bash
# Example updates
CFREDS_BASE="https://cfreds.nist.gov"

# Or update individual URLs if structure changed
DATA_LEAKAGE_URL="<new-url>/data-leakage-case.dd.zip"
HACKING_CASE_URL="<new-url>/SCHARDT.zip"
```

### 4. Test Updated Script

```bash
# Dry run with wget spider mode
wget --spider "$DATA_LEAKAGE_URL"

# If successful, run actual download
./scripts/download-cfreds.sh
```

---

## Alternative Sources

If CFReDS becomes unavailable:

### Digital Corpora
- More modern datasets
- Active maintenance
- URL: https://downloads.digitalcorpora.org/

### DFIR.training
- Contemporary scenarios
- Windows 10/11 focus
- Requires free registration
- URL: https://www.dfir.training/

### Local SANS Instructor Datasets
- Provided with FOR508/FOR500 courses
- Contact SANS instructors for access

---

## Storage Recommendations

**Destination:** `/cases/cfreds/`

**Directory Structure:**
```
/cases/cfreds/
├── data_leakage/
│   ├── data-leakage-case.dd.zip
│   ├── data-leakage-case.sha1
│   └── extracted/
├── hacking_case/
│   ├── SCHARDT.zip
│   ├── SCHARDT.sha1
│   └── extracted/
└── memory_dumps/
    └── (memory images)
```

**Total Space Required:** ~5-10 GB (compressed), ~15-20 GB (extracted)

---

## Checksum Verification

Always verify integrity after download:

```bash
# SHA1 verification
sha1sum -c *.sha1

# If checksum file lists full paths, extract just filename
sed 's|.*/||' original.sha1 > checksums.sha1
sha1sum -c checksums.sha1
```

Expected output: `<filename>: OK`

---

## Troubleshooting

### Issue: HTML Instead of Binary

**Symptom:** Downloaded file is small (~1-2 KB) and contains HTML error page

**Causes:**
- URL structure changed
- File moved to different location
- Access restrictions added

**Solution:**
1. Visit site in browser
2. Navigate to dataset page
3. Copy actual download link
4. Update script URLs

### Issue: 403 Forbidden

**Causes:**
- Server access policy changed
- User-Agent requirements
- Rate limiting

**Solutions:**
```bash
# Try with user-agent
wget --user-agent="Mozilla/5.0" <url>

# Try with retry delay
wget --wait=5 --random-wait <url>
```

### Issue: Slow Download Speed

**Solutions:**
```bash
# Resume interrupted downloads
wget -c <url>

# Use multiple connections (if supported)
aria2c -x 4 <url>
```

---

## Integration with Analysis Workflows

### Mount Disk Images

```bash
# Mount read-only
sudo mkdir -p /mnt/cfreds
sudo mount -o ro,loop /cases/cfreds/data_leakage/data-leakage-case.dd /mnt/cfreds

# When done
sudo umount /mnt/cfreds
```

### Run Analysis Tools

```bash
# Sleuth Kit analysis
fls -r /cases/cfreds/data_leakage/data-leakage-case.dd

# Generate timeline
fls -r -m / /cases/cfreds/data_leakage/data-leakage-case.dd > timeline.body
mactime -b timeline.body > timeline.csv
```

---

## References

- **CFReDS Homepage:** https://cfreds.nist.gov/
- **NIST Computer Forensics Resources:** https://www.nist.gov/itl/ssd/software-quality-group/computer-forensics-tool-testing-program-cftt
- **Sleuth Kit Documentation:** https://wiki.sleuthkit.org/
- **Project Dataset Guide:** `docs/DATASETS.md`
