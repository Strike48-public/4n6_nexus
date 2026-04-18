# CFReDS Download Scripts - README

## Quick Start

### 1. Verify URLs Before Downloading

```bash
./scripts/verify-cfreds-urls.sh
```

This checks if CFReDS URLs are accessible and returning binary files (not HTML error pages).

### 2. Download Datasets

If verification passes:

```bash
./scripts/download-cfreds.sh
```

If verification fails:

1. See `docs/CFREDS_DOWNLOAD_GUIDE.md` for troubleshooting
2. Visit https://cfreds.nist.gov/ to find current URLs
3. Update URLs in `scripts/download-cfreds.sh`
4. Re-run verification

---

## Current Status (2026-04-17)

**URL Verification Result:** FAILING

The verification script is detecting that CFReDS URLs return HTML instead of binary files. This indicates NIST has changed the URL structure or file locations.

### What This Means

- Automated downloads will NOT work with current URLs
- Manual download from https://cfreds.nist.gov/ is required
- Script URLs need to be updated with current links

### Next Steps

1. **Manual Download Option**
   - Visit https://cfreds.nist.gov/ in browser
   - Navigate to dataset pages
   - Download files manually
   - Place in `/cases/cfreds/`

2. **Update Scripts Option**
   - Find current URLs on CFReDS site
   - Update `scripts/download-cfreds.sh` with new URLs
   - Test with verification script
   - Commit updated URLs to repository

---

## Scripts Overview

### verify-cfreds-urls.sh

**Purpose:** Pre-flight check before downloading

**What it checks:**
- HTTP status codes (200 OK vs 404/403/500)
- Content-Type headers (binary vs text/html)
- Response validity

**When to use:**
- Before running download script
- After updating URLs in download script
- When troubleshooting download failures

**Exit codes:**
- 0: All URLs accessible
- 1: One or more URLs failed

### download-cfreds.sh

**Purpose:** Automated download of CFReDS datasets

**Features:**
- URL verification before download
- Progress tracking
- SHA1 checksum verification
- File type validation
- Detailed error reporting

**Configuration:**
- Destination: `/cases/cfreds/` (default)
- Override: `CFREDS_DEST=/custom/path ./scripts/download-cfreds.sh`

**Datasets downloaded:**
1. Data Leakage Case (~600 MB)
2. Hacking Case - SCHARDT (~1.5 GB)
3. Memory Analysis (optional, commented out)

---

## Known Issues

### Issue: NIST URLs Change Periodically

**Symptom:** Downloads receive HTML error pages instead of files

**Root Cause:** NIST periodically updates:
- Server infrastructure
- S3 bucket structure
- CDN configuration
- Access policies

**Similar Issues:**
- NSRL downloads (see `analysis/real_examples/wiped_disk/EXECUTABLE_ANALYSIS_ADDENDUM.md`)
- Other NIST resources

**Solution:** Update script URLs from current CFReDS site

### Issue: Large File Downloads May Timeout

**Solution:** Scripts use `wget -c` for resume support

```bash
# If download interrupted, just re-run
./scripts/download-cfreds.sh
# wget will resume from where it left off
```

---

## Troubleshooting

### Problem: Verification script reports HTML responses

```bash
[WARN] Data Leakage Case: Returns HTML (likely error page)
```

**Solution:**
1. Visit https://cfreds.nist.gov/data_leakage_case/ in browser
2. Find the actual download link
3. Update URL in `download-cfreds.sh`:
   ```bash
   # Old (broken):
   "$CFREDS_BASE/data_leakage_case/data-leakage-case.dd.zip"
   
   # New (update with actual URL from site):
   "https://cfreds.nist.gov/<new-path>/data-leakage-case.dd.zip"
   ```

### Problem: 404 Not Found errors

**Cause:** File moved or removed from server

**Solution:**
1. Check if dataset still available on CFReDS site
2. Look for replacement or updated version
3. Check alternative sources (Digital Corpora, DFIR.training)

### Problem: 403 Forbidden errors

**Possible causes:**
- Access policy changed
- Rate limiting
- User-agent requirements

**Solutions:**
```bash
# Try with user-agent
wget --user-agent="Mozilla/5.0" <url>

# Try with delay between requests
wget --wait=5 --random-wait <url>
```

### Problem: Checksum verification fails

**Causes:**
- Corrupted download
- Checksum file has wrong format
- Checksum file references full paths

**Solution:**
```bash
# Fix checksum file with paths
sed 's|.*/||' original.sha1 > fixed.sha1
sha1sum -c fixed.sha1
```

---

## Directory Structure

After successful download:

```
/cases/cfreds/
├── data_leakage/
│   ├── data-leakage-case.dd.zip     (600 MB)
│   ├── data-leakage-case.sha1        (verified)
│   └── data-leakage-case.dd          (extract manually)
└── hacking_case/
    ├── SCHARDT.zip                   (1.5 GB)
    ├── SCHARDT.sha1                  (verified)
    └── SCHARDT.dd                    (extract manually)
```

---

## Manual Extraction

After download:

```bash
# Extract Data Leakage Case
cd /cases/cfreds/data_leakage
unzip data-leakage-case.dd.zip

# Extract Hacking Case
cd /cases/cfreds/hacking_case
unzip SCHARDT.zip

# Mount for analysis (read-only)
sudo mkdir -p /mnt/cfreds
sudo mount -o ro,loop /cases/cfreds/data_leakage/data-leakage-case.dd /mnt/cfreds
```

---

## Alternative Sources

If CFReDS downloads are problematic:

### Digital Corpora
- URL: https://downloads.digitalcorpora.org/
- Status: Active, modern datasets
- Automation: Excellent
- Coverage: Broader than CFReDS

### DFIR.training
- URL: https://www.dfir.training/
- Status: Active, regularly updated
- Automation: Manual (requires login)
- Coverage: Modern Windows 10/11

---

## Documentation

- **Comprehensive Guide:** `docs/CFREDS_DOWNLOAD_GUIDE.md`
- **Solution Summary:** `CFREDS_SOLUTION_SUMMARY.md`
- **Quick Reference:** `DOWNLOAD_PRIORITY_QUICK_REFERENCE.md`
- **Source Analysis:** `ADDITIONAL_SOURCES_RESEARCH.md`

---

## Contributing

If you successfully download CFReDS datasets and find that URLs have changed:

1. Update URLs in `scripts/download-cfreds.sh`
2. Test with verification script
3. Update this README with current status
4. Commit changes with note about URL update date
5. Submit PR or push to main branch

Include in commit message:
- Date of URL update
- Which URLs changed
- Verification test results

---

Last Updated: 2026-04-17
