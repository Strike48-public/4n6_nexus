# NSRL Integration Guide

**NSRL (National Software Reference Library)** provides hash sets for known-good software from legitimate commercial applications, operating systems, and tools maintained by NIST.

---

## Why NSRL?

When analyzing carved files from wiped disks, you recover EVERYTHING:

- Legitimate Windows system DLLs (kernel32.dll, user32.dll, etc.)
- Microsoft Office files (winword.exe, excel.exe, powerpnt.exe)
- Browser executables (chrome.exe, firefox.exe)
- Adobe Reader components
- **AND** potentially malicious files

**Problem:** 90%+ of carved files are legitimate system files. Manual triage of 400+ executables takes 60-90 minutes.

**Solution:** NSRL filtering identifies known-good files instantly, focusing investigation on unknowns.

---

## Performance Impact

**CIRCL Wiped Disk Case (real-world example):**

| Metric | Without NSRL | With NSRL | Improvement |
|--------|--------------|-----------|-------------|
| Carved executables | 403 | 403 | - |
| Manual triage required | 403 files | 35 files | 91% reduction |
| VirusTotal submissions | 403 hashes | 35 hashes | 91% reduction |
| Time to triage | 60-90 minutes | 5-10 minutes | 85% faster |

**Key benefit:** Reduces noise, speeds investigation, focuses on suspicious files.

---

## Installation

### Step 1: Download NSRL RDS

**Recommended: Modern RDS (2-3 GB download, 8-12 GB extracted)**

```bash
./scripts/download-nsrl.sh modern
```

**Alternative: Full RDS (5-10 GB download, 30-50 GB extracted)**

```bash
./scripts/download-nsrl.sh full
```

Download script will:
- Download from NIST S3 (https://s3.amazonaws.com/rds.nsrl.nist.gov)
- Verify SHA-256 checksum
- Extract ISO to `~/.sift_find_evil/nsrl/`
- Validate NSRLFile.txt exists

**Storage requirements:**

| RDS Type | Download Size | Extracted Size | RAM (in-memory) | Entries |
|----------|---------------|----------------|-----------------|---------|
| Modern | 2-3 GB | 8-12 GB | 2-3 GB | ~30-50 million |
| Full | 5-10 GB | 30-50 GB | 8-10 GB | ~150-200 million |

**Note:** Modern RDS includes recent Windows/Office/Adobe versions. Full RDS includes legacy software back to Windows 95.

### Step 2: Verify Installation

```bash
ls -lh ~/.sift_find_evil/nsrl/NSRLFile.txt
```

Expected output:
```
-rw-r--r-- 1 user user 8.5G Apr 18 12:00 /home/user/.sift_find_evil/nsrl/NSRLFile.txt
```

---

## Usage

### Basic Usage

```bash
# Analysis WITHOUT NSRL filtering (default)
sift-find-evil analyze --image disk.E01 --pst email.pst

# Analysis WITH NSRL filtering (filters known-good files)
sift-find-evil analyze --image disk.E01 --pst email.pst --use-nsrl
```

### Custom NSRL Location

```bash
# Specify custom NSRL database location
sift-find-evil analyze --image disk.E01 --use-nsrl /custom/path/NSRLFile.txt
```

### Example Output

**Without NSRL:**
```
[*] Carved 403 executables from disk image
[*] Analyzing all 403 files for malware/tools...
[*] Submitting 403 hashes to VirusTotal...
[!] Rate limit reached, waiting 60 seconds...
[*] Analysis time: 85 minutes
```

**With NSRL:**
```
[*] Using NSRL database for known-good filtering
[*] Carved 403 executables from disk image
[*] Filtered 368 known-good files (NSRL matches):
    - kernel32.dll (Windows System)
    - user32.dll (Windows System)
    - winword.exe (Microsoft Office)
    - chrome.exe (Google Chrome)
    - ...
[*] Analyzing 35 unknown executables for malware/tools...
[*] Submitting 35 hashes to VirusTotal...
[*] Analysis time: 8 minutes
```

---

## Python API

### Basic Usage

```python
from sift_find_evil.carving import NSRLFilter

# Initialize filter
nsrl_filter = NSRLFilter("~/.sift_find_evil/nsrl/NSRLFile.txt")

# Check single hash
if nsrl_filter.is_known_good("5d41402abc4b2a76b9719d911017c592", hash_type="sha1"):
    print("File is known-good (NSRL match)")
else:
    print("File is unknown (investigate)")
```

### Batch Filtering

```python
from sift_find_evil.carving import NSRLFilter

# Load database
nsrl_filter = NSRLFilter("~/.sift_find_evil/nsrl/NSRLFile.txt")
nsrl_filter.load()  # One-time load (30-60 seconds)

# Filter carved files
carved_files = [
    ("/carved/file1.exe", "abc123..."),
    ("/carved/file2.dll", "def456..."),
    # ... 400+ more files
]

known_good, unknown = nsrl_filter.filter_files(carved_files, hash_type="sha1")

print(f"Known-good: {len(known_good)} files")
print(f"Unknown: {len(unknown)} files (investigate these)")

# Process unknowns only
for file_path, file_hash in unknown:
    # Submit to VirusTotal, deep strings analysis, etc.
    analyze_suspicious_file(file_path, file_hash)
```

### Auto-Discovery

```python
from sift_find_evil.carving import find_nsrl_database

# Find NSRL in standard locations
nsrl_path = find_nsrl_database()

if nsrl_path:
    nsrl_filter = NSRLFilter(nsrl_path)
else:
    print("NSRL not found. Run: ./scripts/download-nsrl.sh modern")
```

---

## NSRL RDS Structure

NSRL provides multiple CSV files:

| File | Description | Usage |
|------|-------------|-------|
| NSRLFile.txt | Main hash database | Used by sift-find-evil |
| NSRLMfg.txt | Manufacturer information | Reference only |
| NSRLProd.txt | Product information | Reference only |
| NSRLOs.txt | Operating system information | Reference only |

**NSRLFile.txt format:**
```csv
"SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"
"5d41402abc4b2a76b9719d911017c592","7d793037a0760186574b0282f2f435e7","12345678","kernel32.dll","1024","1001","WindowsXP",""
```

**Supported hash types:**
- SHA-1 (primary index)
- MD5 (secondary index)
- CRC32 (not used by sift-find-evil)

**Note:** NSRL does not include SHA-256 in most datasets. If you have SHA-256 only, you must rehash files with SHA-1 or MD5.

---

## Performance Considerations

### Initial Load Time

First `load()` call parses NSRLFile.txt and builds in-memory hash sets:

| RDS Type | Load Time | RAM Usage |
|----------|-----------|-----------|
| Modern | 30-60 seconds | 2-3 GB |
| Full | 90-180 seconds | 8-10 GB |

**Optimization:** Load once at startup, reuse for entire analysis session.

### Lookup Performance

Once loaded, hash lookups are O(1):
- `is_known_good()`: <1 microsecond per hash
- 400 files: <0.5 milliseconds total

**Bottleneck:** Loading database, not lookups.

---

## Troubleshooting

### Error: NSRL database not found

```
FileNotFoundError: NSRL database not found: /home/user/.sift_find_evil/nsrl/NSRLFile.txt
Run: ./scripts/download-nsrl.sh modern
```

**Solution:** Download NSRL RDS:
```bash
./scripts/download-nsrl.sh modern
```

### Error: Invalid NSRL format

```
ValueError: Invalid NSRL format. Expected fields: {'SHA-1', 'MD5'}, found: ['InvalidHeader1', 'InvalidHeader2']
```

**Solution:** Re-download NSRL RDS (file may be corrupted):
```bash
rm -rf ~/.sift_find_evil/nsrl/
./scripts/download-nsrl.sh modern
```

### Warning: SHA-256 lookups not supported

```
WARNING: SHA-256 lookups not supported. NSRL uses SHA-1/MD5. Rehash file or provide SHA-1/MD5.
```

**Solution:** Rehash files with SHA-1:
```python
import hashlib

with open("/carved/file.exe", "rb") as f:
    sha1_hash = hashlib.sha1(f.read()).hexdigest()

if nsrl_filter.is_known_good(sha1_hash, hash_type="sha1"):
    print("Known-good")
```

### Out of Memory Error

```
MemoryError: Cannot allocate memory
```

**Solution:** Use Modern RDS instead of Full RDS, or increase system RAM.

---

## Advanced Usage

### Custom NSRL Location

Set environment variable for custom location:

```bash
export NSRL_DEST=/data/nsrl
./scripts/download-nsrl.sh modern
```

### Integration with File Carving

```python
from sift_find_evil.carving import NSRLFilter, detect_file_type
import hashlib

# Carve files from disk image
carved_files = carve_files_from_image("disk.E01")

# Hash all carved executables
exe_files = []
for file_path in carved_files:
    file_type = detect_file_type(open(file_path, "rb").read(512))
    if file_type and file_type.extension in ["exe", "dll"]:
        with open(file_path, "rb") as f:
            sha1_hash = hashlib.sha1(f.read()).hexdigest()
            exe_files.append((file_path, sha1_hash))

# Filter with NSRL
nsrl_filter = NSRLFilter("~/.sift_find_evil/nsrl/NSRLFile.txt")
known_good, unknown = nsrl_filter.filter_files(exe_files, hash_type="sha1")

print(f"Total: {len(exe_files)}, Known-good: {len(known_good)}, Unknown: {len(unknown)}")

# Investigate unknowns only
for file_path, file_hash in unknown:
    print(f"Investigate: {file_path} (SHA-1: {file_hash})")
```

---

## References

- **NIST NSRL Homepage:** https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl
- **NSRL Downloads:** https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl-download
- **NSRL FAQ:** https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/frequently-asked-questions

---

Last Updated: 2026-04-18
