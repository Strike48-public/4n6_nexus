# M57 Patents - Quick Start Guide

Get up and running with the M57 Patents scenario in 30 minutes.

## Step 1: Download Jean's Evidence (5-10 minutes)

Jean is the primary suspect. Start here:

```bash
./download_all.sh jean
```

This downloads:
- Jean's laptop disk image (nps-2008-jean.E01, .E02, .E03)
- Jean's USB drive (jean-usb-2009-12-11.E01)

**Total size:** ~4-5 GB

## Step 2: Verify Downloads (2 minutes)

```bash
./verify_files.sh
```

This calculates and displays MD5/SHA1/SHA256 hashes for integrity verification.

## Step 3: Mount the Evidence (2 minutes)

```bash
# Create mount points
sudo mkdir -p /mnt/ewf/jean /mnt/evidence/jean

# Mount E01 image (creates virtual raw disk)
sudo ewfmount jean/nps-2008-jean.E01 /mnt/ewf/jean

# Mount filesystem read-only
sudo mount -o ro,loop,show_sys_files,streams_interface=windows \
  /mnt/ewf/jean/ewf1 /mnt/evidence/jean
```

## Step 4: Quick Browse (5 minutes)

```bash
# Check OS version
ls -la /mnt/evidence/jean/Windows/System32/config/

# List user profiles
ls -la /mnt/evidence/jean/Users/

# Find documents
find /mnt/evidence/jean/Users -name "*.doc*" -o -name "*.pdf" | head -20

# Check browser history locations
find /mnt/evidence/jean -name "History" -o -name "places.sqlite" -o -name "index.dat"

# Look for email
find /mnt/evidence/jean -name "*.pst" -o -name "*.ost"
```

## Step 5: Run Autopsy (GUI Analysis)

```bash
# Launch Autopsy
autopsy &

# In Autopsy:
# 1. Create new case "M57-Jean"
# 2. Add data source: /mnt/ewf/jean/ewf1
# 3. Run ingest modules:
#    - Recent Activity
#    - Hash Lookup
#    - File Type Identification
#    - Keyword Search
#    - Email Parser
# 4. Wait for processing (10-30 minutes)
```

## Step 6: Initial Findings Checklist

While Autopsy runs, review these key questions:

### Timeline Questions
- [ ] When was the last system activity?
- [ ] What files were accessed in November-December 2009?
- [ ] Any unusual after-hours activity?

### USB Questions
- [ ] What USB devices were connected?
- [ ] When were they connected?
- [ ] What files were copied to/from USB?

### Email Questions
- [ ] What email client was used?
- [ ] Any communications with external parties?
- [ ] Keywords: "patent", "confidential", "competitor"

### Network Questions
- [ ] Web history - what sites were visited?
- [ ] Cloud storage usage (Dropbox, Gmail, etc.)?
- [ ] File upload activity?

### Document Questions
- [ ] What patent documents exist?
- [ ] Document metadata (author, created date, modified date)?
- [ ] Any encrypted files or archives?

## Step 7: Generate Timeline (15 minutes)

```bash
# Create analysis directory
mkdir -p analysis/timelines

# Quick filesystem timeline
sudo fls -r -m / /mnt/ewf/jean/ewf1 > analysis/timelines/bodyfile.txt

# Convert to readable format (filter to suspicious timeframe)
mactime -b analysis/timelines/bodyfile.txt -d -z UTC \
  | grep "2009-11\|2009-12" \
  > analysis/timelines/jean_nov_dec_2009.csv

# View in less
less analysis/timelines/jean_nov_dec_2009.csv
```

## Step 8: Search for Keywords (5 minutes)

```bash
# Create keyword list
cat > analysis/keywords.txt << EOF
patent
intellectual property
confidential
competitor
secret
salary
resign
quit
theft
steal
EOF

# Search mounted filesystem
sudo grep -r -i -f analysis/keywords.txt /mnt/evidence/jean/Users/ \
  2>/dev/null | head -50 > analysis/keyword_hits.txt

# Review findings
cat analysis/keyword_hits.txt
```

## Quick Wins - Where to Look First

### 1. Email
Location: `/mnt/evidence/jean/Users/[username]/AppData/Local/Microsoft/Outlook/`

Look for:
- Communications about patents
- External email addresses
- Resignation hints
- Financial discussions

### 2. Documents Folder
Location: `/mnt/evidence/jean/Users/[username]/Documents/`

Look for:
- Patent files
- Company confidential docs
- Personal resumes
- Competitor information

### 3. Downloads Folder
Location: `/mnt/evidence/jean/Users/[username]/Downloads/`

Look for:
- Recently downloaded files
- Archives (ZIP, RAR)
- Executable files

### 4. USB History
Check registry: `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`

Look for:
- Device serial numbers
- Connection timestamps
- Device names

### 5. Browser History
Locations vary by browser:
- IE: `index.dat` files
- Chrome: `History` database
- Firefox: `places.sqlite`

Look for:
- Webmail access
- Cloud storage sites
- Competitor websites
- Job search sites

## Common First Findings

Based on this scenario type, expect to find:

1. **Unusual USB activity** around incident dates
2. **Email communications** with external parties
3. **Large file transfers** to cloud storage or email
4. **After-hours access** to patent documents
5. **Browser history** showing competitor research or job searching
6. **Document metadata** revealing file copies or modifications
7. **Encrypted archives** prepared for exfiltration

## Next Steps After Quick Start

Once you have initial findings:

1. **Read SCENARIO_INFO.md** - Full scenario background
2. **Review ANALYSIS_WORKFLOW.md** - Comprehensive analysis guide
3. **Download other evidence** - Pat, Terry, Charlie, Jo
4. **Analyze network captures** - Correlate with disk timeline
5. **Generate super timeline** - Use log2timeline/Plaso
6. **Cross-correlate evidence** - Link activities across devices
7. **Document findings** - Build case report

## Troubleshooting

### Can't mount E01 image
```bash
# Check if ewfmount is installed
which ewfmount

# Install if needed (on SIFT)
sudo apt-get install ewf-tools

# Check mount
mount | grep ewf
```

### Permission denied errors
```bash
# Use sudo for mount operations
sudo ewfmount ...
sudo mount ...

# Or run analysis as root (not recommended)
```

### Autopsy crashes or hangs
```bash
# Increase Java heap size
export _JAVA_OPTIONS="-Xmx4g"

# Or analyze via command line tools
# (fls, icat, bulk_extractor, etc.)
```

### Can't find evidence
```bash
# Verify download completed
ls -lh jean/

# Check all segments downloaded
ls -lh jean/*.E0*

# Verify mount worked
ls /mnt/ewf/jean/
ls /mnt/evidence/jean/
```

## Time Estimates

- **Quick browse:** 30 minutes
- **Autopsy ingest:** 1-2 hours
- **Initial findings:** 2-3 hours
- **Comprehensive analysis:** 10-20 hours
- **Full scenario (all users):** 40+ hours

## Getting Help

- **Tool issues:** SANS SIFT documentation
- **Scenario questions:** Digital Corpora forums
- **Forensic techniques:** SANS FOR508 materials

---

**Ready to begin? Run: `./download_all.sh jean`**
