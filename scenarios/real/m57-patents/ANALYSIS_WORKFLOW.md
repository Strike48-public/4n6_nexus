# M57 Patents - Analysis Workflow Guide

This guide provides a structured approach to analyzing the M57 Patents scenario evidence.

## Phase 1: Evidence Acquisition & Verification

### 1.1 Download Evidence
```bash
# Start with primary suspect
./download_all.sh jean

# Or download all if you have storage
./download_all.sh all
```

### 1.2 Verify Integrity
```bash
# Generate hash inventory
./verify_files.sh

# Compare with published hashes
cat file_hashes.txt
```

### 1.3 Document Chain of Custody
Create a case notebook documenting:
- Download date/time
- Source URLs
- Hash verification results
- Storage location
- Access controls

## Phase 2: Initial Triage

### 2.1 Mount Evidence (Read-Only)
```bash
# Create mount points
mkdir -p /mnt/ewf/jean
mkdir -p /mnt/evidence/jean

# Mount E01 image
ewfmount jean/nps-2008-jean.E01 /mnt/ewf/jean

# Mount filesystem (read-only)
mount -o ro,loop,show_sys_files,streams_interface=windows \
  /mnt/ewf/jean/ewf1 /mnt/evidence/jean
```

### 2.2 Quick Assessment
```bash
# Get filesystem info
fsstat /mnt/ewf/jean/ewf1

# List volume info
mmls /mnt/ewf/jean/ewf1

# Check filesystem layout
fls -r /mnt/ewf/jean/ewf1 | head -100
```

### 2.3 Identify Operating System
```bash
# Check for Windows artifacts
ls -la /mnt/evidence/jean/Windows/System32/config/

# Get OS version
cat /mnt/evidence/jean/Windows/System32/config/SOFTWARE | \
  grep -a "CurrentVersion"
```

## Phase 3: Timeline Generation

### 3.1 Create Super Timeline with Plaso
```bash
# Create output directory
mkdir -p analysis/timelines

# Run log2timeline (this takes time!)
log2timeline.py \
  --storage-file analysis/timelines/jean.plaso \
  /mnt/ewf/jean/ewf1

# Export to CSV
psort.py \
  -o l2tcsv \
  -w analysis/timelines/jean_timeline.csv \
  analysis/timelines/jean.plaso

# Filter to suspicious date range (Nov-Dec 2009)
psort.py \
  -o l2tcsv \
  -w analysis/timelines/jean_suspicious.csv \
  --date-filter "2009-11-01..2009-12-31" \
  analysis/timelines/jean.plaso
```

### 3.2 Generate File System Timeline
```bash
# Use mactime for filesystem timeline
fls -r -m / /mnt/ewf/jean/ewf1 > analysis/timelines/jean_bodyfile.txt

mactime -b analysis/timelines/jean_bodyfile.txt \
  -d -z UTC \
  > analysis/timelines/jean_mactime.csv
```

## Phase 4: Artifact Analysis

### 4.1 Registry Analysis
```bash
# Extract registry hives
mkdir -p analysis/registry

# Copy registry files
cp /mnt/evidence/jean/Windows/System32/config/SYSTEM \
   analysis/registry/SYSTEM
cp /mnt/evidence/jean/Windows/System32/config/SOFTWARE \
   analysis/registry/SOFTWARE
cp /mnt/evidence/jean/Windows/System32/config/SAM \
   analysis/registry/SAM

# Analyze with RegRipper
rip.pl -r analysis/registry/SYSTEM -p compname
rip.pl -r analysis/registry/SYSTEM -p timezone
rip.pl -r analysis/registry/SYSTEM -p usbstor
rip.pl -r analysis/registry/SYSTEM -p usbdevices
```

### 4.2 USB Device Analysis
```bash
# Check USB connection history
rip.pl -r analysis/registry/SYSTEM -p usbstor > analysis/usb_devices.txt

# Get USB device timestamps
rip.pl -r analysis/registry/SYSTEM -p usbdevices >> analysis/usb_devices.txt

# Analyze USB drive image separately
ewfmount jean/jean-usb-2009-12-11.E01 /mnt/ewf/jean-usb
fls -r /mnt/ewf/jean-usb/ewf1 > analysis/jean_usb_filelist.txt
```

### 4.3 Email Analysis
```bash
# Locate email stores
find /mnt/evidence/jean -name "*.pst" -o -name "*.ost"

# Extract with readpst (if Outlook)
mkdir -p analysis/email/jean
readpst -D -b -o analysis/email/jean /path/to/mailbox.pst

# Or analyze Thunderbird profile
find /mnt/evidence/jean -path "*Thunderbird*" -name "*.mbox"
```

### 4.4 Browser Forensics
```bash
# Internet Explorer
find /mnt/evidence/jean -name "index.dat"

# Chrome/Firefox
find /mnt/evidence/jean -name "History" -o -name "places.sqlite"

# Extract with bulk_extractor
bulk_extractor \
  -o analysis/bulk_extractor/jean \
  /mnt/ewf/jean/ewf1

# Check for URLs and emails
grep -a "http" analysis/bulk_extractor/jean/url.txt | head -50
```

### 4.5 File Metadata Analysis
```bash
# Find Office documents
fls -r /mnt/ewf/jean/ewf1 | grep -i "\.(doc|xls|ppt|pdf)$"

# Extract metadata from documents
exiftool /mnt/evidence/jean/Users/*/Documents/*.doc* \
  > analysis/document_metadata.txt
```

## Phase 5: Keyword Search & Data Recovery

### 5.1 Search for Keywords
```bash
# Create keyword list
cat > analysis/keywords.txt << EOF
patent
confidential
competitor
secret
salary
resign
theft
EOF

# Search with grep
grep -r -i -f analysis/keywords.txt /mnt/evidence/jean/ \
  > analysis/keyword_hits.txt

# Or use bulk_extractor
bulk_extractor -w analysis/keywords.txt \
  -o analysis/bulk_extractor/jean \
  /mnt/ewf/jean/ewf1
```

### 5.2 Recover Deleted Files
```bash
# Use tsk_recover
mkdir -p analysis/recovered
tsk_recover /mnt/ewf/jean/ewf1 analysis/recovered/

# Or use Autopsy for GUI-based recovery
```

### 5.3 Carve for Specific File Types
```bash
# Use scalpel or photorec
mkdir -p analysis/carved

scalpel /mnt/ewf/jean/ewf1 -o analysis/carved/
```

## Phase 6: Network Analysis

### 6.1 Analyze PCAP Files
```bash
# Get PCAP statistics
capinfos network/*.pcap

# Open in Wireshark for analysis
wireshark network/net-2009-11-*.pcap

# Extract HTTP traffic
tshark -r network/net-2009-11-*.pcap \
  -Y "http.request.method == GET or http.request.method == POST" \
  -T fields -e frame.time -e ip.src -e http.request.full_uri \
  > analysis/http_requests.txt

# Extract email traffic
tshark -r network/*.pcap -Y "smtp" > analysis/smtp_traffic.txt
```

### 6.2 Correlate Network with Timeline
```bash
# Extract network timeline
tshark -r network/*.pcap -T fields \
  -e frame.time -e ip.src -e ip.dst -e frame.protocols \
  > analysis/network_timeline.csv
```

## Phase 7: Memory Analysis (if available)

### 7.1 Analyze Memory Dump with Volatility
```bash
# Identify profile
vol.py -f memory/jean-mem.raw imageinfo

# List processes
vol.py -f memory/jean-mem.raw --profile=Win7SP1x64 pslist

# Check network connections
vol.py -f memory/jean-mem.raw --profile=Win7SP1x64 netscan

# Dump suspicious processes
vol.py -f memory/jean-mem.raw --profile=Win7SP1x64 \
  procdump -p PID -D analysis/memory/
```

## Phase 8: Cross-Correlation

### 8.1 Compare Evidence Across Users
```bash
# Create comparison matrix
# Compare file access times
# Match email communications
# Correlate USB usage
# Cross-reference network activity
```

### 8.2 Build Event Timeline
```bash
# Merge timelines from all sources
# 1. Filesystem timeline
# 2. Registry timestamps
# 3. Email timestamps
# 4. Browser history
# 5. Network captures
# 6. USB connections

# Use Timesketch or manual CSV merge
```

## Phase 9: Evidence Documentation

### 9.1 Screenshot Key Findings
```bash
# Document:
# - Incriminating emails
# - Suspicious file transfers
# - USB connection times
# - Unusual network activity
```

### 9.2 Export Evidence
```bash
# Export specific files with metadata
mkdir -p evidence_exports/

# Copy with timestamps preserved
cp -p /mnt/evidence/jean/path/to/important/file.doc \
  evidence_exports/
```

## Phase 10: Report Writing

### 10.1 Report Structure
1. Executive Summary
2. Case Information
3. Evidence Inventory
4. Analysis Methodology
5. Findings (with evidence references)
6. Timeline of Events
7. Conclusions
8. Recommendations
9. Appendices (technical details)

### 10.2 Key Questions to Answer
- Did IP theft occur?
- Who was responsible?
- What data was stolen?
- When did the theft occur?
- How was data exfiltrated?
- Was there external involvement?
- Is evidence admissible?

## Tools Quick Reference

### SANS SIFT Tools
```bash
# Mounting
ewfmount, mount

# Filesystem Analysis
fls, icat, ils, mmls, fsstat

# Timeline
log2timeline.py, psort.py, mactime

# Registry
rip.pl (RegRipper)

# Email
readpst

# Network
wireshark, tshark, tcpdump

# Memory
volatility

# Bulk Analysis
bulk_extractor

# Metadata
exiftool
```

### Useful Commands
```bash
# Calculate file hash
md5sum file.doc
sha256sum file.doc

# Find files by name
fls -r /path | grep -i "patent"

# Extract specific file by inode
icat /dev/loop0 12345 > extracted_file.doc

# Search for strings
strings file.dat | grep -i "secret"
```

## Investigation Checklist

- [ ] Evidence downloaded and verified
- [ ] Chain of custody documented
- [ ] Images mounted read-only
- [ ] Super timeline generated
- [ ] Registry analyzed (USB, timezone, computer name)
- [ ] USB devices identified
- [ ] Email extracted and reviewed
- [ ] Browser history analyzed
- [ ] Documents examined for metadata
- [ ] Deleted files recovered
- [ ] Network traffic correlated with disk timeline
- [ ] Keyword searches completed
- [ ] Cross-user correlation performed
- [ ] Findings documented with evidence references
- [ ] Timeline of suspicious activity created
- [ ] Report drafted
- [ ] Evidence properly stored

## Common Pitfalls

1. **Not using read-only mounts** - Always mount evidence read-only
2. **Forgetting timezones** - Document timezone and convert to UTC
3. **Missing deleted files** - Always run file carving
4. **Ignoring USB artifacts** - Check USBSTOR registry keys
5. **Not correlating evidence** - Cross-reference all evidence sources
6. **Poor documentation** - Screenshot and document everything
7. **Incomplete timeline** - Include all timestamp sources

## Additional Resources

- SANS FOR508 course materials
- Digital Forensics with Sleuth Kit book
- File System Forensic Analysis (Carrier)
- Network Forensics (Davidoff & Ham)
- NIST forensic guides

---

**Remember:** This is a comprehensive scenario. Take your time, document everything, and follow proper forensic procedures.
