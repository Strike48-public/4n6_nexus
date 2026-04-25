# Quick Start: APT Attack Analysis

**Goal:** Analyze the DMZ FTP server first (most likely initial compromise point).

---

## Prerequisites

```bash
# Install ewftools if not present
sudo apt-get install -y ewf-tools

# Verify installed
ewfinfo --version
mmls --version

# Ensure virtual environment active
cd ~/Code/sift_find_evil
source venv/bin/activate
```

---

## Option 1: Analyze DMZ FTP Server Only (15 minutes)

**Recommended for initial testing.**

```bash
# Navigate to scenario
cd scenarios/real/apt_attack_2015/

# Set paths
EVIDENCE="/media/jtomek/TESLADRIVE/sift_evidence/compromised_apt_attack/SRL-2015-Compromised_Enterprise_Network"
IMAGE="$EVIDENCE/dmz-ftp-cdrive.E01"
OUTPUT="/cases/apt_attack_2015/dmz_ftp"

# Create mount points
sudo mkdir -p /mnt/apt_ewf /mnt/apt_ntfs

# Mount E01 image
sudo ewfmount "$IMAGE" /mnt/apt_ewf

# Find partition offset
sudo mmls /mnt/apt_ewf/ewf1

# Example output:
#      Slot      Start        End          Length       Description
# 000:  Meta      0000000000   0000000000   0000000001   Safety Table
# ...
# 007:  003       0001259520   0062912511   0061652992   Basic data partition ← This one

# Calculate offset (replace 0001259520 with your actual offset)
OFFSET_SECTORS=0001259520
OFFSET_BYTES=$((OFFSET_SECTORS * 512))

# Mount NTFS partition
sudo mount -o ro,loop,offset=$OFFSET_BYTES /mnt/apt_ewf/ewf1 /mnt/apt_ntfs

# Verify MFT exists
ls -lh /mnt/apt_ntfs/\$MFT

# Run analysis
mkdir -p "$OUTPUT"
python -m sift_find_evil.cli_mcp analyze-live \
  --case-id apt_dmz_ftp \
  --mft-file /mnt/apt_ntfs/\$MFT \
  --output-dir "$OUTPUT" \
  --timeout 900

# View results
cat "$OUTPUT/findings.json" | jq '. | length'
cat "$OUTPUT/findings.json" | jq '.[0]'

# Cleanup (when done)
sudo umount /mnt/apt_ntfs
sudo umount /mnt/apt_ewf
```

---

## Option 2: Analyze All 7 Systems (2-3 hours)

**Use automated script.**

```bash
cd scenarios/real/apt_attack_2015/
./analyze_all_systems.sh
```

This will:
1. Mount each E01 image automatically
2. Extract MFT and run detection engine
3. Save findings to `/cases/apt_attack_2015/<system_name>/`
4. Generate summary report
5. Unmount images when done

**Analysis order (prioritized):**
1. dmz_ftp (initial compromise)
2. workstation_01 (lateral movement)
3. domain_controller (privilege escalation)
4. file_server (data exfiltration)
5. rd_01, rd_02 (persistence)
6. workstation_05 (additional lateral movement)

---

## Option 3: Manual Step-by-Step (Learning Mode)

**Mount first system:**

```bash
# 1. Mount E01
sudo ewfmount /media/jtomek/TESLADRIVE/sift_evidence/compromised_apt_attack/SRL-2015-Compromised_Enterprise_Network/dmz-ftp-cdrive.E01 /mnt/apt_ewf

# 2. Check partitions
sudo mmls /mnt/apt_ewf/ewf1

# 3. Mount NTFS (replace OFFSET with actual value from step 2)
sudo mount -o ro,loop,offset=$((OFFSET * 512)) /mnt/apt_ewf/ewf1 /mnt/apt_ntfs

# 4. Explore filesystem
ls -la /mnt/apt_ntfs/
ls -la /mnt/apt_ntfs/Users/
ls -la /mnt/apt_ntfs/Windows/System32/

# 5. Run analysis
python -m sift_find_evil.cli_mcp analyze-live \
  --case-id apt_dmz_ftp \
  --mft-file /mnt/apt_ntfs/\$MFT \
  --output-dir /cases/apt_attack_2015/dmz_ftp \
  --timeout 900
```

---

## Expected Findings

### DMZ FTP Server (Initial Compromise)

**Look for:**
- Web shells or backdoors in FTP root directory
- Unusual executable files in system directories
- Credential dumping tools (Mimikatz, procdump)
- Network reconnaissance tools (nmap, netcat)
- Timestomping evidence (MFT timestamp mismatches)
- Missing Prefetch files for suspicious executables
- Event log clearing (System.evtx missing entries)

**Self-correction examples:**
- Legitimate FTP uploads flagged but downgraded confidence (normal business activity)
- Administrative tools used at unusual times (confidence adjusted based on user context)
- Network connections to internal IPs (legitimate vs. lateral movement)

---

## Troubleshooting

### Error: "ewfmount: command not found"

```bash
sudo apt-get update
sudo apt-get install -y ewf-tools
```

### Error: "mmls: command not found"

```bash
sudo apt-get install -y sleuthkit
```

### Error: "$MFT not found"

Check that you mounted the correct partition:
```bash
# List all partitions
sudo mmls /mnt/apt_ewf/ewf1

# Try mounting different partitions
# Usually the largest NTFS partition (003 or 007)
```

### Error: "Permission denied"

All mount operations require sudo:
```bash
sudo ewfmount ...
sudo mount ...
sudo umount ...
```

### Error: "Analysis timeout"

Increase timeout for large images:
```bash
python -m sift_find_evil.cli_mcp analyze-live \
  ... \
  --timeout 1800  # 30 minutes
```

---

## Next Steps After Analysis

### 1. Review Findings

```bash
# Count findings
cat /cases/apt_attack_2015/dmz_ftp/findings.json | jq '. | length'

# Show high-confidence findings
cat /cases/apt_attack_2015/dmz_ftp/findings.json | jq '.[] | select(.confidence > 0.80)'

# Show self-correction examples
cat /cases/apt_attack_2015/dmz_ftp/findings.json | jq '.[] | select(.contradictions | length > 0)'
```

### 2. Generate Report

```bash
python -m sift_find_evil.reporting.single_system_report \
  --input /cases/apt_attack_2015/dmz_ftp/findings.json \
  --output /cases/apt_attack_2015/dmz_ftp/report.md
```

### 3. Update Documentation

Add results to:
- `docs/ACCURACY_REPORT.md` - Add row for DMZ FTP system
- `docs/PERFORMANCE_BENCHMARK.md` - Add timing and throughput metrics
- `scenarios/real/apt_attack_2015/FINDINGS.md` - Document specific findings

### 4. Continue with Next System

```bash
# Analyze workstation next (lateral movement target)
# Follow same mount/analyze/unmount process
```

---

## Performance Benchmarking

Track these metrics:

```bash
# Start timer
START=$(date +%s)

# Run analysis
python -m sift_find_evil.cli_mcp analyze-live ...

# End timer
END=$(date +%s)
DURATION=$((END - START))
echo "Analysis took $DURATION seconds ($((DURATION / 60)) minutes)"

# Check memory usage (run in separate terminal during analysis)
watch -n 5 'ps aux | grep python | grep -v grep'
```

**Target metrics:**
- Time: < 15 minutes per system
- Memory: < 8 GB peak
- MFT entries/second: > 10,000
- Findings: F1 >= 0.90

---

## Evidence Details

**DMZ FTP Server:**
- Filename: `dmz-ftp-cdrive.E01`
- Size: 12 GB
- Role: External-facing FTP server
- IP: Likely 10.3.58.x (DMZ subnet)
- OS: Unknown (likely Windows Server 2008/2012)

**Why start here:**
- Most likely initial compromise point
- External-facing service (higher attack surface)
- DMZ placement (bridge between internet and internal network)
- Smallest image (faster analysis for initial testing)

---

## Success Criteria

You've successfully analyzed the DMZ FTP server if:

- ✓ Findings JSON generated with > 0 results
- ✓ Audit log shows MFTECmd execution
- ✓ Self-correction instances detected (contradictions array)
- ✓ High-confidence findings (> 0.80) are actionable
- ✓ Low-confidence findings (< 0.50) are suppressed
- ✓ Analysis completed in < 15 minutes
- ✓ No false positives on legitimate FTP activity

---

## Quick Reference Commands

```bash
# Mount
sudo ewfmount IMAGE.E01 /mnt/apt_ewf
sudo mmls /mnt/apt_ewf/ewf1
sudo mount -o ro,loop,offset=$((OFFSET * 512)) /mnt/apt_ewf/ewf1 /mnt/apt_ntfs

# Analyze
python -m sift_find_evil.cli_mcp analyze-live \
  --case-id apt_dmz_ftp \
  --mft-file /mnt/apt_ntfs/\$MFT \
  --output-dir /cases/apt_attack_2015/dmz_ftp \
  --timeout 900

# Review
cat /cases/apt_attack_2015/dmz_ftp/findings.json | jq '. | length'
cat /cases/apt_attack_2015/dmz_ftp/findings.json | jq '.[0]'

# Unmount
sudo umount /mnt/apt_ntfs
sudo umount /mnt/apt_ewf
```

---

Good luck with the analysis!
