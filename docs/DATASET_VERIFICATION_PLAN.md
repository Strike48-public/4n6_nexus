# Dataset Verification Plan

**Purpose**: Systematically test SIFT Find Evil against all available datasets to confirm detection capabilities and identify gaps.

**Status**: Phase 0 Complete (3/3 initial datasets)  
**Next**: Expand to complete M57 scenario and additional datasets

---

## Current Status

### Verified Datasets (3/3)

#### 1. M57 Jean Laptop ✅
**Location**: `scenarios/real/m57-jean/evidence/`  
**Size**: 2.9 GB  
**Files**: 
- nps-2008-jean.E01 (1.5 GB)
- nps-2008-jean.E02 (1.4 GB)

**Status**: ✅ **VERIFIED - PASSING**  
**Result**: Exfiltration detection with 0.95 confidence (2/2 files detected)  
**Analysis**: `analysis/m57-jean/`

**What Was Tested:**
- MFT parser (91,459 entries)
- PST parser (email artifacts)
- Exfiltration detector (file-email correlation)
- Self-correction engine (confidence scoring)

**Performance:**
- CSV-only mode: 4-6 seconds
- Full disk + PST mode: 4-25 minutes (depending on PST size)

**Attack Techniques Detected:**
- T1048.003 (Exfiltration over email)
- T1005 (Data from local system)

---

#### 2. Nitroba Harassment Investigation ✅
**Location**: `scenarios/real/nitroba/evidence/`  
**Size**: 54 MB  
**Files**: nitroba.pcap

**Status**: ✅ **VERIFIED - PASSING**  
**Result**: Harassment suspect identified with 0.95 confidence (Beth via Facebook auth)  
**Analysis**: `analysis/nitroba/`

**What Was Tested:**
- PCAP parser (tshark-based)
- HTTP session extraction
- SMTP email analysis
- Cookie-based authentication tracking

**Attack Techniques Detected:**
- T1071.001 (Web-based C2/investigation)
- Network forensics capability

---

#### 3. CIRCL Wiped Disk Challenge ✅
**Location**: `scenarios/circl-2023-wiped/`  
**Size**: 52 MB (sparse E01 for 8 GB disk)  
**Files**: wiped_disk.E01

**Status**: ✅ **VERIFIED - PASSING**  
**Result**: GPT analysis successful, 403 executables carved  
**Analysis**: `analysis/circl-2023-wiped/`

**What Was Tested:**
- E01 mounting
- GPT partition table analysis
- Signature-based file carving (40+ signatures)
- Sparse image handling

**Performance:**
- GPT analysis: <1 second
- File carving: Manual (photorec used)

**Gap Identified:**
- 60-90 minute manual triage of 403 carved executables
- No NSRL filtering (90% likely system DLLs)
- No YARA classification
- **Solution**: Phase 1 NSRL integration, Phase 2 YARA

---

## Available Datasets (Untested)

### M57 Patents - Additional Characters

#### Pat's Desktop ⏳
**Location**: Download to `scenarios/real/m57-patents/evidence/pat/`  
**Estimated Size**: ~4 GB  
**Status**: ⏳ **NOT DOWNLOADED**

**Expected Files:**
- nps-2009-pat.E01
- nps-2009-pat.E02
- pat-usb-2009-12-11.E01 (USB drive)

**Test Plan:**
1. Download via `scenarios/m57-patents/download_all.sh pat`
2. Mount E01 images
3. Extract MFT, Prefetch, Event Logs
4. Run sift-find-evil in CSV mode
5. Document findings vs. ground truth

**Expected Attack Vectors:**
- TBD (different from Jean exfiltration pattern?)
- Potential lateral movement evidence
- Email artifacts

---

#### Terry's Laptop ⏳
**Location**: Download to `scenarios/real/m57-patents/evidence/terry/`  
**Estimated Size**: ~4 GB  
**Status**: ⏳ **NOT DOWNLOADED**

**Expected Files:**
- nps-2009-terry.E01
- nps-2009-terry.E02
- terry-usb-2009-12-11.E01

**Test Plan:** (Same as Pat)

---

#### Charlie's Laptop ⏳
**Location**: Download to `scenarios/real/m57-patents/evidence/charlie/`  
**Estimated Size**: ~4 GB  
**Status**: ⏳ **NOT DOWNLOADED**

**Expected Files:**
- nps-2009-charlie.E01
- nps-2009-charlie.E02
- charlie-usb-2009-12-11.E01

**Test Plan:** (Same as Pat)

---

#### Jo's Laptop ⏳
**Location**: Download to `scenarios/real/m57-patents/evidence/jo/`  
**Estimated Size**: ~4 GB  
**Status**: ⏳ **NOT DOWNLOADED**

**Expected Files:**
- nps-2009-jo.E01
- nps-2009-jo.E02
- jo-usb-2009-12-11.E01

**Test Plan:** (Same as Pat)

---

### M57 Patents - Network Traffic ⏳

**Location**: Download to `scenarios/real/m57-patents/evidence/network/`  
**Estimated Size**: TBD (likely 1-5 GB)  
**Status**: ⏳ **NOT DOWNLOADED**

**Expected Files:**
- Network packet captures (PCAP format)
- Potential multi-host communication
- Lateral movement evidence

**Test Plan:**
1. Download network captures
2. Parse with PCAP parser
3. Look for multi-host patterns (lateral movement)
4. Correlate with disk forensics findings
5. Test cross-host attack chain reconstruction

**Expected Attack Vectors:**
- T1021 (Lateral movement)
- T1071 (C2 over network protocols)
- Multi-host exfiltration patterns

---

### M57 Patents - Memory Dumps ⏳

**Location**: Download to `scenarios/real/m57-patents/evidence/memory/`  
**Estimated Size**: 4-16 GB per dump (potentially 20-80 GB total)  
**Status**: ⏳ **NOT DOWNLOADED - CHECK AVAILABILITY**

**Expected Files:**
- Memory dumps for one or more M57 characters
- RAM snapshots (4-16 GB each)

**Test Plan:**
1. Verify memory dumps are available on Digital Corpora
2. Download if available
3. Test Volatility 3 integration (Phase 2)
4. Run windows.pslist, windows.netscan, windows.malfind
5. Correlate with disk forensics findings

**Expected Attack Vectors:**
- T1055 (Process injection)
- T1620 (Reflective DLL loading)
- In-memory cryptographic keys
- Hidden processes

**Storage Consideration:**
- 4 GB per character minimum
- 5 characters = 20 GB minimum
- Requires significant disk space

---

### Mobile Forensics Datasets ⏳

**Location**: `scenarios/reference/mobile/`  
**Size**: 50 GB (already present!)  
**Status**: ⏳ **PRESENT BUT NOT INVENTORIED**

**Test Plan:**
1. Inventory what's in `scenarios/reference/mobile/`
2. Identify file types (Android images? iOS backups? Call logs?)
3. Assess compatibility with current parsers
4. Determine if mobile forensics is in scope for SIFT competition
5. Consider deferring to Phase 6 (advanced detectors)

**Question**: Is mobile forensics in scope for SIFT competition?

---

## Dataset Download Strategy

### Phase 1 Preparation (This Session)
**Goal**: Verify what we have, plan downloads

1. ✅ Inventory scenarios/ contents
2. ⏳ Check M57 memory dump availability on Digital Corpora
3. ⏳ Inventory mobile/ directory (50 GB - what's in there?)
4. ⏳ Estimate total storage needed

### Phase 1 Downloads (As Needed)
**Goal**: Download datasets needed for Phase 1 testing

1. Download Pat (test registry artifacts on different system)
2. Skip Terry, Charlie, Jo until Phase 3 (lateral movement)
3. Skip network traffic until Phase 3
4. Skip memory dumps until Phase 2

**Rationale**: Focus on datasets that test Phase 1 capabilities (browser history, registry)

### Phase 2 Downloads
**Goal**: Memory forensics validation

1. Download M57 memory dumps (if available)
2. Test Volatility 3 integration on real data

### Phase 3 Downloads
**Goal**: Multi-host correlation

1. Download remaining M57 characters (Terry, Charlie, Jo)
2. Download M57 network traffic
3. Test lateral movement detection across multiple hosts

---

## External Datasets (Future)

### CTF Forensics Challenges

#### HackTheBox Forensics ⏳
**Status**: Account required  
**Challenges**:
- Reminiscent (Windows memory forensics)
- Obscured (Linux PCAP analysis)
- Keeper (credential theft)

**Test Plan:**
1. Create HackTheBox account
2. Download retired forensics challenges
3. Test against sift-find-evil
4. Document accuracy vs. known flags

---

#### PicoCTF Forensics ⏳
**Status**: Publicly available  
**Challenges**:
- Trivial Flag Transfer Protocol (TFTP)
- Wireshark doo dooo do doo (PCAP)
- Various disk forensics challenges

**Test Plan:**
1. Download PicoCTF forensics challenges
2. Test automated detection
3. Compare to manual analysis time
4. Document findings

---

### Malware Traffic Analysis ⏳

**Source**: https://malware-traffic-analysis.net  
**Status**: Publicly available  
**Dataset Size**: 50+ PCAP scenarios

**Scenarios Include:**
- Known malware families (Emotet, Trickbot, Cobalt Strike)
- C2 communication patterns
- Real-world attack traffic

**Test Plan (Phase 2 - YARA integration):**
1. Download 5-10 representative scenarios
2. Extract malware samples from PCAPs
3. Test YARA classification
4. Test network C2 detection
5. Validate malware family identification accuracy

---

## Testing Workflow Template

For each new dataset:

### 1. Pre-Analysis
```bash
# Verify file integrity
sha256sum <image_file> > <image_file>.sha256

# Document provenance
echo "Downloaded from: <URL>" > <image_file>.provenance
echo "Download date: $(date)" >> <image_file>.provenance

# Create analysis directory
mkdir -p analysis/<scenario_name>
cd analysis/<scenario_name>
```

### 2. Artifact Extraction
```bash
# Mount disk image (if E01)
sudo ewfmount <image_file>.E01 /mnt/ewf
sudo mount -o ro,loop /mnt/ewf/ewf1 /mnt/image

# Extract artifacts
python3 -m dotnet /opt/zimmermantools/MFTECmd.dll -f /mnt/image \
  --csv . --csvf mft.csv

python3 -m dotnet /opt/zimmermantools/PECmd.dll -d /mnt/image/Windows/Prefetch \
  --csv . --csvf prefetch.csv

python3 -m dotnet /opt/zimmermantools/EvtxECmd/EvtxECmd.dll \
  -d /mnt/image/Windows/System32/winevt/Logs \
  --csv . --csvf evtx.csv

# Browser history (Phase 1+)
# TBD based on implementation

# Registry (Phase 1+)
# TBD based on implementation
```

### 3. Analysis
```bash
# Run sift-find-evil
sift-find-evil detect-exfiltration \
  --mft mft.csv \
  --prefetch prefetch.csv \
  --evtx evtx.csv \
  --output findings.json

# Review findings
cat findings.json | python3 -m json.tool
```

### 4. Validation
```bash
# Compare to ground truth (if available)
# Document true positives / false positives / false negatives

# Calculate metrics
python3 -c "
import json
with open('findings.json') as f:
    findings = json.load(f)
print(f'Findings: {len(findings)}')
print(f'Average confidence: {sum(f[\"confidence\"] for f in findings) / len(findings) if findings else 0:.2f}')
"
```

### 5. Documentation
```bash
# Create analysis report
cat > ANALYSIS_REPORT.md <<EOF
# <Scenario Name> Analysis Report

**Date**: $(date +%Y-%m-%d)
**Dataset**: <dataset_description>
**Version**: sift-find-evil $(git describe --tags)

## Results
- Findings: <count>
- True Positives: <count>
- False Positives: <count>
- False Negatives: <count>
- Average Confidence: <score>

## Attack Techniques Detected
- T1XXX: <technique_name>

## Performance
- Analysis time: <seconds>

## Notes
<observations>
EOF
```

### 6. Cleanup
```bash
# Unmount
sudo umount /mnt/image
sudo umount /mnt/ewf

# Archive findings
tar -czf findings_$(date +%Y%m%d).tar.gz *.csv *.json ANALYSIS_REPORT.md
```

---

## Storage Management

### Current Usage
```bash
du -sh scenarios/*
```

**Output:**
- nitroba: 54 MB
- m57-patents: 2.9 GB
- mobile: 50 GB
- **Total**: ~53 GB

### Projected Storage Needs

**Phase 1:**
- Current: 53 GB
- Pat download: +4 GB
- **Total**: 57 GB

**Phase 2:**
- Memory dumps: +20-80 GB (if available)
- **Total**: 77-137 GB

**Phase 3:**
- Terry, Charlie, Jo: +12 GB
- Network traffic: +5 GB
- **Total**: 94-154 GB

**Storage Recommendation:**
- Minimum: 100 GB free
- Recommended: 200 GB free (room for external datasets)

### Cleanup Strategy
```bash
# Remove after analysis complete
rm -rf scenarios/real/m57-patents/<character>/

# Can always re-download via:
cd scenarios/m57-patents
./download_all.sh <character>
```

---

## Success Criteria

### Phase 1 Testing
- [ ] M57 Jean re-tested with browser history (Phase 1 feature)
- [ ] M57 Jean re-tested with registry analysis (Phase 1 feature)
- [ ] M57 Pat downloaded and tested
- [ ] CIRCL re-tested with NSRL filtering (<10 min triage)
- [ ] 5 new synthetic scenarios created and passing

### Phase 2 Testing
- [ ] CIRCL tested with YARA classification (instant malware ID)
- [ ] M57 memory dumps tested (if available)
- [ ] Process injection test scenario
- [ ] Hidden process test scenario
- [ ] Jump Lists/LNK parser validated

### Phase 3 Testing
- [ ] M57 network traffic tested (lateral movement)
- [ ] Multi-host attack chain reconstruction
- [ ] Terry, Charlie, Jo tested for completeness

### External Testing
- [ ] 3+ HackTheBox challenges tested
- [ ] 3+ PicoCTF challenges tested
- [ ] 5+ Malware Traffic Analysis scenarios tested

---

## Risk Mitigation

### Download Failures
**Risk**: Large file downloads interrupted  
**Mitigation**: Use `wget -c` for resumable downloads  
**Backup**: All files re-downloadable via scripts

### Storage Exhaustion
**Risk**: Run out of disk space mid-analysis  
**Mitigation**: Monitor `df -h` before downloads  
**Backup**: Delete processed datasets, re-download as needed

### Dataset Unavailability
**Risk**: M57 memory dumps not publicly available  
**Mitigation**: Test Volatility on known-good dumps (e.g., SANS DFIR challenges)  
**Backup**: Create synthetic memory dumps for testing

### Time Budget
**Risk**: Testing all datasets takes too long  
**Mitigation**: Prioritize by phase (Jean → Pat → others)  
**Backup**: Automated testing harness in Phase 4

---

## Questions for Investigation

1. **M57 Memory Dumps**: Are they available on Digital Corpora?
   - Check: https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/
   - If not: Find alternative memory forensics datasets

2. **Mobile Forensics**: What's in `scenarios/reference/mobile/` (50 GB)?
   - Inventory: `ls -lah scenarios/reference/mobile/`
   - Determine: Android? iOS? Call logs? Messages?
   - Decision: In scope for SIFT competition?

3. **SIFT Competition Scope**: What datasets are required?
   - Review competition documentation
   - Prioritize required datasets
   - Defer optional datasets to Phase 6

4. **Ground Truth**: Do we have expected findings for M57 characters?
   - Jean: Known exfiltration (verified)
   - Pat, Terry, Charlie, Jo: Unknown (research needed)
   - Network traffic: Unknown (multi-host analysis needed)

---

## Next Steps

### Immediate (This Session)
1. ✅ Document verification plan
2. ⏳ Check M57 memory dump availability
3. ⏳ Inventory mobile/ directory
4. ⏳ Commit verification plan

### Phase 1 Preparation
1. Download Pat's desktop (test Phase 1 features)
2. Re-test Jean with Phase 1 capabilities
3. Re-test CIRCL with NSRL

### Phase 2 Preparation
1. Download memory dumps (if available)
2. Download malware traffic analysis samples
3. Prepare YARA test corpus

---

**Last Updated**: 2026-04-19  
**Status**: Verification plan complete, ready for Phase 1 implementation
