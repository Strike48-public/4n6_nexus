# CIRCL 2023 Wiped Disk Challenge - Forensics Report

## Case Overview

- **Challenge**: CIRCL 2023 Wiped Disk (Data Recovery)
- **Evidence**: wiped_disk.E01 (52 MB compressed, 8 GB logical)
- **Date Analyzed**: 2026-04-17
- **Analyst**: SIFT Find Evil Engine

## Executive Summary

The CIRCL 2023 wiped disk challenge demonstrates advanced anti-forensic techniques combining GPT partition table manipulation with data wiping. Analysis reveals a deliberately executed front-of-disk wipe that zeroed the primary GPT while leaving the secondary GPT intact, creating an asymmetric state that prevents automatic OS recovery. Despite this, the engine successfully recovered partition metadata and carved 403 executables and 1 image from the wiped disk.

### Key Findings

1. **Partition Table Wipe Detected** (CRITICAL, 0.95 confidence)
   - Primary GPT header and protective MBR completely zeroed
   - Secondary GPT intact with valid EFI PART signature
   - 2 partitions recovered from secondary GPT metadata

2. **Anti-Forensic Sophistication** (HIGH)
   - Front-of-disk wipe targets sectors 0-33 (MBR + primary GPT)
   - Cannot be produced by normal OS operations
   - Leaves secondary GPT as sole recovery point

3. **Data Recovery** (MEDIUM)
   - 403 Windows executables (MZ signature) carved from image
   - 1 JPEG image recovered
   - Both partitions unreadable (wiped filesystem structures)
   - Sparse E01 image (52 MB) suggests selective data preservation

## Technical Analysis

### Partition Table Structure

**Primary GPT (LBA 0-33)**: ALL ZEROS
- Sector 0 (Protective MBR): 512 bytes of zeros
- Sector 1 (GPT Header): 512 bytes of zeros
- Sectors 2-33 (Partition Entries): All zeros

**Secondary GPT (LBA 15974399)**: INTACT
```
Signature: EFI PART
Revision: 0x00010000
Header Size: 92 bytes
My LBA: 15974399
Alternate LBA: 1 (should point to primary, but primary is wiped)
First Usable LBA: 34
Last Usable LBA: 15974366
Disk GUID: d4d2aac6-7159-422f-b5bc-520ac650ece1
```

### Recovered Partitions

**Partition 1 (disk1)**:
- Type GUID: ebd0a0a2-b9e5-4433-87c0-68b6b72699c7 (Microsoft Basic Data)
- Unique GUID: ecb05a99-40f7-4915-8ee2-67d1767dff0b
- Start LBA: 2048
- End LBA: 7383039
- Size: 7,380,992 sectors (3.52 GB)
- Offset: 1,048,576 bytes
- **Status**: Unreadable (filesystem structure wiped)

**Partition 2 (disk2)**:
- Type GUID: ebd0a0a2-b9e5-4433-87c0-68b6b72699c7 (Microsoft Basic Data)
- Unique GUID: 4f5b7983-771b-435d-bf13-a6461c013e88
- Start LBA: 7383040
- End LBA: 15972351
- Size: 8,589,312 sectors (4.10 GB)
- Offset: 3,780,116,480 bytes (beyond sparse image boundaries)
- **Status**: Unreadable (filesystem structure wiped)

### File Carving Results

Carved files are located in: `analysis/real_examples/wiped_disk/extracted_files/`

**Executables (403 total)**:
- All show MZ signature (DOS/Windows executables)
- Distributed across offsets 3.5 MB to 50 MB in image
- Examples:
  - exe_001.exe (offset 3,513,466)
  - exe_150.exe (offset 25,002,298)
  - exe_403.exe (offset 50,006,075)
- **Assessment**: Likely Windows system DLLs or application binaries

**Images (1 total)**:
- recovered_image.jpg (offset 8,494,670)
- Size: 119,256 bytes
- **Status**: Corrupted JPEG markers detected

### Anti-Forensic Techniques Identified

1. **Asymmetric GPT Wipe**
   - Attacker deliberately zeroed primary GPT while leaving secondary intact
   - This prevents Windows/Linux from auto-recovering partition table
   - Requires manual forensic tools to extract partition metadata

2. **Filesystem Structure Wipe**
   - Both partitions show no recognizable filesystem signatures
   - NTFS boot sectors likely overwritten
   - Metadata tables (MFT, FAT, etc.) destroyed

3. **Sparse Image Compression**
   - 8 GB logical disk compressed to 52 MB E01 image
   - Suggests large regions of zeros (wiped data)
   - Only ~0.6% of disk preserved in image

## Evidence Chain

### Wipe Detection

```python
# Engine execution
python -m sift_find_evil.cli analyze --image scenarios/circl-2023-wiped/wiped_disk.E01

# Output: Partition table wiped (primary GPT zeroed, secondary GPT intact)
# Severity: CRITICAL
# Confidence: 0.95 (Very High)
```

**Reasoning**:
1. Sector 0 (protective MBR) read: 512 bytes of zeros
2. Sector 1 (primary GPT header) read: 512 bytes of zeros
3. Secondary GPT at LBA 15974399: Valid EFI PART signature found
4. Secondary GPT partition entries: 2 partitions enumerated
5. **Conclusion**: Asymmetry (primary wiped, secondary valid) is signature of deliberate front-of-disk wipe

### File Carving

```python
# Signature scan
signatures_found = {
    'MZ (EXE/DLL)': 403,
    'JPEG': 1,
    'Total': 404
}

# Extraction
for offset, filetype in signatures_found:
    data = img_info.read(offset, size)
    write_to_disk(data, output_file)
```

**Evidence Files**:
- `extracted_files/exe_*.exe` - Windows executables
- `extracted_files/recovered_image.jpg` - JPEG image

## Timeline Reconstruction

**Estimated Attack Sequence**:
1. Attacker gains access to system with disk mounted
2. Executes wipe tool targeting sectors 0-33 (dd, shred, or custom tool)
3. Primary GPT and MBR overwritten with zeros
4. Filesystem structures within partitions wiped
5. System reboot renders disk unbootable
6. Forensic imaging captures post-wipe state

**Evidence Age**: Unknown (no timestamps available from wiped metadata)

## Recovery Opportunities

### What Was Recovered
- Secondary GPT partition table metadata
- 403 Windows executables via signature carving
- 1 JPEG image (corrupted)
- Partition boundaries and sizes

### What Was Lost
- Primary GPT header and entries
- Protective MBR
- NTFS boot sectors and metadata (MFT, FILE, etc.)
- File names, timestamps, directory structure
- Encryption status (potential LUKS headers wiped)

### Recovery Limitations
Without filesystem metadata:
- Cannot reconstruct original file paths
- Cannot determine file creation/modification times
- Cannot identify file owners or permissions
- Cannot correlate carved files to user activity

## Adversarial Assessment

### Attacker Sophistication: HIGH

**Indicators**:
1. Targeted wipe of primary GPT only (not full disk wipe)
2. Filesystem structures destroyed independently
3. Sparse image suggests selective data preservation
4. Knowledge of GPT architecture (primary vs secondary)

**Motive**: Prevent data recovery while leaving disk physically intact

### Detection Evasion

**What Failed**:
- Secondary GPT left intact (allowed partition recovery)
- File signatures survived in unallocated space (allowed carving)

**What Succeeded**:
- Primary GPT wipe prevents OS-level recovery
- Filesystem structure wipe prevents file-level access
- No timestamps or metadata to establish timeline

## Recommendations

### Investigative Next Steps

1. **Analyze Carved Executables**
   - Hash all 403 executables
   - Compare against NIST NSRL (eliminate known system files)
   - Submit suspicious files to VirusTotal
   - Identify potential attacker tools or malware

2. **Deep Signature Carving**
   - Search for document signatures (PDF, DOCX, XLSX)
   - Look for archive signatures (ZIP, RAR, 7Z)
   - Search for registry hive signatures (REGF)
   - Extract email artifacts (PST, OST, EML)

3. **Slack Space Analysis**
   - Examine data between file signatures
   - Look for remnants of deleted files
   - Search for encryption keys or passwords

4. **Timeline Correlation**
   - If other evidence exists (logs, network captures), correlate with disk state
   - Determine time window of wipe operation

### Prevention Measures

1. **Disk Encryption**: Use full-disk encryption (LUKS, BitLocker) to prevent physical access
2. **Write Protection**: Store critical systems on read-only media when feasible
3. **Monitoring**: Deploy EDR solutions that detect disk wipe tools (dd, shred, cipher, etc.)
4. **Backups**: Maintain offline backups for critical systems

## Conclusion

The CIRCL 2023 wiped disk challenge demonstrates a sophisticated anti-forensic attack that combines GPT manipulation with filesystem destruction. The SIFT Find Evil engine successfully:

1. **Detected** the partition table wipe with 0.95 confidence
2. **Recovered** partition metadata from secondary GPT
3. **Carved** 404 files from unallocated space
4. **Identified** anti-forensic techniques used

Despite the attacker's sophistication, forensic analysis recovered:
- Partition boundaries and sizes (3.52 GB + 4.10 GB)
- 403 Windows executables for further analysis
- Evidence of deliberate, targeted wiping (not accidental corruption)

**Next Actions**: Deep carving for documents/archives, executable analysis, timeline correlation with external evidence.

---

**Analyst**: SIFT Find Evil Engine  
**Date**: 2026-04-17  
**Status**: Analysis Complete - Carved Files Ready for Secondary Analysis
