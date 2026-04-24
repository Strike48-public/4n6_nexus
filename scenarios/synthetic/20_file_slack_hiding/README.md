# Scenario 20: File Slack Space Hiding

**Type:** Anti-forensics / Data hiding
**Difficulty:** High
**Attack Vector:** Attacker hides data in NTFS file slack space

## Scenario Description

An attacker hides malicious payloads and exfiltrated credentials in NTFS file slack space to evade detection. Slack space is the unused space between the logical end of a file and the physical end of the last cluster allocated to the file. This technique allows hiding data without creating new files or modifying file sizes visible in directory listings.

## Attack Timeline

1. **2024-04-28 10:00:00 UTC** - Attacker gains access to target system
2. **2024-04-28 10:05:00 UTC** - Attacker harvests credentials from browser storage
3. **2024-04-28 10:05:30 UTC** - Credentials encoded and prepared for hiding
4. **2024-04-28 10:06:00 UTC** - Legitimate file selected: `report.docx` (25 KB)
5. **2024-04-28 10:06:15 UTC** - Credential data (15 KB) written to slack space of `report.docx`
6. **2024-04-28 10:07:00 UTC** - Backdoor payload (40 KB) written to slack space of `system.dll`
7. **2024-04-28 10:08:00 UTC** - Attacker creates extraction script for later retrieval
8. **2024-04-28 10:10:00 UTC** - Original files appear unchanged in directory listings

## Evidence Artifacts

### Present (File Slack Indicators)
- **MFT Analysis:** File size vs allocated size mismatch
  - `report.docx`:
    - Logical size: 25,600 bytes (25 KB)
    - Allocated size: 40,960 bytes (40 KB)
    - Slack space: 15,360 bytes (15 KB) - contains hidden data
  - `system.dll`:
    - Logical size: 102,400 bytes (100 KB)
    - Allocated size: 143,360 bytes (140 KB)
    - Slack space: 40,960 bytes (40 KB) - contains backdoor
- **File Access Timestamps:** Files modified after initial creation
  - `report.docx` modified at 10:06:15 (no visible content change)
  - `system.dll` modified at 10:07:00 (no visible content change)
- **Raw Disk Analysis:** Non-zero data in slack space
  - Slack contains structured data (not random, not residual)
  - Base64 encoded credentials detected in `report.docx` slack
  - PE header signature detected in `system.dll` slack (backdoor executable)
- **User Activity:** File access by unusual process
  - `slack_writer.exe` accessed files (not standard Windows process)

### Absent (Stealth Characteristics)
- **No new files:** Attacker used existing files
- **Directory listings:** File sizes appear normal (only show logical size)
- **Standard forensic tools:** Many tools only examine logical file content, missing slack

## Expected Findings

### Finding 1: File Size vs Allocated Size Mismatch
```json
{
  "title": "File Slack Space Anomaly Detected",
  "severity": "medium",
  "confidence": 0.60,
  "evidence": {
    "files": [
      {
        "filename": "report.docx",
        "path": "C:\\Users\\analyst\\Documents\\report.docx",
        "logical_size": 25600,
        "allocated_size": 40960,
        "slack_size": 15360,
        "last_modified": "2024-04-28T10:06:15Z"
      },
      {
        "filename": "system.dll",
        "path": "C:\\Windows\\System32\\system.dll",
        "logical_size": 102400,
        "allocated_size": 143360,
        "slack_size": 40960,
        "last_modified": "2024-04-28T10:07:00Z"
      }
    ]
  },
  "contradictions": [
    {
      "type": "legitimate_slack_space",
      "description": "File slack space is a normal NTFS characteristic. Most files have some slack space due to cluster allocation."
    }
  ],
  "resolutions": [
    {
      "action": "confidence_reduced",
      "reasoning": "File slack space is inherent to NTFS filesystem design. Large slack space alone is not definitive evidence of data hiding.",
      "original_confidence": 0.75,
      "adjusted_confidence": 0.60
    }
  ]
}
```

### Finding 2: Non-Zero Data in File Slack Space
```json
{
  "title": "Active Data Found in File Slack Space",
  "severity": "high",
  "confidence": 0.85,
  "evidence": {
    "file": "report.docx",
    "slack_location": "Offset 25600-40960 (bytes)",
    "slack_content_type": "Base64 encoded text",
    "decoded_content": "Credentials: username=admin, password=P@ssw0rd123, domain=corp.local",
    "entropy": 5.8,
    "structured_data": true,
    "not_residual": true
  },
  "contradictions": [
    {
      "type": "intentional_data_hiding",
      "description": "Slack space contains structured, encoded data rather than random residual bytes"
    }
  ],
  "resolutions": [
    {
      "action": "confidence_maintained",
      "reasoning": "Non-zero structured data in slack space is highly unusual. Legitimate file operations do not write to slack space. This indicates intentional data hiding.",
      "original_confidence": 0.85,
      "adjusted_confidence": 0.85
    }
  ]
}
```

### Finding 3: Backdoor Executable Hidden in System File Slack
```json
{
  "title": "Malicious Payload Hidden in File Slack Space",
  "severity": "critical",
  "confidence": 0.95,
  "evidence": {
    "file": "system.dll",
    "slack_location": "Offset 102400-143360 (bytes)",
    "slack_content_type": "PE executable (backdoor)",
    "pe_header": "MZ signature detected",
    "malware_hash": "a1b2c3d4e5f6...",
    "malware_name": "TrojanBackdoor.Win32.Agent",
    "virustotal_detections": "45/70",
    "timeline_correlation": [
      {
        "time": "2024-04-28T10:05:00Z",
        "event": "Credentials harvested from browser"
      },
      {
        "time": "2024-04-28T10:06:15Z",
        "event": "Credentials hidden in report.docx slack"
      },
      {
        "time": "2024-04-28T10:07:00Z",
        "event": "Backdoor hidden in system.dll slack"
      }
    ]
  },
  "contradictions": [
    {
      "type": "malware_stealth_technique",
      "description": "Executable hidden in DLL file slack space for persistence and evasion"
    }
  ],
  "resolutions": [
    {
      "action": "confidence_increased",
      "reasoning": "Timeline correlation: credential theft → hiding in slack space → backdoor deployment. PE executable signature in slack space is definitive evidence of malware hiding. This is an advanced anti-forensics technique.",
      "original_confidence": 0.85,
      "adjusted_confidence": 0.95
    }
  ]
}
```

## Ground Truth

**True Positives:** 3
- File slack space was used for data hiding
- Credentials were hidden in slack space
- Backdoor executable was hidden in slack space

**False Positives:** 0
**False Negatives:** 0

**Expected Metrics:**
- Precision: 1.00
- Recall: 1.00
- F1 Score: 1.00

## Self-Correction Validation

**Contradiction Detection:**
- ✅ File slack space alone is normal NTFS behavior → Confidence reduced (0.75 → 0.60)
- ✅ Non-zero structured data in slack is suspicious → Confidence maintained (0.85)
- ✅ Timeline correlation: credential theft → slack hiding → backdoor → Confidence increased (0.85 → 0.95)

**Reasoning Quality:**
- Engine correctly identifies that file slack space is a normal NTFS characteristic
- Engine correctly identifies that structured data in slack is unusual
- Engine correctly identifies PE executable signature as definitive malware evidence
- Engine correctly correlates timeline to detect data hiding and malware deployment
- Confidence adjustments are proportional to evidence strength

## Detection Logic

### Detector: FileSlackHidingDetector

```python
def detect(self, artifacts: Dict) -> List[Finding]:
    findings = []
    
    # Parse MFT entries
    mft_entries = parse_mft(artifacts['mft'])
    
    # Check for file size vs allocated size mismatch
    for entry in mft_entries:
        logical_size = entry['data_size']
        allocated_size = entry['allocated_size']
        slack_size = allocated_size - logical_size
        
        # Only flag significant slack space (>10% of logical size or >10KB)
        if slack_size > max(logical_size * 0.1, 10240):
            finding = Finding(
                title="File Slack Space Anomaly Detected",
                confidence=0.75,
                evidence={
                    "filename": entry['filename'],
                    "logical_size": logical_size,
                    "allocated_size": allocated_size,
                    "slack_size": slack_size
                }
            )
            
            # Self-correction: Slack space is normal for NTFS
            contradiction = Contradiction(
                type="legitimate_slack_space",
                description="File slack space is a normal NTFS characteristic"
            )
            finding.contradictions.append(contradiction)
            finding.confidence = 0.60  # Reduced
            
            findings.append(finding)
    
    # Analyze slack space content
    for entry in mft_entries:
        slack_content = read_slack_space(entry)
        
        if slack_content and not is_zeros(slack_content):
            entropy = calculate_entropy(slack_content)
            
            # Check for structured data (high entropy or recognizable patterns)
            if entropy > 4.5 or has_structure(slack_content):
                finding = Finding(
                    title="Active Data Found in File Slack Space",
                    confidence=0.85,
                    evidence={
                        "file": entry['filename'],
                        "slack_content_type": identify_content_type(slack_content),
                        "entropy": entropy,
                        "structured_data": True
                    }
                )
                findings.append(finding)
    
    # Check for executable signatures in slack space
    for entry in mft_entries:
        slack_content = read_slack_space(entry)
        
        if has_pe_signature(slack_content):  # "MZ" header
            malware_hash = calculate_hash(slack_content)
            vt_result = check_virustotal(malware_hash)
            
            finding = Finding(
                title="Malicious Payload Hidden in File Slack Space",
                confidence=0.85,
                evidence={
                    "file": entry['filename'],
                    "slack_content_type": "PE executable (backdoor)",
                    "malware_hash": malware_hash,
                    "virustotal_detections": vt_result['detections']
                }
            )
            
            # Self-correction: Timeline correlation increases confidence
            timeline = build_timeline(artifacts)
            if timeline.matches_data_hiding_pattern():
                finding.confidence = 0.95  # Increased
            
            findings.append(finding)
    
    return findings
```

## Testing

### Run Scenario
```bash
cd /home/jtomek/Code/sift_find_evil
PYTHONPATH=. python3 tests/scenario_harness.py --scenario 20
```

### Expected Output
```
Scenario 20: File Slack Space Hiding
  True Positives: 3
  False Positives: 0
  False Negatives: 0
  Precision: 1.00
  Recall: 1.00
  F1 Score: 1.00
  Status: ✅ PASS
```

## References

- **File Slack Space Forensics:** https://www.sans.org/blog/file-slack-forensics/
- **NTFS Data Hiding:** https://www.sans.org/blog/ntfs-data-hiding/
- **Anti-Forensics Techniques:** SANS FOR508 Advanced Incident Response
- **File System Slack:** https://forensicswiki.xyz/wiki/index.php?title=File_Slack
- **MITRE ATT&CK:** T1564.004 (NTFS File Attributes)
