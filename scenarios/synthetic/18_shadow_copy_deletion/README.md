# Scenario 18: Shadow Copy Deletion (Anti-forensics)

**Type:** Anti-forensics
**Difficulty:** Medium
**Attack Vector:** Ransomware deletes Volume Shadow Copies to prevent recovery

## Scenario Description

Ransomware payload deletes all Volume Shadow Copies (VSS snapshots) before encrypting files to prevent victims from recovering data without paying the ransom. This is a common ransomware technique to maximize damage and force payment.

## Attack Timeline

1. **2024-04-26 03:00:00 UTC** - Ransomware payload dropped (via email attachment)
2. **2024-04-26 03:00:15 UTC** - Ransomware executed by user
3. **2024-04-26 03:00:30 UTC** - Ransomware disables Windows Defender (via registry)
4. **2024-04-26 03:00:45 UTC** - Shadow copy deletion begins
5. **2024-04-26 03:00:46 UTC** - `vssadmin.exe delete shadows /all /quiet` executed
6. **2024-04-26 03:00:48 UTC** - `wmic.exe shadowcopy delete` executed (backup method)
7. **2024-04-26 03:00:50 UTC** - All shadow copies deleted (Volume Shadow Copy Service logs deletion)
8. **2024-04-26 03:01:00 UTC** - File encryption begins (mass file modifications)
9. **2024-04-26 03:15:00 UTC** - Encryption complete (14 minutes, 48,392 files encrypted)
10. **2024-04-26 03:15:30 UTC** - Ransom note dropped: `README_DECRYPT.txt`

## Evidence Artifacts

### Present (Anti-forensics Indicators)
- **Prefetch:** `VSSADMIN.EXE-[HASH].pf` shows execution at 03:00:46
- **Prefetch:** `WMIC.EXE-[HASH].pf` shows execution at 03:00:48
- **Event Log 8222:** Volume Shadow Copy deleted (Event ID 8222)
  - All shadow copies deleted at 03:00:50
  - Deleted by: ransomware process (non-system process)
- **Event Log 4688:** Process creation events
  - `vssadmin.exe` spawned by `ransomware.exe`
  - `wmic.exe` spawned by `ransomware.exe`
- **Command Line Arguments:** Captured in Sysmon logs
  - `vssadmin.exe delete shadows /all /quiet`
  - `wmic.exe shadowcopy delete`
- **Registry:** Windows Defender disabled (tamper protection bypassed)
- **MFT Records:** Mass file modifications starting at 03:01:00 (48,392 files)
- **File Extensions:** `.locked` appended to encrypted files

### Absent (Deleted by Ransomware)
- **Volume Shadow Copies:** All VSS snapshots deleted
- **System Restore Points:** Deleted by ransomware

## Expected Findings

### Finding 1: Volume Shadow Copies Deleted
```json
{
  "title": "All Volume Shadow Copies Deleted",
  "severity": "high",
  "confidence": 0.75,
  "evidence": {
    "deletion_time": "2024-04-26T03:00:50Z",
    "deleted_by_process": "ransomware.exe",
    "deleted_by_user": "SYSTEM",
    "shadow_copies_before": 5,
    "shadow_copies_after": 0,
    "command_executed": "vssadmin.exe delete shadows /all /quiet"
  },
  "contradictions": [
    {
      "type": "legitimate_admin_task",
      "description": "System administrators occasionally delete shadow copies to free disk space or troubleshoot storage issues"
    }
  ],
  "resolutions": [
    {
      "action": "confidence_reduced",
      "reasoning": "Shadow copy deletion can be legitimate maintenance. Cannot definitively prove malicious intent without additional context.",
      "original_confidence": 0.90,
      "adjusted_confidence": 0.75
    }
  ]
}
```

### Finding 2: Shadow Copy Deletion Executed by Non-System Process
```json
{
  "title": "Shadow Copies Deleted by Suspicious Process",
  "severity": "high",
  "confidence": 0.90,
  "evidence": {
    "parent_process": "ransomware.exe",
    "parent_process_path": "C:\\Users\\victim\\AppData\\Local\\Temp\\ransomware.exe",
    "child_processes": [
      "vssadmin.exe",
      "wmic.exe"
    ],
    "execution_context": "User account (not SYSTEM or Administrator)",
    "command_line_flags": "/all /quiet (suppress prompts)"
  },
  "contradictions": [
    {
      "type": "non_system_deletion",
      "description": "Shadow copy deletion executed by user-space executable, not system maintenance tools"
    }
  ],
  "resolutions": [
    {
      "action": "confidence_maintained",
      "reasoning": "Legitimate shadow copy deletion is typically performed by system tools or administrators, not user-space executables from Temp folders. This pattern is highly suspicious.",
      "original_confidence": 0.90,
      "adjusted_confidence": 0.90
    }
  ]
}
```

### Finding 3: Shadow Copy Deletion Followed by Mass File Encryption
```json
{
  "title": "Ransomware Attack: Shadow Copy Deletion + File Encryption",
  "severity": "critical",
  "confidence": 0.98,
  "evidence": {
    "timeline": [
      {
        "time": "2024-04-26T03:00:45Z",
        "event": "Shadow copy deletion begins"
      },
      {
        "time": "2024-04-26T03:00:50Z",
        "event": "All shadow copies deleted"
      },
      {
        "time": "2024-04-26T03:01:00Z",
        "event": "Mass file encryption begins"
      },
      {
        "time": "2024-04-26T03:15:00Z",
        "event": "Encryption complete (48,392 files)"
      },
      {
        "time": "2024-04-26T03:15:30Z",
        "event": "Ransom note dropped"
      }
    ],
    "files_encrypted": 48392,
    "encryption_duration": "14 minutes",
    "ransom_note": "README_DECRYPT.txt",
    "attack_pattern": "Classic ransomware: disable backups → encrypt → demand payment"
  },
  "contradictions": [
    {
      "type": "ransomware_kill_chain",
      "description": "Timeline shows classic ransomware pattern: delete backups → encrypt files → drop ransom note"
    }
  ],
  "resolutions": [
    {
      "action": "confidence_increased",
      "reasoning": "Timeline correlation is definitive: shadow copy deletion immediately preceded mass file encryption. This is a textbook ransomware attack. Confidence is very high.",
      "original_confidence": 0.90,
      "adjusted_confidence": 0.98
    }
  ]
}
```

## Ground Truth

**True Positives:** 3
- Shadow copy deletion was ransomware anti-forensics
- Non-system process execution was malicious
- File encryption was ransomware attack

**False Positives:** 0
**False Negatives:** 0

**Expected Metrics:**
- Precision: 1.00
- Recall: 1.00
- F1 Score: 1.00

## Self-Correction Validation

**Contradiction Detection:**
- ✅ Shadow copy deletion alone could be legitimate maintenance → Confidence reduced (0.90 → 0.75)
- ✅ Non-system process deleting shadow copies is suspicious → Confidence maintained (0.90)
- ✅ Timeline correlation: deletion → encryption → ransom note → Confidence increased (0.90 → 0.98)

**Reasoning Quality:**
- Engine correctly identifies that shadow copy deletion can be legitimate
- Engine correctly identifies that non-system process execution is suspicious
- Engine correctly correlates timeline to detect ransomware attack pattern
- Confidence adjustments are proportional to evidence strength
- Very high confidence (0.98) reflects strong correlation evidence

## Detection Logic

### Detector: RansomwareAntiForensicsDetector

```python
def detect(self, artifacts: Dict) -> List[Finding]:
    findings = []
    
    # Parse shadow copy deletion events
    vss_events = parse_vss_events(artifacts['event_logs'])
    
    for event in vss_events:
        if event['event_id'] == 8222:  # Shadow copy deleted
            finding = Finding(
                title="All Volume Shadow Copies Deleted",
                confidence=0.90,
                evidence={
                    "deletion_time": event['time'],
                    "deleted_by_process": event['process'],
                    "shadow_copies_before": event['before_count'],
                    "shadow_copies_after": 0
                }
            )
            
            # Self-correction: Could be legitimate maintenance
            contradiction = Contradiction(
                type="legitimate_admin_task",
                description="Admins occasionally delete shadow copies for disk space"
            )
            finding.contradictions.append(contradiction)
            finding.confidence = 0.75  # Reduced
            
            findings.append(finding)
    
    # Check if deletion was by non-system process
    process_events = parse_process_events(artifacts['event_logs'])
    
    for proc in process_events:
        if proc['executable'] in ['vssadmin.exe', 'wmic.exe']:
            parent = get_parent_process(proc['parent_pid'])
            
            if not is_system_process(parent):
                finding = Finding(
                    title="Shadow Copies Deleted by Suspicious Process",
                    confidence=0.90,
                    evidence={
                        "parent_process": parent['name'],
                        "parent_process_path": parent['path'],
                        "child_processes": [proc['executable']]
                    }
                )
                findings.append(finding)
    
    # Correlate timeline: shadow copy deletion → file encryption
    timeline = build_timeline(artifacts)
    
    if timeline.matches_ransomware_pattern():
        finding = Finding(
            title="Ransomware Attack: Shadow Copy Deletion + File Encryption",
            confidence=0.90,
            evidence={
                "timeline": timeline['events'],
                "files_encrypted": timeline['encrypted_count'],
                "encryption_duration": timeline['duration'],
                "ransom_note": timeline['ransom_note_path']
            }
        )
        
        # Self-correction: Timeline correlation is definitive for ransomware
        contradiction = Contradiction(
            type="ransomware_kill_chain",
            description="Timeline shows classic ransomware: delete backups → encrypt → ransom"
        )
        finding.contradictions.append(contradiction)
        finding.confidence = 0.98  # Very high confidence
        
        findings.append(finding)
    
    return findings
```

## Testing

### Run Scenario
```bash
cd ~/Code/4n6_nexus
PYTHONPATH=. python3 tests/scenario_harness.py --scenario 18
```

### Expected Output
```
Scenario 18: Shadow Copy Deletion (Anti-forensics)
  True Positives: 3
  False Positives: 0
  False Negatives: 0
  Precision: 1.00
  Recall: 1.00
  F1 Score: 1.00
  Status: ✅ PASS
```

## References

- **Ransomware Techniques:** https://www.sans.org/blog/ransomware-techniques/
- **Volume Shadow Copy Forensics:** https://www.sans.org/blog/vss-forensics/
- **MITRE ATT&CK:** T1490 (Inhibit System Recovery)
- **Ransomware Kill Chain:** SANS FOR508 Advanced Incident Response
