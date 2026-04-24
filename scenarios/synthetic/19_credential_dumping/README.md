# Scenario 19: Credential Dumping (LSASS Access)

**Type:** Intrusion - Privilege escalation
**Difficulty:** High
**Attack Vector:** Attacker dumps credentials from LSASS process memory

## Scenario Description

An attacker with local administrator privileges accesses the LSASS (Local Security Authority Subsystem Service) process memory to extract plaintext passwords, NTLM hashes, and Kerberos tickets. The attacker uses these stolen credentials for privilege escalation and lateral movement.

## Attack Timeline

1. **2024-04-27 16:00:00 UTC** - Attacker gains initial access (phishing)
2. **2024-04-27 16:05:00 UTC** - Privilege escalation to local administrator
3. **2024-04-27 16:10:00 UTC** - Attacker uploads credential dumping tool
4. **2024-04-27 16:10:30 UTC** - `procdump.exe` executed to dump LSASS memory
   - Command: `procdump.exe -ma lsass.exe lsass.dmp`
5. **2024-04-27 16:10:45 UTC** - LSASS memory dump file created (250 MB)
6. **2024-04-27 16:11:00 UTC** - Dump file exfiltrated to attacker C2 server
7. **2024-04-27 16:12:00 UTC** - Dump file deleted from disk (anti-forensics)
8. **2024-04-27 16:15:00 UTC** - Extracted credentials used for lateral movement

## Evidence Artifacts

### Present (LSASS Access Indicators)
- **Event Log 10 (Sysmon):** Process accessed LSASS memory
  - Source process: `procdump.exe` (PID 4892)
  - Target process: `lsass.exe` (PID 628)
  - Access rights: `PROCESS_VM_READ, PROCESS_QUERY_INFORMATION`
  - Time: 16:10:30
- **Event Log 11 (Sysmon):** File created - `lsass.dmp`
  - File path: `C:\Users\attacker\AppData\Local\Temp\lsass.dmp`
  - File size: 262144000 bytes (250 MB)
  - Creation time: 16:10:45
- **Event Log 23 (Sysmon):** File deleted - `lsass.dmp`
  - Deletion time: 16:12:00
- **Prefetch:** `procdump.exe` execution history
- **MFT Records:** `lsass.dmp` file creation and deletion timestamps
- **Network Connection:** `procdump.exe` connects to external IP (192.0.2.100:443)
- **Event Log 4624:** Subsequent logons using stolen credentials
  - Logon Type 9 (NewCredentials) - Pass-the-hash attack

### Supporting Context
- **LSASS Process:** Critical Windows security process (always PID 628)
- **Legitimate Tools:** Procdump is a legitimate Sysinternals tool (also used by attackers)
- **Mimikatz Alternative:** Attackers use Procdump to avoid Mimikatz detection

## Expected Findings

### Finding 1: LSASS Process Memory Accessed
```json
{
  "title": "LSASS Memory Accessed by External Process",
  "severity": "high",
  "confidence": 0.70,
  "evidence": {
    "source_process": "procdump.exe",
    "source_pid": 4892,
    "target_process": "lsass.exe",
    "target_pid": 628,
    "access_rights": [
      "PROCESS_VM_READ",
      "PROCESS_QUERY_INFORMATION"
    ],
    "access_time": "2024-04-27T16:10:30Z",
    "user_context": "WORKSTATION\\Administrator"
  },
  "contradictions": [
    {
      "type": "legitimate_tool_use",
      "description": "Legitimate security tools and antivirus software also access LSASS memory for monitoring and protection"
    }
  ],
  "resolutions": [
    {
      "action": "confidence_reduced",
      "reasoning": "LSASS access is common for security software, monitoring tools, and system utilities. Cannot definitively prove malicious intent without additional context.",
      "original_confidence": 0.85,
      "adjusted_confidence": 0.70
    }
  ]
}
```

### Finding 2: LSASS Memory Dump File Created
```json
{
  "title": "LSASS Memory Dump Created",
  "severity": "critical",
  "confidence": 0.95,
  "evidence": {
    "dump_file": "C:\\Users\\attacker\\AppData\\Local\\Temp\\lsass.dmp",
    "file_size": 262144000,
    "creation_time": "2024-04-27T16:10:45Z",
    "created_by_process": "procdump.exe",
    "created_by_user": "WORKSTATION\\Administrator",
    "file_deleted": true,
    "deletion_time": "2024-04-27T16:12:00Z"
  },
  "contradictions": [
    {
      "type": "credential_theft_artifact",
      "description": "LSASS dump file is a clear artifact of credential theft attempt"
    },
    {
      "type": "anti_forensics",
      "description": "Dump file was deleted 90 seconds after creation (evidence cleanup)"
    }
  ],
  "resolutions": [
    {
      "action": "confidence_maintained",
      "reasoning": "Creating an LSASS memory dump is a strong indicator of credential theft. Legitimate troubleshooting rarely requires LSASS dumps, and deletion after creation suggests malicious intent.",
      "original_confidence": 0.95,
      "adjusted_confidence": 0.95
    }
  ]
}
```

### Finding 3: Credential Theft and Lateral Movement
```json
{
  "title": "Credential Dumping Followed by Lateral Movement",
  "severity": "critical",
  "confidence": 0.98,
  "evidence": {
    "timeline": [
      {
        "time": "2024-04-27T16:10:30Z",
        "event": "LSASS memory accessed by procdump.exe"
      },
      {
        "time": "2024-04-27T16:10:45Z",
        "event": "LSASS dump file created (250 MB)"
      },
      {
        "time": "2024-04-27T16:11:00Z",
        "event": "Dump file exfiltrated to 192.0.2.100:443"
      },
      {
        "time": "2024-04-27T16:12:00Z",
        "event": "Dump file deleted (anti-forensics)"
      },
      {
        "time": "2024-04-27T16:15:00Z",
        "event": "NewCredentials logon (pass-the-hash) to DC01"
      }
    ],
    "stolen_credentials_used": true,
    "lateral_movement_target": "DC01 (192.168.1.10)",
    "logon_type": "NewCredentials (Type 9)",
    "attack_pattern": "Credential dumping → exfiltration → lateral movement"
  },
  "contradictions": [
    {
      "type": "credential_theft_kill_chain",
      "description": "Timeline shows classic credential theft pattern: dump LSASS → exfiltrate → use stolen creds"
    }
  ],
  "resolutions": [
    {
      "action": "confidence_increased",
      "reasoning": "Timeline correlation is definitive: LSASS dump → exfiltration → credential reuse within 5 minutes. This is a textbook credential dumping attack followed by immediate use of stolen credentials.",
      "original_confidence": 0.90,
      "adjusted_confidence": 0.98
    }
  ]
}
```

## Ground Truth

**True Positives:** 3
- LSASS memory access was credential theft attempt
- Memory dump file was credential theft artifact
- Lateral movement used stolen credentials

**False Positives:** 0
**False Negatives:** 0

**Expected Metrics:**
- Precision: 1.00
- Recall: 1.00
- F1 Score: 1.00

## Self-Correction Validation

**Contradiction Detection:**
- ✅ LSASS access alone could be legitimate security software → Confidence reduced (0.85 → 0.70)
- ✅ LSASS dump file creation + deletion is highly suspicious → Confidence maintained (0.95)
- ✅ Timeline correlation: dump → exfiltration → credential reuse → Confidence increased (0.90 → 0.98)

**Reasoning Quality:**
- Engine correctly identifies that LSASS access can be legitimate
- Engine correctly identifies that LSASS dump file creation is strong indicator
- Engine correctly identifies that file deletion suggests anti-forensics
- Engine correctly correlates timeline to detect credential theft attack chain
- Confidence adjustments are proportional to evidence strength
- Very high confidence (0.98) reflects strong correlation and subsequent credential use

## Detection Logic

### Detector: CredentialDumpingDetector

```python
def detect(self, artifacts: Dict) -> List[Finding]:
    findings = []
    
    # Parse Sysmon Event ID 10 (Process Access)
    lsass_access_events = parse_sysmon_process_access(artifacts['sysmon_logs'])
    
    for event in lsass_access_events:
        if event['target_process'].lower() == 'lsass.exe':
            finding = Finding(
                title="LSASS Memory Accessed by External Process",
                confidence=0.85,
                evidence={
                    "source_process": event['source_process'],
                    "target_process": "lsass.exe",
                    "access_rights": event['access_rights'],
                    "access_time": event['time']
                }
            )
            
            # Self-correction: Legitimate security tools also access LSASS
            contradiction = Contradiction(
                type="legitimate_tool_use",
                description="Security software and monitoring tools access LSASS memory"
            )
            finding.contradictions.append(contradiction)
            finding.confidence = 0.70  # Reduced
            
            findings.append(finding)
    
    # Parse Sysmon Event ID 11 (File Create) for dump files
    file_creation_events = parse_sysmon_file_create(artifacts['sysmon_logs'])
    
    for event in file_creation_events:
        if 'lsass' in event['filename'].lower() and event['filename'].endswith('.dmp'):
            # Check if file was deleted (Event ID 23)
            deletion_event = find_file_deletion(artifacts['sysmon_logs'], event['filename'])
            
            finding = Finding(
                title="LSASS Memory Dump Created",
                confidence=0.95,
                evidence={
                    "dump_file": event['filename'],
                    "file_size": event['file_size'],
                    "creation_time": event['time'],
                    "created_by_process": event['process'],
                    "file_deleted": deletion_event is not None,
                    "deletion_time": deletion_event['time'] if deletion_event else None
                }
            )
            findings.append(finding)
    
    # Correlate timeline: LSASS access → dump → exfiltration → credential use
    timeline = build_timeline(artifacts)
    
    if timeline.matches_credential_dumping_pattern():
        finding = Finding(
            title="Credential Dumping Followed by Lateral Movement",
            confidence=0.90,
            evidence={
                "timeline": timeline['events'],
                "stolen_credentials_used": True,
                "lateral_movement_target": timeline['target_system']
            }
        )
        
        # Self-correction: Timeline correlation is definitive
        contradiction = Contradiction(
            type="credential_theft_kill_chain",
            description="Timeline shows credential theft → immediate reuse"
        )
        finding.contradictions.append(contradiction)
        finding.confidence = 0.98  # Very high confidence
        
        findings.append(finding)
    
    return findings
```

## Testing

### Run Scenario
```bash
cd /home/jtomek/Code/sift_find_evil
PYTHONPATH=. python3 tests/scenario_harness.py --scenario 19
```

### Expected Output
```
Scenario 19: Credential Dumping (LSASS Access)
  True Positives: 3
  False Positives: 0
  False Negatives: 0
  Precision: 1.00
  Recall: 1.00
  F1 Score: 1.00
  Status: ✅ PASS
```

## References

- **Credential Dumping:** https://attack.mitre.org/techniques/T1003/001/
- **LSASS Forensics:** https://www.sans.org/blog/lsass-memory-forensics/
- **Detecting Credential Theft:** SANS FOR508 Advanced Incident Response
- **Mimikatz Alternatives:** https://www.sans.org/blog/detecting-mimikatz/
- **Sysmon Event ID 10:** Process access monitoring
