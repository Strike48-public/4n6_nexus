# Scenario 17: Network Share Access (Lateral Movement)

**Type:** Intrusion - Lateral movement
**Difficulty:** Medium
**Attack Vector:** Attacker accesses network shares on other systems

## Scenario Description

An attacker with compromised credentials accesses SMB network shares on multiple systems to map the environment, locate sensitive data, and establish additional footholds. The attacker connects to administrative shares (C$, ADMIN$) and copies tools for further compromise.

## Attack Timeline

1. **2024-04-25 14:00:00 UTC** - Initial compromise: Credentials stolen from memory (LSASS dump)
2. **2024-04-25 14:05:00 UTC** - Attacker authenticates to DC01 via SMB (192.168.1.10)
3. **2024-04-25 14:05:15 UTC** - Access ADMIN$ share on DC01
4. **2024-04-25 14:06:00 UTC** - Copy tools to DC01: `psexec.exe`, `mimikatz.exe`
5. **2024-04-25 14:10:00 UTC** - Connect to FILE01 (192.168.1.20) via SMB
6. **2024-04-25 14:10:30 UTC** - Access C$ share on FILE01
7. **2024-04-25 14:11:00 UTC** - Browse shares looking for sensitive data
8. **2024-04-25 14:15:00 UTC** - Connect to WEB01 (192.168.1.30) via SMB
9. **2024-04-25 14:15:45 UTC** - Access ADMIN$ share on WEB01
10. **2024-04-25 14:16:00 UTC** - Execute remote command via PsExec

## Evidence Artifacts

### Present (Lateral Movement Indicators)
- **Event Log 5140:** Network share accessed (DC01, FILE01, WEB01)
  - Account: `CORP\jsmith` (compromised account)
  - Share names: `\\DC01\ADMIN$`, `\\FILE01\C$`, `\\WEB01\ADMIN$`
- **Event Log 5145:** Detailed file share access events
  - Files accessed: `psexec.exe`, `mimikatz.exe` copied to targets
- **Event Log 4624:** Logon Type 3 (Network) from source workstation
- **Event Log 4625:** Failed logon attempts (reconnaissance)
- **MFT Records:** New files created on target systems at time of access
- **Prefetch:** `net.exe` and `psexec.exe` execution on source system
- **Command History:** `net use \\DC01\ADMIN$ /user:CORP\jsmith`, `copy tools.zip \\DC01\ADMIN$`
- **Network Connections:** Multiple SMB connections (TCP 445) from compromised workstation

### Supporting Context
- **Time of Day:** 14:00-14:16 (work hours, but rapid successive connections)
- **Source System:** Workstation (WS-105) - unusual for workstation to connect to admin shares
- **Account Used:** Standard user account accessing administrative shares
- **Access Pattern:** Sequential access to multiple systems within 16 minutes

## Expected Findings

### Finding 1: Multiple Network Share Connections from Single Source
```json
{
  "title": "Multiple Administrative Share Connections Detected",
  "severity": "medium",
  "confidence": 0.65,
  "evidence": {
    "source_system": "WS-105 (192.168.1.100)",
    "account": "CORP\\jsmith",
    "target_systems": [
      "DC01 (192.168.1.10)",
      "FILE01 (192.168.1.20)",
      "WEB01 (192.168.1.30)"
    ],
    "shares_accessed": [
      "\\\\DC01\\ADMIN$",
      "\\\\FILE01\\C$",
      "\\\\WEB01\\ADMIN$"
    ],
    "time_window": "16 minutes",
    "first_access": "2024-04-25T14:05:00Z",
    "last_access": "2024-04-25T14:15:45Z"
  },
  "contradictions": [
    {
      "type": "legitimate_admin_activity",
      "description": "System administrators routinely access network shares for maintenance and troubleshooting"
    }
  ],
  "resolutions": [
    {
      "action": "confidence_reduced",
      "reasoning": "Network share access is common for legitimate IT operations. Cannot definitively prove malicious intent without additional context.",
      "original_confidence": 0.80,
      "adjusted_confidence": 0.65
    }
  ]
}
```

### Finding 2: Suspicious Files Copied to Administrative Shares
```json
{
  "title": "Lateral Movement Tools Copied to Network Shares",
  "severity": "high",
  "confidence": 0.90,
  "evidence": {
    "files_copied": [
      {
        "filename": "psexec.exe",
        "destination": "\\\\DC01\\ADMIN$\\Temp\\psexec.exe",
        "copy_time": "2024-04-25T14:06:00Z",
        "file_hash": "0A29B90DCBD4C8A74D8A5B3A9D8A5B3A"
      },
      {
        "filename": "mimikatz.exe",
        "destination": "\\\\DC01\\ADMIN$\\Temp\\mimikatz.exe",
        "copy_time": "2024-04-25T14:06:10Z",
        "file_hash": "1B30A81DCBD5C9A85D9A6B4A0E9A6B4A"
      }
    ],
    "tool_purpose": "Lateral movement and credential dumping"
  },
  "contradictions": [
    {
      "type": "known_attack_tools",
      "description": "PsExec and Mimikatz are well-known penetration testing and attack tools"
    }
  ],
  "resolutions": [
    {
      "action": "confidence_maintained",
      "reasoning": "Copying PsExec and Mimikatz to administrative shares is a strong indicator of lateral movement. These tools are rarely used legitimately in production environments.",
      "original_confidence": 0.90,
      "adjusted_confidence": 0.90
    }
  ]
}
```

### Finding 3: Credential Reuse Across Multiple Systems
```json
{
  "title": "Lateral Movement via Credential Reuse",
  "severity": "critical",
  "confidence": 0.95,
  "evidence": {
    "compromised_account": "CORP\\jsmith",
    "source_system": "WS-105",
    "target_systems": [
      "DC01 (Domain Controller)",
      "FILE01 (File Server)",
      "WEB01 (Web Server)"
    ],
    "timeline": [
      {
        "time": "2024-04-25T14:00:00Z",
        "event": "LSASS memory dump on WS-105 (credential theft)"
      },
      {
        "time": "2024-04-25T14:05:00Z",
        "event": "Logon to DC01 with stolen credentials"
      },
      {
        "time": "2024-04-25T14:10:00Z",
        "event": "Logon to FILE01 with same credentials"
      },
      {
        "time": "2024-04-25T14:15:00Z",
        "event": "Logon to WEB01 with same credentials"
      }
    ],
    "attack_pattern": "Pass-the-hash or credential reuse"
  },
  "contradictions": [
    {
      "type": "lateral_movement_pattern",
      "description": "Timeline shows credential theft followed by rapid multi-system access with same account"
    }
  ],
  "resolutions": [
    {
      "action": "confidence_increased",
      "reasoning": "Timeline correlation: credential theft → SMB connections → tool deployment → remote execution. This is a textbook lateral movement attack chain.",
      "original_confidence": 0.85,
      "adjusted_confidence": 0.95
    }
  ]
}
```

## Ground Truth

**True Positives:** 3
- Network share access was attacker lateral movement
- Files copied were malicious tools (PsExec, Mimikatz)
- Credential reuse was part of attack chain

**False Positives:** 0
**False Negatives:** 0

**Expected Metrics:**
- Precision: 1.00
- Recall: 1.00
- F1 Score: 1.00

## Self-Correction Validation

**Contradiction Detection:**
- ✅ Network share access alone could be legitimate admin work → Confidence reduced (0.80 → 0.65)
- ✅ Copying PsExec and Mimikatz is highly suspicious → Confidence maintained (0.90)
- ✅ Timeline correlation: credential theft → multi-system access → Confidence increased (0.85 → 0.95)

**Reasoning Quality:**
- Engine correctly identifies that network share access is common for IT operations
- Engine correctly identifies that PsExec and Mimikatz are attack tools
- Engine correctly correlates timeline to detect lateral movement pattern
- Confidence adjustments are proportional to evidence strength

## Detection Logic

### Detector: LateralMovementDetector

```python
def detect(self, artifacts: Dict) -> List[Finding]:
    findings = []
    
    # Parse SMB share access logs
    smb_events = parse_smb_events(artifacts['event_logs'])
    
    # Group by source system and time window
    connection_clusters = group_by_source_and_time(smb_events, window_minutes=30)
    
    for cluster in connection_clusters:
        if len(cluster['target_systems']) >= 3:
            finding = Finding(
                title="Multiple Administrative Share Connections Detected",
                confidence=0.80,
                evidence={
                    "source_system": cluster['source'],
                    "account": cluster['account'],
                    "target_systems": cluster['targets'],
                    "shares_accessed": cluster['shares'],
                    "time_window": cluster['duration']
                }
            )
            
            # Self-correction: Legitimate admins also access multiple shares
            contradiction = Contradiction(
                type="legitimate_admin_activity",
                description="System administrators routinely access network shares"
            )
            finding.contradictions.append(contradiction)
            finding.confidence = 0.65  # Reduced
            
            findings.append(finding)
    
    # Check for suspicious files copied to shares
    file_access_events = parse_file_access_events(artifacts['event_logs'])
    
    for event in file_access_events:
        if is_known_attack_tool(event['filename']):
            finding = Finding(
                title="Lateral Movement Tools Copied to Network Shares",
                confidence=0.90,
                evidence={
                    "files_copied": [
                        {
                            "filename": event['filename'],
                            "destination": event['destination'],
                            "copy_time": event['time'],
                            "file_hash": event['hash']
                        }
                    ],
                    "tool_purpose": get_tool_purpose(event['filename'])
                }
            )
            findings.append(finding)
    
    # Correlate timeline: credential theft → SMB connections
    timeline = build_timeline(artifacts)
    
    if timeline.matches_lateral_movement_pattern():
        finding = Finding(
            title="Lateral Movement via Credential Reuse",
            confidence=0.85,
            evidence={
                "compromised_account": timeline['account'],
                "source_system": timeline['source'],
                "target_systems": timeline['targets'],
                "timeline": timeline['events']
            }
        )
        
        # Self-correction: Timeline correlation increases confidence
        contradiction = Contradiction(
            type="lateral_movement_pattern",
            description="Timeline shows credential theft → multi-system access"
        )
        finding.contradictions.append(contradiction)
        finding.confidence = 0.95  # Increased
        
        findings.append(finding)
    
    return findings
```

## Testing

### Run Scenario
```bash
cd /home/jtomek/Code/sift_find_evil
PYTHONPATH=. python3 tests/scenario_harness.py --scenario 17
```

### Expected Output
```
Scenario 17: Network Share Access (Lateral Movement)
  True Positives: 3
  False Positives: 0
  False Negatives: 0
  Precision: 1.00
  Recall: 1.00
  F1 Score: 1.00
  Status: ✅ PASS
```

## References

- **Lateral Movement:** https://attack.mitre.org/tactics/TA0008/
- **SMB Forensics:** https://www.sans.org/blog/smb-forensics/
- **PsExec Detection:** https://www.sans.org/blog/detecting-psexec/
- **Credential Dumping:** MITRE ATT&CK T1003
