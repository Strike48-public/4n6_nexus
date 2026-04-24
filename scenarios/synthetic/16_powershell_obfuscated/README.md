# Scenario 16: PowerShell Script Execution (Obfuscated)

**Type:** Malware execution
**Difficulty:** Medium
**Attack Vector:** Attacker runs obfuscated PowerShell script

## Scenario Description

An attacker executes an obfuscated PowerShell script that downloads and executes a malicious payload. The script uses Base64 encoding and compression to evade detection. However, PowerShell logging captures the obfuscated commands and execution context.

## Attack Timeline

1. **2024-04-24 11:30:00 UTC** - Attacker gains remote access via WMI
2. **2024-04-24 11:30:15 UTC** - PowerShell process spawned by wmiprvse.exe (no console)
3. **2024-04-24 11:30:16 UTC** - PowerShell executes with obfuscated command line
4. **2024-04-24 11:30:17 UTC** - Script downloads payload from attacker C2 server
5. **2024-04-24 11:30:20 UTC** - Payload executed in memory (fileless)
6. **2024-04-24 11:30:25 UTC** - PowerShell process exits

## Evidence Artifacts

### Present (Contradictory Evidence)
- **Prefetch:** `POWERSHELL.EXE-[HASH].pf` shows execution at 11:30:15
- **Event Log 4104:** PowerShell Script Block Logging captured obfuscated command
  ```powershell
  powershell.exe -NoP -sta -NonI -W Hidden -Enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACIASAA0AHMASQBBAEEAQQBBAEEAQQBBAEEAQQBLADEAVgB5ADUAYwBhAHoASgBDAE0AQQBBAEEAQQBBAGcAZwBBAEEAQQBBAD0APQAiACkAKQA=
  ```
- **Event Log 4688:** Process creation - PowerShell spawned by wmiprvse.exe
- **Event Log 3:** Sysmon Network Connection - PowerShell connects to 192.0.2.50:443
- **Command Line Arguments:** Base64 encoded, hidden window, no profile, non-interactive
- **Parent Process:** wmiprvse.exe (WMI Provider Host) - unusual for legitimate PowerShell scripts
- **Network Artifacts:** DNS query to suspicious domain, HTTPS connection to C2

### Absent (Fileless Execution)
- **No script file:** PowerShell executed from command line, not .ps1 file
- **No dropped payload:** Malware executed entirely in memory

## Expected Findings

### Finding 1: Obfuscated PowerShell Command Detected
```json
{
  "title": "Obfuscated PowerShell Execution Detected",
  "severity": "high",
  "confidence": 0.70,
  "evidence": {
    "process": "powershell.exe",
    "pid": 5832,
    "execution_time": "2024-04-24T11:30:16Z",
    "command_line_flags": [
      "-NoP (No Profile)",
      "-NonI (Non-Interactive)",
      "-W Hidden (Hidden Window)",
      "-Enc (Base64 Encoded Command)"
    ],
    "encoded_command": "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtAC...",
    "decoded_command_snippet": "$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String(\"H4sIAAAAAAAAK1Vy5cazJCMAAAAAggAAAA==\"))"
  },
  "contradictions": [
    {
      "type": "legitimate_use_possible",
      "description": "System administrators also use PowerShell with -Enc for automation and scripts"
    }
  ],
  "resolutions": [
    {
      "action": "confidence_reduced",
      "reasoning": "Obfuscated PowerShell alone is not definitive. Legitimate automation tools also use Base64 encoding for script deployment.",
      "original_confidence": 0.85,
      "adjusted_confidence": 0.70
    }
  ]
}
```

### Finding 2: PowerShell Spawned by WMI (No User Interaction)
```json
{
  "title": "PowerShell Spawned Remotely via WMI",
  "severity": "high",
  "confidence": 0.85,
  "evidence": {
    "parent_process": "wmiprvse.exe",
    "parent_pid": 1248,
    "child_process": "powershell.exe",
    "child_pid": 5832,
    "spawn_time": "2024-04-24T11:30:15Z",
    "user_context": "NT AUTHORITY\\SYSTEM",
    "no_console_window": true
  },
  "contradictions": [
    {
      "type": "remote_execution_pattern",
      "description": "PowerShell spawned by WMI provider, not interactive user session"
    }
  ],
  "resolutions": [
    {
      "action": "confidence_maintained",
      "reasoning": "WMI remote execution is commonly used by attackers for lateral movement and remote code execution. Running as SYSTEM without console is suspicious.",
      "original_confidence": 0.85,
      "adjusted_confidence": 0.85
    }
  ]
}
```

### Finding 3: PowerShell Downloads from Suspicious Domain
```json
{
  "title": "PowerShell Connected to Suspicious External Server",
  "severity": "critical",
  "confidence": 0.95,
  "evidence": {
    "process": "powershell.exe",
    "pid": 5832,
    "connection_time": "2024-04-24T11:30:17Z",
    "destination_ip": "192.0.2.50",
    "destination_port": 443,
    "domain": "update-server-cdn[.]com",
    "domain_age": "7 days",
    "domain_reputation": "malicious",
    "certificate": "self-signed"
  },
  "contradictions": [
    {
      "type": "c2_communication",
      "description": "PowerShell connects to newly registered domain with malicious reputation"
    }
  ],
  "resolutions": [
    {
      "action": "confidence_increased",
      "reasoning": "Timeline correlation: obfuscated PowerShell → WMI spawn → network connection to malicious domain. This is a clear command and control pattern.",
      "original_confidence": 0.85,
      "adjusted_confidence": 0.95
    }
  ]
}
```

## Ground Truth

**True Positives:** 3
- PowerShell command was malicious (obfuscated downloader)
- Remote execution via WMI was attacker-controlled
- Network connection was to attacker C2 server

**False Positives:** 0
**False Negatives:** 0

**Expected Metrics:**
- Precision: 1.00
- Recall: 1.00
- F1 Score: 1.00

## Self-Correction Validation

**Contradiction Detection:**
- ✅ Obfuscated PowerShell alone could be legitimate automation → Confidence reduced (0.85 → 0.70)
- ✅ WMI spawned PowerShell is suspicious but not definitive → Confidence maintained (0.85)
- ✅ Timeline correlation: obfuscated + WMI + C2 connection → Confidence increased (0.85 → 0.95)

**Reasoning Quality:**
- Engine correctly identifies that Base64 encoded PowerShell is used legitimately
- Engine correctly identifies that WMI remote execution is suspicious
- Engine correctly correlates timeline to detect C2 communication pattern
- Confidence adjustments are proportional to evidence strength

## Detection Logic

### Detector: PowerShellMalwareDetector

```python
def detect(self, artifacts: Dict) -> List[Finding]:
    findings = []
    
    # Parse PowerShell event logs
    ps_events = parse_powershell_events(artifacts['event_logs'])
    
    for event in ps_events:
        # Check for obfuscation indicators
        if is_obfuscated_command(event['command_line']):
            finding = Finding(
                title="Obfuscated PowerShell Execution Detected",
                confidence=0.85,
                evidence={
                    "process": "powershell.exe",
                    "pid": event['pid'],
                    "command_line_flags": extract_flags(event['command_line']),
                    "encoded_command": extract_encoded_command(event['command_line'])
                }
            )
            
            # Self-correction: Legitimate automation also uses encoding
            contradiction = Contradiction(
                type="legitimate_use_possible",
                description="System administrators use -Enc for automation"
            )
            finding.contradictions.append(contradiction)
            finding.confidence = 0.70  # Reduced
            
            findings.append(finding)
    
    # Check for suspicious parent process
    for event in ps_events:
        if event['parent_process'] in ['wmiprvse.exe', 'wscript.exe', 'mshta.exe']:
            finding = Finding(
                title="PowerShell Spawned Remotely via WMI",
                confidence=0.85,
                evidence={
                    "parent_process": event['parent_process'],
                    "child_process": "powershell.exe",
                    "user_context": event['user']
                }
            )
            findings.append(finding)
    
    # Check for network connections from PowerShell
    network_events = parse_network_events(artifacts['sysmon_logs'])
    
    for net_event in network_events:
        if net_event['process'] == 'powershell.exe':
            domain_reputation = check_domain_reputation(net_event['domain'])
            
            if domain_reputation == 'malicious':
                finding = Finding(
                    title="PowerShell Connected to Suspicious External Server",
                    confidence=0.85,
                    evidence={
                        "destination_ip": net_event['dest_ip'],
                        "domain": net_event['domain'],
                        "domain_reputation": domain_reputation
                    }
                )
                
                # Self-correction: Timeline correlation increases confidence
                if correlates_with_obfuscated_ps(event, net_event):
                    finding.confidence = 0.95  # Increased
                
                findings.append(finding)
    
    return findings
```

## Testing

### Run Scenario
```bash
cd /home/jtomek/Code/sift_find_evil
PYTHONPATH=. python3 tests/scenario_harness.py --scenario 16
```

### Expected Output
```
Scenario 16: PowerShell Script Execution (Obfuscated)
  True Positives: 3
  False Positives: 0
  False Negatives: 0
  Precision: 1.00
  Recall: 1.00
  F1 Score: 1.00
  Status: ✅ PASS
```

## References

- **PowerShell Forensics:** https://www.sans.org/blog/powershell-forensics/
- **PowerShell Logging:** https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html
- **Obfuscation Detection:** https://github.com/danielbohannon/Revoke-Obfuscation
- **MITRE ATT&CK:** T1059.001 (PowerShell)
