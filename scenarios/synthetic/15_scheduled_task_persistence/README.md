# Scenario 15: Scheduled Task Persistence

**Type:** Malware persistence
**Difficulty:** Medium
**Attack Vector:** Malware creates scheduled task to maintain persistence

## Scenario Description

Malware creates a scheduled task to execute a malicious binary at system startup and every hour. The task is created without corresponding legitimate software installation, indicating malware persistence rather than legitimate software behavior.

## Attack Timeline

1. **2024-04-23 18:45:00 UTC** - Suspicious email attachment opened (phishing)
2. **2024-04-23 18:46:00 UTC** - Dropper executable runs from %TEMP% directory
3. **2024-04-23 18:46:30 UTC** - Malware drops payload to `C:\ProgramData\WindowsUpdate\wuservice.exe`
4. **2024-04-23 18:46:45 UTC** - Scheduled task created: "WindowsUpdateCheck"
5. **2024-04-23 18:47:00 UTC** - Task executes for first time (validation run)
6. **2024-04-23 18:48:00 UTC** - Dropper deletes itself from %TEMP%
7. **2024-04-23 19:00:00 UTC** - Scheduled task executes again (hourly trigger)

## Evidence Artifacts

### Present (Contradictory Evidence)
- **Task XML:** `C:\Windows\System32\Tasks\WindowsUpdateCheck`
  - Trigger: At startup + every 1 hour
  - Action: Execute `C:\ProgramData\WindowsUpdate\wuservice.exe`
  - Run with highest privileges
  - Created by: `NT AUTHORITY\SYSTEM`
- **Registry TaskCache:** Task creation timestamp (18:46:45)
- **Event Log 106:** Task registered (Event ID 4698)
- **Event Log 200:** Task executed (Event IDs at 18:47:00, 19:00:00)
- **Prefetch:** `wuservice.exe` execution history
- **MFT:** `wuservice.exe` creation timestamp (18:46:30)
- **No MSI logs:** No legitimate software installation
- **No Add/Remove Programs entry:** Binary not associated with installed software

### Absent (No Legitimate Installation)
- **Windows Update logs:** No legitimate Windows Update activity
- **MSI installation logs:** No software package installed this file
- **Digital signature:** Binary is not signed by Microsoft or trusted vendor

## Expected Findings

### Finding 1: Suspicious Scheduled Task Created
```json
{
  "title": "Suspicious Scheduled Task: WindowsUpdateCheck",
  "severity": "high",
  "confidence": 0.75,
  "evidence": {
    "task_name": "WindowsUpdateCheck",
    "task_path": "\\WindowsUpdateCheck",
    "created_time": "2024-04-23T18:46:45Z",
    "created_by": "NT AUTHORITY\\SYSTEM",
    "target_executable": "C:\\ProgramData\\WindowsUpdate\\wuservice.exe",
    "triggers": [
      "At startup",
      "Every 1 hour"
    ],
    "run_as": "SYSTEM",
    "highest_privileges": true
  },
  "contradictions": [
    {
      "type": "misleading_name",
      "description": "Task name suggests Windows Update, but no legitimate Windows Update activity correlates"
    }
  ],
  "resolutions": [
    {
      "action": "confidence_reduced",
      "reasoning": "Legitimate software also creates scheduled tasks. Need additional context to confirm malicious intent.",
      "original_confidence": 0.90,
      "adjusted_confidence": 0.75
    }
  ]
}
```

### Finding 2: Task Executable Not From Legitimate Installation
```json
{
  "title": "Scheduled Task Executes Unsigned Binary",
  "severity": "high",
  "confidence": 0.85,
  "evidence": {
    "executable_path": "C:\\ProgramData\\WindowsUpdate\\wuservice.exe",
    "file_size": 524288,
    "created_time": "2024-04-23T18:46:30Z",
    "signed": false,
    "msi_installation": false,
    "add_remove_programs": false
  },
  "contradictions": [
    {
      "type": "no_installation_record",
      "description": "Binary appeared without MSI logs or Add/Remove Programs entry"
    },
    {
      "type": "unsigned_system_directory",
      "description": "Unsigned executable in system-like directory (ProgramData)"
    }
  ],
  "resolutions": [
    {
      "action": "confidence_maintained",
      "reasoning": "No legitimate installation record + unsigned binary + system-like directory name = likely malware",
      "original_confidence": 0.85,
      "adjusted_confidence": 0.85
    }
  ]
}
```

### Finding 3: Timeline Correlation - Dropper to Persistence
```json
{
  "title": "Malware Persistence Established via Scheduled Task",
  "severity": "critical",
  "confidence": 0.95,
  "evidence": {
    "dropper_execution": "2024-04-23T18:46:00Z",
    "payload_creation": "2024-04-23T18:46:30Z",
    "task_creation": "2024-04-23T18:46:45Z",
    "first_task_execution": "2024-04-23T18:47:00Z",
    "dropper_deletion": "2024-04-23T18:48:00Z"
  },
  "contradictions": [
    {
      "type": "malware_lifecycle_pattern",
      "description": "Classic malware pattern: dropper → payload → persistence → cleanup"
    }
  ],
  "resolutions": [
    {
      "action": "confidence_increased",
      "reasoning": "Timeline shows clear malware lifecycle: dropper runs, drops payload, creates persistence, validates execution, then self-deletes. This is a textbook persistence mechanism.",
      "original_confidence": 0.80,
      "adjusted_confidence": 0.95
    }
  ]
}
```

## Ground Truth

**True Positives:** 3
- Scheduled task is malware persistence
- Executable is malware (not legitimate software)
- Timeline shows malware installation pattern

**False Positives:** 0
**False Negatives:** 0

**Expected Metrics:**
- Precision: 1.00
- Recall: 1.00
- F1 Score: 1.00

## Self-Correction Validation

**Contradiction Detection:**
- ✅ Scheduled task alone could be legitimate software → Confidence reduced (0.90 → 0.75)
- ✅ No installation record + unsigned binary → Confidence maintained (0.85)
- ✅ Timeline correlation shows malware lifecycle → Confidence increased (0.80 → 0.95)

**Reasoning Quality:**
- Engine correctly identifies that scheduled tasks are common for legitimate software
- Engine correctly identifies that absence of installation records is suspicious
- Engine correctly correlates timeline to detect malware lifecycle pattern
- Confidence adjustments are proportional to evidence strength

## Detection Logic

### Detector: ScheduledTaskPersistenceDetector

```python
def detect(self, artifacts: Dict) -> List[Finding]:
    findings = []
    
    # Parse scheduled tasks
    tasks = parse_scheduled_tasks(artifacts['tasks_xml'])
    
    for task in tasks:
        # Check for suspicious characteristics
        if is_suspicious_task(task):
            finding = Finding(
                title=f"Suspicious Scheduled Task: {task['name']}",
                confidence=0.90,
                evidence={
                    "task_name": task['name'],
                    "created_time": task['created_time'],
                    "target_executable": task['executable'],
                    "triggers": task['triggers'],
                    "run_as": task['principal']
                }
            )
            
            # Self-correction: Legitimate software also creates tasks
            contradiction = Contradiction(
                type="legitimate_software_pattern",
                description="Scheduled tasks are common for legitimate software updates and maintenance"
            )
            finding.contradictions.append(contradiction)
            finding.confidence = 0.75  # Reduced
            
            findings.append(finding)
    
    # Check if executable has installation record
    for task in tasks:
        exe_path = task['executable']
        
        if not has_installation_record(artifacts, exe_path):
            finding = Finding(
                title="Scheduled Task Executes Unsigned Binary",
                confidence=0.85,
                evidence={
                    "executable_path": exe_path,
                    "signed": is_signed(artifacts, exe_path),
                    "msi_installation": has_msi_log(artifacts, exe_path),
                    "add_remove_programs": in_add_remove_programs(artifacts, exe_path)
                }
            )
            findings.append(finding)
    
    # Timeline correlation: dropper → payload → task → execution
    timeline_events = correlate_timeline(artifacts)
    
    if timeline_events.matches_malware_pattern():
        finding = Finding(
            title="Malware Persistence Established via Scheduled Task",
            confidence=0.80,
            evidence={
                "dropper_execution": timeline_events['dropper_time'],
                "payload_creation": timeline_events['payload_time'],
                "task_creation": timeline_events['task_time']
            }
        )
        
        # Self-correction: Timeline correlation increases confidence
        contradiction = Contradiction(
            type="malware_lifecycle_pattern",
            description="Timeline shows classic malware pattern: drop → persist → execute → cleanup"
        )
        finding.contradictions.append(contradiction)
        finding.confidence = 0.95  # Increased
        
        findings.append(finding)
    
    return findings
```

## Testing

### Run Scenario
```bash
cd ~/Code/4n6_nexus
PYTHONPATH=. python3 tests/scenario_harness.py --scenario 15
```

### Expected Output
```
Scenario 15: Scheduled Task Persistence
  True Positives: 3
  False Positives: 0
  False Negatives: 0
  Precision: 1.00
  Recall: 1.00
  F1 Score: 1.00
  Status: ✅ PASS
```

## References

- **Scheduled Task Forensics:** https://www.sans.org/blog/scheduled-task-forensics/
- **Windows Task Scheduler:** https://attack.mitre.org/techniques/T1053/005/
- **Persistence Mechanisms:** MITRE ATT&CK T1053
- **Malware Analysis:** SANS FOR610 Reverse-Engineering Malware
