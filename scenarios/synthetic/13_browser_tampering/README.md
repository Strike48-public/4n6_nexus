# Scenario 13: Browser Artifact Tampering

**Type:** Anti-forensics
**Difficulty:** Medium
**Attack Vector:** Manual history clearing to hide web activity

## Scenario Description

An attacker accesses suspicious websites, then manually clears browser history, cookies, and cache to hide their activity. However, forensic artifacts remain that contradict the "clean" browser state.

## Attack Timeline

1. **2024-04-20 14:30:00 UTC** - Attacker opens Chrome browser
2. **2024-04-20 14:31:00 UTC** - Visits multiple suspicious domains
3. **2024-04-20 14:35:00 UTC** - Downloads potentially malicious file
4. **2024-04-20 14:37:00 UTC** - Manually clears browser history via Chrome settings
5. **2024-04-20 14:38:00 UTC** - Clears cookies and cache
6. **2024-04-20 14:39:00 UTC** - Closes browser

## Evidence Artifacts

### Present (Contradictory Evidence)
- **Prefetch:** `CHROME.EXE-[HASH].pf` shows recent execution at 14:30:00
- **MFT:** Chrome cache directory shows file deletions at 14:37:00-14:38:00
- **Registry:** `NTUSER.DAT` contains browser launch timestamps
- **Downloads folder:** Downloaded file exists with timestamp 14:35:00

### Absent (Cleared by Attacker)
- **Browser History:** SQLite database is empty (cleared)
- **Cookies:** All cookies removed
- **Cache Files:** Cache directory is empty

## Expected Findings

### Finding 1: Browser History Cleared
```json
{
  "title": "Browser History Cleared: chrome.exe",
  "severity": "medium",
  "confidence": 0.50,
  "evidence": {
    "browser": "Google Chrome",
    "history_db": "C:\\Users\\analyst\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History",
    "history_entries": 0,
    "prefetch_last_run": "2024-04-20T14:30:00Z"
  },
  "contradictions": [
    {
      "type": "execution_without_history",
      "description": "Prefetch shows Chrome executed recently, but history database is empty"
    }
  ],
  "resolutions": [
    {
      "action": "confidence_reduced",
      "reasoning": "History clearing could be legitimate privacy behavior or anti-forensics. Cannot definitively prove malicious intent without additional context.",
      "original_confidence": 0.80,
      "adjusted_confidence": 0.50
    }
  ]
}
```

### Finding 2: Mass File Deletion in Cache Directory
```json
{
  "title": "Mass File Deletion: Chrome Cache",
  "severity": "low",
  "confidence": 0.40,
  "evidence": {
    "directory": "C:\\Users\\analyst\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache",
    "deleted_files": 347,
    "deletion_time": "2024-04-20T14:37:00Z to 2024-04-20T14:38:00Z",
    "method": "Manual clearing (not normal browser exit)"
  },
  "contradictions": [
    {
      "type": "intentional_clearing",
      "description": "Files deleted in bulk within 1 minute window, indicating manual clearing action"
    }
  ],
  "resolutions": [
    {
      "action": "confidence_reduced",
      "reasoning": "Manual cache clearing is common privacy behavior. Indicates intentional action, but not necessarily malicious.",
      "original_confidence": 0.60,
      "adjusted_confidence": 0.40
    }
  ]
}
```

### Finding 3: Downloaded File Remains
```json
{
  "title": "Downloaded File After History Clearing",
  "severity": "medium",
  "confidence": 0.75,
  "evidence": {
    "file_path": "C:\\Users\\analyst\\Downloads\\update_installer.exe",
    "download_time": "2024-04-20T14:35:00Z",
    "history_cleared_time": "2024-04-20T14:37:00Z",
    "file_size": 2457600,
    "suspicious": true
  },
  "contradictions": [
    {
      "type": "file_without_history",
      "description": "Downloaded file exists, but browser history shows no download record"
    }
  ],
  "resolutions": [
    {
      "action": "confidence_maintained",
      "reasoning": "File download occurred 2 minutes before history clearing. Attacker likely downloaded malware, then cleared evidence. Downloaded file is suspicious (.exe with generic name).",
      "original_confidence": 0.75,
      "adjusted_confidence": 0.75
    }
  ]
}
```

## Ground Truth

**True Positives:** 3
- Browser history was intentionally cleared (anti-forensics attempt)
- Cache was manually cleared (anti-forensics attempt)
- Suspicious file was downloaded before clearing

**False Positives:** 0
**False Negatives:** 0

**Expected Metrics:**
- Precision: 1.00
- Recall: 1.00
- F1 Score: 1.00

## Self-Correction Validation

**Contradiction Detection:**
- ✅ Prefetch exists but history is empty → Confidence reduced (0.80 → 0.50)
- ✅ Mass cache deletion pattern → Confidence reduced (0.60 → 0.40)
- ✅ Downloaded file without history record → Confidence maintained (legitimate concern)

**Reasoning Quality:**
- Engine correctly identifies that history clearing can be legitimate privacy behavior
- Engine correctly identifies that downloaded .exe after clearing is more suspicious
- Confidence adjustments are proportional to evidence strength

## Detection Logic

### Detector: BrowserTamperingDetector

```python
def detect(self, artifacts: Dict) -> List[Finding]:
    findings = []
    
    # Check if browser executed but history is empty
    if prefetch_shows_execution(artifacts) and history_is_empty(artifacts):
        finding = Finding(
            title="Browser History Cleared",
            confidence=0.80,
            evidence={...}
        )
        
        # Self-correction: Could be legitimate privacy clearing
        contradiction = Contradiction(
            type="execution_without_history",
            description="Prefetch shows execution, but history is empty"
        )
        finding.contradictions.append(contradiction)
        finding.confidence = 0.50  # Reduced
        
        findings.append(finding)
    
    # Check for mass cache deletion
    if mass_deletion_detected(artifacts, "Cache"):
        finding = Finding(
            title="Mass File Deletion: Chrome Cache",
            confidence=0.60,
            evidence={...}
        )
        
        # Self-correction: Manual clearing is common
        finding.confidence = 0.40  # Reduced
        findings.append(finding)
    
    # Check for downloads without history
    if downloads_exist(artifacts) and history_is_empty(artifacts):
        finding = Finding(
            title="Downloaded File After History Clearing",
            confidence=0.75,
            evidence={...}
        )
        findings.append(finding)
    
    return findings
```

## Testing

### Run Scenario
```bash
cd ~/Code/4n6_nexus
PYTHONPATH=. python3 tests/scenario_harness.py --scenario 13
```

### Expected Output
```
Scenario 13: Browser Artifact Tampering
  True Positives: 3
  False Positives: 0
  False Negatives: 0
  Precision: 1.00
  Recall: 1.00
  F1 Score: 1.00
  Status: ✅ PASS
```

## References

- **Browser Forensics:** https://www.sans.org/blog/browser-forensics/
- **Chrome Artifacts:** https://github.com/obsidianforensics/hindsight
- **Anti-Forensics Techniques:** SANS FOR508 Advanced Incident Response
