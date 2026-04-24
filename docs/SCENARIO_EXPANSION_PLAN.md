# Scenario Expansion Plan: 12 → 20 Scenarios

**Goal:** Increase test scenarios from 12 to 20 to demonstrate comprehensive validation
**Timeline:** Complete before competition submission (June 15, 2026)
**Status:** Planning

---

## Strategy Rationale

**Why expand scenarios instead of adding Linux/macOS:**
- ✅ Lower risk (Windows-only maintains F1=1.00)
- ✅ Faster implementation (2-3 weeks vs 4-6 weeks)
- ✅ Shows thoroughness and comprehensive testing
- ✅ Demonstrates system works across many attack types
- ✅ More compelling: "F1=1.00 across 20 scenarios" vs "12 scenarios + incomplete multi-OS"
- ✅ Tests different aspects of self-correction engine

**What judges will see:**
- 20 validated test scenarios (not just 12)
- Real evidence (155K entries) + comprehensive synthetic coverage
- Perfect accuracy across diverse attack types
- Thorough validation methodology

---

## Current Scenarios (12)

| # | Scenario | Type | Status |
|---|----------|------|--------|
| 1 | Clean Windows baseline | Baseline | ✅ Tested |
| 2 | Timestomping detection | Anti-forensics | ✅ Tested |
| 3 | Hidden files (Windows) | Anti-forensics | ✅ Tested |
| 4 | Suspicious extensions (.exe masquerading) | Malware | ✅ Tested |
| 5 | Zero-byte executables | Malware | ✅ Tested |
| 6 | Timeline inconsistencies | Anti-forensics | ✅ Tested |
| 7 | Ransomware (Windows) | Malware | ✅ Tested |
| 8 | Lateral movement (Windows network) | Intrusion | ✅ Tested |
| 9 | Data exfiltration (Windows) | Intrusion | ✅ Tested |
| 10 | Privilege escalation (Windows Registry) | Intrusion | ✅ Tested |
| 11 | Memory intrusion (Windows processes) | Intrusion | ✅ Tested |
| 12 | Insider threat (real Windows image) | Real Evidence | ✅ Tested |

**Coverage:**
- Anti-forensics: 3 scenarios
- Malware: 3 scenarios
- Intrusion: 4 scenarios
- Baseline: 1 scenario
- Real Evidence: 1 scenario

---

## New Scenarios (8 Additional)

### Scenario 13: Browser Artifact Tampering

**Type:** Anti-forensics
**Description:** Attacker clears browser history, cookies, and cache to hide web activity

**Artifacts:**
- Deleted Chrome history (but SQLite journal remains)
- Cleared cookies (but cookie timestamps in Registry)
- Cache files deleted (but Prefetch shows browser access)

**Expected Findings:**
- Browser history deletion detected
- Contradiction: Prefetch shows browser.exe execution but no history
- Self-correction: Confidence reduced (0.80 → 0.50) - could be legitimate privacy clearing

**Ground Truth:**
- True Positive: Browser history was deliberately cleared

**Implementation Effort:** 2-3 days

---

### Scenario 14: USB Device Activity (Unauthorized Data Transfer)

**Type:** Data exfiltration
**Description:** Insider copies sensitive files to USB drive

**Artifacts:**
- USB device Registry entries (USBSTOR)
- File copy timestamps to USB drive letter
- MFT records show large file deletions after USB insertion
- Windows Event Log: USB device connection

**Expected Findings:**
- USB device connected at specific time
- Large files copied to removable drive
- Files deleted from internal drive after copy
- Timeline correlation: USB insertion → file copy → file deletion

**Self-correction:**
- Confidence high (0.90) when all artifacts align
- Confidence reduced (0.65) if only USB insertion detected (could be legitimate)

**Ground Truth:**
- True Positive: Unauthorized data transfer occurred

**Implementation Effort:** 3-4 days

---

### Scenario 15: Scheduled Task Persistence

**Type:** Malware persistence
**Description:** Malware creates scheduled task to maintain persistence

**Artifacts:**
- Scheduled Task XML in `C:\Windows\System32\Tasks\`
- Registry entries for task scheduling
- Prefetch for task execution
- Event Log: Task creation and execution

**Expected Findings:**
- New scheduled task created
- Task executes suspicious binary
- No legitimate software installation (no MSI logs)
- Self-correction: Legitimate software also creates tasks, confidence adjusted

**Ground Truth:**
- True Positive: Malware persistence mechanism

**Implementation Effort:** 2-3 days

---

### Scenario 16: PowerShell Script Execution (Obfuscated)

**Type:** Malware execution
**Description:** Attacker runs obfuscated PowerShell script

**Artifacts:**
- PowerShell event logs (Script Block Logging)
- Prefetch for powershell.exe
- Unusual command-line arguments (Base64 encoded)
- No associated legitimate executable

**Expected Findings:**
- PowerShell execution detected
- Obfuscated command detected (Base64, compression)
- No parent process (spawned remotely or via WMI)
- Self-correction: PowerShell is also used legitimately, check context

**Ground Truth:**
- True Positive: Malicious PowerShell execution

**Implementation Effort:** 2-3 days

---

### Scenario 17: Network Share Access (Lateral Movement)

**Type:** Intrusion - Lateral movement
**Description:** Attacker accesses network shares on other systems

**Artifacts:**
- SMB connection logs (Event ID 5140, 5145)
- Remote file access via UNC paths
- Credential usage (Event ID 4624, 4625)
- MFT records show network share access

**Expected Findings:**
- Unusual network share access
- Lateral movement pattern (multiple systems accessed)
- Credential reuse detected
- Self-correction: Legitimate admin activity also uses network shares

**Ground Truth:**
- True Positive: Lateral movement via SMB

**Implementation Effort:** 3-4 days

---

### Scenario 18: Shadow Copy Deletion (Anti-forensics)

**Type:** Anti-forensics
**Description:** Ransomware deletes Volume Shadow Copies to prevent recovery

**Artifacts:**
- `vssadmin.exe` or `wmic.exe` execution (Prefetch)
- Event Log: Volume Shadow Copy deletion (Event ID 8222)
- Timeline: Shadow copy deletion before file encryption
- Command-line arguments captured

**Expected Findings:**
- Shadow copy deletion detected
- Executed by non-system process (suspicious)
- Timeline correlation with file modifications (ransomware)
- Self-correction: Confidence high (0.95) - legitimate admins rarely delete all shadow copies

**Ground Truth:**
- True Positive: Anti-forensics technique (ransomware)

**Implementation Effort:** 2-3 days

---

### Scenario 19: Credential Dumping (LSASS Access)

**Type:** Intrusion - Privilege escalation
**Description:** Attacker dumps credentials from LSASS process

**Artifacts:**
- Suspicious process accessed LSASS.exe (Event ID 10, Sysmon)
- MiniDump file created (memory dump)
- Tools: Mimikatz, ProcDump, Comsvcs.dll
- Timeline: LSASS access → privilege escalation actions

**Expected Findings:**
- LSASS memory access detected
- Known credential dumping tool signatures
- Subsequent privilege escalation (supports credential theft)
- Self-correction: Some legitimate tools access LSASS (antiviruses)

**Ground Truth:**
- True Positive: Credential theft

**Implementation Effort:** 3-4 days

---

### Scenario 20: File Slack Space Hiding

**Type:** Anti-forensics / Data hiding
**Description:** Attacker hides data in NTFS file slack space

**Artifacts:**
- File size vs allocated size mismatch (MFT analysis)
- File slack contains non-zero data
- Timeline: File modified after initial creation
- No legitimate reason for slack space usage

**Expected Findings:**
- Data in file slack space detected
- File appears normal in directory listing
- Hidden data could be malware, credentials, or exfiltration staging
- Self-correction: Some legitimate scenarios create slack space (file truncation)

**Ground Truth:**
- True Positive: Data hiding in slack space

**Implementation Effort:** 3-4 days

---

## Implementation Summary

### New Scenario Breakdown by Type

| Type | Scenarios | Total |
|------|-----------|-------|
| **Anti-forensics** | 13 (Browser), 18 (Shadow Copy), 20 (Slack Space) | 3 |
| **Malware** | 15 (Scheduled Task), 16 (PowerShell) | 2 |
| **Intrusion** | 17 (Network Share), 19 (Credential Dumping) | 2 |
| **Data Exfiltration** | 14 (USB Device) | 1 |

### Final Coverage (20 Scenarios)

| Type | Count | Percentage |
|------|-------|------------|
| Anti-forensics | 6 | 30% |
| Malware | 5 | 25% |
| Intrusion | 6 | 30% |
| Data Exfiltration | 2 | 10% |
| Baseline | 1 | 5% |

**Balanced coverage** across all major DFIR categories.

---

## Implementation Timeline

### Week 1 (Apr 24 - Apr 30): Quick Wins
- [ ] Scenario 13: Browser artifact tampering (2-3 days)
- [ ] Scenario 15: Scheduled task persistence (2-3 days)
- [ ] Scenario 18: Shadow copy deletion (2-3 days)

**Deliverable:** 3 new scenarios (15 total)

### Week 2 (May 1 - May 7): Medium Complexity
- [ ] Scenario 16: PowerShell script execution (2-3 days)
- [ ] Scenario 14: USB device activity (3-4 days)

**Deliverable:** 2 new scenarios (17 total)

### Week 3 (May 8 - May 14): Advanced Scenarios
- [ ] Scenario 17: Network share access (3-4 days)
- [ ] Scenario 19: Credential dumping (3-4 days)

**Deliverable:** 2 new scenarios (19 total)

### Week 4 (May 15 - May 21): Final Scenario + Buffer
- [ ] Scenario 20: File slack space hiding (3-4 days)
- [ ] Testing and validation (2-3 days)

**Deliverable:** 1 new scenario (20 total)

### Week 5 (May 22 - May 28): Testing & Polish
- [ ] Run all 20 scenarios
- [ ] Verify F1=1.00 maintained
- [ ] Update accuracy report
- [ ] Fix any bugs

### Week 6 (May 29 - June 4): Demo Video
- [ ] Record demo video
- [ ] Edit and finalize
- [ ] Upload to YouTube

### Week 7 (June 5 - June 11): Final Review & Submit
- [ ] Final documentation review
- [ ] Team sign-off
- [ ] Submit to Devpost (by June 15)

**Buffer:** 4 days before deadline

---

## Scenario Creation Process

### 1. Define Attack Scenario
- What happened?
- What artifacts are left?
- What is the attacker's goal?

### 2. Create Synthetic Fixtures
```bash
scenarios/synthetic/13_browser_tampering/
├── evidence/
│   ├── mft_fixture.csv          # MFT entries for browser files
│   ├── registry_fixture.json    # Registry keys for browser
│   ├── prefetch_fixture.csv     # Prefetch for browser.exe
│   └── eventlog_fixture.json    # Event logs
├── ground_truth.json            # Expected findings
└── README.md                    # Scenario description
```

### 3. Create Detector (If Needed)
```python
# sift_find_evil/detectors/browser_tampering.py
class BrowserTamperingDetector(BaseDetector):
    def detect(self, artifacts: Dict) -> List[Finding]:
        # Look for cleared history but Prefetch exists
        # Contradiction: User cleared history but browser ran
        pass
```

### 4. Test Against Fixtures
```bash
pytest tests/test_scenario_13_browser_tampering.py
```

### 5. Validate F1 Score
```bash
PYTHONPATH=. python3 tests/scenario_harness.py --scenario 13
# Should output: F1=1.00
```

### 6. Update Accuracy Report
```json
{
  "scenario_id": 13,
  "name": "Browser Artifact Tampering",
  "true_positives": 1,
  "false_positives": 0,
  "false_negatives": 0,
  "precision": 1.0,
  "recall": 1.0,
  "f1": 1.0
}
```

---

## Self-Correction Examples for New Scenarios

### Scenario 13: Browser Tampering
```json
{
  "finding": "Browser History Cleared",
  "initial_confidence": 0.80,
  "contradiction": {
    "type": "legitimate_use_possible",
    "description": "Prefetch shows browser execution, but history could be legitimately cleared for privacy"
  },
  "adjusted_confidence": 0.50,
  "reasoning": "Cannot definitively prove malicious intent. User privacy clearing is common."
}
```

### Scenario 18: Shadow Copy Deletion
```json
{
  "finding": "All Shadow Copies Deleted",
  "initial_confidence": 0.85,
  "supporting_evidence": {
    "type": "timeline_correlation",
    "description": "Shadow copy deletion immediately preceded mass file encryption"
  },
  "adjusted_confidence": 0.95,
  "reasoning": "Timeline correlation with ransomware activity increases confidence"
}
```

---

## Quality Metrics

### Target Metrics (20 Scenarios)
- **Overall F1 Score:** 1.00 (perfect precision and recall)
- **True Positives:** 20 (one per scenario)
- **False Positives:** 0
- **False Negatives:** 0

### Per-Scenario Requirements
- Each scenario must have ground truth
- Each scenario must test different detection logic
- Each scenario should demonstrate self-correction
- Each scenario must be reproducible

---

## Documentation Updates Needed

### Update These Files:
1. **README_COMMUNITY.md**
   - Change "12 validation scenarios" → "20 validation scenarios"
   - Update test results section

2. **EVIDENCE_COMPATIBILITY.md**
   - Expand synthetic scenarios list (12 → 20)
   - Add new scenario descriptions

3. **OPEN_SOURCE_STRATEGY.md**
   - Update validation testing section

4. **PRE_FLIGHT_CHECKLIST.md**
   - Update competition requirements (20 scenarios)

5. **DOCUMENTATION_INDEX.md**
   - Add reference to SCENARIO_EXPANSION_PLAN.md

---

## Risk Assessment

### Low Risk
- All scenarios are Windows-based (existing detector framework)
- Synthetic fixtures (controlled, reproducible)
- Can test incrementally (15, 17, 19, 20)

### Medium Risk
- Time pressure (5 weeks of development)
- Each new scenario could introduce bugs
- Must maintain F1=1.00 across all scenarios

### Mitigation
- Test each scenario individually before adding to harness
- Keep existing 12 scenarios passing at all times
- Add new scenarios incrementally (don't batch)
- Automated testing after each addition

---

## Success Criteria

**Must achieve before competition:**
- [ ] 20 scenarios implemented
- [ ] All scenarios have synthetic fixtures
- [ ] Ground truth defined for each scenario
- [ ] F1=1.00 maintained across all 20 scenarios
- [ ] Self-correction demonstrated in at least 15 scenarios
- [ ] Documentation updated
- [ ] Accuracy report updated
- [ ] Demo video includes mention of 20 scenarios

---

## Fallback Plan

**If timeline is too tight:**
- **Minimum:** 16 scenarios (4 new scenarios instead of 8)
- **Focus on:** Quick wins (Browser, Scheduled Task, Shadow Copy, PowerShell)
- **Still impressive:** 16 scenarios with F1=1.00

**Decision point:** May 15 (3 weeks in)
- If <18 scenarios complete, cut scope to 16
- If 18+ scenarios complete, push for 20

---

## Team Assignments (Suggested)

**Developer 1: Anti-forensics scenarios**
- Scenario 13: Browser tampering
- Scenario 18: Shadow copy deletion
- Scenario 20: File slack space

**Developer 2: Malware scenarios**
- Scenario 15: Scheduled task persistence
- Scenario 16: PowerShell execution

**Developer 3: Intrusion scenarios**
- Scenario 14: USB device activity
- Scenario 17: Network share access
- Scenario 19: Credential dumping

**Lead:** Integration testing, F1 validation, documentation updates

---

**Document Owner:** Core Team
**Status:** Approved for implementation
**Next Review:** May 15, 2026 (midpoint check)
