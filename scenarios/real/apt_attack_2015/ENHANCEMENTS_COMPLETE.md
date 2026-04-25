# Detection Engine Enhancements - Complete

**Date:** 2026-04-25  
**Status:** ✅ COMPLETE

---

## Summary

Enhanced the self-correction engine with three major improvements:
1. **Positive confidence boost for Event Log confirmations**
2. **Scaled confidence by execution frequency**
3. **Command line attack pattern detection**

---

## Enhancement 1: Positive Confidence Boost

### Before
- Event Log confirmation just reduced penalty (-0.10 vs -0.30)
- No recognition that Event ID 4688 is ground truth

### After
- Event Log confirmation provides **scaled confidence boost**:
  - **1 execution:** -0.10 penalty (LOW severity)
  - **2-5 executions:** -0.08 penalty (LOW severity)
  - **6+ executions:** -0.05 penalty (INFO severity, system service pattern)

### Impact
- System services (VMware tools, etc.) now get **INFO severity** instead of LOW/MEDIUM
- Multi-execution processes get higher confidence
- Better distinction between "suspicious" vs "legitimate system behavior"

---

## Enhancement 2: Command Line Attack Pattern Detection

### Capabilities

**New module:** `attack_pattern_detector.py`

**Detection categories:**
1. **Reconnaissance** (T1087, T1082, T1016, T1049, T1033, T1057, T1018)
   - netstat, ipconfig, whoami, systeminfo
   - net user/group/share, tasklist, quser
   - nltest domain controller enumeration

2. **PowerShell Attack Patterns** (T1059.001, T1027)
   - Download cradles (IEX, DownloadString)
   - Encoded commands (-enc, -encodedcommand)
   - Hidden execution (-nop, -windowstyle hidden)
   - Invoke-Mimikatz, Invoke-ReflectivePEInjection

3. **Credential Dumping** (T1003)
   - Mimikatz
   - LSASS memory dumps (procdump)
   - Registry hive exports (SAM, SYSTEM, SECURITY)
   - Volume shadow copies (vssadmin)
   - NTDS.dit extraction (ntdsutil)

4. **Lateral Movement** (T1021, T1047, T1570)
   - PsExec
   - WMI remote execution
   - Remote service manipulation
   - PowerShell remoting

5. **LOLBins Abuse** (T1218, T1105)
   - certutil download
   - bitsadmin transfer
   - rundll32 JavaScript
   - mshta remote execution
   - regsvr32 Squiblydoo

6. **Persistence** (T1053, T1547, T1543)
   - Scheduled tasks
   - Registry Run keys
   - Service creation

7. **Exfiltration** (T1560, T1048)
   - Password-protected archives
   - Automated FTP uploads

### Output Format

**Example finding:**
```json
{
  "title": "Attack Pattern: Network connection enumeration",
  "description": "Detected reconnaissance activity in command line:\nC:\\Windows\\System32\\NETSTAT.EXE netstat -an",
  "type": "behavior",
  "severity": "medium",
  "category": "reconnaissance",
  "evidence": {
    "executable": "NETSTAT.EXE",
    "command_line": "netstat -an",
    "technique": "reconnaissance",
    "mitre_id": "T1049",
    "pattern_name": "Network connection enumeration",
    "event_id": 4688,
    "time_created": "2018-07-16T19:05:25.560509+00:00"
  },
  "confidence": 0.85,
  "confidence_label": "High",
  "reasoning_chain": [
    "Event ID 4688 captured process execution",
    "Command line matches pattern: Network connection enumeration",
    "MITRE ATT&CK Technique: T1049",
    "Confidence: 0.85 (pattern-based detection)"
  ]
}
```

---

## Enhancement 3: New Finding Categories

**Added to `FindingCategory` enum:**
- `RECONNAISSANCE` - System/network enumeration
- `CREDENTIAL_ACCESS` - Credential dumping/theft
- `EXECUTION` - Script/command execution
- `COMMAND_AND_CONTROL` - C2 communication

**Existing categories used:**
- `LATERAL_MOVEMENT` - PsExec, WMI, remoting
- `PERSISTENCE` - Tasks, services, Run keys
- `ANTI_FORENSICS` - Defense evasion, LOLBins
- `DATA_EXFILTRATION` - Archive creation, FTP uploads

---

## Expected Results on DMZ FTP Server

### Before Enhancements
- 922 findings, all "missing Prefetch"
- Average confidence: 0.20
- Max confidence: 0.80
- No attack behavior detection

### After Enhancements
- **System service findings:** INFO severity, 0.85-0.90 confidence
- **Reconnaissance detected:** 
  - `netstat -an | findstr 21` (Network enumeration)
  - Confidence: 0.85, Severity: MEDIUM
- **Attack chain visibility:** Full command line context with MITRE ATT&CK mapping

---

## Code Changes

### Files Modified
1. `sift_find_evil/self_correction/contradiction_detector.py`
   - Enhanced `detect_missing_execution_artifact()` with scaled penalties
   - Added execution frequency thresholds (1, 2-5, 6+)

2. `sift_find_evil/self_correction/engine.py`
   - Added `AttackPatternDetector` initialization
   - Added `_detect_attack_patterns()` method
   - Added `_pattern_to_category()` mapper

3. `sift_find_evil/parsers/evtx_parser.py`
   - Added JSON payload parsing for Event ID 4688
   - Enhanced `get_process_name()` to extract from `NewProcessName` field
   - Added `payload_json` field to `EventLogEntry`

4. `sift_find_evil/findings/categories.py`
   - Added 4 new finding categories with documentation

### Files Created
1. `sift_find_evil/self_correction/attack_pattern_detector.py`
   - 7 pattern categories with 40+ detection rules
   - MITRE ATT&CK technique mapping
   - Confidence scoring per pattern
   - Severity assignment logic

---

## Ready for Option 2

All enhancements complete. Ready to analyze all 7 systems:

```bash
cd ~/Code/sift_find_evil/scenarios/real/apt_attack_2015/
./analyze_all_systems.sh
```

**Expected outcomes across 7 systems:**
- Reconnaissance commands detected on DMZ FTP server
- Lateral movement tools (PsExec) on workstations
- Credential dumping attempts on Domain Controller
- Full attack chain reconstruction with MITRE ATT&CK mapping
- High-confidence findings (0.85-0.98) for actual attack behavior
- Low-confidence findings (0.15-0.30) for legitimate system activity

---

## Competition Value

**For judges/demo:**

✅ **Pattern-based attack detection** - 40+ attack patterns across 7 MITRE categories  
✅ **MITRE ATT&CK mapping** - Every attack finding tagged with technique ID  
✅ **Confidence scoring** - 0.85-0.98 for attack patterns, scaled by evidence strength  
✅ **Command line forensics** - Full visibility into attacker commands  
✅ **Attack chain reconstruction** - Timeline + command lines + cross-system correlation  

**Key talking points:**
1. "Detects actual attack behavior, not just missing artifacts"
2. "Every finding mapped to MITRE ATT&CK framework"
3. "Reconnaissance commands (netstat, whoami) automatically flagged"
4. "PowerShell attack patterns (encoded commands, download cradles) detected"
5. "Lateral movement tools (PsExec, WMI) identified with high confidence"

---

**Status:** ✅ All 3 enhancements COMPLETE  
**Next:** Option 2 (analyze all 7 systems)  
**ETA:** Ready immediately
