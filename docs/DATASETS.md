# Test Datasets

**Last Updated:** 2026-06-15

> This is the authoritative "what was tested / source / what was found" document
> (FIND EVIL! Deliverable #5). For the per-finding accuracy self-assessment see
> [ACCURACY_REPORT.md](ACCURACY_REPORT.md).

This document describes all forensic datasets used for testing, validation, and accuracy reporting.

---

## Why this matters: the speed problem

The datasets below are not chosen to chase a benchmark score — they exist to prove
an agent can investigate at the pace modern threats demand.

In November 2025, Anthropic's security team published findings on **GTG-1002**, a
Chinese state-sponsored operation in which attackers drove **Claude Code** to run
autonomous reconnaissance, exploitation, and lateral movement at **80-90% autonomy**,
at request rates Anthropic described as **"physically impossible"** for human
operators. That is the offensive side of agentic AI; the SANS SIFT Workstation and
Protocol SIFT are the defensive platform, and FIND EVIL! exists to close the gap.

The gap is one of velocity. Manual command-line incident response cannot keep up
with autonomous agents executing thousands of requests:

| Signal | Figure | Source |
|--------|--------|--------|
| Fastest observed eCrime breakout time | **2 minutes 7 seconds** | CrowdStrike 2024 Threat Hunting Report |
| Average eCrime breakout time | **62 minutes** | CrowdStrike 2024 |
| Autonomous AI recon-to-exploit cycles | minutes, unattended | Horizon3 / industry red-team reporting |
| AI-augmented adversary speed multiplier | up to **~47x** faster than manual | MIT / academic red-team studies |

Breakout time is the window between initial foothold and lateral movement — the
minutes a defender has to detect, triage, and contain before the intrusion spreads.
When that window is measured in single-digit minutes, a human looking up
command-line flags has already lost.

**This drives our dataset strategy.** We test against (a) deterministic synthetic
fixtures that prove the detection logic is correct and regression-locked at machine
speed (F1 = 1.00 in CI, seconds per run), and (b) real, independently-sourced
evidence (CIRCL, Digital Corpora) that proves the same logic holds on genuine
artifacts. The agent's job is to do the senior-analyst reasoning — sequence the
approach, notice when artifacts disagree, self-correct — fast enough to matter
inside the breakout window. The per-finding accuracy self-assessment lives in
[ACCURACY_REPORT.md](ACCURACY_REPORT.md).

---

## Dataset Strategy

**Hybrid approach:**
1. **Synthetic scenarios** (`scenarios/synthetic/`) - Deterministic CSV fixtures covering the five core detection paths; used by the automated harness and CI.
2. **NIST CFReDS datasets** - Ground truth for accuracy report (Precision/Recall)
3. **SANS starter datasets** - Realistic cases with multiple artifact types
4. **Synthetic ransomware case** - Custom-built for demo video with known self-correction triggers

---

## 0. Synthetic Scenario Fixtures

Location: [`scenarios/synthetic/`](../scenarios/synthetic/README.md)

Five small CSV triples that exercise the self-correction engine deterministically:

| Scenario | Purpose |
|----------|---------|
| `01_clean_baseline` | Legitimate activity - must produce zero findings |
| `02_ransomware` | Three causality violations resolved via Event ID 4688 |
| `03_timestomping` | `$SI`/`$FN` discrepancy (critical, unresolved) |
| `04_edge_cases` | Tolerance boundary, null timestamps, future dates |
| `05_missing_prefetch` | Executable in MFT+Event Log but no Prefetch |

Run the harness:

```bash
PYTHONPATH=. python tests/scenario_harness.py
```

The harness writes precision/recall/F1 metrics to `analysis/scenario_report.json` and the corresponding summary is tracked in [`docs/ACCURACY_REPORT.md`](ACCURACY_REPORT.md).

---

## 1. NIST CFReDS - Hacking Case

**Purpose:** Ground truth for accuracy report (mandatory hackathon deliverable)

**Source:** https://cfreds.nist.gov/

**Scenario:** Windows system compromise with:
- Initial access via web exploit
- Lateral movement
- Data exfiltration
- Persistence mechanisms

**Evidence Files:**
- Disk image: `4del-1-flat.dd` (12 GB)
- Format: Raw disk image
- Filesystem: NTFS
- OS: Windows XP SP2 (historical, but well-documented)

**Ground Truth Artifacts:**
- Known malicious files (hashes, paths)
- Known attacker IP addresses
- Known timeline events (intrusion start time, data exfiltration time)
- Known attack techniques (documented by NIST)

**Expected Findings:**
- Hacker tools: `nc.exe` (Netcat), `psexec.exe`, `fgdump.exe`
- Evidence of lateral movement (net commands, shares)
- Exfiltrated files (SAM database, password hashes)
- Persistence: Registry RunKey, scheduled tasks

**Accuracy Metrics to Calculate:**
| Metric | Formula | Target |
|--------|---------|--------|
| Precision | TP / (TP + FP) | ≥85% |
| Recall | TP / (TP + FN) | ≥80% |
| F1 Score | 2 × (Precision × Recall) / (Precision + Recall) | ≥82% |

**Status:** To be downloaded and tested (Issue #9)

---

## 2. SANS Starter Datasets

**Purpose:** Realistic multi-artifact cases for development and testing

**Source:** SANS FIND EVIL! Hackathon organizers (TBD - to be provided)

**Expected Contents:**
- Disk images (E01 or DD format)
- Memory dumps (raw or VMEM format)
- Windows Event Logs (EVTX format)
- Network captures (PCAP format - optional)

**Scenarios Expected:**
- Ransomware infection
- Insider data theft
- APT lateral movement
- Web server compromise

**Usage:**
- Development: Test tool wrappers and correlation logic
- Integration testing: Verify end-to-end investigation flow
- Demo preparation: Familiarize with artifact types and analysis patterns

**Status:** Awaiting dataset release from SANS (Issue #9)

---

## 3. Synthetic Ransomware Case (Demo Video)

**Purpose:** Custom-built case with known self-correction triggers for compelling demo

**Scenario:** Ransomware infection with intentionally planted contradictions to demonstrate self-correction

**Evidence Files:**
- Disk image: `synthetic_ransomware_v1.dd` (10 GB)
- Memory dump: `synthetic_ransomware_v1.raw` (8 GB)
- Event Logs: `synthetic_ransomware_v1_eventlogs/` directory

**Planted Artifacts:**

### 3.1 Timestamp Contradiction (Self-Correction Trigger #1)
- **MFT:** `C:\Users\victim\ransom_note.txt` modified at 2026-04-15 10:00:00
- **Prefetch:** `C:\Temp\evil.exe` last run at 2026-04-15 09:55:00
- **Event Log 4688:** Process `evil.exe` (PID 1234) created at 2026-04-15 09:55:03
- **Expected:** Agent detects contradiction, queries Event Log, resolves in favor of Prefetch

### 3.2 Low-Confidence Findings (Self-Correction Trigger #2)
- Multiple findings with confidence scores: 0.70, 0.65, 0.62, 0.60, 0.58
- Average confidence: 0.63 → Uncertainty: 0.37 (exceeds 0.25 threshold)
- **Expected:** Agent triggers uncertainty budget re-analysis

### 3.3 Tool Failure Scenario (Self-Correction Trigger #3)
- Corrupted Prefetch file: `evil.exe-ABC123.pf` (invalid format)
- **Expected:** Agent attempts to parse, fails, opens circuit breaker, falls back to Event Logs

### 3.4 Actual Ransomware Indicators
- Ransom notes: `README.txt`, `decrypt.html` in multiple directories
- Encrypted files: `.locked` extension on 500+ files
- Ransomware executable: `C:\Temp\evil.exe` (custom-built, not real malware)
- Registry persistence: `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Evil`
- Bitcoin payment address in ransom notes
- File encryption timeline: 2026-04-15 09:56:00 to 10:15:00 (19 minutes)

**Ground Truth (for validation):**
```json
{
  "case_id": "synthetic_ransomware_v1",
  "attack_type": "ransomware",
  "timeline": {
    "initial_access": "2026-04-15T09:55:00Z",
    "execution": "2026-04-15T09:55:03Z",
    "encryption_start": "2026-04-15T09:56:00Z",
    "encryption_end": "2026-04-15T10:15:00Z"
  },
  "iocs": {
    "files": [
      {
        "path": "C:\\Temp\\evil.exe",
        "hash": "abc123def456...",
        "type": "ransomware_executable"
      },
      {
        "path": "C:\\Users\\victim\\README.txt",
        "hash": "def789ghi012...",
        "type": "ransom_note"
      }
    ],
    "registry": [
      {
        "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil",
        "value": "C:\\Temp\\evil.exe",
        "type": "persistence"
      }
    ],
    "bitcoin_addresses": [
      "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    ]
  },
  "self_correction_triggers": [
    {
      "type": "timestamp_contradiction",
      "description": "MFT timestamp 10:00 vs Prefetch 09:55"
    },
    {
      "type": "uncertainty_budget",
      "description": "Multiple low-confidence findings (avg 0.63)"
    },
    {
      "type": "tool_failure",
      "description": "Corrupted Prefetch file"
    }
  ]
}
```

**Creation Process:**
1. Start with clean Windows VM (Windows 10)
2. Plant "ransomware" (actually harmless script that renames files to `.locked`)
3. Create ransom notes with payment addresses
4. Add registry persistence key
5. Modify MFT timestamp using PowerShell (to create contradiction)
6. Corrupt one Prefetch file (to trigger tool failure)
7. Create memory dump using DumpIt or FTK Imager
8. Export Event Logs
9. Create disk image using FTK Imager or dd
10. Verify all self-correction triggers are present

**Status:** To be created (Issue #9)

---

## Dataset Directory Structure

```
/evidence/
├── nist_cfrids_hacking/
│   ├── 4del-1-flat.dd           # Disk image (12 GB)
│   ├── ground_truth.json        # Known IoCs and timeline
│   └── README.txt               # NIST documentation
│
├── sans_starter_case_1/
│   ├── disk.E01                 # Disk image
│   ├── memory.vmem              # Memory dump
│   ├── eventlogs/               # Windows Event Logs
│   │   ├── Security.evtx
│   │   ├── System.evtx
│   │   └── Application.evtx
│   └── README.txt
│
├── sans_starter_case_2/
│   └── ...
│
└── synthetic_ransomware_v1/
    ├── disk.dd                  # Disk image (10 GB)
    ├── memory.raw               # Memory dump (8 GB)
    ├── eventlogs/               # Windows Event Logs
    ├── ground_truth.json        # Known IoCs and self-correction triggers
    └── README.txt
```

**Note:** Evidence files are **gitignored** due to large size. Store in `/evidence/` directory locally.

---

## Dataset Download & Setup Instructions

### NIST CFReDS Hacking Case

```bash
# Download from NIST
wget https://cfreds.nist.gov/4del/4del-1-flat.dd.bz2

# Extract
bunzip2 4del-1-flat.dd.bz2

# Verify checksum (from NIST docs)
sha256sum 4del-1-flat.dd
# Expected: [checksum from NIST]

# Move to evidence directory
mv 4del-1-flat.dd /evidence/nist_cfrids_hacking/
```

### SANS Starter Datasets

```bash
# To be provided by SANS organizers
# Instructions will be updated when datasets are released
```

### Synthetic Ransomware Case

```bash
# Creation instructions in separate script
# See: scripts/create_synthetic_case.sh
```

---

## Dataset Usage in Testing

### Unit Tests
- Use small, synthetic files (not full disk images)
- Mock MCP tool responses with known outputs
- Focus on logic, not actual forensic tool execution

### Integration Tests
- Use full synthetic ransomware case
- Verify end-to-end investigation flow
- Test all self-correction triggers

### Accuracy Report
- Use NIST CFReDS Hacking Case
- Calculate Precision, Recall, F1 Score
- Compare agent findings to ground truth
- Generate confusion matrix

---

## Accuracy Report Template

```markdown
# Accuracy Report - NIST CFReDS Hacking Case

## Test Configuration
- Dataset: NIST CFReDS - 4del-1-flat.dd
- Agent version: v1.0-hackathon
- Test date: 2026-06-05
- Investigation time: 28 minutes

## Ground Truth vs. Findings

### True Positives (TP): 12
- nc.exe (Netcat) - Correctly identified as hacker tool
- psexec.exe - Correctly identified as lateral movement tool
- fgdump.exe - Correctly identified as credential dumper
- [... 9 more]

### False Positives (FP): 2
- notepad.exe flagged as suspicious (legitimate Windows utility)
- cmd.exe flagged as suspicious (legitimate, but used by attacker)

### False Negatives (FN): 3
- Attacker IP 192.168.1.100 not identified (missing network artifact analysis)
- Scheduled task persistence not detected (Event Log parsing incomplete)
- Exfiltrated file timestamps not flagged

## Metrics

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| Precision | 85.7% (12 / 14) | ≥85% | ✅ PASS |
| Recall | 80.0% (12 / 15) | ≥80% | ✅ PASS |
| F1 Score | 82.8% | ≥82% | ✅ PASS |

## Analysis

**Why did we miss 3 IoCs (FN)?**
1. Network artifact analysis not yet implemented (MVP scope)
2. Event Log parsing incomplete for scheduled tasks
3. File exfiltration detection requires network + timeline correlation (Phase 2)

**Why did we flag 2 false positives (FP)?**
1. Notepad.exe: Heuristic flagged due to unusual access patterns (rare file opened)
2. Cmd.exe: Legitimate, but used by attacker - difficult to distinguish without behavioral analysis

## Conclusion

Agent meets accuracy targets for MVP. False negatives are due to scope limitations (network analysis, advanced correlation). False positives are acceptable for triage phase (human analyst would quickly dismiss).
```

---

*Datasets are the foundation of our accuracy claims. Must be documented, reproducible, and diverse.*
