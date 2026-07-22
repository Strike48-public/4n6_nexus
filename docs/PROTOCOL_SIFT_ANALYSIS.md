# Protocol SIFT Analysis & Discovery

**Date:** 2026-04-16  
**Status:** Initial Discovery Complete  
**Repository:** https://github.com/teamdfir/protocol-sift  
**Author:** Rob Lee (SANS)

---

## Executive Summary

Protocol SIFT is **NOT an MCP server** in the traditional sense. It's a **Claude Code configuration package** that provides:
1. Global behavioral instructions (CLAUDE.md)
2. Pre-configured permissions for 200+ DFIR tools
3. Domain-specific skill files (prompt libraries)
4. Case templates for investigation workflows
5. PDF report generation utilities

**Key Insight:** Protocol SIFT uses **Claude Code's native skill system** + **direct CLI tool execution** rather than wrapping tools in MCP functions. This is simpler and more powerful than we initially assumed.

---

## What Protocol SIFT Actually Is

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Claude Code CLI                         │
│  (Direct agent, no MCP server needed for SIFT tools)       │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│              ~/.claude/CLAUDE.md (Global Config)            │
│  • Operator role: "Principal DFIR Orchestrator"             │
│  • Evidence integrity rules (read-only enforcement)         │
│  • Tool routing table (which skill to use for each domain)  │
│  • Installed tool paths                                     │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│           ~/.claude/settings.json (Permissions)             │
│  • Pre-approved: Volatility, Sleuth Kit, EZ Tools, Plaso    │
│  • Denied: rm -rf, dd, wget, curl, ssh, WebFetch           │
│  • Write restrictions: ./analysis/*, ./reports/*,           │
│                        ./exports/* only                     │
│  • Stop hook: Audit log to forensic_audit.log              │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│              ~/.claude/skills/ (Skill Files)                │
│  • memory-analysis/SKILL.md (Volatility 3 patterns)        │
│  • sleuthkit/SKILL.md (fls, icat, mmls, mactime)           │
│  • windows-artifacts/SKILL.md (EZ Tools, EVTX, Registry)   │
│  • plaso-timeline/SKILL.md (log2timeline, psort)           │
│  • yara-hunting/SKILL.md (YARA rules, IOC sweeps)          │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│          /cases/<CASENAME>/CLAUDE.md (Per-Case)            │
│  • Case overview, client, threat actor                      │
│  • Evidence files list                                      │
│  • Network topology                                         │
│  • Known IOCs                                               │
│  • Incident timeline                                        │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    SIFT Tools (Direct CLI)                  │
│  • Volatility 3: /opt/volatility3-2.20.0/vol.py            │
│  • EZ Tools: /opt/zimmermantools/*.dll                      │
│  • Sleuth Kit: fls, icat, mmls, mactime, tsk_recover       │
│  • Plaso: log2timeline.py, psort.py                        │
│  • YARA: /usr/local/bin/yara                                │
│  • bulk_extractor, photorec, ewftools                      │
└─────────────────────────────────────────────────────────────┘
```

---

## Available Tools (Confirmed)

### 1. Memory Analysis
**Skill File:** `~/.claude/skills/memory-analysis/SKILL.md`

**Tools:**
- Volatility 3 (`/opt/volatility3-2.20.0/vol.py`)
- Memory Baseliner (`/opt/memory-baseliner/baseline.py`)

**Capabilities:**
- Process listing (pslist, psscan, pstree)
- Network connections (netscan, netstat)
- Registry hives (hivelist, printkey)
- DLL/driver analysis
- Malware detection

### 2. Filesystem Forensics
**Skill File:** `~/.claude/skills/sleuthkit/SKILL.md`

**Tools:**
- Sleuth Kit: `fls`, `icat`, `ils`, `blkls`, `mactime`, `tsk_recover`
- EWF tools: `ewfmount`, `ewfinfo`, `ewfverify`

**Capabilities:**
- File listing (MFT parsing via fls)
- File recovery
- Timeline generation (MACB format)
- Partition analysis (mmls)
- Evidence mounting (read-only)

### 3. Windows Artifacts
**Skill File:** `~/.claude/skills/windows-artifacts/SKILL.md`

**Tools (EZ Tools):**
- MFTECmd (MFT parser)
- EvtxECmd (Windows Event Log parser)
- RECmd (Registry parser)
- PECmd (Prefetch parser)
- AmcacheParser
- JLECmd (Jump Lists)
- LECmd (LNK files)
- SBECmd (ShellBags)

**Capabilities:**
- **MFT analysis** ✅ (needed for cross-artifact validation)
- **Prefetch analysis** ✅ (needed for cross-artifact validation)
- **Event Log parsing** ✅ (needed for tiebreaker in contradictions)
- Registry artifacts
- Program execution evidence
- File access history

### 4. Timeline Generation
**Skill File:** `~/.claude/skills/plaso-timeline/SKILL.md`

**Tools:**
- Plaso: `log2timeline.py`, `psort.py`, `pinfo.py`

**Capabilities:**
- **Super-timeline generation** ✅ (our correlation requirement)
- Multi-source timeline merging
- Timeline filtering and sorting
- MACB format support

### 5. Threat Hunting
**Skill File:** `~/.claude/skills/yara-hunting/SKILL.md`

**Tools:**
- YARA (v4.1.0)
- bulk_extractor
- photorec (file carving)

**Capabilities:**
- YARA rule scanning
- IOC sweeps
- File carving
- Signature detection

---

## Critical Findings for Our Project

### ✅ What Protocol SIFT Provides

1. **All tools we need for cross-artifact validation:**
   - MFT parsing (MFTECmd)
   - Prefetch parsing (PECmd)
   - Event Log parsing (EvtxECmd)
   - Timeline merging (Plaso)

2. **Read-only enforcement via permissions:**
   - Write operations restricted to `./analysis/*`, `./reports/*`, `./exports/*`
   - Evidence directories (`/cases/`, `/mnt/`, `/media/`) are write-protected
   - Destructive commands (`rm -rf`, `dd`, `wget`, `curl`) are blocked

3. **Audit trail via Stop hook:**
   - Every conversation appends to `./analysis/forensic_audit.log`
   - Chain of custody documentation built-in

4. **Autonomous operation by default:**
   - "NEVER ask questions during a task" in global CLAUDE.md
   - Fully autonomous start-to-finish execution
   - No confirmations, no check-ins

### ❌ What Protocol SIFT Does NOT Provide

1. **No MCP server wrapper** - Tools are called directly via CLI, not through MCP functions
2. **No built-in self-correction** - No contradiction detection, no uncertainty budget
3. **No confidence scoring** - No automated assessment of finding reliability
4. **No cross-artifact validation** - No automated timestamp comparison
5. **No MITRE ATT&CK mapping** - No automated technique tagging

### 🎯 Implications for Our Project

**GOOD NEWS:**
- We don't need to build MCP wrappers - Protocol SIFT already handles tool access
- Read-only enforcement is already architectural (permissions system)
- Audit logging is already implemented (Stop hook)
- All required tools are available (MFT, Prefetch, Event Logs, Timeline)

**WHAT WE NEED TO ADD:**
- **Self-correction engine** (our innovation layer on top of Protocol SIFT)
- **Cross-artifact validation logic** (timestamp comparison, contradiction detection)
- **Confidence scoring system** (assess finding reliability)
- **Uncertainty budget tracking** (cumulative confidence monitoring)
- **Reasoning chain logging** (why each tool was chosen)
- **MITRE ATT&CK mapping** (automatic technique tagging)

---

## Architecture Realization

Our project should be:

```
┌─────────────────────────────────────────────────────────────┐
│        SIFT Find Evil (Our Innovation Layer)                │
│                                                              │
│  • Self-correction engine                                   │
│  • Cross-artifact validation                                │
│  • Confidence scoring                                       │
│  • Uncertainty budget                                       │
│  • Enhanced reasoning chains                                │
│  • MITRE ATT&CK mapping                                     │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│              Protocol SIFT (Foundation)                     │
│                                                              │
│  • Tool access (Volatility, Sleuth Kit, EZ Tools, Plaso)   │
│  • Read-only enforcement                                    │
│  • Basic audit logging                                      │
│  • Skill-based tool routing                                │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                Claude Code + SANS SIFT                      │
└─────────────────────────────────────────────────────────────┘
```

**Key Insight:** We're not building an MCP server. We're building a **self-correction layer** that enhances Protocol SIFT's autonomous capabilities with architectural guardrails for evidence integrity and reasoning transparency.

---

## Installation Requirements

### Prerequisites (from Protocol SIFT README)
1. SANS SIFT Workstation (Ubuntu x86-64) - Download OVA from sans.org/tools/sift-workstation
2. Claude Code CLI - `npm install -g @anthropic-ai/claude-code`
3. Anthropic API key - Set in `~/.claude/.credentials.json`
4. Python 3 + WeasyPrint - `pip3 install weasyprint`
5. dotnet runtime v6 - Pre-installed on SIFT

### Installation Command
```bash
curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash
```

### What Gets Installed
- `~/.claude/CLAUDE.md` - Global behavioral instructions
- `~/.claude/settings.json` - Tool permissions + Stop hook
- `~/.claude/settings.local.json` - Local overrides
- `~/.claude/skills/*` - 5 skill files (memory, sleuthkit, windows, plaso, yara)
- `~/.claude/case-templates/CLAUDE.md` - Per-case template
- `~/.claude/analysis-scripts/generate_pdf_report.py` - PDF generator

---

## Skills Deep Dive

Each skill file is a **prompt library** that Claude loads on demand before using tools in that domain.

### Memory Analysis Skill
**File:** `~/.claude/skills/memory-analysis/SKILL.md`

**Contents (likely):**
- Volatility 3 plugin list and usage
- Common memory analysis workflows
- Symbol resolution guidance
- Output interpretation patterns
- Known gotchas and workarounds

### Sleuth Kit Skill
**File:** `~/.claude/skills/sleuthkit/SKILL.md`

**Contents (likely):**
- fls usage for MFT parsing
- icat for file extraction
- mmls for partition tables
- mactime for timeline generation
- Evidence mounting patterns (ewfmount + loop mount)
- Offset calculation for NTFS partitions

### Windows Artifacts Skill
**File:** `~/.claude/skills/windows-artifacts/SKILL.md`

**Contents (likely):**
- EZ Tools invocation patterns
- MFTECmd flags and output format
- PECmd (Prefetch) parsing
- EvtxECmd (Event Logs) parsing
- Registry analysis with RECmd
- Timeline artifact correlation

### Plaso Timeline Skill
**File:** `~/.claude/skills/plaso-timeline/SKILL.md`

**Contents (likely):**
- log2timeline.py usage
- psort.py filtering and output
- Super-timeline generation workflow
- Timeline merging from multiple sources
- MACB format explanation

### YARA Hunting Skill
**File:** `~/.claude/skills/yara-hunting/SKILL.md`

**Contents (likely):**
- YARA rule syntax
- Scanning workflows
- IOC sweep patterns
- bulk_extractor usage

---

## Permission Model

### Allowed Tools (Pre-Approved)
From `~/.claude/settings.json`:
- Volatility 3
- Sleuth Kit (fls, icat, mmls, etc.)
- EZ Tools (all .dll executables)
- Plaso (log2timeline.py, psort.py)
- YARA
- bulk_extractor
- photorec
- ewftools
- Hash tools (md5sum, sha256sum)

### Denied Commands
- `rm -rf` (destructive)
- `dd` (can write to evidence)
- `wget`, `curl` (exfiltration risk)
- `ssh` (lateral movement)
- `WebFetch` (data exfiltration)

### Write Path Restrictions
**Allowed:**
- `./analysis/*`
- `./reports/*`
- `./exports/*`

**Blocked:**
- `/cases/*` (evidence directories)
- `/mnt/*` (mounted evidence)
- `/media/*` (removable media)
- `/` (root filesystem)

---

## Audit Trail System

### Stop Hook (from settings.json)
Every Claude Code conversation automatically appends to:
```
./analysis/forensic_audit.log
```

**Contents:**
- Conversation summary
- Tools executed
- Findings generated
- Timestamp of session

**Purpose:** Chain of custody documentation for legal defensibility

---

## Case Workflow (Protocol SIFT Pattern)

### 1. Create Case Directory
```bash
export CASE=CLIENT-IR-2025-001
mkdir -p /cases/${CASE}/{analysis,exports,reports}
cp ~/.claude/case-templates/CLAUDE.md /cases/${CASE}/CLAUDE.md
cp ~/.claude/analysis-scripts/generate_pdf_report.py /cases/${CASE}/analysis/
nano /cases/${CASE}/CLAUDE.md   # Customize case details
```

### 2. Mount Evidence
```bash
sudo mkdir -p /mnt/ewf_rd01 /mnt/rd01
sudo ewfmount /cases/${CASE}/suspect.E01 /mnt/ewf_rd01
OFFSET=$(sudo mmls /mnt/ewf_rd01/ewf1 | awk '/NTFS/{print $3; exit}')
sudo mount -o ro,loop,noatime,offset=$((OFFSET*512)) /mnt/ewf_rd01/ewf1 /mnt/rd01
```

### 3. Launch Claude
```bash
cd /cases/${CASE}
claude
```

### 4. Per-Case CLAUDE.md
The case-specific CLAUDE.md (loaded automatically when you `cd` into case directory) contains:
- Case overview (client, domain, threat actor, incident date)
- Evidence files list
- Common commands (pre-filled with image paths)
- Network topology
- Domain accounts
- Known IOCs
- Incident timeline (updated as analysis progresses)

---

## Gap Analysis vs. Our PRD

### ✅ Protocol SIFT Provides
- All forensic tools we need (MFT, Prefetch, Event Logs, Timeline, Memory)
- Read-only enforcement (architectural via permissions)
- Audit logging (Stop hook)
- Autonomous operation mode (no confirmations)
- Tool routing (skill system)

### ❌ We Need to Add
1. **Self-correction engine** - Contradiction detection, uncertainty budget, circuit breakers
2. **Cross-artifact validation** - Timestamp comparison logic
3. **Confidence scoring** - 0.0-1.0 scores for all findings
4. **Reasoning chain logging** - Why each tool was chosen (enhanced audit logs)
5. **MITRE ATT&CK mapping** - Automatic technique tagging
6. **Persistent learning** - IoC database across cases (stretch goal)
7. **Demo video capabilities** - Visual confidence meter, timeline visualization

---

## Next Steps

### Phase 1: Environment Setup (Now)
1. Download SIFT Workstation OVA
2. Import to VM
3. Install Protocol SIFT
4. Verify skill files are present
5. Test basic tool execution (fls, MFTECmd, EvtxECmd)

### Phase 2: Tool Testing (Tomorrow)
1. Download SANS starter case data (Egnyte link)
2. Mount evidence read-only
3. Execute basic forensic commands
4. Capture and parse outputs
5. Verify MFT, Prefetch, Event Log extraction works

### Phase 3: Self-Correction Prototype (This Week)
1. Extract timestamps from MFT (MFTECmd)
2. Extract timestamps from Prefetch (PECmd)
3. Compare timestamps programmatically
4. Detect contradictions
5. Log confidence degradation
6. Query Event Logs as tiebreaker (EvtxECmd)
7. Log resolution and confidence recovery

### Phase 4: Integration (Next Week)
1. Wrap self-correction logic in skill file
2. Add to Protocol SIFT configuration
3. Test on full case
4. Generate enhanced audit logs with reasoning chains
5. Measure autonomous execution quality

---

## Reference Implementation: Valhuntir

**Repository:** https://github.com/AppliedIR/Valhuntir  
**Author:** Steve Anson (SANS)

This is the "example submission" showing the quality level to meet/exceed for the hackathon.

**Next Action:** Clone and analyze Valhuntir architecture to learn from the winning pattern.

---

## Conclusion

**Protocol SIFT is a foundation, not a complete solution.**

It provides:
- Tool access
- Basic permissions
- Audit logging

We need to add:
- Self-correction intelligence
- Cross-artifact validation
- Confidence scoring
- Enhanced reasoning

Our competitive advantage is **architectural self-correction** layered on top of Protocol SIFT's autonomous execution foundation.

---

*Last Updated: 2026-04-16*
