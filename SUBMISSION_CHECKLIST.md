# FIND EVIL! Hackathon Submission Checklist

**Deadline:** June 15, 2026 11:45 PM EDT

---

## Required Deliverables

### 1. Code Repository ✅
- [x] Public GitHub repository: https://github.com/Strike48/sift_find_evil
- [x] MIT License file in root (visible in About section)
- [x] README.md with setup instructions
- [x] All source code, assets, and dependencies included
- [x] Functional and testable

**Verification:**
```bash
git remote -v
cat LICENSE
cat README.md | grep -A 10 "Installation"
```

### 2. Deployment Instructions ✅
- [x] Live deployment URL OR local setup instructions
- [x] Step-by-step setup in README.md
- [x] Dependencies documented (Python 3.12+, SIFT tools)
- [x] DEPLOY_TO_SIFT.md for SIFT OVA deployment

**Files:** `README.md`, `DEPLOY_TO_SIFT.md`

### 3. Text Description ✅
- [x] Features and functionality explained
- [x] README.md includes:
  - Project overview
  - Detection accuracy table (F1=1.00)
  - CLI usage examples
  - Architecture overview

**File:** `README.md` (902 lines)

### 4. Demo Video ❌ CRITICAL
- [ ] Less than 5 minutes duration
- [ ] Live terminal screencast (NOT slides)
- [ ] Shows agent working against real evidence
- [ ] Includes at least one self-correction sequence
- [ ] Audio narration throughout
- [ ] Uploaded to YouTube/Vimeo/Youku
- [ ] Link added to Devpost submission form

**Requirements:**
- Screencast of live terminal execution
- Real evidence: insider_threat_2022/Narcos-CCleaner.E01
- Show self-correction examples from 1,071 findings
- No third-party trademarks or copyrighted music

**Script:** `docs/DEMO_RECORDING_VERIFIED.md`

**Recording Checklist:**
- [ ] SIFT VM running with evidence mounted
- [ ] Terminal font size increased for readability
- [ ] OBS/screen recording configured (1080p, 30fps)
- [ ] Audio microphone tested (-18dB to -12dB)
- [ ] Split screen: terminal (top) + audit log (bottom)
- [ ] Test run completed successfully
- [ ] Final recording <5 minutes
- [ ] Video uploaded and link obtained

### 5. Architecture Diagram ✅
- [x] Clear visual showing component connections
- [x] Agent, SIFT tools, MCP servers, evidence sources, output pipeline
- [x] Mermaid diagrams in docs/ARCHITECTURE_DIAGRAM.md
- [x] GitHub renders Mermaid automatically

**File:** `docs/ARCHITECTURE_DIAGRAM.md`

**Optional:** Export PNG/SVG if judges require standalone image
```bash
# Via Mermaid CLI
npm install -g @mermaid-js/mermaid-cli
mmdc -i docs/ARCHITECTURE_DIAGRAM.md -o docs/architecture.png

# OR use https://mermaid.live/ to export manually
```

### 6. Evidence Dataset Documentation ✅
- [x] What agent was tested against
- [x] Source of data
- [x] What agent found

**Evidence Tested:**
1. **insider_threat_2022/Narcos-CCleaner.E01** (7.7GB, real forensic image)
   - 155,452 MFT entries parsed
   - 1,071 findings detected
   - 247 self-correction instances
   - Results in `/cases/insider_threat_test/analysis/`

2. **12 Synthetic Test Scenarios** (automated harness)
   - Perfect F1=1.00 across all scenarios
   - 47 true positives, 0 false positives, 0 false negatives
   - Results in `analysis/scenario_report.json`

**Files:** `docs/DATASETS.md`, `docs/ACCURACY_REPORT.md`, `analysis/scenario_report.json`

### 7. Accuracy Report ✅
- [x] Self-assessment of findings accuracy
- [x] False positives identified
- [x] Missed artifacts documented
- [x] Hallucinated claims caught
- [x] Honesty valued over perfection

**Files:** `docs/ACCURACY_REPORT.md`, `README.md` (detection accuracy table)

**Key Metrics:**
- Precision: 1.00 (no false positives)
- Recall: 1.00 (no false negatives)
- F1 Score: 1.00 (perfect)
- Self-correction instances: 247 from real evidence
- Confidence adjustment: 0.35-0.95 range based on evidence quality

### 8. Agent Execution Logs ✅
- [x] Structured logs with full agent communication
- [x] Tool execution sequence with timestamps
- [x] Token usage tracked
- [x] Judges can trace findings back to tool executions

**Format:** Append-only JSONL

**Files:**
- Real evidence: `/cases/insider_threat_test/analysis/audit.jsonl`
- Test scenarios: `tests/scenario_harness.py` generates `analysis/scenario_report.json`

**Sample audit log entry:**
```jsonl
{"timestamp":"2026-04-24T01:58:50Z","tool":"mftecmd","command":"mftecmd -f $MFT --csv ./analysis","exit_code":0,"duration_ms":3605,"output_hash":"58c9720ab50db65e"}
```

**Verification:**
```bash
# View audit log from real evidence
cat /cases/insider_threat_test/analysis/audit.jsonl | jq .

# View scenario test results
cat analysis/scenario_report.json | jq .
```

---

## Devpost Submission Form

**When submitting on findevil.devpost.com:**

### Required Fields

1. **Project Title**
   ```
   SIFT Find Evil - Autonomous DFIR with Architectural Self-Correction
   ```

2. **Tagline** (80 chars max)
   ```
   Autonomous DFIR agent with real-time self-correction via cross-artifact validation
   ```

3. **Description**
   - Copy from README.md introduction
   - Emphasize: autonomous execution, architectural constraints, self-correction
   - Include F1=1.00 metric prominently

4. **GitHub Repository URL**
   ```
   https://github.com/Strike48/sift_find_evil
   ```

5. **Demo Video URL**
   ```
   [TO BE ADDED AFTER UPLOAD]
   YouTube/Vimeo link goes here
   ```

6. **Architecture Diagram**
   - Upload PNG/SVG exported from docs/ARCHITECTURE_DIAGRAM.md
   - OR link to GitHub markdown (renders Mermaid automatically)
   ```
   https://github.com/Strike48/sift_find_evil/blob/main/docs/ARCHITECTURE_DIAGRAM.md
   ```

7. **Evidence Dataset Documentation**
   ```
   https://github.com/Strike48/sift_find_evil/blob/main/docs/DATASETS.md
   ```

8. **Accuracy Report**
   ```
   https://github.com/Strike48/sift_find_evil/blob/main/docs/ACCURACY_REPORT.md
   ```

9. **Agent Execution Logs**
   ```
   Real evidence: /cases/insider_threat_test/analysis/audit.jsonl
   Test scenarios: analysis/scenario_report.json
   Both included in repository
   ```

10. **Built With** (select technologies)
    - Claude Code
    - Python
    - SANS SIFT Workstation
    - MCP (Model Context Protocol)
    - Volatility 3
    - EZ Tools (MFTECmd, PECmd, EvtxECmd)

### Optional Fields

11. **Try It Out URL**
    ```
    See DEPLOY_TO_SIFT.md for setup instructions
    Docker deployment coming soon
    ```

12. **What's Next for Your Project**
    ```
    - Web UI for case management
    - Multi-case queue support
    - Persistent learning across cases
    - Team collaboration features
    - Enterprise SSO and SIEM integration
    ```

---

## Pre-Submission Testing

### Verify Repository

```bash
cd ~/Code/sift_find_evil

# Check all files present
ls -la README.md LICENSE DEPLOY_TO_SIFT.md
ls -la docs/ARCHITECTURE_DIAGRAM.md docs/ACCURACY_REPORT.md docs/DATASETS.md

# Verify license is MIT
head -1 LICENSE

# Test setup instructions work
python -m pytest tests/scenario_harness.py

# Verify scenarios still pass
PYTHONPATH=. python3 tests/scenario_harness.py
# Should show: F1=1.00 on all 12 scenarios
```

### Verify Audit Logs

```bash
# Check audit log exists from real evidence test
ls -la /cases/insider_threat_test/analysis/audit.jsonl

# Verify JSONL format
cat /cases/insider_threat_test/analysis/audit.jsonl | head -1 | jq .

# Count tool invocations
wc -l /cases/insider_threat_test/analysis/audit.jsonl
```

### Test Video Recording

```bash
# Increase terminal font for video
gsettings set org.gnome.desktop.interface text-scaling-factor 1.5

# Test recording with OBS
# 1. Open OBS Studio
# 2. Add source: Screen Capture
# 3. Test audio levels
# 4. Record 10-second test clip
# 5. Verify quality

# Reset font after test
gsettings set org.gnome.desktop.interface text-scaling-factor 1.0
```

---

## Final Checklist Before Submission

- [ ] All 8 deliverables completed
- [ ] Demo video uploaded and link obtained
- [ ] Architecture diagram exported (if needed)
- [ ] All code pushed to GitHub
- [ ] README.md up to date
- [ ] LICENSE file present and correct (MIT)
- [ ] Scenarios still pass (F1=1.00)
- [ ] Audit logs accessible
- [ ] Video <5 minutes
- [ ] No third-party trademarks in video
- [ ] No copyrighted music in video
- [ ] Devpost form filled out completely
- [ ] GitHub repository is PUBLIC
- [ ] License badge visible in About section

---

## Submission Confirmation

After submitting on Devpost:

- [ ] Screenshot confirmation page
- [ ] Note submission timestamp
- [ ] Save submission ID
- [ ] Verify public visibility
- [ ] Test all links work
- [ ] Watch submitted video to confirm no issues

---

## Contact Information

**Team/Individual:** Jonathan Tomek
**Email:** jonathan.tomek@strike48.com
**GitHub:** https://github.com/jtomek
**Project Repository:** https://github.com/Strike48/sift_find_evil

---

## Judging Criteria Focus

When finalizing submission, emphasize:

1. **Autonomous Execution Quality** ✅
   - Real-time reasoning about next steps
   - Handles failures via circuit breaker
   - Self-corrects without human intervention

2. **IR Accuracy** ✅
   - F1=1.00 on 12 test scenarios
   - Contradictions detected and flagged
   - Confidence scores reflect evidence quality

3. **Breadth and Depth** ✅
   - MFT, Prefetch, Registry, Event Logs, Memory
   - Deep cross-artifact correlation
   - 155K entries analyzed from real evidence

4. **Constraint Implementation** ✅
   - **Architectural** (not prompt-based)
   - Read-only enforcement in code
   - Timeout guards in MCP client
   - Circuit breaker pattern
   - All tested for bypass attempts

5. **Audit Trail Quality** ✅
   - Every finding traceable to tool execution
   - JSONL with timestamps + exit codes + hashes
   - Reproducible from logs

6. **Usability and Documentation** ✅
   - One-command execution
   - Clear README with examples
   - Step-by-step deployment guide
   - 80%+ code coverage

---

## Emergency Contacts

**Devpost Support:** help@devpost.com
**Hackathon Organizers:** Check findevil.devpost.com/help

---

**Last Updated:** 2026-04-24
**Submission Deadline:** June 15, 2026 11:45 PM EDT (52 days remaining)
