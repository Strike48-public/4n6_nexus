# Validation Plan - Proof of Concept

**Date:** 2026-04-16  
**Status:** Ready to Execute  
**Objective:** Validate core hypothesis before building full system

---

## Core Hypothesis

**"We can use Claude Code + Protocol SIFT to build an autonomous DFIR agent with architectural self-correction that matches Valhuntir-quality output while differentiating on autonomous validation capabilities."**

---

## Discovery Phase - COMPLETE ✅

### What We Learned

**Protocol SIFT (teamdfir/protocol-sift):**
- ✅ Real, maintained, production-ready
- ✅ NOT an MCP server - it's Claude Code configuration
- ✅ Provides: Skills, permissions, audit logging, tool routing
- ✅ Has all tools we need: MFTECmd, PECmd, EvtxECmd, Plaso
- ✅ Read-only enforcement via permissions (architectural)
- ✅ Autonomous operation mode built-in

**Valhuntir (AppliedIR/Valhuntir):**
- ✅ Reference implementation showing winning quality standard
- ✅ Full MCP gateway with 8 backends (90+ tools)
- ✅ OpenSearch indexing for scale (50M+ records)
- ✅ Human approval workflow (crypto signing)
- ✅ Does NOT have self-correction - relies on human review

**Our Positioning:**
- Build ON TOP of Protocol SIFT (not replace it)
- Add self-correction layer (our innovation)
- Match Valhuntir quality on docs, security, findings model
- Differentiate on autonomous validation + confidence scoring

---

## Validation Phases

### Phase 1: Environment Setup & Basic Tool Execution (1-2 hours)

**Goal:** Confirm Protocol SIFT works and we can execute forensic tools

**Tasks:**
1. Download SANS SIFT Workstation OVA from sans.org/tools/sift-workstation
2. Import to VirtualBox/VMware (16 GB RAM recommended)
3. Boot SIFT Ubuntu
4. Install Protocol SIFT: `curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash`
5. Verify installation: `ls ~/.claude/skills/`
6. Download SANS starter case data from Egnyte

**Success Criteria:**
- [ ] SIFT VM running
- [ ] Protocol SIFT installed (`~/.claude/CLAUDE.md` exists)
- [ ] Skills present (`~/.claude/skills/memory-analysis`, etc.)
- [ ] Starter evidence downloaded

**Risks:**
- SIFT OVA might be large (10+ GB download)
- VM import might fail
- Protocol SIFT install might have dependencies we don't have

**Mitigation:**
- Document exact steps as we go
- Capture error messages
- Have fallback: use SIFT ISO instead of OVA

---

### Phase 2: Single Tool Test (1 hour)

**Goal:** Execute ONE forensic tool through Protocol SIFT and parse output

**Tasks:**
1. Create test case directory: `/cases/proof_of_concept`
2. Copy Protocol SIFT case template: `cp ~/.claude/case-templates/CLAUDE.md /cases/proof_of_concept/`
3. Mount starter evidence read-only
4. Launch Claude Code: `cd /cases/proof_of_concept && claude`
5. Ask Claude: "Run fls on the disk image and show me the file listing for C:\\ directory"
6. Capture output
7. Verify:
   - Tool executed successfully
   - Output is structured and parseable
   - Claude interpreted results
   - No evidence modification (hash before/after)

**Success Criteria:**
- [ ] fls executes successfully
- [ ] Output is captured and readable
- [ ] Claude provides interpretation (not just raw output)
- [ ] Evidence hash unchanged (SHA256 verification)

**Risks:**
- Evidence mounting might fail
- Tool paths might be wrong
- Claude might not know how to parse output

**Mitigation:**
- Start with simplest tool (fls, not Volatility)
- Check Protocol SIFT global CLAUDE.md for tool paths
- Use Protocol SIFT sleuthkit skill file as reference

---

### Phase 3: Multi-Tool Workflow (2 hours)

**Goal:** Chain 3 tools together and demonstrate autonomous orchestration

**Workflow:** MFT → Prefetch → Event Logs

1. Extract MFT timestamps for a suspicious file: "Find the most recently modified .exe files in C:\\Temp"
2. Check Prefetch for execution evidence: "Check if any of those .exe files have Prefetch artifacts"
3. Correlate with Event Logs: "Find Event ID 4688 (process creation) logs for those executables"

**Success Criteria:**
- [ ] Claude chains tools without prompting for each step
- [ ] Results from tool 1 inform tool 2
- [ ] Results from tool 2 inform tool 3
- [ ] Final answer synthesizes all 3 sources
- [ ] Audit log shows reasoning chain

**Risks:**
- Claude might ask for confirmation at each step
- Tool outputs might not parse correctly
- Correlation might fail (no matching records)

**Mitigation:**
- Protocol SIFT global CLAUDE.md says "NEVER ask questions" - should work autonomously
- Use synthetic evidence with known matches
- If correlation fails, document gap for self-correction engine

---

### Phase 4: Cross-Artifact Validation Prototype (3 hours)

**Goal:** Build and test the MVP star feature - timestamp contradiction detection

**Tasks:**
1. Create synthetic evidence with known timestamp contradiction:
   - MFT: file.exe modified at 10:00 AM
   - Prefetch: file.exe ran at 9:55 AM
   - Event Log 4688: file.exe created at 9:55:03 AM

2. Write Python script (`sift_find_evil/self_correction/timestamp_validator.py`):
   ```python
   def detect_timestamp_contradiction(mft_time, prefetch_time, tolerance_minutes=5):
       # Returns Contradiction object if detected
       pass
   
   def resolve_via_event_logs(file_path):
       # Queries Event Logs for tiebreaker
       pass
   ```

3. Test standalone (without Claude):
   - Extract timestamps from MFTECmd output
   - Extract timestamps from PECmd output
   - Detect contradiction
   - Query EvtxECmd for tiebreaker
   - Log resolution

4. Integrate with Claude Code:
   - Add as skill file: `~/.claude/skills/self-correction/SKILL.md`
   - Test in investigation workflow

**Success Criteria:**
- [ ] Script detects timestamp contradiction
- [ ] Script queries Event Logs autonomously
- [ ] Script logs:
   - Contradiction detected (type, sources, timestamps)
   - Confidence before (0.85)
   - Confidence after (0.40 → 0.85)
   - Resolution reasoning
- [ ] Audit log contains full chain

**Risks:**
- Timestamp parsing might fail (different formats)
- Event Log querying might be slow
- Contradiction might not be detectable in real data

**Mitigation:**
- Use synthetic data with guaranteed contradiction
- Document timestamp formats from each tool
- Cache Event Log results to avoid repeated queries

---

### Phase 5: End-to-End Investigation (4 hours)

**Goal:** Run complete investigation on synthetic ransomware case

**Workflow:**
1. Evidence intake (hash, mount)
2. Triage (scan for ransom notes, suspicious .exe files)
3. Hypothesis generation ("This appears to be ransomware")
4. Deep analysis (MFT, Prefetch, Event Logs, Timeline)
5. Self-correction triggers:
   - Timestamp contradiction detected → Re-investigation
   - Uncertainty budget exceeded → Re-analysis
6. Correlation (timeline reconstruction, IoC extraction)
7. Report generation (findings, timeline, IoCs, confidence scores)

**Success Criteria:**
- [ ] Investigation completes autonomously (<30 min runtime)
- [ ] ≥3 self-correction instances logged
- [ ] Timeline generated with ≥3 sources
- [ ] Findings include:
   - Ransomware executable (path, hash, confidence)
   - Ransom notes (paths, content snippets)
   - Encryption timeline (start/end times)
   - MITRE ATT&CK techniques (T1486, T1204, etc.)
- [ ] Report is structured (JSON or HTML)
- [ ] Audit logs are complete and readable

**Risks:**
- Full investigation might take too long (>30 min)
- Self-correction might not trigger
- Report generation might fail

**Mitigation:**
- Use small disk image (10 GB, not 100 GB)
- Plant known contradictions in synthetic case
- Start with JSON report (simpler than HTML)

---

## Success Metrics

### Phase 1-2: Foundation (MUST PASS)
- [ ] SIFT + Protocol SIFT installed and working
- [ ] Can execute ≥1 forensic tool via Claude Code
- [ ] Tool output is parseable

### Phase 3: Orchestration (SHOULD PASS)
- [ ] Can chain ≥3 tools autonomously
- [ ] Results correlate across tools

### Phase 4: Innovation (CRITICAL)
- [ ] Timestamp contradiction detection works
- [ ] Self-correction logic executes
- [ ] Confidence scoring logs properly

### Phase 5: Integration (STRETCH)
- [ ] Full investigation runs end-to-end
- [ ] Report generation works
- [ ] Audit logs are complete

---

## Go/No-Go Decision Points

### After Phase 1-2 (Foundation)
**Go:** Protocol SIFT works, tools execute  
**No-Go:** Can't install SIFT, can't execute tools  
**Action if No-Go:** Pivot to direct CLI + custom MCP (more work, but doable)

### After Phase 3 (Orchestration)
**Go:** Tools chain together, Claude orchestrates autonomously  
**No-Go:** Claude requires too much prompting, correlation fails  
**Action if No-Go:** Add more explicit instructions in case CLAUDE.md, create helper scripts

### After Phase 4 (Innovation)
**Go:** Self-correction works, logs are good  
**No-Go:** Can't detect contradictions, logic is flawed  
**Action if No-Go:** Simplify self-correction (just log anomalies, don't resolve)

### After Phase 5 (Integration)
**Go:** Full investigation works, ready to build full system  
**No-Go:** Too slow, too brittle, missing pieces  
**Action if No-Go:** Reduce scope (manual triage, simpler reports)

---

## Time Budget

| Phase | Estimated Time | Deadline |
|-------|----------------|----------|
| Phase 1-2: Foundation | 2-3 hours | End of Day 1 |
| Phase 3: Orchestration | 2 hours | Morning of Day 2 |
| Phase 4: Innovation | 3 hours | Afternoon of Day 2 |
| Phase 5: Integration | 4 hours | Day 3 |
| **Total** | **11-12 hours** | **3 days** |

**Contingency:** If any phase fails, we have documented fallback plans and can still submit a working system (even if not at full MVP scope).

---

## Deliverables from Validation

### Documentation
- [ ] `docs/SIFT_SETUP_GUIDE.md` - Step-by-step SIFT installation
- [ ] `docs/PROTOCOL_SIFT_TOOL_INVENTORY.md` - Complete tool list with paths
- [ ] `docs/TIMESTAMP_FORMATS.md` - How each tool outputs timestamps
- [ ] `docs/SELF_CORRECTION_TEST_RESULTS.md` - Validation test results

### Code
- [ ] `sift_find_evil/self_correction/timestamp_validator.py` - Core logic
- [ ] `~/.claude/skills/self-correction/SKILL.md` - Integration with Claude Code
- [ ] `tests/test_timestamp_validator.py` - Unit tests

### Evidence
- [ ] Synthetic ransomware case with known contradictions
- [ ] Ground truth file (expected findings)
- [ ] Validation logs (tool outputs, self-correction triggers)

---

## Next Immediate Action

**Option A: Environment Setup (Recommended if you have VM capability)**
1. Download SIFT Workstation OVA
2. Import to VirtualBox/VMware
3. Boot and verify
4. Install Protocol SIFT
5. Report back on success/failure

**Option B: Continue Documentation (If VM setup will take time)**
1. Complete remaining PRD sections (3-11)
2. Design findings model (mirror Valhuntir)
3. Design report structure
4. Write more detailed implementation plans

**Option C: Analyze Protocol SIFT Skills (Deep Dive)**
1. Read all 5 skill files from Protocol SIFT
2. Document exact patterns for tool invocation
3. Understand how Claude uses skills
4. Plan our self-correction skill integration

**What would you like to do next?**

---

*Last Updated: 2026-04-16*
