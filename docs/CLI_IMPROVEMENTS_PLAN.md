# CLI Improvements Plan

**Goal:** Better result persistence + Interactive "find evil" mode

---

## Problem Statement

1. **Missing detailed findings:** `--output` only saves test metrics (F1, precision, recall), not actual Finding objects with descriptions, evidence, MITRE techniques
2. **No interactive mode:** CLI requires knowing exact command syntax upfront
3. **Results not timestamped:** Can't track multiple runs over time
4. **No batch review:** After analyzing multiple scenarios, can't review all findings together

---

## Proposed Changes

### 1. Automatic Result Persistence

**Current:**
```bash
python -m sift_find_evil.cli run --scenario scenarios/real/m57-charlie/ --output findings.json
# Saves only: {"f1": 1.0, "precision": 1.0, "findings_count": 1}
```

**Proposed:**
```bash
python -m sift_find_evil.cli run --scenario scenarios/real/m57-charlie/
# Auto-saves to: test-results/real/m57-charlie/2026-04-25_21-45-00/
#   ├── findings.json      # Full Finding objects with evidence
#   ├── metadata.json      # Test metrics (F1, precision, recall)
#   └── SUMMARY.md        # Human-readable report
```

**Implementation:**
- Integrate `sift_find_evil/testing/save_results.py` into `cmd_run()`
- Use timestamped directories: `test-results/{tier}/{scenario_name}/{timestamp}/`
- Save both metrics AND full Finding objects
- Keep `--output` flag for custom location (backward compat)

### 2. Interactive "Find Evil" Mode

**Proposed:**
```bash
python -m sift_find_evil.cli
# or
python -m sift_find_evil.cli interactive
```

**Flow:**
```
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   SIFT FIND EVIL - Let's Hunt for Evil                       ║
║   Autonomous DFIR Detection Engine                           ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

What evidence do you have?

1. Forensic disk image (E01, dd, raw)
2. Pre-extracted artifacts (MFT, Prefetch, Event Logs)
3. Scenario test suite
4. USB/external drive with multiple images

Choice [1-4]: 1

Enter path to disk image: /mnt/usb-evidence/suspect.E01

What type of investigation?

1. Full analysis (disk + memory if available)
2. Quick triage (filesystem only)
3. Custom (select artifact types)

Choice [1-3]: 1

Analyzing evidence...
[Progress indicators]

Found 3 findings:
  1. HIGH - Timeline tampering detected (confidence: 0.95)
  2. MEDIUM - Suspicious executable (confidence: 0.75)
  3. LOW - Unusual browser activity (confidence: 0.60)

Results saved to: test-results/analysis/2026-04-25_21-45-00/

What next?

1. View detailed findings
2. Generate report (PDF/Markdown/JSON)
3. Approve/reject findings
4. Analyze another image
5. Exit

Choice [1-5]:
```

**Implementation:**
- New `cmd_interactive()` function
- Use `input()` for prompts
- Guide users through common workflows
- Auto-detect USB-mounted evidence
- Show progress during analysis

### 3. Banner Update

**Current:**
```
SIFT FIND EVIL - Autonomous DFIR Agent
Cross-Artifact Validation with Self-Correction
```

**Proposed:**
```
SIFT FIND EVIL - Let's Hunt for Evil
Autonomous DFIR Detection with Self-Correction
```

Or catchier options:
- "Find Evil. Fast."
- "Evil Doesn't Hide from SIFT"
- "Hunting Evil in Forensic Artifacts"
- "Where Evil Hides, SIFT Finds"

### 4. Batch Review Command

**Proposed:**
```bash
python -m sift_find_evil.cli review --results-dir test-results/usb-evidence/
```

**Output:**
```
╔═══════════════════════════════════════════════════════════════╗
║   USB Evidence Analysis Summary                               ║
╚═══════════════════════════════════════════════════════════════╝

Analyzed 3 scenarios:

┌─────────────────────┬──────────┬──────┬──────────┬────────────┐
│ Scenario            │ Size     │ F1   │ Findings │ Status     │
├─────────────────────┼──────────┼──────┼──────────┼────────────┤
│ m57-charlie         │ 3.7 GB   │ 1.00 │ 1        │ PASS       │
│ ngdc-carry-tablet   │ 1.1 GB   │ 1.00 │ 1        │ PASS       │
│ ngdc-tracy-external │ 3.6 GB   │ 1.00 │ 0        │ PASS       │
└─────────────────────┴──────────┴──────┴──────────┴────────────┘

Total findings: 2
  - HIGH: 2
  - MEDIUM: 0
  - LOW: 0

View findings?
1. Show all findings
2. Show HIGH severity only
3. Export to report
4. Back to menu

Choice [1-4]:
```

---

## Implementation Priority

### Phase 1: Result Persistence (HIGH)
- [ ] Integrate `save_results.py` into `cmd_run()`
- [ ] Create timestamped directories automatically
- [ ] Save full Finding objects + metadata
- [ ] Keep `--output` flag for backward compat

### Phase 2: Banner + Tagline (MEDIUM)
- [ ] Update banner with catchier tagline
- [ ] Add to demo, analyze, run commands
- [ ] User feedback on tagline options

### Phase 3: Interactive Mode (MEDIUM)
- [ ] Create `cmd_interactive()` skeleton
- [ ] Add USB evidence auto-detection
- [ ] Build guided workflows
- [ ] Add progress indicators

### Phase 4: Batch Review (LOW)
- [ ] Create `cmd_review()` function
- [ ] Parse timestamped result directories
- [ ] Aggregate statistics
- [ ] Table formatting

---

## User Experience Goals

1. **Zero-config first run:** Just point at evidence and go
2. **Automatic persistence:** Never lose findings
3. **Guided workflows:** Help users who don't know all the flags
4. **Expert-friendly:** CLI flags still work for automation
5. **Reviewable results:** Easy to review multiple analyses

---

## Files to Modify

1. `sift_find_evil/cli.py`
   - Add `cmd_interactive()`
   - Update `cmd_run()` to auto-save results
   - Add `cmd_review()`
   - Update banner

2. `sift_find_evil/testing/save_results.py`
   - Already exists, just needs integration

3. `sift_find_evil/scenario_runner.py`
   - Ensure `ScenarioReport` includes full Finding objects
   - May need to add `findings` field

---

## Testing Plan

1. Run modified `cmd_run()` against M57-Charlie
2. Verify timestamped directory created
3. Verify `findings.json` contains full Finding objects
4. Test interactive mode locally
5. Test batch review with existing USB results

---

## Next Steps

1. Get user feedback on tagline options
2. Implement Phase 1 (result persistence)
3. Test with USB evidence
4. Deploy to SIFT VM
5. Implement Phase 2-4 based on feedback

---

**Priority:** HIGH (Phase 1)  
**Estimated Effort:** 2-3 hours  
**User Impact:** Critical for real-world usage
