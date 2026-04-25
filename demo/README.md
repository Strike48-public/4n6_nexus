# Demo Folder - Everything You Need for the Live Demo

This folder contains all materials for delivering the 5-minute competition demo.

---

## Contents

| File | Purpose |
|------|---------|
| **QUICK_REFERENCE.md** | Print and tape next to laptop - essential commands and talking points |
| **commands.sh** | All demo commands in executable script format |
| **findings_sample.json** | Backup findings file (use if live extraction fails) |
| **audit_sample.jsonl** | Backup audit log (use if live extraction fails) |

---

## Setup Instructions

### Before Competition Day

1. **Generate backup files** (run once, commit to repo):

   ```bash
   # Run analysis on real evidence to generate findings
   cd ~/Code/sift_find_evil
   source venv/bin/activate
   
   python -m sift_find_evil.cli_mcp analyze-live \
     --case-id demo_backup \
     --mft-file /mnt/windows_mount/$MFT \
     --output-dir /cases/demo_backup \
     --timeout 600
   
   # Copy outputs to demo folder as backups
   cp /cases/demo_backup/findings.json demo/findings_sample.json
   cp /cases/demo_backup/audit.jsonl demo/audit_sample.jsonl
   
   # Commit these backups
   git add demo/findings_sample.json demo/audit_sample.jsonl
   git commit -m "chore: add backup demo files for live presentation"
   ```

2. **Practice the demo** (see DEMO_RUNBOOK.md):
   - Run demo 5x with runbook open (Day 1-2)
   - Run demo 5x with runbook closed (Day 3-4)
   - Run demo with simulated failures (Day 5-6)
   - Final dress rehearsal, timed (Day 7)

3. **Prepare for demo day**:
   - Print QUICK_REFERENCE.md and tape next to laptop
   - Bookmark GitHub repo in browser
   - Charge laptop fully
   - Test on projector/screen beforehand

---

## Demo Day Workflow

### Option A: Live Extraction (Higher Risk, More Impressive)

```bash
# 1. Navigate to project
cd ~/Code/sift_find_evil
source venv/bin/activate

# 2. Run live analysis
python -m sift_find_evil.cli_mcp analyze-live \
  --case-id demo_video_live \
  --mft-file /mnt/windows_mount/$MFT \
  --output-dir /cases/demo_video \
  --timeout 600

# 3. Show findings
cat /cases/demo_video/findings.json | jq '.[0]'
```

**Pros:** Shows system actually works, more authentic
**Cons:** 11 minutes runtime, tool could fail, network issues

---

### Option B: Pre-Extracted Findings (Lower Risk, Recommended)

```bash
# 1. Navigate to demo folder
cd ~/Code/sift_find_evil/demo/

# 2. Copy pre-generated findings to case directory
mkdir -p /cases/demo_video
cp findings_sample.json /cases/demo_video/findings.json
cp audit_sample.jsonl /cases/demo_video/audit.jsonl

# 3. Show findings (same commands as Option A)
cat /cases/demo_video/findings.json | jq '.[0]'
```

**Pros:** Fast, reliable, no risk of failure
**Cons:** Not showing live execution

**Recommendation:** Use Option B for competition. Explain: "We ran this analysis earlier - here are the results..."

---

## Fallback Plan (If Something Breaks)

### If findings.json is missing:

```bash
cp demo/findings_sample.json /cases/demo_video/findings.json
```

### If audit.jsonl is missing:

```bash
cp demo/audit_sample.jsonl /cases/demo_video/audit.jsonl
```

### If jq command fails:

```bash
# Install jq
sudo apt-get install -y jq

# OR use Python fallback
python -c "import json; print(json.dumps(json.load(open('/cases/demo_video/findings.json'))[0], indent=2))"
```

### If case directory doesn't exist:

```bash
mkdir -p /cases/demo_video
cp demo/findings_sample.json /cases/demo_video/findings.json
cp demo/audit_sample.jsonl /cases/demo_video/audit.jsonl
```

---

## File Descriptions

### findings_sample.json

Pre-generated findings from analyzing the insider_threat_2022 evidence. Contains:
- 1,071 total findings
- Self-correction examples (confidence adjustments)
- Timestomping detection
- Missing Prefetch artifacts
- Complete reasoning chains

**Use this file:** If live extraction fails or you want guaranteed demo success.

### audit_sample.jsonl

Pre-generated audit log showing:
- MFTECmd tool execution
- Timestamps, exit codes, duration
- SHA-256 output hashes
- Complete chain of custody

**Use this file:** If live extraction fails or audit.jsonl is empty.

### commands.sh

All demo commands in executable script format. Sections match the demo runbook:
1. Problem Statement (tree output)
2. Solution Overview (MCP client code)
3. Demo Setup (evidence verification)
4. Show Findings (jq queries)
5. Self-Correction Examples (timestomping)
6. Audit Log & Results (summary)

**Use this file:** For quick reference or to copy-paste commands during demo.

### QUICK_REFERENCE.md

Single-page cheat sheet with:
- Essential commands
- Talking points
- Q&A answers
- Fallback plan
- Key numbers
- Pre-demo checklist

**Use this file:** Print and keep next to laptop during demo. Contains everything you need on one page.

---

## Pre-Demo Checklist (15 minutes before)

Run through this checklist exactly as written:

```bash
# 1. Navigate to demo directory
cd ~/Code/sift_find_evil/demo/

# 2. Verify backup files present
ls -la findings_sample.json audit_sample.jsonl

# 3. Verify case directory exists
ls -la /cases/demo_video/

# 4. Test jq command
echo '{"test":"ok"}' | jq .

# 5. Verify evidence mounted (if doing live extraction)
ls -la /mnt/windows_mount/\$MFT

# 6. Test key command
cat /cases/demo_video/findings.json | jq '. | length' || echo "Need to copy backup files!"

# 7. If last command failed, copy backups
cp findings_sample.json /cases/demo_video/findings.json
cp audit_sample.jsonl /cases/demo_video/audit.jsonl
```

---

## Demo Timing Guide

| Segment | Duration | What to Show |
|---------|----------|--------------|
| 1. Problem | 0:00-0:30 | Tree output, explain pain point |
| 2. Solution | 0:30-1:00 | MCP code, 3 innovations |
| 3. Setup | 1:00-1:30 | Evidence files, case directory |
| 4. Findings | 1:30-3:00 | First finding, self-correction |
| 5. Timestomping | 3:00-4:00 | Timestamp mismatch example |
| 6. Audit Log | 4:00-5:00 | Chain of custody, summary |

**Total: 5 minutes**

---

## Success Criteria

You've delivered a great demo if:

- ✓ Judges understand the problem (manual forensics is slow)
- ✓ Judges understand the solution (autonomous agent with self-correction)
- ✓ Judges see proof (real evidence, real findings, real self-correction)
- ✓ Judges can reproduce (open source, documented, accessible)
- ✓ Judges ask follow-up questions (they're engaged)

---

## Additional Resources

- **Full demo guide:** `docs/DEMO_RUNBOOK.md`
- **Video storyboard:** `docs/VIDEO_STORYBOARD.md`
- **Voiceover script:** `docs/VOICEOVER_SCRIPT_REVISED.txt`
- **Accuracy report:** `docs/ACCURACY_REPORT.md`
- **Performance benchmarks:** `docs/PERFORMANCE_BENCHMARK.md`
- **Competition comparison:** `docs/COMPETITION_COMPARISON.md`

---

## Notes

- **Practice makes perfect:** Run the demo at least 10 times before competition day
- **Know your fallbacks:** If live extraction fails, switch to backup files immediately
- **Stay calm:** Judges are looking for technical innovation, not perfect execution
- **Offer to show code:** If judges ask, you have everything ready in GitHub

Good luck!
