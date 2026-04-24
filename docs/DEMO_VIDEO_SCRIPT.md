# FIND EVIL! Hackathon Demo Video Script

**Duration:** 5 minutes
**Format:** Live terminal screencast with audio narration
**Evidence:** insider_threat_2022/Narcos-CCleaner.E01 (7.7GB, real forensic image)

---

## Timing Breakdown

| Segment | Duration | Content |
|---------|----------|---------|
| Problem | 0:30 | DFIR analyst time burden |
| Solution | 0:30 | Autonomous agent + architectural self-correction |
| Demo Setup | 0:30 | Evidence mounting, case initialization |
| Live Execution | 2:30 | MCP tool execution → detection → findings |
| Self-Correction | 1:00 | Show contradiction detection + resolution |
| Results | 0:30 | F1 metrics, audit logs, architecture |

---

## Script

### SEGMENT 1: Problem Statement (0:00-0:30)

**[Screen: Terminal with SIFT logo]**

**NARRATION:**
> "DFIR investigations are manual and time-intensive. A senior analyst spends 40 to 120 hours per case running 50+ specialized forensic tools, correlating artifacts across disk images, memory dumps, and logs, then documenting findings in court-admissible reports.
>
> Existing automation falls short: scripts lack reasoning capability, and prompt-engineered LLMs hallucinate findings without evidence integrity guarantees.
>
> This is SIFT Find Evil - an autonomous DFIR agent with architectural self-correction."

### SEGMENT 2: Solution Overview (0:30-1:00)

**[Screen: Terminal showing project structure]**

**NARRATION:**
> "Our solution combines three architectural innovations:
>
> First: MCP integration for safe forensic tool execution. Read-only enforcement, timeout guards, circuit breakers, and append-only audit logging ensure evidence chain-of-custody.
>
> Second: Cross-artifact validation. The detection engine automatically correlates timestamps from MFT, Prefetch, Registry, and Event Logs to detect contradictions.
>
> Third: Autonomous self-correction. When timestamp discrepancies exceed confidence thresholds, the engine triggers re-investigation and adjusts findings confidence without human intervention.
>
> Let's see it working on real evidence."

### SEGMENT 3: Demo Setup (1:00-1:30)

**[Screen: Terminal commands shown live]**

**COMMANDS SHOWN:**
```bash
# Mount E01 forensic image
sudo ewfmount insider_threat_2022/Narcos-CCleaner.E01 /mnt/ewf_mount

# Mount Windows partition read-only
sudo mount -o ro,loop,offset=$((1259520 * 512)) /mnt/ewf_mount/ewf1 /mnt/windows_mount

# Initialize case
python -m sift_find_evil.cli_mcp analyze-live \
  --case-id insider_threat_2022 \
  --mft-file /mnt/windows_mount/$MFT \
  --output-dir ./analysis
```

**NARRATION:**
> "We're analyzing a 7.7 gigabyte insider threat case - a real forensic image from our evidence collection.
>
> The agent mounts the E01 image read-only, identifies the Windows partition, extracts the MFT file, and initializes the case with audit logging enabled.
>
> Watch as the agent autonomously executes forensic tools via MCP."

### SEGMENT 4: Live Execution (1:30-4:00)

**[Screen: Split screen - top shows terminal, bottom shows audit log tail -f]**

**COMMANDS RUNNING (shown live):**
```bash
# Agent executes MFTECmd via MCP
[MCP] Executing: mftecmd -f $MFT --csv ./analysis
[MCP] Duration: 3605ms | Exit: 0 | Records: 123,495

# Parsing tool output
[Parser] Loaded 155,452 MFT entries

# Detection engine analyzing
[Engine] Running 12 detectors...
[Engine] TimestampValidator: analyzing 8,742 executables
[Engine] Found 1,071 potential findings

# Self-correction engine
[Self-Correction] Analyzing cross-artifact consistency...
[Self-Correction] Detected 247 timestamp contradictions
```

**NARRATION:**
> "The agent executes MFTECmd - a forensic tool that parses the Master File Table. Notice the MCP client enforces read-only access and logs every invocation with SHA-256 output hashing for chain-of-custody.
>
> The parser converts 155 thousand MFT entries into structured data. The detection engine runs 12 specialized detectors looking for suspicious patterns.
>
> 1,071 potential findings detected. Now watch the self-correction engine analyze cross-artifact consistency."

**[Screen: Show finding example with contradiction]**

```json
{
  "title": "Suspicious Activity: MessagingApplication.exe",
  "severity": "medium",
  "confidence": 0.55,
  "contradictions": [
    {
      "type": "mft_prefetch_mismatch",
      "description": "Executable exists in MFT but has no Prefetch artifact",
      "confidence_penalty": 0.30
    }
  ]
}
```

**NARRATION:**
> "Here's a finding: MessagingApplication dot exe exists in the MFT but has no Prefetch artifact. Normal Windows executables leave Prefetch traces. The absence suggests either anti-forensics or the executable never actually ran.
>
> The self-correction engine detected this contradiction and reduced the confidence from 0.85 to 0.55 - distinguishing confirmed evidence from inference."

### SEGMENT 5: Self-Correction Deep Dive (4:00-5:00)

**[Screen: Show another self-correction example]**

```json
{
  "title": "Timestomping Detected: backdoor.exe",
  "confidence": 0.35,
  "contradictions": [
    {
      "type": "si_fn_mismatch",
      "mft_si_time": "2019-01-15T08:00:00Z",
      "mft_fn_time": "2019-02-06T20:45:00Z",
      "delta_seconds": 1900800,
      "confidence_penalty": 0.50
    }
  ],
  "resolution": {
    "resolution_type": "lower_confidence",
    "reasoning": "MFT $STANDARD_INFORMATION timestamps can be modified by attackers. MFT $FILE_NAME timestamps are more reliable but show 22-day discrepancy. Marking as suspicious but low confidence."
  }
}
```

**NARRATION:**
> "Here's timestomping detection: backdoor dot exe has a 22-day timestamp discrepancy between MFT dollar STANDARD_INFORMATION and dollar FILE_NAME attributes.
>
> The self-correction engine knows STANDARD_INFORMATION can be modified by attackers but FILE_NAME is harder to forge. It flags the finding as suspicious but reduces confidence to 0.35 because we can't definitively prove malicious intent.
>
> This is architectural self-correction - not prompt engineering. The constraint is in code."

**[Screen: Show audit log excerpt]**

```jsonl
{"timestamp":"2026-04-24T01:58:50Z","tool":"mftecmd","command":"mftecmd -f $MFT --csv ./analysis","exit_code":0,"duration_ms":3605,"output_hash":"58c9720ab50db65e"}
```

**NARRATION:**
> "Every tool execution is logged to append-only JSONL with timestamps, exit codes, and SHA-256 output hashes. Any finding can be traced back to the specific tool invocation that produced it."

### SEGMENT 6: Results & Architecture (5:00-5:30)

**[Screen: Terminal showing summary]**

```bash
RESULTS:
- Total findings: 1,071
- True positives: 47/47 on synthetic test scenarios (F1=1.00)
- Self-correction instances: 247 contradictions detected
- Audit log: 3 tool invocations recorded with full chain-of-custody

ARCHITECTURE SAFETY FEATURES:
✓ Read-only enforcement (MCP client blocks write operations)
✓ Timeout guards (600s default, configurable)
✓ Circuit breaker (max 3 consecutive failures)
✓ Audit logging (JSONL with SHA-256 hashing)
```

**NARRATION:**
> "Results: 1,071 findings from real evidence, with 247 self-correction instances where contradictions were detected and confidence adjusted.
>
> On synthetic test scenarios, perfect F1 score of 1.0 - no false positives, no false negatives across 12 validation cases.
>
> Architecture safety features ensure evidence integrity: read-only enforcement prevents modification, timeout guards prevent runaway processes, circuit breakers handle tool failures gracefully, and every action is logged for chain-of-custody.
>
> All code is open source MIT license on GitHub. Documentation, setup instructions, and accuracy reports included.
>
> SIFT Find Evil - autonomous DFIR with architectural self-correction."

**[Screen: Fade to project README on GitHub]**

---

## Technical Execution Notes

### Pre-Recording Checklist

- [ ] SIFT VM running with insider_threat_2022 evidence mounted
- [ ] Clear terminal history
- [ ] Increase terminal font size (readable in video)
- [ ] Set up split screen: terminal (top 70%), audit log tail (bottom 30%)
- [ ] Test run to ensure smooth execution
- [ ] Prepare finding examples to highlight (2-3 good self-correction cases)
- [ ] OBS/screen recording software configured (1080p, 30fps minimum)

### Recording Setup

**Terminal Configuration:**
```bash
# Increase font for readability
gsettings set org.gnome.desktop.interface text-scaling-factor 1.5

# Clear history
history -c

# Split screen
tmux new-session -d -s demo
tmux split-window -v -p 30
tmux select-pane -t 0
```

**Screen Recording:**
- OBS Studio or similar
- 1920x1080 resolution
- 30fps minimum
- Audio: USB microphone, -18dB to -12dB levels
- Test audio levels before final recording

### Post-Production

- [ ] Trim any dead air at start/end
- [ ] Add intro title card (2 seconds): "SIFT Find Evil - FIND EVIL! Hackathon"
- [ ] Add outro card (2 seconds): GitHub URL + license badge
- [ ] Verify final length <5 minutes
- [ ] Export: H.264, 1080p, 30fps
- [ ] Upload to YouTube (unlisted or public)
- [ ] Test playback before submission

---

## Alternative Ending (if time allows)

If under 5 minutes after main demo, can add:

**[Screen: Show scenario harness results]**

```bash
python tests/scenario_harness.py

Scenario                    TP  FP  FN    Prec     Rec      F1
--------------------------------------------------------------
12 scenarios               47   0   0    1.00    1.00    1.00
```

**NARRATION:**
> "Validation: 12 test scenarios ranging from clean baseline to ransomware to memory intrusion. Perfect precision and recall. Zero false positives. Zero missed findings."

---

## Backup Plan

If live demo fails during recording:

1. Use pre-recorded terminal session with `script` command
2. Narrate over the recorded session
3. Ensure audit.jsonl and findings.json are from actual run
4. Judges value honesty - note in description if using recorded terminal output

---

## Key Messaging for Judges

**Emphasize in narration:**

1. **Architectural constraints** (not prompt engineering)
   - MCP client enforces read-only at code level
   - Self-correction thresholds are hardcoded constants
   - Circuit breaker is architectural pattern, not LLM decision

2. **Audit trail completeness**
   - Every tool execution logged
   - Timestamps + exit codes + output hashes
   - Can trace any finding to source tool invocation

3. **Real-time self-correction**
   - Contradictions detected during analysis (not post-processing)
   - Confidence adjusted based on evidence quality
   - Reasoning chains preserved in finding objects

4. **Depth over breadth**
   - Focus on MFT + Prefetch + Registry cross-validation
   - Deep timestamp correlation across 3+ artifact types
   - Better than shallow coverage of many tools

5. **Usability**
   - One command execution
   - Clear setup documentation
   - Reproducible results from audit logs

---

## Upload Details

**YouTube/Vimeo Settings:**
- Title: "SIFT Find Evil - Autonomous DFIR with Self-Correction | FIND EVIL! Hackathon"
- Description: Include GitHub URL, license, setup instructions link
- Tags: DFIR, digital forensics, autonomous agent, Claude Code, SANS SIFT
- Thumbnail: Terminal screenshot with "F1=1.00" or "Self-Correction" overlay
- Visibility: Unlisted (shareable link) or Public
