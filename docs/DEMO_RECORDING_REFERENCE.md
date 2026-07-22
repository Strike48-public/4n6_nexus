# Demo Recording Quick Reference

## Available Scripts

| Script | Purpose | When to Use |
|--------|---------|-------------|
| `scripts/record_demo.sh` | Full demo (requires SIFT VM + Claude Code) | On SIFT VM with AWS Bedrock |
| `scripts/record_demo_local.sh` | Local demo (works anywhere) | Local testing, practice runs |
| `scripts/test_audio_setup.sh` | Audio testing | Before first recording |
| `scripts/setup_obs_recording.sh` | OBS configuration guide | First-time setup |

## Quick Start (Local Testing)

```bash
cd ~/Code/4n6_nexus

# Test audio (optional)
bash scripts/test_audio_setup.sh

# Practice run (local)
bash scripts/record_demo_local.sh

# Press SPACE to advance through segments
# Press Ctrl+C to exit
```

## Quick Start (Full Demo on SIFT VM)

```bash
# On SIFT VM
export AWS_PROFILE=bedrock CLAUDE_CODE_USE_BEDROCK=1
aws sso login --profile bedrock

cd ~/sift_find_evil
source venv/bin/activate

# Start OBS recording

# Run full demo
bash scripts/record_demo.sh

# Press SPACE between segments for voice-over
```

## Segment Structure (5 minutes total)

```
1. Problem (0:00-0:40) ────> Voice-over only
   └─ Narrate adversary speed vs manual IR

2. System (0:40-1:20) ─────> claude mcp list + agent tools
   └─ Narrate no shell, MCP guardrails

3. Real Evidence (1:20-2:30) ─> Analyze CIRCL + nitroba
   └─ Narrate GPT wipe + beaconing detection

4. Multi-Agent (2:30-3:40) ─> Run orchestration
   └─ Narrate self-correction, F-005 held

5. Guardrail (3:40-4:20) ──> Block /etc/shadow attempt
   └─ Narrate architectural boundary

6. Traceability (4:20-4:40) ─> Show tool traces + F1 score
   └─ Narrate zero false positives/negatives

7. Report (4:40-5:00) ─────> Generate investigation report
   └─ Narrate court-ready with Mermaid diagrams
```

## Controls

| Key | Action |
|-----|--------|
| **SPACE or ENTER** | Advance to next segment |
| **Any key** | Also advances (for convenience) |
| **Ctrl+C** | Abort demo |
| **Ctrl+L** | Clear screen (before recording) |

## Voice-Over Tips

**Tone:** Conversational, confident, clear  
**Pace:** Normal speaking speed (not rushed)  
**Style:** Natural inflection, pause between sentences  
**Energy:** Match the technical content  

**Key Points to Emphasize:**
- Machine speed (80-90% autonomy)
- Real evidence (hash-verified)
- Self-correction (autonomous)
- F1 = 1.00 (perfect accuracy)
- Architectural boundary (agent can't, not shouldn't)
- Court-ready report

## Recording Checklist

### Before Recording
- [ ] Terminal font 14-16pt, high contrast
- [ ] Scrollback cleared (Ctrl+L)
- [ ] Desktop clean, notifications off
- [ ] Microphone tested, audio levels good
- [ ] OBS configured and preview looks good
- [ ] 10-second test recording successful

### During Recording
- [ ] Press SPACE to advance segments
- [ ] Let commands complete before speaking
- [ ] Read voice-over naturally (not verbatim)
- [ ] Pause briefly between sentences
- [ ] Monitor audio levels stay green

### After Recording
- [ ] Video saved successfully
- [ ] Audio is clear throughout
- [ ] All commands executed correctly
- [ ] Timing close to 5 minutes
- [ ] No awkward pauses or mistakes

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Directory not found | Use `record_demo_local.sh` for local testing |
| Claude not connected | Run `aws sso login --profile bedrock` |
| MCP server down | Check `claude mcp list` |
| Evidence missing | Download or use local script (shows expected output) |
| Audio too quiet | Increase mic gain, move closer |
| Terminal too small | Increase font to 14-16pt |

## Expected Outputs

| Segment | Expected |
|---------|----------|
| Pre-flight | All checks pass (green ✓) |
| System | tools: ["Read", "Grep", "Glob", "mcp__*"] |
| Evidence | CRITICAL - Partition table wiped |
| Multi-agent | 6 findings, F-005 held at 0.45 |
| Guardrail | tool_blocked: /etc/shadow denied |
| Traceability | TOTAL 62 0 0 1.00 1.00 1.00 |
| Report | Markdown with Mermaid diagrams |

## File Locations

```
~/Code/4n6_nexus/
├── scripts/
│   ├── record_demo.sh              # Full demo (SIFT VM)
│   ├── record_demo_local.sh        # Local demo (testing)
│   ├── test_audio_setup.sh         # Audio testing
│   └── setup_obs_recording.sh      # OBS guide
├── docs/
│   ├── DEMO_RECORDING_VERIFIED.md  # Source script
│   ├── DEMO_RECORDING_QUICKSTART.md # Step-by-step guide
│   ├── DEMO_RECORDING_FILES.md     # File overview
│   └── DEMO_RECORDING_REFERENCE.md # This file
└── scenarios/
    └── real/
        ├── circl-2023-wiped/       # Wiped disk evidence
        └── nitroba/                # Network PCAP
```

## OBS Settings Quick Reference

**Video:**
- Resolution: 1920x1080
- FPS: 30
- Encoder: x264 or hardware

**Audio:**
- Sample Rate: 48kHz
- Mic Input: Enabled
- Desktop Audio: Disabled

**Output:**
- Format: MP4
- Quality: High Quality, Medium File Size
- Path: ~/Videos/sift_demos/

## Post-Recording

1. Find video: `~/Videos/sift_demos/*.mp4`
2. Review quality (audio + video)
3. Edit if needed:
   - Trim silence
   - Normalize audio
   - Add fade in/out
4. Export final version
5. Share (YouTube, Vimeo, etc.)

## Support

**Documentation:**
- Full guide: `docs/DEMO_RECORDING_QUICKSTART.md`
- Source script: `docs/DEMO_RECORDING_VERIFIED.md`
- File overview: `docs/DEMO_RECORDING_FILES.md`

**Testing:**
```bash
# Test local demo (no SIFT VM required)
bash scripts/record_demo_local.sh

# Test audio setup
bash scripts/test_audio_setup.sh
```

---

**Goal:** Professional 5-minute demo video with voice-over narration  
**Format:** Terminal screencast + microphone audio  
**Output:** MP4 video ready for sharing
