# Demo Recording Files Overview

Complete setup for recording the SIFT Find Evil demo with voice-over narration.

## Files Created

| File | Purpose | Usage |
|------|---------|-------|
| `scripts/record_demo.sh` | Automated demo script | Run this during recording |
| `scripts/setup_obs_recording.sh` | OBS configuration guide | Read before first recording |
| `docs/DEMO_RECORDING_QUICKSTART.md` | Quick start guide | Step-by-step recording workflow |
| `docs/DEMO_RECORDING_VERIFIED.md` | Source script (existing) | Reference for expected outputs |

## Quick Start

### 1. First Time Setup (5 minutes)

```bash
# Read the OBS setup guide
bash ~/Code/4n6_nexus/scripts/setup_obs_recording.sh

# Install OBS Studio
sudo apt install obs-studio

# Configure OBS (follow guide)
# - Add terminal window capture
# - Add microphone audio
# - Set 1920x1080 @ 30fps
# - Test recording
```

### 2. Before Each Recording (2 minutes)

```bash
# On SIFT VM
export AWS_PROFILE=bedrock CLAUDE_CODE_USE_BEDROCK=1
aws sso login --profile bedrock
cd ~/sift_find_evil && source venv/bin/activate

# Verify system
claude -p "Reply with exactly: BEDROCK_OK"
claude mcp list

# Terminal setup
# - Large font (14-16pt)
# - High contrast colors
# - Clear scrollback
# - Fullscreen/maximize
```

### 3. Record the Demo (5 minutes)

```bash
# Start OBS recording

# Run demo script
bash scripts/record_demo.sh

# The script:
# - Runs pre-flight checks automatically
# - Executes each segment
# - Shows voice-over text on screen
# - Pauses for you to narrate
# - Waits for SPACE to continue

# When complete, stop OBS recording
```

## How It Works

### The Recording Script (`record_demo.sh`)

**Pre-flight checks:**
- Verifies AWS Bedrock connection
- Checks MCP server status
- Validates evidence file hashes
- Ensures environment is ready

**Seven segments with voice-over pauses:**

```
SEGMENT 1: Problem statement (0:00-0:40)
├── Voice-over text displayed
└── SPACE to continue

SEGMENT 2: System architecture (0:40-1:20)
├── claude mcp list
├── grep agent tools
├── Voice-over text
└── SPACE to continue

SEGMENT 3: Real evidence (1:20-2:30)
├── Analyze CIRCL wiped disk
├── Show critical finding
├── Optional: nitroba network
├── Voice-over text
└── SPACE to continue

SEGMENT 4: Multi-agent (2:30-3:40)
├── Run orchestration
├── Show 6 findings + self-correction
├── Voice-over text
└── SPACE to continue

SEGMENT 5: Guardrail (3:40-4:20)
├── Attempt /etc/shadow read (blocked)
├── Show audit log
├── Voice-over text
└── SPACE to continue

SEGMENT 6: Traceability (4:20-4:40)
├── Trace finding to tools
├── Show F1 score = 1.00
├── Voice-over text
└── SPACE to continue

SEGMENT 7: Report (4:40-5:00)
├── Generate investigation report
├── Open in viewer (Mermaid diagrams)
├── Voice-over text
└── SPACE to finish
```

### Key Features

**Spacebar pauses:** Each segment waits for SPACE before continuing, giving you time to do your voice-over naturally.

**Voice-over text on screen:** The script displays talking points for each segment, so you know what to say.

**Color-coded output:** Success messages in green, info in yellow, errors in red - easy to read on screen.

**Automatic verification:** Pre-flight checks catch issues before recording starts.

**Reproducible:** Same commands, same outputs every time (deterministic scenarios).

## Expected Outputs

All outputs match `DEMO_RECORDING_VERIFIED.md`:

| Segment | Expected Output | Status |
|---------|-----------------|--------|
| Pre-flight | BEDROCK_OK, MCP Connected, hash verified | ✓ |
| Segment 2 | tools: ["Read", "Grep", "Glob", "mcp__*"] | ✓ |
| Segment 3 | 1 CRITICAL: Partition table wiped | ✓ |
| Segment 3 (optional) | HIGH beaconing, conf 0.7, CoV 0.0016 | ✓ |
| Segment 4 | 6 findings, 5 resolved, F-005 held | ✓ |
| Segment 5 | tool_blocked: /etc/shadow denied | ✓ |
| Segment 6 | Tool trace + F1=1.00 (62 findings, 0 FP/FN) | ✓ |
| Segment 7 | Report with Mermaid diagrams | ✓ |

## Voice-Over Guidelines

### Speaking Style
- Conversational, not robotic
- Clear articulation
- Normal pace (not rushed)
- Natural inflection
- Confident tone

### Recording Environment
- Quiet space (no background noise)
- Consistent microphone distance
- No echo/reverb
- Door closed, phone silenced

### Delivery Tips
- Read voice-over text as a guide, not verbatim
- Pause briefly between sentences
- Match energy to technical content
- Emphasize key points (F1=1.00, self-correction, architectural boundary)
- Don't rush - let terminal output display fully

## Troubleshooting

### Common Issues

**"Claude Code not connected"**
```bash
aws sso login --profile bedrock
export AWS_PROFILE=bedrock CLAUDE_CODE_USE_BEDROCK=1
```

**"MCP server not connected"**
```bash
claude mcp list
# If not showing, restart Claude Code
```

**"Evidence hash mismatch"**
```bash
# Re-download evidence or check file path
ls -lh scenarios/real/circl-2023-wiped/evidence/
```

**"Terminal too small"**
- Increase font size to 14-16pt
- Use fullscreen or maximize window
- Adjust OBS window capture to fill canvas

**"Audio too quiet"**
- Increase microphone input gain in system settings
- Move closer to microphone
- Check OBS audio mixer shows green bars

**"Commands taking too long"**
- First Bedrock call is slowest (warming up)
- Subsequent calls are faster
- Run script once before recording to warm up

### Re-recording Segments

If you need to re-record a segment:

1. Stop the recording
2. Clear terminal: `clear`
3. Run script again
4. Use SPACE to quickly skip through earlier segments
5. Narrate the segment you're re-recording
6. Continue or stop as needed

You can also edit multiple takes together in post-production.

## Post-Production

### Basic Editing (Optional)

**Trimming:**
- Remove silence at start/end
- Cut out any mistakes or long pauses

**Audio:**
- Normalize audio levels
- Remove background noise (if any)
- Add fade in/out

**Visual:**
- Add title card at beginning (optional)
- Add fade transitions between segments (optional)

**Export:**
- Format: MP4 (H.264)
- Resolution: 1920x1080
- Bitrate: 5-10 Mbps
- Audio: AAC, 192 kbps

### Recommended Tools

- **Kdenlive** (Linux): Full-featured video editor
- **OpenShot** (Linux): Simpler, beginner-friendly
- **DaVinci Resolve** (All platforms): Professional, free version available
- **Audacity** (Audio only): Clean up audio before video editing

## Sharing the Recording

### File Sizes (Approximate)

- 5-minute video @ 1920x1080: ~150-300 MB
- Lower resolution (1280x720): ~75-150 MB

### Upload Options

- YouTube (unlisted or public)
- Vimeo
- Google Drive / Dropbox (share link)
- GitHub Release (if under 100 MB)
- Self-hosted

### Video Metadata

**Title:** SIFT Find Evil - Autonomous DFIR Agent Demo

**Description:**
```
SIFT Find Evil: An autonomous digital forensics agent that investigates 
real evidence at machine speed with human-level accuracy.

Key features demonstrated:
- Real evidence analysis (CIRCL wiped disk)
- Multi-agent orchestration with self-correction
- Architectural guardrails (read-only, bounded execution)
- F1=1.00 detection accuracy (zero false positives/negatives)
- Court-ready investigation reports with traceability

Built on Protocol SIFT, Claude Code, AWS Bedrock, and Custom MCP servers.

Project: https://github.com/yourusername/sift_find_evil
```

**Tags:** DFIR, digital forensics, incident response, AI agents, 
Claude Code, autonomous IR, cybersecurity, threat hunting

## Summary

You now have:

✓ Automated recording script with voice-over pauses  
✓ OBS Studio setup guide  
✓ Quick start workflow documentation  
✓ Expected outputs for verification  
✓ Troubleshooting guide  

**Time to first recording:** ~10-15 minutes setup, 5-minute recording

**Ready to record!** Follow `DEMO_RECORDING_QUICKSTART.md` for step-by-step instructions.
