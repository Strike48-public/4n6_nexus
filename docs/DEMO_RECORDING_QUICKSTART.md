# Demo Recording Quick Start Guide

This guide walks you through recording the SIFT Find Evil demo with voice-over narration.

## Overview

You have two scripts:
1. `scripts/record_demo.sh` - Automated demo script with spacebar pauses for voice-over
2. `scripts/setup_obs_recording.sh` - OBS Studio configuration guide

## Recording Workflow

### Step 1: Pre-Flight Setup

Run this on your SIFT VM **before** starting the recording:

```bash
# SSH to SIFT VM
ssh sansforensics@<vm-ip>

# Set up environment
export AWS_PROFILE=bedrock 
export CLAUDE_CODE_USE_BEDROCK=1
export PATH="$HOME/.local/bin:$PATH"

# Login to AWS SSO (if session expired)
aws sso login --profile bedrock

# Navigate to project
cd ~/sift_find_evil
source venv/bin/activate

# Verify system ready
claude -p "Reply with exactly: BEDROCK_OK"
claude mcp list

# Verify evidence hash
sha256sum scenarios/real/circl-2023-wiped/evidence/wiped_disk.E01
```

Expected hash: `c4a8145bcbfd5485cd7b36a0603bdec68674c2f27e6c2dcf3ef25aa7a4f4ef15`

### Step 2: Set Up OBS Studio

On your local machine (or VM with GUI):

```bash
# Read the setup guide
bash ~/Code/4n6_nexus/scripts/setup_obs_recording.sh

# Install OBS if needed
sudo apt install obs-studio
```

**Key OBS Settings:**
- Video: 1920x1080 @ 30fps
- Output: High Quality MP4
- Audio: Enable microphone, disable desktop audio
- Source: Window capture of terminal

**Test Recording:**
1. Start a 10-second test recording
2. Verify audio levels (peak around -12dB to -6dB)
3. Check terminal is readable and fills screen

### Step 3: Terminal Preparation

**Terminal Settings:**
- Font size: 14-16pt minimum
- Color scheme: High contrast (light on dark)
- Fullscreen or maximize window
- Clear all scrollback: `clear` or Ctrl+L

**Environment:**
- Close unnecessary applications
- Disable notifications
- Ensure quiet recording space
- Position microphone at consistent distance

### Step 4: Record the Demo

```bash
cd ~/sift_find_evil

# Start OBS recording (or press F9)

# Run the demo script
bash scripts/record_demo.sh

# The script will:
# 1. Run pre-flight checks
# 2. Execute each segment
# 3. Pause for your voice-over
# 4. Wait for SPACE to continue
```

**During Recording:**
- Read the voice-over text naturally (shown on screen)
- Press SPACE when ready for next segment
- Let commands complete fully before advancing
- Don't rush - clarity over speed

### Step 5: Review Recording

After recording:

```bash
# Find your recording
ls -lh ~/Videos/sift_demos/

# Review the video
vlc ~/Videos/sift_demos/<filename>.mp4
```

**Quality Checklist:**
- [ ] Audio is clear and consistent volume
- [ ] Terminal text is readable
- [ ] All commands executed successfully
- [ ] No awkward pauses or dead air
- [ ] Timing matches 5-minute target

## Segment Breakdown

| Segment | Duration | What Happens | Voice-Over Points |
|---------|----------|--------------|-------------------|
| 1. Problem | 0:00-0:40 | Text only | Adversary speed vs. manual IR |
| 2. System | 0:40-1:20 | `claude mcp list`, agent tools | No shell, MCP guardrails |
| 3. Real Evidence | 1:20-2:30 | CIRCL + nitroba analysis | Hash-verified, GPT wipe, beaconing |
| 4. Multi-Agent | 2:30-3:40 | Orchestration run | Self-correction, F-005 held |
| 5. Guardrail | 3:40-4:20 | Block /etc/shadow read | Architectural boundary |
| 6. Traceability | 4:20-4:40 | Tool traces, F1 score | Zero false positives/negatives |
| 7. Report | 4:40-5:00 | Generate + show report | Court-ready, Mermaid diagrams |

## Voice-Over Script Locations

Each segment displays voice-over text on screen. Key talking points:

**Segment 1:** Attackers at 80-90% autonomy vs. defenders looking up flags  
**Segment 2:** SIFT + Bedrock + MCP, no shell access  
**Segment 3:** CIRCL wiped disk (real evidence), primary GPT zeroed  
**Segment 4:** Multi-agent self-correction, F-005 cannot resolve  
**Segment 5:** Agent can't vs. shouldn't, architectural boundary  
**Segment 6:** Tool traceability, F1=1.00 across 16 scenarios  
**Segment 7:** Court-ready report with auto-generated diagrams  

## Troubleshooting

### Audio Issues
- Test microphone before full recording
- Check OBS audio mixer shows green bars when speaking
- Adjust input gain in system settings if too quiet/loud
- Use headphones to monitor audio during recording

### Video Issues
- Increase terminal font size if text not readable
- Use high-contrast terminal theme
- Ensure terminal fills most of screen
- Close overlapping windows

### Script Issues
- If command fails, press Ctrl+C and re-run from that segment
- Pre-flight checks will catch most issues
- Verify AWS SSO session is active
- Check MCP server is connected

### Timing Issues
- Script automatically pauses between segments
- Take your time with voice-over
- Better to go slightly over 5 minutes than rush
- You can edit/trim in post-production

## Post-Production (Optional)

**Basic Editing:**
- Trim silence at start/end
- Add 2-second fade in/out
- Normalize audio levels
- Add title card (optional)

**Tools:**
- Kdenlive (Linux video editor): `sudo apt install kdenlive`
- OpenShot (simpler): `sudo apt install openshot-qt`
- DaVinci Resolve (professional, free)

**Export Settings:**
- Format: MP4 (H.264)
- Resolution: 1920x1080
- Bitrate: 5-10 Mbps
- Audio: AAC, 192 kbps

## Tips for Success

### Before Recording
- Practice the voice-over once without recording
- Test microphone and audio levels
- Clear terminal and set large readable font
- Disable notifications and close unnecessary apps

### During Recording
- Speak clearly at normal conversational pace
- Pause briefly between sentences
- Let commands fully complete before speaking
- Use natural inflection (not monotone)

### After Recording
- Watch the full recording immediately
- Note any issues for re-recording
- Check audio quality throughout
- Verify all segments captured correctly

## Quick Commands Reference

```bash
# Start recording workflow
cd ~/sift_find_evil
bash scripts/record_demo.sh

# During demo
SPACE              # Advance to next segment
Ctrl+C             # Abort demo

# Find recordings
ls ~/Videos/sift_demos/

# Play recording
vlc ~/Videos/sift_demos/<file>.mp4
```

## Support

If you encounter issues:
1. Check pre-flight verification steps
2. Review DEMO_RECORDING_VERIFIED.md for expected outputs
3. Verify AWS SSO session: `aws sso login --profile bedrock`
4. Check MCP server: `claude mcp list`
5. Re-run pre-flight checks in the script

---

**Target:** 5-minute professional demo recording  
**Format:** Terminal screencast + voice narration  
**Output:** MP4 video ready for sharing

Good luck with your recording!
