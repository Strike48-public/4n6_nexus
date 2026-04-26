# Terminal Recording Guide

**Purpose:** Record clean terminal session, add voiceover in post-production

---

## Pre-Recording Setup

### 1. Environment Preparation

```bash
# Clear terminal history
history -c

# Increase font size for video readability
gsettings set org.gnome.desktop.interface text-scaling-factor 1.5

# Navigate to project directory
cd ~/Code/sift_find_evil

# Verify evidence is available
ls -lh insider_threat_2022/Narcos-CCleaner.E01
```

### 2. Pre-Flight Checks

- [ ] SIFT VM running
- [ ] Evidence file exists and is accessible
- [ ] `/mnt/ewf_mount` and `/mnt/windows_mount` directories exist
- [ ] Screen recording software ready (OBS, SimpleScreenRecorder, etc.)
- [ ] Terminal window sized appropriately (1920x1080 or 1280x720)
- [ ] Test run completed successfully

### 3. Finding IDs to Prepare

**Before recording, run the analysis once to identify good finding IDs:**

```bash
# Run analysis
python -m sift_find_evil.cli_mcp analyze-live \
  --case-id insider_threat_2022 \
  --mft-file /mnt/windows_mount/$MFT \
  --output-dir ./analysis

# List findings
python -m sift_find_evil.cli list \
  --findings /cases/insider_threat_2022/findings.json \
  --status draft

# Find examples with contradictions
grep -l "mft_prefetch_mismatch" /cases/insider_threat_2022/findings.json
grep -l "si_fn_mismatch" /cases/insider_threat_2022/findings.json
```

**Update `RECORDING_COMMANDS.sh` with actual finding IDs:**
- Line 95: `--finding-id F-042` (replace with actual MFT/Prefetch mismatch ID)
- Line 106: `--finding-id F-015` (replace with actual timestomping ID)

---

## Recording Process

### Option A: Direct Recording with Pauses

```bash
# Start screen recording (OBS, etc.)
# Run commands manually, pause between segments for narration timing
bash demo/RECORDING_COMMANDS.sh
```

**Pros:** Natural typing flow, can ad-lib
**Cons:** Harder to time perfectly, may need multiple takes

### Option B: Scripted with asciinema

```bash
# Record terminal session
asciinema rec demo_recording.cast

# Run commands
bash demo/RECORDING_COMMANDS.sh

# Stop recording (Ctrl+D)
```

**Pros:** Clean recording, easy to replay
**Cons:** Requires asciinema playback or conversion

### Option C: Script Output Capture

```bash
# Capture all output to file
script -c "bash demo/RECORDING_COMMANDS.sh" demo_output.txt

# Replay with controlled timing
cat demo_output.txt
```

**Pros:** Reproducible, no live command errors
**Cons:** Less authentic-looking

---

## Recording Settings

### Screen Recording (OBS Studio)

**Video:**
- Resolution: 1920x1080 (or 1280x720)
- Frame rate: 30fps
- Format: MP4 (H.264)
- Bitrate: 2500-5000 kbps

**Audio:**
- Record silence or system audio only (add voiceover later)
- Sample rate: 44.1kHz or 48kHz

**Scene Setup:**
- Source: Window Capture (terminal only)
- Background: Black or transparent
- No webcam overlay needed

### Terminal Configuration

```bash
# Font size
gsettings set org.gnome.desktop.interface text-scaling-factor 1.5

# Color scheme: Use high-contrast theme
# Recommended: Dark background, light text (green/white)

# Window size: Maximize or set to 1920x1080
```

---

## Segment Timing Reference

Use these timings when adding voiceover:

| Segment | Time | Commands | Narration Focus |
|---------|------|----------|-----------------|
| Intro | 0:00-0:30 | Show environment | Problem statement |
| Mount | 0:30-1:30 | ewfmount, mount | Evidence setup, read-only |
| Init | 1:30-2:00 | case init | Case management |
| Execute | 2:00-3:30 | analyze-live (MCP) | Tool execution, parsing, detection |
| Findings | 3:30-4:30 | show findings | Self-correction examples |
| Audit | 4:30-5:00 | audit log/summary | Chain-of-custody |
| Results | 5:00-5:30 | Summary display | Metrics, safety features |

**Total:** ~5:30 (trim to <5:00 in post-production)

---

## Post-Recording Workflow

### 1. Review Recording

- [ ] All commands executed successfully
- [ ] Output is readable at video resolution
- [ ] No errors or unexpected failures
- [ ] Timing allows for narration pauses

### 2. Add Voiceover

**Tools:**
- Audacity (free, open source)
- DaVinci Resolve (free video editor)
- Adobe Premiere (commercial)
- Final Cut Pro (Mac)

**Process:**
1. Import video into editor
2. Watch video, note timing of key moments
3. Record narration following DEMO_VIDEO_SCRIPT.md
4. Sync narration to video actions
5. Adjust pacing (speed up boring parts, slow down key findings)

### 3. Add Title Cards (Optional)

**Intro card (2 seconds):**
```
SIFT Find Evil
Autonomous DFIR with Self-Correction
SANS FIND EVIL! Hackathon 2026
```

**Outro card (2 seconds):**
```
GitHub: Strike48/sift_find_evil
License: MIT (Open Source)
Documentation: docs/START_HERE.md
```

### 4. Final Export

**Settings:**
- Format: MP4 (H.264)
- Resolution: 1920x1080
- Frame rate: 30fps
- Audio: AAC, 128-192 kbps
- Total length: <5:00 (trim excess)

**Verify before upload:**
- [ ] Video plays smoothly
- [ ] Audio is clear and synchronized
- [ ] Text is readable at YouTube quality
- [ ] Total length <5:00
- [ ] No dead air >3 seconds

---

## Troubleshooting

### Command Fails During Recording

**Option 1:** Pause, fix, continue
**Option 2:** Edit out the error in post
**Option 3:** Re-record from that segment

### Output Too Fast to Read

**Solution:** Add `sleep` commands between segments or slow down video in post (0.75x speed)

### Finding IDs Changed

**Solution:** Before final recording, run analysis and update RECORDING_COMMANDS.sh with actual IDs

### Evidence File Not Available

**Fallback:** Use synthetic scenario instead:
```bash
python -m sift_find_evil.cli run \
  --scenario scenarios/synthetic/12_memory_intrusion \
  --output analysis/demo_run.json
```

---

## Tips for Clean Recording

1. **Disable notifications** (Do Not Disturb mode)
2. **Close unnecessary applications** (free up resources)
3. **Use a dedicated terminal window** (no tabs, clean prompt)
4. **Test run first** (verify all commands work)
5. **Have a backup plan** (synthetic scenario if evidence unavailable)
6. **Don't rush** (better to trim silence than rush commands)
7. **Show, don't tell** (let output speak, narrate context in voiceover)

---

## Checklist Before Final Recording

- [ ] Environment prepared (font size, colors, window size)
- [ ] Evidence mounted and verified
- [ ] Finding IDs identified and updated in script
- [ ] Test run completed successfully
- [ ] Screen recording software configured
- [ ] Backup plan ready (synthetic scenario)
- [ ] Demo script reviewed (DEMO_VIDEO_SCRIPT.md)
- [ ] Timing reference printed or on second monitor
- [ ] Do Not Disturb enabled
- [ ] Ready to record!

---

**Good luck with the recording!**
