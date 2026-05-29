# Hackathon Demo Recording Guide

Complete guide for recording the 5-minute hackathon demo video.

---

## Quick Start

```bash
cd ~/Code/sift_find_evil

# Option 1: Ransomware scenario (RECOMMENDED - works reliably)
bash demo/RECORDING_COMMANDS_APT.sh

# Option 2: M57-Jean E01 evidence (requires mounting)
bash demo/RECORDING_COMMANDS_HACKATHON.sh
```

**Recording method:** Use OBS Studio to capture terminal output, add voiceover later.

---

## Demo Scripts Overview

| Script | Evidence | Runtime | Status |
|--------|----------|---------|--------|
| **RECORDING_COMMANDS_APT.sh** | Synthetic ransomware scenario | ~5 min | ✓ Working |
| **RECORDING_COMMANDS_HACKATHON.sh** | M57-Jean E01 (real evidence) | ~5 min | Requires mount |

### RECORDING_COMMANDS_APT.sh (Recommended)

**What it demonstrates:**
- Self-healing: Tool timeout + corrupt output recovery
- Self-correction: Ransomware detection with confidence adjustment
- Autonomous execution: Agent reasoning visible throughout
- Analyst workflow: Review → Approve → Report
- Audit trail: Finding → Tool execution traceability

**Evidence used:**
- Synthetic ransomware scenario (02_ransomware)
- 3 findings: Mass encryption, timestomping, persistence
- F1 Score: 1.00 (perfect precision/recall)

**Segments:**
1. (0:00-0:30) Problem statement
2. (0:30-2:00) Agent execution with failure recovery
3. (2:00-2:45) Self-correction sequence
4. (2:45-3:30) Results dashboard
5. (3:30-4:00) Analyst workflow
6. (4:00-4:45) Audit trail & value proposition

### RECORDING_COMMANDS_HACKATHON.sh (Alternative)

**What it demonstrates:**
- Same features as APT script
- Uses real M57-Jean E01 forensic image

**Requirements:**
- Evidence file: `scenarios/real/m57-jean/evidence/nps-2008-jean.E01`
- Mounted at: `/mnt/ewf_mount` and `/mnt/windows_mount`
- Sudo permissions for mounting

**Setup:**
```bash
# Create mount points
sudo mkdir -p /mnt/ewf_mount /mnt/windows_mount

# Mount E01
sudo ewfmount scenarios/real/m57-jean/evidence/nps-2008-jean.E01 /mnt/ewf_mount

# Mount Windows partition
sudo mount -o ro,loop,offset=32256 /mnt/ewf_mount/ewf1 /mnt/windows_mount

# Verify
ls -lh /mnt/windows_mount/\$MFT
```

---

## Recording Setup

### 1. Install OBS Studio

```bash
sudo add-apt-repository ppa:obsproject/obs-studio
sudo apt update
sudo apt install obs-studio
```

### 2. OBS Configuration

**Video Settings:**
- Resolution: 1920x1080 (or 1280x720)
- Frame rate: 30fps
- Format: MP4 (H.264)
- Bitrate: 2500-5000 kbps

**Scene Setup:**
1. Add Source → Window Capture
2. Select terminal window
3. Set background to black

**Recording Output:**
- Default path: `~/Videos/`
- File format: MP4
- Quality: High

### 3. Terminal Preparation

```bash
# Increase font size for readability
gsettings set org.gnome.desktop.interface text-scaling-factor 1.5

# Clear terminal history
history -c

# Navigate to project
cd ~/Code/sift_find_evil
```

---

## Recording Workflow

### Step 1: Pre-Flight Check

```bash
# Verify script is executable
ls -lh demo/RECORDING_COMMANDS_APT.sh

# Test run (check for errors)
bash demo/RECORDING_COMMANDS_APT.sh

# Verify output looks correct
```

### Step 2: Record Terminal Session

1. **Start OBS** - Configure window capture for terminal
2. **Hit Record** - Start recording in OBS
3. **Run Script** - `bash demo/RECORDING_COMMANDS_APT.sh`
4. **Wait for Completion** - Script shows "Demo Complete"
5. **Stop Recording** - Stop OBS recording

**Video saved to:** `~/Videos/` (check OBS settings)

### Step 3: Add Voiceover (Post-Production)

Use voiceover script from `docs/DEMO_VIDEO_SCRIPT.md`:

**Tools for voiceover:**
- Audacity (free audio editor)
- DaVinci Resolve (free video editor)
- Adobe Premiere (commercial)
- Final Cut Pro (Mac)

**Process:**
1. Import terminal recording into video editor
2. Record narration following `docs/DEMO_VIDEO_SCRIPT.md`
3. Sync narration to video segments
4. Add 2-second intro/outro cards (optional)
5. Export as MP4 (H.264, 1080p, <5 minutes)

---

## Hackathon Requirements Checklist

Verify your recording meets all requirements:

- [ ] **<5 minutes total runtime**
- [ ] **Live terminal screencast** (not slides)
- [ ] **Real evidence** (ransomware scenario or M57-Jean E01)
- [ ] **Self-correction sequence visible** (MANDATORY)
- [ ] **Agent reasoning shown** (visible at each step)
- [ ] **Self-healing demonstrated** (tool failure recovery)
- [ ] **Audit trail shown** (finding → tool execution)
- [ ] **User workflow shown** (review → approve → report)
- [ ] **Audio narration** (can be added in post-production)

---

## Script Features Explained

### Timer Display

Each segment shows elapsed time:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[1:34] SEGMENT 4: Results Dashboard
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Screen Clearing

Each segment starts with `clear` for professional transitions.

### Self-Healing Examples

**Failure 1: Tool Timeout**
```
[ERROR] Tool timeout after 5 seconds
[Agent Reasoning] Root cause: Timeout too short
[Agent Recovery] Retry with 60-second timeout
[OK] Parsing successful
```

**Failure 2: Corrupt Output**
```
[ERROR] Output validation failed - schema mismatch
[Agent Reasoning] Map 'Args' → 'CommandLine'
[Agent Recovery] Schema normalized
[OK] Validation passed
```

### Self-Correction Examples

**Example 1: Mass Encryption**
- Initial confidence: 0.70
- Cross-artifact validation: MFT + Prefetch + Registry timestamps align
- Adjusted confidence: 0.95
- Reason: Multiple artifacts confirm ransomware

**Example 2: Timestomping**
- Initial confidence: 0.40
- Detected: SI/FN timestamp 22-day delta
- Adjusted confidence: 0.90
- Reason: Decoded payload confirms malicious intent

---

## Troubleshooting

### Script Hangs or Errors

**If script stops early:**
```bash
# Check for Python errors
PYTHONPATH=. python -m sift_find_evil.cli run --scenario scenarios/synthetic/02_ransomware

# Verify scenario works
ls -lh scenarios/synthetic/02_ransomware/
```

**If no output:**
```bash
# Check Python path
which python
python --version  # Should be 3.12+

# Verify CLI module exists
ls -lh sift_find_evil/cli.py
```

### OBS Recording Issues

**Black screen:**
- Check window capture source
- Verify terminal window is selected
- Try "Window Capture (Xcomposite)" source

**Poor video quality:**
- Increase bitrate: Settings → Output → Recording Quality
- Use CRF 18-23 for high quality
- Resolution: 1920x1080 minimum

**Audio not recording:**
- Check Audio Mixer shows desktop audio
- Settings → Audio → Desktop Audio Device

### Terminal Font Too Small

```bash
# Increase terminal font
gsettings set org.gnome.desktop.interface text-scaling-factor 2.0

# Or manually: Terminal → Preferences → Text → Font Size
```

---

## Alternative: asciinema Recording

If OBS is problematic, use asciinema:

```bash
# Install
sudo apt install asciinema

# Record
asciinema rec demo_recording.cast

# Run script
bash demo/RECORDING_COMMANDS_APT.sh

# Stop (Ctrl+D)

# Play back
asciinema play demo_recording.cast

# Convert to video (requires additional tools)
# See: https://github.com/asciinema/agg
```

---

## Post-Recording Checklist

After recording, verify:

- [ ] Video file exists in `~/Videos/`
- [ ] Total length <5 minutes
- [ ] All 6 segments visible
- [ ] Timer display readable
- [ ] Text is clear at 1080p
- [ ] No frozen frames or glitches
- [ ] Audio levels good (if recorded with narration)

---

## Final Export Settings

**For YouTube/Vimeo submission:**

- **Container:** MP4
- **Video codec:** H.264
- **Resolution:** 1920x1080 (1080p)
- **Frame rate:** 30fps
- **Audio:** AAC, 128-192 kbps
- **Bitrate:** 5000-8000 kbps (high quality)
- **Total size:** ~100-150 MB (for 5 minutes)

---

## Resources

- **Voiceover script:** `docs/DEMO_VIDEO_SCRIPT.md`
- **Recording notes:** `demo/RECORDING_NOTES.md`
- **Hackathon requirements:** See conversation summary or findevil.devpost.com

---

## Quick Reference Commands

```bash
# Run recommended demo
bash demo/RECORDING_COMMANDS_APT.sh

# Test scenario separately
PYTHONPATH=. python -m sift_find_evil.cli run --scenario scenarios/synthetic/02_ransomware

# Check video output
ls -lh ~/Videos/

# Increase terminal font
gsettings set org.gnome.desktop.interface text-scaling-factor 1.5
```

---

**Ready to record? Start with RECORDING_COMMANDS_APT.sh - it's tested and working!**
