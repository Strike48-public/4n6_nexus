# Demo Video Recording Guide

Complete guide for recording both **Option A (AI Voice)** and **Option B (Your Voice)** versions.

---

## Pre-Recording Checklist

### Hardware Setup
- [ ] SIFT VM accessible and running
- [ ] USB-C drive with evidence mounted
- [ ] Microphone connected and tested (Option B only)
- [ ] Headphones for monitoring audio (Option B only)

### Software Setup
- [ ] OBS Studio installed (or ffmpeg for simple recording)
- [ ] Terminal font increased for readability
- [ ] Evidence accessible at `/media/sansforensics/TESLADRIVE/`
- [ ] sift_find_evil repository up to date

### Test Run
- [ ] Run through commands once to verify everything works
- [ ] Check audio levels (Option B: -18dB to -12dB)
- [ ] Verify screen resolution (1920x1080 minimum)
- [ ] Close unnecessary windows/notifications

---

## Option A: AI Voiceover (Chatterbox on RTX 4090)

### Step 1: Generate AI Voice (Do This Tomorrow)

**On system with RTX 4090:**

```bash
# Clone Chatterbox
git clone https://github.com/resemble-ai/chatterbox.git
cd chatterbox

# Install dependencies
pip install -r requirements.txt

# Run inference on voiceover script
python inference.py \
  --input ~/sift_find_evil/docs/VOICEOVER_SCRIPT.txt \
  --output demo_voiceover.wav \
  --voice professional_male  # or choose from available voices

# Export segments individually (recommended)
python inference.py --input segment_1.txt --output segment_1_problem.wav
python inference.py --input segment_2.txt --output segment_2_solution.wav
# ... etc
```

**Output Files:**
- `segment_1_problem.wav`
- `segment_2_solution.wav`
- `segment_3_setup.wav`
- `segment_4_execution.wav`
- `segment_5_self_correction.wav`
- `segment_6_results.wav`

### Step 2: Record Terminal Session (Silent)

**On your workstation:**

```bash
# Start screen recording (no audio)
obs-studio
# OR
ffmpeg -video_size 1920x1080 -framerate 30 -f x11grab -i :0.0 \
       -c:v libx264 -preset ultrafast -crf 18 \
       terminal_recording.mp4

# Run commands from TERMINAL_RECORDING_COMMANDS.sh
bash ~/Code/sift_find_evil/docs/TERMINAL_RECORDING_COMMANDS.sh

# Stop recording
```

**Tips:**
- Don't rush - let each command output show for 2-3 seconds
- Pause between segments to match voiceover timing
- If you make a mistake, just keep going - edit it out later

### Step 3: Combine Video + AI Voice

**Using FFmpeg:**

```bash
# Simple merge (if timing matches perfectly)
ffmpeg -i terminal_recording.mp4 -i demo_voiceover.wav \
       -c:v copy -c:a aac -strict experimental \
       demo_video_ai.mp4

# Advanced: Combine video with multiple audio segments
ffmpeg -i terminal_recording.mp4 \
       -i segment_1_problem.wav \
       -i segment_2_solution.wav \
       -i segment_3_setup.wav \
       -i segment_4_execution.wav \
       -i segment_5_self_correction.wav \
       -i segment_6_results.wav \
       -filter_complex "[1:a][2:a][3:a][4:a][5:a][6:a]concat=n=6:v=0:a=1[aout]" \
       -map 0:v -map "[aout]" \
       -c:v copy -c:a aac \
       demo_video_ai.mp4
```

**Using Video Editor (Kdenlive/DaVinci Resolve):**

1. Import terminal recording (video track)
2. Import AI voiceover segments (audio track)
3. Align video with audio timing
4. Add fade in/out transitions
5. Add title cards (intro/outro)
6. Export: H.264, 1080p, 30fps

### Step 4: Add Title Cards

**Intro Card (2 seconds):**
```
SIFT Find Evil
Autonomous DFIR with Self-Correction
FIND EVIL! Hackathon 2026
```

**Outro Card (2 seconds):**
```
github.com/jtomek/sift_find_evil
MIT License
```

---

## Option B: Live Narration (Your Voice)

### Step 1: Setup Audio

```bash
# Test microphone
arecord -l  # List recording devices

# Test recording
arecord -f cd -d 10 test_audio.wav
aplay test_audio.wav

# Check levels in Audacity or:
ffmpeg -f alsa -i default -t 10 -f null -
# Should see audio levels around -18dB to -12dB
```

### Step 2: Record Video + Audio Together

**Using OBS Studio (Recommended):**

1. **Setup sources:**
   - Add "Screen Capture" (full screen or window)
   - Add "Audio Input Capture" (your microphone)
   
2. **Configure settings:**
   - Resolution: 1920x1080
   - FPS: 30
   - Video bitrate: 5000 kbps
   - Audio bitrate: 192 kbps
   - Format: MP4 (H.264)

3. **Recording process:**
   - Open terminal with large font
   - Start OBS recording
   - Take a deep breath, relax
   - Read from `docs/DEMO_VIDEO_SCRIPT.md` (have it on another monitor)
   - Run commands while narrating
   - Stop recording when done

4. **Tips for narration:**
   - Speak clearly and confidently
   - Don't rush - judges need time to read terminal output
   - Pause between segments (edit out long pauses later)
   - If you make a mistake, pause, then restart that sentence
   - Smile while talking (sounds better even if not on camera)

**Using FFmpeg (Command Line):**

```bash
# Record screen + audio simultaneously
ffmpeg -video_size 1920x1080 -framerate 30 -f x11grab -i :0.0 \
       -f alsa -i default \
       -c:v libx264 -preset ultrafast -crf 18 \
       -c:a aac -b:a 192k \
       demo_video_live.mp4

# Run your commands in the terminal
# Press Ctrl+C in ffmpeg window to stop
```

### Step 3: Edit Recording

**Quick edits with FFmpeg:**

```bash
# Trim beginning (remove first 5 seconds)
ffmpeg -i demo_video_live.mp4 -ss 5 -c copy demo_trimmed.mp4

# Trim end (keep only first 5 minutes)
ffmpeg -i demo_video_live.mp4 -t 300 -c copy demo_5min.mp4

# Combine trim start + end
ffmpeg -i demo_video_live.mp4 -ss 5 -t 295 -c copy demo_final.mp4
```

**Full editing with Kdenlive/DaVinci Resolve:**

1. Import recording
2. Cut out mistakes/long pauses
3. Add title cards (intro/outro)
4. Adjust audio levels if needed (normalize to -3dB)
5. Add subtle background music (optional, low volume)
6. Export: H.264, 1080p, 30fps

---

## Recording Tips (Both Options)

### Terminal Display

**Before recording:**
```bash
# Increase font size
gsettings set org.gnome.desktop.interface text-scaling-factor 1.5
gsettings set org.gnome.desktop.interface monospace-font-name 'Ubuntu Mono 16'

# Clean terminal
clear
history -c

# Optional: Enable terminal colors for better visibility
export PS1='\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
```

**After recording:**
```bash
# Reset to normal
gsettings set org.gnome.desktop.interface text-scaling-factor 1.0
gsettings set org.gnome.desktop.interface monospace-font-name 'Ubuntu Mono 13'
```

### Timing Guidelines

| Segment | Duration | What to Show |
|---------|----------|--------------|
| Problem | 0:30 | Project README, terminal prompt |
| Solution | 0:30 | Code structure, MCP client safety features |
| Setup | 0:30 | Evidence mounting, partition analysis |
| Execution | 2:30 | MCP tool run, parsing, detection, audit log |
| Self-Correction | 1:00 | Specific findings with contradictions |
| Results | 0:30 | Summary screen, GitHub repo |

### Common Mistakes to Avoid

❌ **Rushing through commands**
- Let output display for 2-3 seconds before moving on

❌ **Terminal too small**
- Judges need to read the output clearly

❌ **No pauses between sections**
- Add 1-2 second pause to let viewers absorb information

❌ **Too much scrolling**
- Keep important output visible longer

❌ **Audio too quiet or too loud**
- Target: -18dB to -12dB for spoken word

❌ **Background noise**
- Record in quiet environment
- Close doors/windows
- Turn off fans if possible

---

## Split Screen Alternative

For more professional look, show audit log in real-time:

**Using tmux:**

```bash
# Start tmux session
tmux new-session -s demo

# Split horizontally (top 70%, bottom 30%)
tmux split-window -v -p 30

# Top pane: commands
tmux select-pane -t 0

# Bottom pane: audit log tail
tmux select-pane -t 1
tmux send-keys "tail -f /cases/demo_video/audit.jsonl | jq ." C-m

# Return to top pane
tmux select-pane -t 0

# Now record the entire tmux session
# Bottom will update automatically as tools run
```

---

## Post-Recording Checklist

### Quality Check
- [ ] Video length <5 minutes (or <10 max)
- [ ] Audio clearly audible
- [ ] Terminal text readable at 1080p
- [ ] No sensitive information visible (passwords, API keys)
- [ ] Title cards present (intro/outro)
- [ ] Self-correction examples shown clearly

### Technical Requirements
- [ ] Resolution: 1920x1080 minimum
- [ ] Frame rate: 30fps minimum
- [ ] Format: MP4 (H.264)
- [ ] Audio: AAC, 192kbps
- [ ] No copyrighted music
- [ ] No third-party trademarks

### Content Requirements
- [ ] Shows real terminal execution (not slides)
- [ ] Demonstrates at least one self-correction sequence
- [ ] Shows audit logging
- [ ] Explains architectural constraints
- [ ] Includes F1=1.00 results

---

## Upload Instructions

### YouTube Upload

1. Go to youtube.com/upload
2. Select video file
3. Fill out details:
   ```
   Title: SIFT Find Evil - Autonomous DFIR | FIND EVIL! Hackathon
   
   Description:
   Autonomous DFIR agent with architectural self-correction for the SANS FIND EVIL! Hackathon.
   
   Features:
   - MCP integration for safe forensic tool execution
   - Cross-artifact validation and contradiction detection
   - F1=1.00 on 12 test scenarios (perfect precision/recall)
   - 247 self-correction instances on real evidence
   
   GitHub: https://github.com/jtomek/sift_find_evil
   License: MIT Open Source
   
   Evidence: insider_threat_2022/Narcos-CCleaner.E01 (7.7GB real forensic image)
   Results: 155,452 MFT entries → 1,071 findings → 247 contradictions detected
   
   #DFIR #DigitalForensics #AutonomousAgent #ClaudeCode #SANS #FINDEVIL
   ```
   
4. Visibility: **Unlisted** (only people with link can view)
5. Add to playlist: "FIND EVIL! Hackathon"
6. Thumbnail: Screenshot of terminal showing "F1=1.00"
7. Click "Publish"
8. Copy link and paste into Devpost submission

### Vimeo Upload (Alternative)

1. Go to vimeo.com/upload
2. Select video file
3. Settings:
   - Privacy: "Anyone" or "Only people with a link"
   - Allow embedding
   - Title/Description same as YouTube
4. Publish and copy link

---

## Troubleshooting

### Problem: Video too long (>5 minutes)

**Solution 1: Speed up execution sections**
```bash
# Increase video playback speed for boring parts
ffmpeg -i input.mp4 -filter:v "setpts=0.75*PTS" output.mp4
```

**Solution 2: Cut less critical parts**
- Shorten setup section (0:30 → 0:20)
- Trim execution output (show summary instead of full output)

**Solution 3: Tighter narration**
- Remove filler words ("um", "so", "basically")
- Speak slightly faster (but still clear)

### Problem: Audio out of sync with video (Option A)

**Solution:**
```bash
# Shift audio forward by 0.5 seconds
ffmpeg -i video.mp4 -i audio.wav -itsoffset 0.5 -i audio.wav \
       -map 0:v -map 1:a -c copy output.mp4

# OR use video editor for precise alignment
```

### Problem: Terminal output too fast to read

**Solution:**
- Add `sleep 3` commands between outputs in recording script
- Use video editor to slow down specific sections
- Add freeze frames on important findings

### Problem: Background noise in recording (Option B)

**Solution using Audacity:**
1. Open audio in Audacity
2. Select 1-2 seconds of pure noise
3. Effect → Noise Reduction → Get Noise Profile
4. Select all audio
5. Effect → Noise Reduction → OK (start with 12dB reduction)

---

## Comparison: Which Version to Submit?

### Option A (AI Voice) Strengths:
- ✅ Professional, consistent narration
- ✅ No "ums" or mistakes
- ✅ Easy to re-record if needed
- ✅ Can do unlimited takes of terminal without worrying about voice

### Option B (Your Voice) Strengths:
- ✅ More authentic and personal
- ✅ Shows passion for the project
- ✅ Judges may appreciate the human touch
- ✅ Can improvise if something unexpected happens

### My Recommendation:
**Record both, then decide!** Whichever sounds better and feels more authentic to you.

If Option B recording goes smoothly on first take, use that. If you do multiple takes and it feels forced, use Option A.

---

## Final Export Settings

**FFmpeg Export:**
```bash
ffmpeg -i input.mp4 \
       -c:v libx264 -preset slow -crf 18 \
       -c:a aac -b:a 192k \
       -pix_fmt yuv420p \
       -movflags +faststart \
       -vf scale=1920:1080 \
       final_demo_video.mp4
```

**Settings Explained:**
- `libx264`: H.264 codec (widely compatible)
- `preset slow`: Better quality, slower encoding
- `crf 18`: High quality (18-23 is good, lower = better quality)
- `aac 192k`: Good audio quality
- `yuv420p`: Color space compatible with all players
- `faststart`: Optimize for web streaming
- `scale=1920:1080`: Ensure 1080p resolution

**File size target:** 200-500MB for 5-minute video is fine

---

## Ready to Record?

### Quick Start Checklist
- [ ] Read through DEMO_VIDEO_SCRIPT.md
- [ ] Test run TERMINAL_RECORDING_COMMANDS.sh
- [ ] Configure terminal font (large and readable)
- [ ] Test screen recording software
- [ ] Test audio (Option B only)
- [ ] Close unnecessary windows
- [ ] Take a deep breath and relax!

**When ready:**
1. Start recording
2. Follow the script naturally
3. Don't worry about perfection - you can edit
4. Stop recording
5. Review footage
6. Edit as needed
7. Export final video
8. Upload to YouTube/Vimeo
9. Submit to Devpost

**You've got this!** 🎬
