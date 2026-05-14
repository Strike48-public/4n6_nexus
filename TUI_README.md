# SIFT Find Evil TUI Demo

Terminal User Interface for hackathon demo showcasing autonomous detection, self-correction, and forensic analysis workflows.

## Quick Start

```bash
# Launch the TUI
python3 demo_tui.py

# Or run directly
python3 -m sift_find_evil.tui
```

## Layout

Four-panel design demonstrating key capabilities:

```
┌─ sift-find-evil ──────────────────────────────────────────┐
│ Case: M57-Jean    Evidence: nps-2008-jean.E01    ● ANALYZING │
├───────────────┬───────────────────────────────────────────┤
│ DETECTORS     │ FINDINGS                                  │
│ ✓ NSRL filter │ ▸ CRIT  Ransomware: mass .encrypted       │
│ ✓ Prefetch    │ ▸ HIGH  Timestomp: 4 files backdated      │
│ ● Memory      │ ▸ MED   Exfil: 18MB upload to mega.nz     │
│ ● YARA scan   │                                           │
│ ○ Timeline    │                                           │
├───────────────┼───────────────────────────────────────────┤
│ SELF-CORRECT  │ REASONING                                  │
│ ⚠ CONTRADICT  │ MFT $STANDARD_INFORMATION shows 2019-01-15│
│   Resolved 3× │ MFT $FILE_NAME shows 2019-02-06 (22 days)│
│               │ → Timestomping detected. SI can be modified│
└───────────────┴───────────────────────────────────────────┘
 [a]pprove  [r]eject  [d]rill down  [e]xport  [q]uit
```

### Panel Descriptions

1. **Detectors Panel (Top-Left)**
   - Shows live detector execution progress
   - Status: ✓ (complete), ● (running), ○ (queued)
   - Demonstrates breadth of autonomous analysis

2. **Findings Panel (Top-Right)**
   - Prioritized list of suspicious artifacts
   - Color-coded by severity (CRIT, HIGH, MED, LOW)
   - Cursor navigation with arrow keys
   - Shows analyst-actionable results

3. **Self-Correction Log (Bottom-Left)**
   - Real-time contradiction detection
   - Counter showing resolved issues
   - The differentiator: visible self-healing
   - Flashes amber when contradictions resolve

4. **Reasoning Panel (Bottom-Right)**
   - Shows WHY, not just WHAT
   - Trace chain for selected finding
   - Multi-artifact correlation visible
   - Demonstrates forensic rigor

## Keybindings

| Key | Action | Description |
|-----|--------|-------------|
| `a` | Approve | Approve selected finding |
| `r` | Reject | Reject selected finding |
| `d` | Drill Down | Show detailed evidence |
| `e` | Export | Export findings to report |
| `q` | Quit | Exit the TUI |
| `↑↓` | Navigate | Move through findings table |

## Data Sources

The TUI reads from existing analysis artifacts:

- **Findings:** `demo/findings_sample.json` or `analysis/demo_ransomware.json`
- **Audit Log:** `demo/audit_sample.jsonl` (future: live tail)
- **Detectors:** Hardcoded list (future: read from scenario runner)

## For the Demo Video

**Recording tips:**
1. Launch TUI in a clean terminal (80x24 or larger)
2. Use OBS Studio to capture screen
3. Voiceover can be added post-recording
4. Navigate findings with arrow keys to show interactivity
5. Press `d` to "drill down" and show notifications
6. Press `e` to "export" and show workflow completion

**Wow moments to capture:**
- Self-correction counter incrementing
- Findings table populating with detections
- Reasoning pane showing multi-artifact correlation
- Detector progress bars advancing

## Architecture

**Standalone Design:**
- Reads existing JSONL outputs (no engine refactor needed)
- Replay mode for bulletproof demo recording
- 1-day build vs. 1-week integration

**Future Enhancements:**
- Live tail of audit JSONL with `watchdog`
- Real-time detector progress from scenario runner events
- Case loader screen for selecting .E01 or synthetic scenarios
- Export generates PDF report with findings + reasoning chains
- Color-coded severity highlighting (red/yellow/blue)
- Animated contradiction resolution flash

## Implementation Notes

- Built with [Textual](https://textual.textualize.io/) v8.2.6
- CSS-like styling for terminal UI
- DataTable widget for findings (cursor navigation)
- Grid layout (2x2) for four panels
- Header shows case context, footer shows keybindings

## Development

```bash
# Install dependencies
pip install textual

# Test the TUI
python3 demo_tui.py

# Run with Textual dev mode (live reload)
textual run --dev sift_find_evil/tui.py
```

## Troubleshooting

**TUI doesn't launch:**
- Check Python 3.12+ is installed
- Verify `textual` is installed: `pip list | grep textual`
- Run with `python3 -m sift_find_evil.tui` for better error messages

**Findings don't load:**
- Ensure `demo/findings_sample.json` exists
- Check file paths are relative to repo root
- Run from `/home/jtomek/Code/sift_find_evil/` directory

**Layout looks broken:**
- Resize terminal to at least 80x24
- Some terminals don't support full TUI features
- Try `alacritty`, `wezterm`, or `iTerm2` for best results

## Next Steps

1. **Record demo video** (5 minutes)
2. **Add live JSONL tailing** for real-time self-correction
3. **Wire to scenario runner** for actual detector progress
4. **Build case loader** for .E01 vs synthetic scenario selection
5. **Export to PDF** with findings + reasoning chains

---

**Estimated implementation time:** 10 hours (MVP complete in ~1 hour)

**Demo-ready:** ✓ Yes (current version shows all four panels with data)
