# SIFT Find Evil TUI Demo

Professional Terminal User Interface for digital forensics and incident response. Showcases autonomous detection, self-correction, and forensic analysis workflows.

## Quick Start

```bash
# Launch the TUI
python3 demo_tui.py

# Or run directly
python3 -m sift_find_evil.tui
```

**Professional 3-screen workflow:**
1. **File Selection** - Browse filesystem for evidence files or synthetic scenarios
2. **Analysis Configuration** - Choose analysis mode (Quick, Full, Memory, Timeline, Custom)
3. **Live Analysis** - Real-time detection with four-panel dashboard

## Workflow

### Screen 1: File Selection
```
┌─ SIFT FIND EVIL - SELECT EVIDENCE ────────────────────────┐
│ Navigate to evidence file or synthetic scenario directory │
│ ┌──────────────────────────────────────────────────────┐  │
│ │ /home/user/evidence/cases/                           │  │
│ └──────────────────────────────────────────────────────┘  │
│ 📁 scenarios/                                             │
│   📁 synthetic/                                           │
│     📁 02_ransomware/                                     │
│     📁 03_timestomping/                                   │
│   📁 real/                                                │
│     📄 nps-2008-jean.E01                                  │
│                                                            │
│ [Load Evidence]  [Cancel]                                 │
└────────────────────────────────────────────────────────────┘
```

### Screen 2: Analysis Configuration
```
┌─ SIFT FIND EVIL - ANALYSIS CONFIGURATION ─────────────────┐
│ Evidence: 02_ransomware                                   │
│ Path: /home/user/scenarios/synthetic/02_ransomware       │
│                                                            │
│ Select Analysis Mode:                                     │
│ [Quick Triage - Essential artifacts only        ]         │
│ [Full Analysis - All detectors + YARA           ]         │
│ [Memory Analysis - Volatility + baselining      ]         │
│ [Timeline - Supertimeline + analysis            ]         │
│ [Custom - Select detectors manually             ]         │
│                                                            │
│ [Start Analysis]  [Back]                                  │
└────────────────────────────────────────────────────────────┘
```

### Screen 3: Live Analysis (Four Panels)
```
┌─ sift-find-evil ──────────────────────────────────────────┐
│ Case: 02_ransomware    Evidence: 02_ransomware    Mode: QUICK    ● ANALYZING │
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
 [a]pprove  [r]eject  [d]rill down  [e]xport  [b]ack  [q]uit
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

### File Selection Screen
| Key | Action | Description |
|-----|--------|-------------|
| `↑↓` | Navigate | Browse directory tree |
| `Enter` | Select | Choose file/directory |
| `Tab` | Focus | Switch between tree and input |
| `q` | Quit | Exit the TUI |

### Analysis Configuration Screen
| Key | Action | Description |
|-----|--------|-------------|
| `↑↓` | Navigate | Scroll through options |
| `Enter` / `Click` | Select | Choose analysis mode |
| `q` | Quit | Exit the TUI |

### Live Analysis Screen
| Key | Action | Description |
|-----|--------|-------------|
| `a` | Approve | Approve selected finding |
| `r` | Reject | Reject selected finding |
| `d` | Drill Down | Show detailed evidence |
| `e` | Export | Export findings to report |
| `b` | Back | Return to configuration |
| `q` | Quit | Exit the TUI |
| `↑↓` | Navigate | Move through findings table |

## Data Sources

The TUI reads from existing analysis artifacts:

- **Findings:** `demo/findings_sample.json` or `analysis/demo_ransomware.json`
- **Audit Log:** `demo/audit_sample.jsonl` (future: live tail)
- **Detectors:** Hardcoded list (future: read from scenario runner)

## For the Demo Video

**Professional demo flow (5 minutes):**

**0:00-0:30 Opening**
- "This is SIFT Find Evil, a professional DFIR analysis tool"
- Launch TUI, show file selection screen

**0:30-1:00 Evidence Selection**
- Navigate directory tree to `scenarios/synthetic/02_ransomware/`
- Click "Load Evidence" button
- Show configuration screen appears automatically

**1:00-1:30 Analysis Configuration**
- Highlight different analysis modes (Quick, Full, Memory, Timeline)
- Select "Quick Triage" mode
- Click "Start Analysis"

**1:30-3:30 Live Analysis**
- Show four-panel dashboard
- Detectors panel: Show progression (○ → ● → ✓)
- Findings panel: Navigate with arrow keys, show severity levels
- Self-correction panel: Point out contradiction resolution counter
- Reasoning panel: Explain multi-artifact correlation

**3:30-4:30 Interaction**
- Press 'd' to drill down on a finding
- Press 'a' to approve a detection
- Press 'e' to export report (notification appears)

**4:30-5:00 Closing**
- Press 'b' to return to config (show it works)
- Press 'q' to exit cleanly
- "Autonomous detection with built-in self-correction"

**Recording tips:**
- Terminal size: 120x40 or larger for comfortable viewing
- OBS Studio for screen capture
- No voiceover needed - UI is self-explanatory
- Focus on showing the professional workflow, not test metadata

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
