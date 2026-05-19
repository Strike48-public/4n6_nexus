# Progress Panel Design

## Overview

Enhanced progress panel for real-time investigation status during long-running analyses. Appears at bottom of screen when analysis is active, provides rich feedback on progress, findings, and system state.

## Layout

```
┌─ Investigation Progress ────────────────────────────────────────────────────────┐
│ Current Phase: Running YARA scans                                               │
│ ████████████████░░░░░░░░ 65% (78/120 files)  │  Elapsed: 00:02:45  ETA: 00:01:15│
│                                                                                  │
│ Phases: [✓] Load  [✓] Timestamps  [●] YARA  [ ] Memory  [ ] Persist  [ ] Report│
│                                                                                  │
│ Findings: Critical: 2  High: 1  Medium: 0  Low: 0  Info: 3                      │
│                                                                                  │
│ Recent Activity:                                                                │
│ • 00:02:45 - YARA match: APT29_Loader in malware.exe                            │
│ • 00:02:32 - Timestomping detected: cmd.exe (22-day delta)                      │
│ • 00:02:18 - Checked registry key: HKCU\Run\WindowsUpdate (clean)               │
│                                                                                  │
│ ⚠ High memory usage (2.1GB/4GB)            [Press 'Esc' to cancel] [↓ Collapse]│
└──────────────────────────────────────────────────────────────────────────────────┘
```

## Collapsed State

```
┌─ Investigation Progress ────────────────────────────────────────────────────────┐
│ YARA: 65% (78/120)  │  Elapsed: 00:02:45  ETA: 00:01:15  │  Findings: C:2 H:1 M:0 │
│ [✓] Load [✓] Time [●] YARA [ ] Mem [ ] Persist      ⚠ Memory  [↑ Expand] [Esc]│
└──────────────────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Main Progress Bar
- Current phase name displayed above bar
- Visual progress bar with percentage
- Item count if applicable (files scanned, artifacts processed)
- Elapsed time (HH:MM:SS format)
- ETA if calculable (based on current phase velocity)

### 2. Phase Status Indicators
- Compact phase overview showing pipeline progression
- States:
  - `[✓]` Complete (green)
  - `[●]` In progress (yellow/animated)
  - `[ ]` Pending (gray)
  - `[!]` Error/warning (red)
- Short phase names (5-8 chars max) for space efficiency

### 3. Findings Counter
- Real-time tally of findings by severity
- Format: `Critical: N  High: N  Medium: N  Low: N  Info: N`
- Color-coded by severity
- Updates live as detections fire

### 4. Activity Feed
- Last 3-5 actions with timestamps
- Auto-scrolling (most recent at top)
- Format: `• HH:MM:SS - Action description`
- Shows:
  - Files scanned with interesting results
  - Detections triggered
  - Phase transitions
  - Errors or warnings

### 5. Resource Monitor (bottom-right)
- Memory usage indicator
- Shows warning icon when:
  - Memory > 80% of available
  - CPU sustained high load
  - Disk I/O bottleneck detected
- Format: `⚠ High memory usage (2.1GB/4GB)`
- Only visible when there's an issue

### 6. Control Actions (bottom)
- `[Press 'Esc' to cancel]` - Interrupt analysis, save partial results
- `[↓ Collapse]` / `[↑ Expand]` - Toggle between full and compact views
- Actions are keyboard-driven (no mouse required)

## Panel Behavior

### Visibility
- Appears when `AnalysisScreen.on_mount()` starts investigation
- Persists until analysis completes or is canceled
- Automatically collapses if user focuses on findings panel
- Can be manually toggled with keybinding (suggest: `p`)

### Height
- Full view: 10-12 lines
- Collapsed view: 2 lines
- Dynamically sized based on terminal height (min 10 lines for full)

### Position
- Always bottom of screen, above footer
- Pushes other panels up slightly
- Footer remains at absolute bottom

### State Persistence
- Remembers collapse/expand preference for session
- Resets to expanded on new analysis

## Implementation Notes

### Phase Detection Pipeline Order
Based on typical DFIR workflow:
1. Load - Loading artifacts and evidence
2. Timestamps - Checking for timestamp anomalies
3. YARA - Malware signature scanning
4. Memory - Memory forensics (Volatility)
5. Persist - Persistence mechanism detection
6. Report - Generating final report

This is configurable based on analysis mode.

### Progress Calculation
- Per-phase progress tracked independently
- Overall progress weighted by estimated phase duration
- ETA based on:
  - Items remaining in current phase
  - Average processing velocity (items/sec)
  - Estimated time for pending phases

### Findings Feed Integration
- Detectors emit events when findings are generated
- Progress panel subscribes to finding events
- Updates counter and activity feed in real-time
- No polling required

### Resource Monitoring
- Lightweight sampling every 5 seconds
- Uses `psutil` for memory/CPU metrics
- Warning thresholds:
  - Memory: 80% of available
  - CPU: 90% sustained for >30 seconds
- Helps diagnose slow analysis

### Cancellation Handling
- `Esc` key sends stop signal to running detectors
- Detectors checkpoint progress at phase boundaries
- Partial results saved to disk
- User notified: "Analysis canceled. Partial results saved."

## Textual Widget Structure

```python
class ProgressPanel(Static):
    """Collapsible progress panel for investigation status."""

    def __init__(self):
        super().__init__()
        self.current_phase = "Loading"
        self.progress_pct = 0.0
        self.items_current = 0
        self.items_total = 0
        self.elapsed_seconds = 0
        self.eta_seconds = None
        self.phases = [...]  # Phase status list
        self.findings_by_severity = {...}
        self.recent_activities = []  # Circular buffer
        self.is_collapsed = False
        self.resource_warning = None

    def compose(self):
        # Build widget tree
        if self.is_collapsed:
            yield self._render_collapsed()
        else:
            yield self._render_full()

    def toggle_collapse(self):
        self.is_collapsed = not self.is_collapsed
        self.refresh()

    def update_progress(self, phase, pct, current, total):
        self.current_phase = phase
        self.progress_pct = pct
        self.items_current = current
        self.items_total = total
        self.refresh()

    def add_activity(self, timestamp, message):
        self.recent_activities.insert(0, (timestamp, message))
        if len(self.recent_activities) > 5:
            self.recent_activities.pop()
        self.refresh()

    def update_findings(self, severity):
        self.findings_by_severity[severity] += 1
        self.refresh()
```

## CSS Styling

```css
#progress-panel {
    dock: bottom;
    height: auto;
    max-height: 12;
    min-height: 2;
    border: solid $accent;
    padding: 1;
    background: $surface-darken-1;
}

.progress-bar {
    height: 1;
    width: 100%;
    background: $panel-lighten-1;
}

.progress-bar-filled {
    background: $success;
}

.phase-indicator {
    display: inline;
    margin: 0 1;
}

.phase-complete {
    color: $success;
}

.phase-active {
    color: $warning;
}

.phase-pending {
    color: $text-muted;
}

.findings-counter {
    color: $text;
}

.findings-critical {
    color: $error;
    text-style: bold;
}

.findings-high {
    color: $warning;
}

.activity-feed {
    height: 4;
    overflow-y: auto;
    color: $text-muted;
}

.activity-item {
    padding: 0;
}

.resource-warning {
    color: $warning;
    text-style: bold;
}
```

## Integration with AnalysisScreen

### Mounting
```python
def on_mount(self):
    # Create progress panel
    progress_panel = ProgressPanel()
    self.mount(progress_panel, before=self.query_one(Footer))

    # Start analysis workflow
    self.run_worker(self._run_analysis, exclusive=True)
```

### Progress Updates
```python
async def _run_analysis(self):
    for phase in self.phases:
        self.progress_panel.update_phase(phase.name)
        for i, item in enumerate(phase.items):
            # Process item
            result = await phase.process(item)

            # Update progress
            pct = (i + 1) / len(phase.items) * 100
            self.progress_panel.update_progress(
                phase=phase.name,
                pct=pct,
                current=i + 1,
                total=len(phase.items)
            )

            # Add activity if interesting
            if result.is_finding:
                self.progress_panel.add_activity(
                    timestamp=time.time(),
                    message=result.description
                )
                self.progress_panel.update_findings(result.severity)
```

## Testing Scenarios

### Happy Path
1. Start timeline analysis
2. Progress panel appears
3. Phases progress sequentially
4. Findings accumulate in counter
5. Activity feed updates with detections
6. Analysis completes, panel auto-hides

### Edge Cases
- Very fast analysis (<5 seconds) - panel may only flash
- No findings detected - counter stays at 0, activity feed shows "clean" items
- Analysis canceled mid-phase - partial results saved, panel shows cancellation message
- Resource exhaustion - warning appears, analysis may slow down
- Window resize - panel adapts to new terminal size

### Error Handling
- Phase crashes - panel shows error state, option to continue or abort
- Out of memory - panel shows critical warning, recommends cleanup
- Keyboard interrupt - graceful shutdown, partial results saved

## Future Enhancements

- Export progress log to JSON for review
- Real-time graph of findings over time
- Network activity indicator for remote evidence sources
- Detector-specific progress (drill down into YARA scan sub-phases)
- Historical comparison (current run vs. baseline)
