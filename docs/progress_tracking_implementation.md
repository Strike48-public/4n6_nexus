# Progress Tracking Implementation

## Overview

Fully wired real-time progress tracking system for the TUI analysis screen, showing live investigation status with system resource monitoring.

## Components

### 1. Progress Tracker (`progress_tracker.py`)

Central progress tracking system that manages:

- **Phase Management**
  - Registers investigation phases (Load, Timestamps, YARA, Memory, Persist, Report)
  - Tracks current phase status (pending, active, complete, error)
  - Calculates progress percentage and ETA per phase

- **Progress Updates**
  - Tracks items processed vs. total
  - Calculates velocity (items/second)
  - Estimates time remaining based on current phase velocity

- **Findings Tracking**
  - Counts findings by severity (Critical, High, Medium, Low, Info)
  - Updates real-time as detections fire

- **Activity Logging**
  - Maintains circular buffer of last 5 activities
  - Timestamps each event
  - Provides formatted time display

- **Event System**
  - Callback registration for:
    - Progress updates
    - Finding additions
    - Activity additions
    - Phase changes
    - Resource updates
  - Notifies UI panels when data changes

### 2. Resource Monitor (`resource_monitor.py`)

System resource monitoring using `psutil`:

- **CPU Usage**: Non-blocking CPU percentage sampling
- **RAM Usage**: Used/total memory in GB, calculates percentage
- **Disk I/O**: Read/write rate in MB/s (calculated from deltas)
- **Warning Detection**: Flags when RAM >80% or CPU >90%
- **Graceful Fallback**: Returns mock data if psutil unavailable

Runs monitoring loop every 5 seconds, updates progress tracker.

### 3. System Resources Panel

Bottom-left panel showing real-time system metrics:

- CPU percentage
- RAM usage (used/total GB)
- Disk I/O rate (MB/s)
- Resource warnings (⚠ High memory usage)
- Cancel action hint

Updates automatically when resource monitor reports new data.

### 4. Progress Panel

Bottom-right panel showing investigation progress:

**Full View:**
- Current phase name
- Progress bar (visual + percentage + item count)
- Elapsed time (HH:MM:SS)
- Estimated time remaining (HH:MM:SS)
- Phase indicators ([✓] complete, [●] active, [ ] pending)
- Findings counter by severity
- Recent activity feed (last 3 activities with timestamps)
- Collapse control

**Collapsed View:**
- Single-line summary with key metrics
- Phase indicators
- Expand control

Toggles with 'p' key. Updates automatically when tracker state changes.

## Data Flow

```
Resource Monitor (5s interval)
    ↓
Progress Tracker.update_resources()
    ↓
Callback: _on_resources_updated()
    ↓
SystemResourcesPanel.update_resources()
    ↓
UI updates


Analysis Worker
    ↓
Progress Tracker.start_phase() / increment_progress() / add_finding()
    ↓
Callbacks: _on_progress_update() / _on_phase_changed() / _on_activity_added()
    ↓
ProgressPanel.refresh()
    ↓
UI updates
```

## Demo Analysis Workflow

Simulated investigation with realistic progression:

1. **Load Phase** (10 items, 0.5s each) - Load artifacts
2. **Timestamps Phase** (50 items, 0.1s each) - Check for timestomping
   - Adds HIGH finding at item 25: "Timestomping detected"
3. **YARA Phase** (120 items, 0.05s each) - Malware scanning
   - Adds CRITICAL finding at item 45: "APT29_Loader detected"
   - Adds INFO finding at item 78: "Registry key clean"
4. **Memory Phase** (30 items, 0.2s each) - Memory analysis
5. **Persist Phase** (20 items, 0.15s each) - Persistence detection
6. **Report Phase** (5 items, 1.0s each) - Generate report

Total runtime: ~25 seconds with realistic findings and activity feed.

## Integration Points

### Adding Real Detectors

Replace `_run_demo_analysis()` with real detector execution:

```python
async def _run_analysis(self) -> None:
    # Phase 1: YARA scanning
    self.progress_tracker.start_phase("yara", items_total=len(files_to_scan))
    
    for file_path in files_to_scan:
        # Run YARA scanner
        matches = yara_scanner.scan_file(file_path)
        
        # Update progress
        self.progress_tracker.increment_progress()
        
        # Log findings
        for match in matches:
            self.progress_tracker.add_finding(
                FindingSeverity.CRITICAL,
                f"YARA match: {match.rule} in {file_path.name}"
            )
    
    self.progress_tracker.complete_phase()
```

### Cancellation Handling

The system supports graceful cancellation:

1. User presses 'Esc'
2. `progress_tracker.cancel()` is called
3. `is_canceled` flag set to True
4. Workers check flag and exit cleanly
5. Partial results preserved

### Custom Phase Pipelines

Register different phases based on analysis mode:

```python
# Quick triage mode
tracker.register_phases([
    ("load", "Load"),
    ("prefetch", "Prefetch"),
    ("yara", "YARA"),
])

# Full analysis mode
tracker.register_phases([
    ("load", "Load"),
    ("timestamps", "Timestamps"),
    ("yara", "YARA"),
    ("memory", "Memory"),
    ("persist", "Persist"),
    ("timeline", "Timeline"),
    ("report", "Report"),
])
```

## Testing

Run the TUI to see live progress tracking:

```bash
./demo_tui.py
```

Navigate to analysis screen:
1. Select any evidence path
2. Choose analysis mode
3. Click "Start Analysis"
4. Watch progress panels update in real-time

**Expected Behavior:**
- System resources update every 5 seconds
- Progress bar advances as phases complete
- Findings counter increments when detections fire
- Activity feed shows timestamped events
- Phase indicators show pipeline progression
- ETA calculates based on current velocity

## Future Enhancements

- Pause/resume functionality
- Save progress checkpoints
- Export progress logs to JSON
- Historical analysis comparison
- Phase duration analytics
- Detector performance profiling
