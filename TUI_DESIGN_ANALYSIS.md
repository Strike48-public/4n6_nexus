# TUI Design Analysis: grok-cli

Analysis of https://github.com/superagent-ai/grok-cli for design patterns applicable to sift-find-evil TUI.

## Technology Stack

- **Framework:** OpenTUI (React-based TUI framework)
- **Language:** TypeScript
- **Runtime:** Bun
- **Stars:** 3,047

## Design Patterns Worth Adopting

### 1. Theme System (theme.ts)

**What they do:**
- Centralized color palette with semantic naming
- 52 distinct colors for different UI elements
- Specialized colors for diffs, markdown, plans, etc.

**Example:**
```typescript
export const dark = {
  background: "#000000",
  backgroundPanel: "#111111",
  backgroundElement: "#1a1a1a",
  border: "#333333",
  text: "#e0e0e0",
  textMuted: "#666666",
  accent: "#5c9cf5",
  subagentAccent: "#66d9c2",
  diffAdded: "#1e3a1e",
  diffAddedFg: "#8adf8a",
  // ... 40+ more semantic colors
}
```

**How we could apply it:**
- Replace hardcoded Textual color variables with semantic naming
- Add specialized colors for evidence types (disk image, memory dump, network capture)
- Add colors for detection states (suspicious, confirmed, benign)

**Implementation for sift-find-evil:**
```python
# sift_find_evil/tui/theme.py
FORENSIC_THEME = {
    "bg_primary": "#0a0a0a",
    "bg_panel": "#1a1a1a",
    "bg_highlight": "#2a2a2a",
    
    "text_primary": "#e0e0e0",
    "text_muted": "#808080",
    "text_dim": "#505050",
    
    "evidence_disk": "#5c9cf5",      # Blue for disk images
    "evidence_memory": "#9c5cf5",    # Purple for memory dumps
    "evidence_network": "#5cf59c",   # Green for network captures
    
    "detection_suspicious": "#f5a542", # Orange
    "detection_confirmed": "#f54242",  # Red
    "detection_benign": "#42f554",     # Green
    "detection_unknown": "#808080",    # Gray
    
    "timeline_before": "#5c9cf5",
    "timeline_ioc": "#f54242",
    "timeline_after": "#f5a542",
}
```

### 2. Slash Command Menu (slash-menu.ts)

**What they do:**
- Type `/` to show command palette
- Fuzzy search with scoring algorithm
- Aliases for commands (e.g., `/model`, `/models`, `/mode` all work)

**Example:**
```typescript
export const SLASH_MENU_ITEMS: SlashMenuItem[] = [
  { id: "help", label: "help", description: "Show available commands" },
  { id: "agents", label: "agents", description: "Manage custom sub-agents" },
  { id: "models", label: "models", description: "Select a model", aliases: ["model", "mode"] },
  // ...
]
```

**How we could apply it:**
- Add `/` command palette for common forensic tasks
- Commands like `/timeline`, `/yara`, `/memory`, `/export`
- Fuzzy search for quick access

**Implementation for sift-find-evil:**
```python
FORENSIC_COMMANDS = [
    {"id": "timeline", "label": "timeline", "desc": "Generate timeline view"},
    {"id": "yara", "label": "yara", "desc": "Run YARA scan", "aliases": ["scan", "malware"]},
    {"id": "memory", "label": "memory", "desc": "Memory analysis", "aliases": ["mem", "volatility"]},
    {"id": "export", "label": "export", "desc": "Export findings", "aliases": ["save", "report"]},
    {"id": "filter", "label": "filter", "desc": "Filter by artifact type"},
]
```

### 3. Modal System (agents-modal.tsx, mcp-modal.tsx)

**What they do:**
- Pop-up modals for complex configuration
- Browser modals (list view) + Editor modals (form view)
- Keyboard navigation (arrow keys, enter, escape)

**Benefits:**
- Don't clutter main UI with configuration
- Context-specific help text
- Validation before submission

**How we could apply it:**
- Modal for YARA rule selection
- Modal for timeline filters (date range, artifact types)
- Modal for export options (format, destination, fields)
- Modal for evidence source configuration

### 4. Suggestion Overlay (SuggestionOverlay.tsx)

**What they do:**
- Autocomplete overlay that appears as you type
- Arrow key navigation
- Enter to select

**How we could apply it:**
- Path autocomplete when browsing evidence
- IOC lookup autocomplete (known hashes, domains, IPs)
- Artifact type autocomplete in search

### 5. Rich Markdown Rendering (markdown.tsx)

**What they do:**
- Syntax highlighting for code blocks
- Proper table rendering with borders
- Link styling, bold, italic, headings
- Selectable text for copy/paste

**How we could apply it:**
- Render detection findings as markdown
- Format YARA rule matches with syntax highlighting
- Display memory analysis results in formatted tables
- Make findings copyable for reports

### 6. Diff Visualization

**What they have:**
- Dedicated diff colors (added, removed, context, line numbers)
- Side-by-side or unified diff view

**How we could apply it:**
- Show timestomping (original vs modified timestamps)
- Compare prefetch vs shimcache artifacts
- Show registry key changes

### 7. Keyboard-First Navigation

**What they do:**
- Global keybindings visible in footer
- Context-specific keybindings
- No mouse required for any operation

**What we have:**
- Basic navigation (arrows, enter)
- Delete bookmark with 'd'

**What we could add:**
- 'f' for filter
- 't' for timeline view
- 'y' for YARA scan
- 'e' for export
- '/' for command palette
- '?' for help (already have)

### 8. Status Indicators

**What they have:**
- Loading spinners with animation frames
- Progress indicators for long operations
- Queue status display

**How we could apply it:**
- YARA scan progress (X/Y files scanned)
- Evidence processing progress
- Export/report generation progress

### 9. Panel System

**What they have:**
- Resizable panels
- Collapsible sections
- Clear visual hierarchy

**How we could apply it:**
- Left: Evidence browser (current)
- Center: Detection findings list
- Right: Finding details (YARA match, timeline context, etc.)
- Bottom: Command palette / quick actions

## Implementation Priority

### High Priority (Immediate Value)

1. **Theme System** - Semantic colors for evidence types and detection states
2. **Slash Command Palette** - Quick access to forensic functions
3. **Status Indicators** - Show scan/processing progress

### Medium Priority (Enhanced UX)

4. **Keyboard Shortcuts** - More keybindings for common operations
5. **Modal System** - Configuration dialogs (YARA, timeline, export)
6. **Markdown Rendering** - Formatted detection findings

### Low Priority (Polish)

7. **Suggestion Overlay** - Autocomplete for paths/IOCs
8. **Diff Visualization** - Compare artifacts
9. **Panel System** - Multi-pane layout

## Code Quality Observations

**What they do well:**
- TypeScript for type safety
- Separate concerns (UI, logic, data)
- Testable components (`.test.ts` files)
- Clear file organization (`ui/`, `agent/`, `tools/`)

**What we do well:**
- Python with type hints
- Detector modules separated by artifact type
- Synthetic fixtures for testing
- Test harness for validation

## Differences in Approach

**grok-cli:**
- Chat-based interaction (LLM conversation)
- Code generation focus
- Remote control via Telegram
- Sub-agent orchestration

**sift-find-evil:**
- Evidence-first workflow (file/disk selection)
- Forensic artifact detection
- Autonomous detection without interaction
- Self-correction on contradictions

## Recommendation

Focus on **Theme System** and **Slash Command Palette** first:

1. Create `sift_find_evil/tui/theme.py` with semantic forensic colors
2. Add `/` command palette for quick actions
3. Show scan progress with spinners
4. Add more keyboard shortcuts (visible in footer)

These provide the most immediate UX improvement with minimal refactoring.
