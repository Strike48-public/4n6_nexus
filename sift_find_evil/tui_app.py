"""
Textual TUI for SIFT Find Evil Demo

Terminal User Interface showcasing autonomous detection, self-correction,
and forensic analysis workflows for hackathon demo.
"""

import json
from pathlib import Path
from typing import Any

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button,
    DataTable,
    DirectoryTree,
    Footer,
    Header,
    Input,
    Label,
    Static,
)

from .tui import CommandPalette, TEXTUAL_CSS


# Bookmarks file location
BOOKMARKS_FILE = Path.home() / ".sift" / "bookmarks.json"


def load_bookmarks() -> list[dict]:
    """Load saved bookmarks from disk."""
    if not BOOKMARKS_FILE.exists():
        return []
    try:
        return json.loads(BOOKMARKS_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def save_bookmarks(bookmarks: list[dict]) -> None:
    """Save bookmarks to disk."""
    BOOKMARKS_FILE.parent.mkdir(parents=True, exist_ok=True)
    BOOKMARKS_FILE.write_text(json.dumps(bookmarks, indent=2))


def detect_mounts() -> list[dict]:
    """Auto-detect mounted drives in /media and /mnt."""
    mounts = []

    # Scan /media/*
    media_path = Path("/media")
    if media_path.exists():
        try:
            for user_dir in media_path.iterdir():
                if user_dir.is_dir():
                    try:
                        for mount in user_dir.iterdir():
                            if mount.is_dir():
                                mounts.append({
                                    "name": f"{mount.name} ({user_dir.name})",
                                    "path": str(mount),
                                    "type": "media"
                                })
                    except PermissionError:
                        # Skip directories we can't read
                        continue
        except PermissionError:
            # Can't read /media
            pass

    # Scan /mnt/*
    mnt_path = Path("/mnt")
    if mnt_path.exists():
        try:
            for mount in mnt_path.iterdir():
                if mount.is_dir() and not mount.name.startswith('.'):
                    mounts.append({
                        "name": mount.name,
                        "path": str(mount),
                        "type": "mnt"
                    })
        except PermissionError:
            # Can't read /mnt
            pass

    return sorted(mounts, key=lambda m: m['name'].lower())


class FileSelectionScreen(Screen):
    """File browser for selecting evidence files or synthetic scenarios."""

    CSS = TEXTUAL_CSS + """
    FileSelectionScreen {
        align: center middle;
    }

    #file-container {
        width: 90%;
        max-width: 120;
        height: 90%;
        border: solid $primary;
        padding: 1 2;
        background: $surface;
    }

    .screen-title {
        text-style: bold;
        color: $accent;
        text-align: center;
        padding: 0;
    }

    #path-input {
        margin: 0;
    }

    .section-header {
        text-style: bold;
        color: $accent;
        margin: 0;
    }

    .quick-access {
        height: auto;
        max-height: 20;
        overflow-y: auto;
        margin: 0 0 1 0;
        border: solid $primary-lighten-1;
        padding: 0 1;
    }

    #quick-access-container {
        height: auto;
    }

    .quick-access-columns {
        layout: grid;
        grid-size: 4 1;
        grid-gutter: 0 1;
        height: auto;
    }

    .mount-button {
        width: 100%;
        height: 3;
        margin: 0;
        min-height: 3;
    }

    .bookmark-button {
        width: 100%;
        height: 3;
        margin: 0;
        min-height: 3;
        background: $success-darken-1;
    }

    .no-items {
        color: $text-muted;
        text-align: center;
        padding: 1;
    }

    .help-text {
        color: $text-muted;
        text-style: italic;
        padding: 0;
    }

    .current-selection {
        background: $accent-darken-1;
        color: $text;
        padding: 0 1;
        margin: 1 0;
    }

    DirectoryTree {
        height: 8;
        margin: 1 0;
    }

    .action-buttons {
        layout: horizontal;
        height: auto;
        margin-top: 1;
    }

    .action-button {
        width: 1fr;
        margin: 0 1;
    }

    .cancel-button {
        background: $error;
    }

    .refresh-button {
        width: 100%;
        margin: 0 0 1 0;
        background: $accent;
    }
    """

    def __init__(self, **kwargs: Any):
        super().__init__(**kwargs)
        self.selected_path: Path | None = None
        self.current_tree_path = Path.cwd()
        self.bookmarks = load_bookmarks()
        self.mounts = detect_mounts()
        self._mount_id_counter = 0  # Counter for unique mount button IDs
        self._bookmark_id_counter = 0  # Counter for unique bookmark button IDs
        self._mount_id_to_index: dict[str, int] = {}  # Map button ID to mount index
        self._bookmark_id_to_index: dict[str, int] = {}  # Map button ID to bookmark index

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with VerticalScroll(id="file-container"):
            yield Label("SIFT FIND EVIL - SELECT EVIDENCE", classes="screen-title")

            # Quick Access section (no header, more compact)
            # Container will be populated by on_mount() calling _rebuild_quick_access()
            with Container(classes="quick-access", id="quick-access-container"):
                yield Button("Refresh Drives", id="refresh-drives-btn", classes="refresh-button")

            # Current selection indicator
            if self.selected_path:
                yield Label(f"Selected: {self.selected_path}", classes="current-selection")

            # Manual navigation (no header, more compact)
            yield Input(
                placeholder="Enter path and press Enter...",
                id="path-input"
            )
            yield DirectoryTree(str(self.current_tree_path), id="evidence-tree")

            with Horizontal(classes="action-buttons"):
                yield Button("Cancel", id="cancel-btn", classes="action-button cancel-button")
                yield Button("Bookmark Current", id="bookmark-current-btn", classes="action-button")
                yield Button("Load Evidence", id="load-btn", classes="action-button")

        yield Footer()

    def on_mount(self) -> None:
        """Populate Quick Access after screen is mounted."""
        self._rebuild_quick_access()

    def on_key(self, event) -> None:
        """Handle keyboard shortcuts."""
        # Command palette with '/'
        if event.key == "slash":
            self._show_command_palette()
            event.prevent_default()
            event.stop()
            return

        # Delete bookmark when 'd' is pressed and a bookmark button has focus
        if event.key == "d":
            focused = self.app.focused
            if focused and hasattr(focused, "id") and focused.id and focused.id.startswith("bookmark_"):
                button_id = focused.id
                if button_id in self._bookmark_id_to_index:
                    bookmark_idx = self._bookmark_id_to_index[button_id]
                    if 0 <= bookmark_idx < len(self.bookmarks):
                        bookmark_name = self.bookmarks[bookmark_idx]["name"]
                        del self.bookmarks[bookmark_idx]
                        save_bookmarks(self.bookmarks)
                        self.app.notify(f"Deleted bookmark: {bookmark_name}")
                        self._rebuild_quick_access()
                        event.prevent_default()
                        event.stop()

    def _show_command_palette(self) -> None:
        """Show command palette modal."""
        def handle_command(command):
            if command:
                self._execute_command(command.id)

        self.app.push_screen(CommandPalette(), handle_command)

    def _execute_command(self, command_id: str) -> None:
        """Execute a command by ID.

        Args:
            command_id: Command identifier
        """
        if command_id == "help":
            self.app.action_help()
        elif command_id == "refresh":
            self._refresh_drives()
        elif command_id == "bookmark":
            self._bookmark_current()
        elif command_id == "quit":
            self.app.exit()
        elif command_id == "yara":
            self.app.notify("YARA scan: Not yet implemented")
        elif command_id == "timeline":
            self.app.notify("Timeline view: Not yet implemented")
        elif command_id == "memory":
            self.app.notify("Memory analysis: Not yet implemented")
        elif command_id == "export":
            self.app.notify("Export: Not yet implemented")
        elif command_id == "filter":
            self.app.notify("Filter: Not yet implemented")
        elif command_id == "analyze":
            if self.selected_path:
                self._load_evidence()
            else:
                self.app.notify("Select evidence first", severity="warning")
        else:
            self.app.notify(f"Unknown command: {command_id}", severity="error")

    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected) -> None:
        """Handle file selection from tree."""
        self.selected_path = Path(event.path)
        path_input = self.query_one("#path-input", Input)
        path_input.value = str(self.selected_path)

    def on_directory_tree_directory_selected(self, event: DirectoryTree.DirectorySelected) -> None:
        """Handle directory selection from tree."""
        self.selected_path = Path(event.path)
        path_input = self.query_one("#path-input", Input)
        path_input.value = str(self.selected_path)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle manual path entry."""
        if event.value:
            path = Path(event.value).expanduser()
            if path.exists():
                if path.is_dir():
                    # Navigate tree to this directory
                    self._navigate_to(path)
                else:
                    # Select this file
                    self.selected_path = path
                    self._load_evidence()
            else:
                self.app.notify(f"Path not found: {path}", severity="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button actions."""
        button_id = event.button.id

        if not button_id:
            return

        # Mount buttons
        if button_id.startswith("mount_"):
            # Get index from mapping dictionary
            if button_id in self._mount_id_to_index:
                mount_idx = self._mount_id_to_index[button_id]
                if 0 <= mount_idx < len(self.mounts):
                    mount_path = Path(self.mounts[mount_idx]["path"])
                    self.app.notify(f"Navigating to: {mount_path}")
                    self._navigate_to(mount_path)
                else:
                    self.app.notify(f"Invalid mount index: {mount_idx} (have {len(self.mounts)} mounts)", severity="error")
            else:
                self.app.notify(f"Button {button_id} not found in mount mapping", severity="error")

        # Bookmark buttons
        elif button_id.startswith("bookmark_"):
            # Get index from mapping dictionary
            if button_id in self._bookmark_id_to_index:
                bookmark_idx = self._bookmark_id_to_index[button_id]
                if 0 <= bookmark_idx < len(self.bookmarks):
                    # Navigate to bookmark
                    bookmark_path = Path(self.bookmarks[bookmark_idx]["path"])
                    # Validate bookmark path still exists
                    if bookmark_path.exists():
                        self._navigate_to(bookmark_path)
                    else:
                        self.app.notify(
                            f"Bookmark path no longer exists: {bookmark_path}",
                            severity="warning",
                            timeout=5
                        )
            else:
                self.app.notify(f"Button {button_id} not found in bookmark mapping", severity="error")

        # Action buttons
        elif button_id == "refresh-drives-btn":
            self._refresh_drives()
        elif button_id == "load-btn":
            self._load_evidence()
        elif button_id == "bookmark-current-btn":
            self._bookmark_current()
        elif button_id == "cancel-btn":
            self.app.exit()

    def _navigate_to(self, path: Path) -> None:
        """Navigate the directory tree to a specific path."""
        if not path.exists():
            self.app.notify(
                f"Path not found: {path}\nTip: Drive may have been unmounted",
                severity="error",
                timeout=5
            )
            return

        if not path.is_dir():
            self.app.notify(
                f"Not a directory: {path}\nTip: Use 'Load Evidence' to load files",
                severity="error",
                timeout=5
            )
            return

        try:
            # Test if we can read the directory
            list(path.iterdir())
        except PermissionError:
            self.app.notify(
                f"Permission denied: {path}\nTip: Try running with sudo or check permissions",
                severity="error",
                timeout=5
            )
            return

        # Update the tree
        tree = self.query_one("#evidence-tree", DirectoryTree)
        tree.path = str(path)
        tree.reload()

        # Update path input
        path_input = self.query_one("#path-input", Input)
        path_input.value = str(path)

        # Update selected path
        self.selected_path = path
        self.current_tree_path = path

        # Refresh to show selection
        self.refresh()

    def _bookmark_current(self) -> None:
        """Bookmark the currently selected path."""
        if not self.selected_path:
            self.app.notify("No path selected to bookmark", severity="warning")
            return

        # Check if already bookmarked
        path_str = str(self.selected_path)
        for bookmark in self.bookmarks:
            if bookmark["path"] == path_str:
                self.app.notify("Path already bookmarked", severity="warning")
                return

        # Prompt for bookmark name (use path name as default)
        bookmark_name = self.selected_path.name or "Root"

        # Add bookmark
        self.bookmarks.append({
            "name": bookmark_name,
            "path": path_str
        })

        # Save to disk
        save_bookmarks(self.bookmarks)

        self.app.notify(f"Bookmarked: {bookmark_name} (focus & press 'd' to delete)", timeout=3)

        # Refresh the screen to show new bookmark
        self._rebuild_quick_access()

    def _refresh_drives(self) -> None:
        """Re-scan for mounted drives and rebuild Quick Access section."""
        # Re-detect mounts
        old_count = len(self.mounts)
        self.mounts = detect_mounts()
        new_count = len(self.mounts)

        # Reload bookmarks in case they changed
        self.bookmarks = load_bookmarks()

        # Rebuild the Quick Access section
        self._rebuild_quick_access()

        # Notify user
        if new_count > old_count:
            self.app.notify(f"Found {new_count - old_count} new drive(s)")
        elif new_count < old_count:
            self.app.notify(f"{old_count - new_count} drive(s) unmounted")
        else:
            self.app.notify(f"Refreshed: {new_count} drive(s) detected")

    def _rebuild_quick_access(self) -> None:
        """Rebuild the Quick Access container with updated mounts and bookmarks."""
        from textual.containers import Vertical, Horizontal

        container = self.query_one("#quick-access-container")

        # Clear the mapping dictionaries
        self._mount_id_to_index.clear()
        self._bookmark_id_to_index.clear()

        # Remove all widgets EXCEPT the refresh button
        for widget in list(container.query("*")):
            if widget.id != "refresh-drives-btn":
                widget.remove()

        # Create multi-column layout container
        columns = Horizontal(classes="quick-access-columns")
        container.mount(columns)

        # Determine number of columns needed (3 for mounts, +1 for bookmarks if they exist)
        num_cols = 3 if not self.bookmarks else 4

        # Create columns
        cols = []
        for _ in range(num_cols):
            col = Vertical()
            columns.mount(col)
            cols.append(col)

        # Populate mount columns (distribute across first 3 columns)
        if self.mounts:
            for i, mount in enumerate(self.mounts):
                col_idx = i % 3  # Distribute across first 3 columns
                mount_label = f"{mount['name']}\n{mount['path']}"
                mount_id = f"mount_{self._mount_id_counter}"
                self._mount_id_counter += 1
                self._mount_id_to_index[mount_id] = i
                button = Button(mount_label, id=mount_id, classes="mount-button")
                cols[col_idx].mount(button)
        else:
            cols[0].mount(Label("No drives", classes="no-items"))

        # Populate bookmark column (rightmost column, only if bookmarks exist)
        if self.bookmarks:
            bookmark_col = cols[-1]  # Last column
            for i, bookmark in enumerate(self.bookmarks):
                bm_label = f"{bookmark['name']}\n{bookmark['path']}"
                bookmark_id = f"bookmark_{self._bookmark_id_counter}"
                self._bookmark_id_counter += 1
                self._bookmark_id_to_index[bookmark_id] = i
                button = Button(bm_label, id=bookmark_id, classes="bookmark-button")
                bookmark_col.mount(button)

    def _load_evidence(self) -> None:
        """Validate and load selected evidence."""
        if not self.selected_path:
            self.app.notify("Please select a file or directory", severity="warning")
            return

        if not self.selected_path.exists():
            self.app.notify(f"Path not found: {self.selected_path}", severity="error")
            return

        # Detect evidence type
        if self.selected_path.is_file():
            # Evidence file (.E01, .dd, etc.)
            case_name = self.selected_path.stem
            evidence_type = "image"
        else:
            # Directory (synthetic scenario or mounted image)
            case_name = self.selected_path.name
            evidence_type = "directory"

        # Show loading notification
        self.app.notify(f"Loading: {case_name}")

        self.app.push_screen(AnalysisConfigScreen(
            case_name=case_name,
            evidence_path=self.selected_path,
            evidence_type=evidence_type
        ))


class AnalysisConfigScreen(Screen):
    """Configuration screen for selecting analysis type and options."""

    CSS = """
    AnalysisConfigScreen {
        align: center middle;
    }

    #config-container {
        width: 90%;
        max-width: 100;
        height: 90%;
        border: solid $primary;
        padding: 1 2;
        background: $surface;
    }

    .screen-title {
        text-style: bold;
        color: $accent;
        text-align: center;
        padding: 0 0 1 0;
    }

    .section-title {
        text-style: bold;
        color: $text;
        padding: 0;
        margin-top: 1;
    }

    .config-button {
        width: 100%;
        margin: 0 0 1 0;
        height: 3;
    }

    .action-buttons {
        layout: horizontal;
        height: auto;
        margin-top: 2;
    }

    .action-button {
        width: 1fr;
        margin: 0 1;
    }

    .back-button {
        background: $warning;
    }
    """

    def __init__(
        self,
        case_name: str,
        evidence_path: Path,
        evidence_type: str,
        **kwargs: Any
    ):
        super().__init__(**kwargs)
        self.case_name = case_name
        self.evidence_path = evidence_path
        self.evidence_type = evidence_type
        self.selected_mode: str | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with VerticalScroll(id="config-container"):
            yield Label("SIFT FIND EVIL - ANALYSIS CONFIGURATION", classes="screen-title")
            yield Label(f"Evidence: {self.case_name}")
            yield Label(f"Path: {self.evidence_path}")

            yield Label("Select Analysis Mode:", classes="section-title")

            yield Button("Quick Triage - Essential artifacts only",
                        id="mode_quick", classes="config-button")
            yield Button("Full Analysis - All detectors + YARA",
                        id="mode_full", classes="config-button")
            yield Button("Memory Analysis - Volatility + baselining",
                        id="mode_memory", classes="config-button")
            yield Button("Timeline - Supertimeline + analysis",
                        id="mode_timeline", classes="config-button")
            yield Button("Custom - Select detectors manually",
                        id="mode_custom", classes="config-button")

            with Horizontal(classes="action-buttons"):
                yield Button("Back", id="back-btn", classes="action-button back-button")
                yield Button("Start Analysis", id="start-btn", classes="action-button")

        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle mode selection and navigation."""
        button_id = event.button.id

        if button_id and button_id.startswith("mode_"):
            mode_map = {
                "mode_quick": "quick",
                "mode_full": "full",
                "mode_memory": "memory",
                "mode_timeline": "timeline",
                "mode_custom": "custom",
            }
            self.selected_mode = mode_map.get(button_id)
            # Highlight selected button visually
            for btn in self.query(Button):
                if btn.id == button_id:
                    btn.variant = "success"
                elif btn.id and btn.id.startswith("mode_"):
                    btn.variant = "default"

        elif button_id == "start-btn":
            if not self.selected_mode:
                self.app.notify("Please select an analysis mode", severity="warning")
                return

            # Custom mode goes to detector selection screen
            if self.selected_mode == "custom":
                self.app.push_screen(CustomDetectorScreen(
                    case_name=self.case_name,
                    evidence_path=self.evidence_path,
                    evidence_type=self.evidence_type
                ))
            else:
                self.app.push_screen(AnalysisScreen(
                    case_name=self.case_name,
                    evidence_path=self.evidence_path,
                    evidence_type=self.evidence_type,
                    mode=self.selected_mode
                ))

        elif button_id == "back-btn":
            self.app.pop_screen()


class CustomDetectorScreen(Screen):
    """Detector selection screen for custom analysis mode."""

    CSS = """
    CustomDetectorScreen {
        align: center middle;
    }

    #detector-container {
        width: 90%;
        max-width: 100;
        height: 90%;
        border: solid $primary;
        padding: 1 2;
        background: $surface;
    }

    .screen-title {
        text-style: bold;
        color: $accent;
        text-align: center;
        padding: 0 0 1 0;
    }

    .section-title {
        text-style: bold;
        color: $text;
        padding: 0;
        margin-top: 1;
    }

    .detector-option {
        height: auto;
        margin: 0 0 1 0;
    }

    .action-buttons {
        layout: horizontal;
        height: auto;
        margin-top: 2;
    }

    .action-button {
        width: 1fr;
        margin: 0 1;
    }

    .back-button {
        background: $warning;
    }
    """

    def __init__(
        self,
        case_name: str,
        evidence_path: Path,
        evidence_type: str,
        **kwargs: Any
    ):
        super().__init__(**kwargs)
        self.case_name = case_name
        self.evidence_path = evidence_path
        self.evidence_type = evidence_type
        self.selected_detectors: set[str] = set()

        # Available detectors with descriptions
        self.detectors = [
            ("nsrl", "NSRL Filter", "Filter known-good files using NSRL database"),
            ("prefetch", "Prefetch Analysis", "Windows prefetch file analysis for execution"),
            ("memory", "Memory Forensics", "Volatility analysis for memory artifacts"),
            ("yara", "YARA Scanning", "Malware signature detection with YARA rules"),
            ("timeline", "Timeline Analysis", "Supertimeline generation and analysis"),
            ("carving", "File Carving", "Recover deleted files and fragments"),
            ("registry", "Registry Analysis", "Windows registry hive examination"),
            ("shimcache", "Shimcache", "Application compatibility cache parsing"),
        ]

    def compose(self) -> ComposeResult:
        from textual.widgets import Checkbox

        yield Header(show_clock=False)
        with VerticalScroll(id="detector-container"):
            yield Label("SIFT FIND EVIL - SELECT DETECTORS", classes="screen-title")
            yield Label(f"Evidence: {self.case_name}")
            yield Label(f"Mode: Custom")

            yield Label("Select detectors to run:", classes="section-title")

            for detector_id, name, description in self.detectors:
                yield Checkbox(
                    f"{name} - {description}",
                    value=False,
                    id=f"detector_{detector_id}",
                    classes="detector-option"
                )

            with Horizontal(classes="action-buttons"):
                yield Button("Back", id="back-btn", classes="action-button back-button")
                yield Button("Start Analysis", id="start-btn", classes="action-button")

        yield Footer()

    def on_checkbox_changed(self, event) -> None:
        """Track selected detectors."""
        detector_id = event.checkbox.id.replace("detector_", "")
        if event.value:
            self.selected_detectors.add(detector_id)
        else:
            self.selected_detectors.discard(detector_id)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle navigation."""
        if event.button.id == "start-btn":
            if not self.selected_detectors:
                self.app.notify("Please select at least one detector", severity="warning")
                return

            self.app.push_screen(AnalysisScreen(
                case_name=self.case_name,
                evidence_path=self.evidence_path,
                evidence_type=self.evidence_type,
                mode="custom",
                selected_detectors=list(self.selected_detectors)
            ))

        elif event.button.id == "back-btn":
            self.app.pop_screen()


class AnalysisScreen(Screen):
    """Main analysis screen with four-panel layout."""

    BINDINGS = [
        ("a", "approve", "Approve"),
        ("r", "reject", "Reject"),
        ("d", "drill", "Drill Down"),
        ("e", "export", "Export"),
        ("b", "back", "Back"),
    ]

    def __init__(
        self,
        case_name: str = "Demo",
        evidence_path: Path | None = None,
        evidence_type: str = "synthetic",
        mode: str = "quick",
        selected_detectors: list[str] | None = None,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self.case_name = case_name
        self.evidence_path = evidence_path
        self.evidence_type = evidence_type
        self.mode = mode
        self.selected_detectors = selected_detectors or []

    def compose(self) -> ComposeResult:
        """Compose the four-panel analysis layout."""
        yield Header(show_clock=True)
        yield Container(DetectorPanel(), id="detector-panel")
        yield Container(FindingsPanel(), id="findings-panel")
        yield Container(SelfCorrectionPanel(), id="self-correction-panel")
        yield Container(ReasoningPanel(), id="reasoning-panel")
        yield Footer()

    def on_mount(self) -> None:
        """Update title with case info."""
        evidence_name = str(self.evidence_path.name) if self.evidence_path else self.case_name
        mode_display = self.mode.upper()
        if self.mode == "custom" and self.selected_detectors:
            mode_display = f"CUSTOM ({len(self.selected_detectors)} detectors)"
        self.app.sub_title = f"Case: {self.case_name}    Evidence: {evidence_name}    Mode: {mode_display}    [ANALYZING]"

    def action_approve(self) -> None:
        """Approve selected finding."""
        self.app.notify("Finding approved")

    def action_reject(self) -> None:
        """Reject selected finding."""
        self.app.notify("Finding rejected")

    def action_drill(self) -> None:
        """Drill down into selected finding."""
        self.app.notify("Drilling down...")

    def action_export(self) -> None:
        """Export findings to report."""
        self.app.notify("Exporting report...")

    def action_back(self) -> None:
        """Go back to previous screen."""
        self.app.pop_screen()


class DetectorPanel(Static):
    """Left panel showing detector execution progress."""

    def compose(self) -> ComposeResult:
        yield Label("DETECTORS", classes="panel-title")
        yield DataTable(id="detector-table")

    def on_mount(self) -> None:
        table = self.query_one("#detector-table", DataTable)
        table.add_columns("Detector", "Status", "Progress")
        table.cursor_type = "none"

        # Populate with sample detectors showing progress
        detectors = [
            ("NSRL filter", "[DONE]", "100%"),
            ("Prefetch", "[DONE]", "100%"),
            ("Memory", "[RUN]", "67%"),
            ("YARA scan", "[RUN]", "45%"),
            ("Timeline", "[WAIT]", "0%"),
            ("Carving", "[WAIT]", "0%"),
        ]
        for name, status, progress in detectors:
            table.add_row(name, status, progress)


class FindingsPanel(Static):
    """Top-right panel showing prioritized findings."""

    def compose(self) -> ComposeResult:
        yield Label("FINDINGS", classes="panel-title")
        yield DataTable(id="findings-table")

    def on_mount(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.add_columns("Sev", "Finding", "Details")
        table.cursor_type = "row"

        # Load findings from demo JSON
        findings_path = Path("demo/findings_sample.json")
        if findings_path.exists():
            try:
                findings = json.loads(findings_path.read_text())
                for finding in findings:
                    severity = finding.get("severity", "medium").upper()[:4]
                    title = finding.get("title", "Unknown")
                    # Truncate long titles
                    if len(title) > 40:
                        title = title[:37] + "..."
                    details = finding.get("description", "")[:30]
                    table.add_row(severity, title, details)
            except (json.JSONDecodeError, KeyError) as e:
                table.add_row("ERR", f"Failed to load findings: {e}", "")
        else:
            # Fallback to ransomware demo
            findings_path = Path("analysis/demo_ransomware.json")
            if findings_path.exists():
                try:
                    data = json.loads(findings_path.read_text())
                    for exe in data.get("detected_executables", []):
                        severity = "CRIT" if "ransom" in exe else "HIGH"
                        finding = exe[:40] + "..." if len(exe) > 40 else exe
                        table.add_row(severity, finding, "Mass encryption")
                except (json.JSONDecodeError, KeyError):
                    table.add_row("INFO", "No findings loaded", "")
            else:
                # No data available
                table.add_row("INFO", "No findings available", "Run analysis to generate findings")


class SelfCorrectionPanel(Static):
    """Bottom-left panel showing self-correction events."""

    def compose(self) -> ComposeResult:
        yield Label("SELF-CORRECT", classes="panel-title")
        yield Label("[!] CONTRADICT", classes="status-label")
        yield Label("  Resolved 3x", classes="status-detail")

    def on_mount(self) -> None:
        # Future: tail audit JSONL and highlight contradictions
        pass


class ReasoningPanel(Static):
    """Bottom-right panel showing reasoning trace."""

    def compose(self) -> ComposeResult:
        yield Label("REASONING", classes="panel-title")
        yield Static(
            "MFT $STANDARD_INFORMATION shows 2019-01-15\n"
            "MFT $FILE_NAME shows 2019-02-06 (22-day delta)\n"
            "-> Timestomping detected. SI can be modified,\n"
            "  FN is more reliable. Reduced confidence.",
            id="reasoning-text",
        )


class HelpScreen(Screen):
    """Help screen showing keybindings and usage instructions."""

    CSS = """
    HelpScreen {
        align: center middle;
    }

    #help-container {
        width: 80%;
        max-width: 100;
        height: 80%;
        border: solid $primary;
        padding: 2;
        background: $surface;
    }

    .help-title {
        text-style: bold;
        color: $accent;
        text-align: center;
        padding: 0 0 1 0;
    }

    .help-section {
        text-style: bold;
        color: $text;
        padding: 1 0 0 0;
    }

    .help-item {
        padding: 0 0 0 2;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with VerticalScroll(id="help-container"):
            yield Label("SIFT FIND EVIL - HELP", classes="help-title")

            yield Label("FILE SELECTION", classes="help-section")
            yield Label("- Click detected drives to navigate instantly", classes="help-item")
            yield Label("- Ctrl+Click bookmarks to delete them", classes="help-item")
            yield Label("- Type path and press Enter for manual navigation", classes="help-item")
            yield Label("- Click 'Bookmark Current' to save frequently used paths", classes="help-item")

            yield Label("ANALYSIS SCREEN", classes="help-section")
            yield Label("a - Approve selected finding", classes="help-item")
            yield Label("r - Reject selected finding", classes="help-item")
            yield Label("d - Drill down for more details", classes="help-item")
            yield Label("e - Export findings to report", classes="help-item")
            yield Label("b - Go back to previous screen", classes="help-item")

            yield Label("GLOBAL KEYBINDINGS", classes="help-section")
            yield Label("q - Quit application", classes="help-item")
            yield Label("? - Show this help screen", classes="help-item")

            yield Label("\nPress any key to close this help screen", classes="help-item")

        yield Footer()

    def on_key(self, event) -> None:
        """Close help on any key press."""
        self.app.pop_screen()


class SIFTDemoApp(App):
    """Textual app for SIFT Find Evil hackathon demo."""

    CSS = """
    AnalysisScreen {
        layout: grid;
        grid-size: 2 2;
        grid-rows: 1fr 1fr;
        grid-columns: 1fr 2fr;
    }

    .panel-title {
        text-style: bold;
        background: $boost;
        padding: 0 1;
    }

    #detector-panel {
        border: solid $primary;
        padding: 1;
    }

    #findings-panel {
        border: solid $primary;
        padding: 1;
    }

    #self-correction-panel {
        border: solid $warning;
        padding: 1;
    }

    #reasoning-panel {
        border: solid $primary;
        padding: 1;
    }

    .status-label {
        color: $warning;
        text-style: bold;
    }

    .status-detail {
        color: $text-muted;
    }

    #reasoning-text {
        color: $text;
        padding: 1 0;
    }

    DataTable {
        height: 100%;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("?", "help", "Help"),
        ("/", "command_palette", "Commands"),
        ("d", "delete_bookmark", "Delete Bookmark"),
    ]

    def on_mount(self) -> None:
        """Show file selection on startup."""
        self.push_screen(FileSelectionScreen())

    def action_help(self) -> None:
        """Show help screen."""
        self.push_screen(HelpScreen())

    def action_delete_bookmark(self) -> None:
        """Delete bookmark (handled by FileSelectionScreen.on_key)."""
        pass

    def action_command_palette(self) -> None:
        """Open command palette (handled by FileSelectionScreen.on_key)."""
        pass


def main():
    """Run the SIFT Find Evil TUI demo."""
    app = SIFTDemoApp()
    app.title = "sift-find-evil"
    app.sub_title = "Professional DFIR Analysis Tool"
    app.run()


if __name__ == "__main__":
    main()
