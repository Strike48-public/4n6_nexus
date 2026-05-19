"""
Textual TUI for SIFT Find Evil Demo

Terminal User Interface showcasing autonomous detection, self-correction,
and forensic analysis workflows for hackathon demo.
"""

import json
from pathlib import Path
from typing import Any, Optional

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

from .progress_tracker import (
    ProgressTracker,
    FindingSeverity,
    PhaseStatus,
    Contradiction,
)
from .resource_monitor import ResourceMonitor
from .analysis_runner import AnalysisRunner
from .tui import CommandPalette, TEXTUAL_CSS
from .e01_mounter import E01Mounter, E01Image, MountedImage


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
                                mounts.append(
                                    {
                                        "name": f"{mount.name} ({user_dir.name})",
                                        "path": str(mount),
                                        "type": "media",
                                    }
                                )
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
                if mount.is_dir() and not mount.name.startswith("."):
                    mounts.append(
                        {"name": mount.name, "path": str(mount), "type": "mnt"}
                    )
        except PermissionError:
            # Can't read /mnt
            pass

    return sorted(mounts, key=lambda m: m["name"].lower())


class FileSelectionScreen(Screen):
    """File browser for selecting evidence files or synthetic scenarios."""

    CSS = (
        TEXTUAL_CSS
        + """
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

    .danger-button {
        width: 1fr;
        margin: 0 1;
        background: $forensic-button-danger;
        color: $text;
    }

    .refresh-button {
        width: 100%;
        margin: 0 0 1 0;
        background: $accent;
    }
    """
    )

    def __init__(self, **kwargs: Any):
        super().__init__(**kwargs)
        self.selected_path: Path | None = None
        self.current_tree_path = Path.cwd()
        self.bookmarks = load_bookmarks()
        self.mounts = detect_mounts()
        self._mount_id_counter = 0  # Counter for unique mount button IDs
        self._bookmark_id_counter = 0  # Counter for unique bookmark button IDs
        self._mount_id_to_index: dict[str, int] = {}  # Map button ID to mount index
        self._bookmark_id_to_index: dict[
            str, int
        ] = {}  # Map button ID to bookmark index

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with VerticalScroll(id="file-container"):
            yield Label("SIFT FIND EVIL - SELECT EVIDENCE", classes="screen-title")

            # Quick Access section (no header, more compact)
            # Container will be populated by on_mount() calling _rebuild_quick_access()
            with Container(classes="quick-access", id="quick-access-container"):
                yield Button(
                    "Refresh Drives", id="refresh-drives-btn", classes="refresh-button"
                )

            # Current selection indicator
            if self.selected_path:
                yield Label(
                    f"Selected: {self.selected_path}", classes="current-selection"
                )

            # Manual navigation (no header, more compact)
            yield Input(placeholder="Enter path and press Enter...", id="path-input")
            yield DirectoryTree(str(self.current_tree_path), id="evidence-tree")

            with Horizontal(classes="action-buttons"):
                yield Button(
                    "Cancel", id="cancel-btn", classes="action-button cancel-button"
                )
                yield Button(
                    "Bookmark Current",
                    id="bookmark-current-btn",
                    classes="action-button",
                )
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
            if (
                focused
                and hasattr(focused, "id")
                and focused.id
                and focused.id.startswith("bookmark_")
            ):
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

    def on_directory_tree_file_selected(
        self, event: DirectoryTree.FileSelected
    ) -> None:
        """Handle file selection from tree."""
        self.selected_path = Path(event.path)
        path_input = self.query_one("#path-input", Input)
        path_input.value = str(self.selected_path)
        self._update_bookmark_button()

    def on_directory_tree_directory_selected(
        self, event: DirectoryTree.DirectorySelected
    ) -> None:
        """Handle directory selection from tree."""
        self.selected_path = Path(event.path)
        path_input = self.query_one("#path-input", Input)
        path_input.value = str(self.selected_path)
        self._update_bookmark_button()

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
                    self.app.notify(
                        f"Invalid mount index: {mount_idx} (have {len(self.mounts)} mounts)",
                        severity="error",
                    )
            else:
                self.app.notify(
                    f"Button {button_id} not found in mount mapping", severity="error"
                )

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
                            timeout=5,
                        )
            else:
                self.app.notify(
                    f"Button {button_id} not found in bookmark mapping",
                    severity="error",
                )

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
                timeout=5,
            )
            return

        if not path.is_dir():
            self.app.notify(
                f"Not a directory: {path}\nTip: Use 'Load Evidence' to load files",
                severity="error",
                timeout=5,
            )
            return

        try:
            # Test if we can read the directory
            list(path.iterdir())
        except PermissionError:
            self.app.notify(
                f"Permission denied: {path}\nTip: Try running with sudo or check permissions",
                severity="error",
                timeout=5,
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

        # Update bookmark button to reflect new path
        self._update_bookmark_button()

        # Refresh to show selection
        self.refresh()

    def _is_path_bookmarked(self, path: Path | None) -> bool:
        """Check if a path is bookmarked.

        Args:
            path: Path to check

        Returns:
            True if bookmarked, False otherwise
        """
        if not path:
            return False

        path_str = str(path)
        return any(bookmark["path"] == path_str for bookmark in self.bookmarks)

    def _update_bookmark_button(self) -> None:
        """Update bookmark button text based on current selection."""
        try:
            bookmark_btn = self.query_one("#bookmark-current-btn", Button)
            if self._is_path_bookmarked(self.selected_path):
                bookmark_btn.label = "Delete Bookmark"
                bookmark_btn.remove_class("action-button")
                bookmark_btn.add_class("danger-button")
            else:
                bookmark_btn.label = "Bookmark Current"
                bookmark_btn.remove_class("danger-button")
                bookmark_btn.add_class("action-button")
        except Exception:
            # Button might not exist yet during initialization
            pass

    def _bookmark_current(self) -> None:
        """Bookmark or unbookmark the currently selected path."""
        if not self.selected_path:
            self.app.notify("No path selected to bookmark", severity="warning")
            return

        path_str = str(self.selected_path)

        # Check if already bookmarked - if so, delete it
        for i, bookmark in enumerate(self.bookmarks):
            if bookmark["path"] == path_str:
                bookmark_name = bookmark["name"]
                del self.bookmarks[i]
                save_bookmarks(self.bookmarks)
                self.app.notify(f"Deleted bookmark: {bookmark_name}")
                self._rebuild_quick_access()
                self._update_bookmark_button()
                return

        # Not bookmarked - add it
        bookmark_name = self.selected_path.name or "Root"

        self.bookmarks.append({"name": bookmark_name, "path": path_str})

        # Save to disk
        save_bookmarks(self.bookmarks)

        self.app.notify(f"Bookmarked: {bookmark_name}", timeout=3)

        # Refresh the screen to show new bookmark
        self._rebuild_quick_access()
        self._update_bookmark_button()

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
        from textual.containers import Horizontal

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
            evidence_path = self.selected_path
        else:
            # Directory - check for E01 images
            case_name = self.selected_path.name
            evidence_type = "directory"
            evidence_path = self.selected_path

            # Detect E01 images in directory
            e01_images = E01Mounter.detect_e01_images(self.selected_path)
            if e01_images:
                # Show E01 mounting screen
                self.app.push_screen(
                    E01MountScreen(
                        case_name=case_name,
                        evidence_path=self.selected_path,
                        e01_images=e01_images,
                    )
                )
                return

        # No E01 images, proceed to analysis config
        self.app.notify(f"Loading: {case_name}")
        self.app.push_screen(
            AnalysisConfigScreen(
                case_name=case_name,
                evidence_path=evidence_path,
                evidence_type=evidence_type,
            )
        )


class E01MountScreen(Screen):
    """Screen for detecting and mounting E01 forensic images."""

    CSS = (
        TEXTUAL_CSS
        + """
    E01MountScreen {
        align: center middle;
    }

    #mount-container {
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
        padding: 0 0 1 0;
    }

    .section-title {
        text-style: bold;
        color: $text;
        padding: 0;
        margin-top: 1;
    }

    .e01-button {
        width: 100%;
        margin: 0 0 1 0;
        height: 5;
    }

    .disk-button {
        background: $success;
    }

    .memory-button {
        background: $warning;
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

    .skip-button {
        background: $warning;
    }
    """
    )

    def __init__(
        self,
        case_name: str,
        evidence_path: Path,
        e01_images: list[E01Image],
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self.case_name = case_name
        self.evidence_path = evidence_path
        self.e01_images = e01_images
        self.selected_image: E01Image | None = None
        self.mounted_image: MountedImage | None = None
        self.mounting_in_progress = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with VerticalScroll(id="mount-container"):
            yield Label("E01 FORENSIC IMAGES DETECTED", classes="screen-title")
            yield Label(f"Case: {self.case_name}")
            yield Label(f"Path: {self.evidence_path}")

            yield Label(
                f"\nFound {len(self.e01_images)} E01 image(s):", classes="section-title"
            )

            # Show E01 images as buttons
            for img in self.e01_images:
                button_class = (
                    "disk-button" if img.image_type == "disk" else "memory-button"
                )
                button_label = (
                    f"{img.name}\n{img.size_gb:.2f} GB ({img.image_type.upper()})"
                )
                yield Button(
                    button_label,
                    id=f"mount_{img.name}",
                    classes=f"e01-button {button_class}",
                )

            with Horizontal(classes="action-buttons"):
                yield Button(
                    "Skip (Use Raw Files)",
                    id="skip-btn",
                    classes="action-button skip-button",
                )
                yield Button("Back", id="back-btn", classes="action-button")

        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button actions."""
        button_id = event.button.id

        if not button_id:
            return

        # Prevent multiple mount operations
        if self.mounting_in_progress:
            self.app.notify("Mount operation already in progress", severity="warning")
            return

        if button_id.startswith("mount_"):
            # Extract image name
            img_name = button_id.replace("mount_", "")
            # Find the image
            for img in self.e01_images:
                if img.name == img_name:
                    self._mount_image(img)
                    break

        elif button_id == "skip-btn":
            # Skip mounting, go directly to analysis with raw path
            self.app.push_screen(
                AnalysisConfigScreen(
                    case_name=self.case_name,
                    evidence_path=self.evidence_path,
                    evidence_type="directory",
                )
            )

        elif button_id == "back-btn":
            self.app.pop_screen()

    def _mount_image(self, image: E01Image) -> None:
        """Mount an E01 image and proceed to analysis."""
        # Set flag to prevent multiple mounts
        self.mounting_in_progress = True

        self.app.notify(
            f"Mounting {image.name}... (this may take a moment)", timeout=10
        )

        # Mount the image
        success, message, mounted = E01Mounter.mount_e01(image)

        if success and mounted:
            self.app.notify(f"✓ {message}", severity="information", timeout=5)
            self.mounted_image = mounted

            # Determine evidence path
            if mounted.fs_mount_point:
                # Filesystem mounted successfully
                evidence_path = mounted.fs_mount_point
                evidence_type = "directory"
            elif mounted.raw_device:
                # Only raw device available
                evidence_path = mounted.raw_device
                evidence_type = "image"
            else:
                self.app.notify(
                    "Mount succeeded but no access point found", severity="error"
                )
                return

            # Proceed to analysis config
            self.app.push_screen(
                AnalysisConfigScreen(
                    case_name=self.case_name,
                    evidence_path=evidence_path,
                    evidence_type=evidence_type,
                    mounted_image=mounted,  # Pass mounted image for cleanup
                )
            )
        else:
            self.app.notify(f"✗ Mount failed: {message}", severity="error", timeout=10)
            self.mounting_in_progress = False  # Reset flag on failure


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
        mounted_image: MountedImage | None = None,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self.case_name = case_name
        self.evidence_path = evidence_path
        self.evidence_type = evidence_type
        self.mounted_image = mounted_image
        self.selected_mode: str | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with VerticalScroll(id="config-container"):
            yield Label(
                "SIFT FIND EVIL - ANALYSIS CONFIGURATION", classes="screen-title"
            )
            yield Label(f"Evidence: {self.case_name}")
            yield Label(f"Path: {self.evidence_path}")

            yield Label("Select Analysis Mode:", classes="section-title")

            yield Button(
                "Quick Triage - Essential artifacts only",
                id="mode_quick",
                classes="config-button",
            )
            yield Button(
                "Full Analysis - All detectors + YARA",
                id="mode_full",
                classes="config-button",
            )
            yield Button(
                "Memory Analysis - Volatility + baselining",
                id="mode_memory",
                classes="config-button",
            )
            yield Button(
                "Timeline - Supertimeline + analysis",
                id="mode_timeline",
                classes="config-button",
            )
            yield Button(
                "Custom - Select detectors manually",
                id="mode_custom",
                classes="config-button",
            )

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
                self.app.push_screen(
                    CustomDetectorScreen(
                        case_name=self.case_name,
                        evidence_path=self.evidence_path,
                        evidence_type=self.evidence_type,
                    )
                )
            else:
                self.app.push_screen(
                    AnalysisScreen(
                        case_name=self.case_name,
                        evidence_path=self.evidence_path,
                        evidence_type=self.evidence_type,
                        mode=self.selected_mode,
                        mounted_image=self.mounted_image,
                    )
                )

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
        mounted_image: Optional[MountedImage] = None,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self.case_name = case_name
        self.evidence_path = evidence_path
        self.mounted_image = mounted_image
        self.evidence_type = evidence_type
        self.selected_detectors: set[str] = set()

        # Available detectors with descriptions
        self.detectors = [
            ("nsrl", "NSRL Filter", "Filter known-good files using NSRL database"),
            (
                "prefetch",
                "Prefetch Analysis",
                "Windows prefetch file analysis for execution",
            ),
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
            yield Label("Mode: Custom")

            yield Label("Select detectors to run:", classes="section-title")

            for detector_id, name, description in self.detectors:
                yield Checkbox(
                    f"{name} - {description}",
                    value=False,
                    id=f"detector_{detector_id}",
                    classes="detector-option",
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
                self.app.notify(
                    "Please select at least one detector", severity="warning"
                )
                return

            self.app.push_screen(
                AnalysisScreen(
                    case_name=self.case_name,
                    evidence_path=self.evidence_path,
                    evidence_type=self.evidence_type,
                    mode="custom",
                    selected_detectors=list(self.selected_detectors),
                    mounted_image=self.mounted_image,
                )
            )

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
        ("p", "toggle_progress", "Toggle Progress"),
    ]

    def __init__(
        self,
        case_name: str = "Demo",
        evidence_path: Path | None = None,
        evidence_type: str = "synthetic",
        mode: str = "quick",
        selected_detectors: list[str] | None = None,
        mounted_image: Optional[MountedImage] = None,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self.case_name = case_name
        self.evidence_path = evidence_path
        self.evidence_type = evidence_type
        self.mode = mode
        self.selected_detectors = selected_detectors or []
        self.mounted_image = mounted_image
        self.progress_collapsed = False

        # Initialize progress tracking
        self.progress_tracker = ProgressTracker()
        self.resource_monitor = ResourceMonitor(interval=5.0)
        self.analysis_runner = AnalysisRunner(self.progress_tracker)

        # Register phases based on mode
        self._register_phases_for_mode()

    def compose(self) -> ComposeResult:
        """Compose the four-panel analysis layout with bottom panels."""
        yield Header(show_clock=True)
        yield Container(DetectorPanel(self.progress_tracker), id="detector-panel")
        yield Container(FindingsPanel(self.progress_tracker), id="findings-panel")
        yield Container(
            SelfCorrectionPanel(self.progress_tracker), id="self-correction-panel"
        )
        yield Container(ReasoningPanel(self.progress_tracker), id="reasoning-panel")
        yield Container(
            SystemResourcesPanel(self.progress_tracker), id="system-resources-panel"
        )
        yield ProgressPanel(self.progress_tracker, id="progress-panel")
        yield Footer()

    def on_mount(self) -> None:
        """Update title with case info and start resource monitoring."""
        evidence_name = (
            str(self.evidence_path.name) if self.evidence_path else self.case_name
        )
        mode_display = self.mode.upper()
        if self.mode == "custom" and self.selected_detectors:
            mode_display = f"CUSTOM ({len(self.selected_detectors)} detectors)"
        self.app.sub_title = f"Case: {self.case_name}    Evidence: {evidence_name}    Mode: {mode_display}    [ANALYZING]"

        # Register progress tracker callbacks
        self.progress_tracker.on_progress_update(self._on_progress_update)
        self.progress_tracker.on_resources_updated(self._on_resources_updated)
        self.progress_tracker.on_phase_changed(self._on_phase_changed)
        self.progress_tracker.on_activity_added(self._on_activity_added)
        self.progress_tracker.on_finding_added(self._on_finding_added)
        self.progress_tracker.on_contradiction_added(self._on_contradiction_added)

        # Start resource monitoring
        self.run_worker(
            self._monitor_resources(), exclusive=False, name="resource_monitor"
        )

        # Start real analysis
        self.run_worker(self._run_real_analysis(), exclusive=True, name="analysis")

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

    def action_toggle_progress(self) -> None:
        """Toggle progress panel collapse state."""
        # ProgressPanel is NOT wrapped in Container, it's mounted directly
        progress = self.query_one("#progress-panel", ProgressPanel)
        progress.toggle_collapse()

    # Progress tracker callbacks
    def _on_progress_update(self) -> None:
        """Handle progress update from tracker."""
        progress = self.query_one("#progress-panel", ProgressPanel)
        progress.refresh()
        # Update detector panel
        detector_panel = self.query_one("#detector-panel", Container).query_one(
            DetectorPanel
        )
        detector_panel.update_detector_status()

    def _on_resources_updated(self) -> None:
        """Handle resource update from tracker."""
        resources = self.query_one("#system-resources-panel", Container).query_one(
            SystemResourcesPanel
        )
        resources.update_resources()

    def _on_phase_changed(self, phase) -> None:
        """Handle phase change from tracker."""
        progress = self.query_one("#progress-panel", ProgressPanel)
        progress.refresh()
        # Update detector panel
        detector_panel = self.query_one("#detector-panel", Container).query_one(
            DetectorPanel
        )
        detector_panel.update_detector_status()

    def _on_activity_added(self, activity) -> None:
        """Handle new activity from tracker."""
        progress = self.query_one("#progress-panel", ProgressPanel)
        progress.refresh()

    def _on_finding_added(self, severity) -> None:
        """Handle new finding from tracker."""
        # Update findings panel
        findings_panel = self.query_one("#findings-panel", Container).query_one(
            FindingsPanel
        )
        findings_panel.update_findings()

    def _on_contradiction_added(self, contradiction: Contradiction) -> None:
        """Handle contradiction event from tracker."""
        # Update self-correction panel
        self_correct_panel = self.query_one(
            "#self-correction-panel", Container
        ).query_one(SelfCorrectionPanel)
        self_correct_panel.add_contradiction(contradiction.description)

        # Update reasoning panel with resolution
        reasoning_panel = self.query_one("#reasoning-panel", Container).query_one(
            ReasoningPanel
        )
        reasoning_panel.update_reasoning(
            f"Contradiction: {contradiction.description}\n\nResolution: {contradiction.resolution}"
        )

    # Worker methods
    async def _monitor_resources(self) -> None:
        """Monitor system resources and update tracker."""
        import asyncio

        while not self.progress_tracker.is_canceled:
            resources = self.resource_monitor.get_current_resources()
            self.progress_tracker.update_resources(
                cpu_percent=resources["cpu_percent"],
                ram_used_gb=resources["ram_used_gb"],
                ram_total_gb=resources["ram_total_gb"],
                disk_io_mb=resources["disk_io_mb"],
            )
            await asyncio.sleep(5.0)

    def _register_phases_for_mode(self) -> None:
        """Register analysis phases based on selected mode."""
        if self.mode == "quick":
            self.progress_tracker.register_phases(
                [
                    ("load", "Load"),
                    ("prefetch", "Prefetch"),
                    ("yara", "YARA"),
                    ("report", "Report"),
                ]
            )
        elif self.mode == "memory":
            self.progress_tracker.register_phases(
                [
                    ("load", "Load"),
                    ("memory", "Memory"),
                    ("report", "Report"),
                ]
            )
        elif self.mode == "timeline":
            self.progress_tracker.register_phases(
                [
                    ("load", "Load"),
                    ("timestamps", "Timestamps"),
                    ("report", "Report"),
                ]
            )
        else:  # full or custom
            self.progress_tracker.register_phases(
                [
                    ("load", "Load"),
                    ("timestamps", "Timestamps"),
                    ("yara", "YARA"),
                    ("memory", "Memory"),
                    ("persist", "Persist"),
                    ("report", "Report"),
                ]
            )

    async def _run_real_analysis(self) -> None:
        """Run real forensic analysis with progress tracking."""
        analysis_succeeded = False
        try:
            # Configure analysis runner
            if self.evidence_path:
                self.analysis_runner.configure(self.evidence_path, self.mode)

                # Run analysis
                await self.analysis_runner.run_analysis()

                # Mark success before cleanup
                analysis_succeeded = True

                # Notify completion
                self.app.notify("Analysis complete!", severity="information")
            else:
                self.app.notify("No evidence path configured", severity="warning")
        except Exception as e:
            self.app.notify(f"Analysis failed: {str(e)}", severity="error")
            import traceback

            self.progress_tracker.log_activity(f"Error: {traceback.format_exc()}")
            raise
        finally:
            # Cleanup mounted image if present
            if self.mounted_image:
                try:
                    self.progress_tracker.log_activity("Starting E01 cleanup...")
                    commands = self.mounted_image.cleanup()
                    self.progress_tracker.log_activity(
                        f"✓ E01 cleanup complete: {len(commands)} commands executed"
                    )
                    if analysis_succeeded:
                        self.app.notify("✓ E01 image unmounted", severity="information")
                except Exception as cleanup_error:
                    error_msg = f"Cleanup error: {str(cleanup_error)}"
                    self.progress_tracker.log_activity(f"✗ {error_msg}")
                    self.app.notify(
                        f"Cleanup warning: {str(cleanup_error)}", severity="warning"
                    )
                    # Don't re-raise cleanup errors if analysis succeeded
                    if not analysis_succeeded:
                        raise


class DetectorPanel(Static):
    """Left panel showing detector execution progress."""

    def __init__(self, progress_tracker: ProgressTracker, **kwargs: Any):
        super().__init__(**kwargs)
        self.progress_tracker = progress_tracker

    def compose(self) -> ComposeResult:
        yield Label("DETECTORS", classes="panel-title")
        yield DataTable(id="detector-table")

    def on_mount(self) -> None:
        table = self.query_one("#detector-table", DataTable)
        table.add_columns("Detector", "Status", "Progress")
        table.cursor_type = "none"
        self.update_detector_status()

    def update_detector_status(self) -> None:
        """Update detector status from progress tracker."""
        table = self.query_one("#detector-table", DataTable)
        table.clear()

        if not self.progress_tracker.phases:
            table.add_row("No detectors", "[IDLE]", "0%")
            return

        for phase in self.progress_tracker.phases:
            # Map phase status to display status
            if phase.status == PhaseStatus.COMPLETE:
                status = "[DONE]"
                progress = "100%"
            elif phase.status == PhaseStatus.ACTIVE:
                status = "[RUN]"
                progress = f"{int(phase.progress_pct)}%"
            elif phase.status == PhaseStatus.ERROR:
                status = "[ERR]"
                progress = "0%"
            else:  # PENDING
                status = "[WAIT]"
                progress = "0%"

            table.add_row(phase.display_name, status, progress)


class FindingsPanel(Static):
    """Top-right panel showing prioritized findings."""

    def __init__(self, progress_tracker: ProgressTracker, **kwargs: Any):
        super().__init__(**kwargs)
        self.progress_tracker = progress_tracker

    def compose(self) -> ComposeResult:
        yield Label("FINDINGS", classes="panel-title")
        yield DataTable(id="findings-table")

    def on_mount(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.add_columns("Sev", "Finding", "Details")
        table.cursor_type = "row"
        self.update_findings()

    def update_findings(self) -> None:
        """Update findings table from progress tracker."""
        table = self.query_one("#findings-table", DataTable)
        table.clear()

        if not self.progress_tracker.findings:
            table.add_row("INFO", "No findings yet", "Analysis in progress...")
            return

        # Sort findings by severity (Critical -> Info)
        severity_order = {
            FindingSeverity.CRITICAL: 0,
            FindingSeverity.HIGH: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 3,
            FindingSeverity.INFO: 4,
        }
        sorted_findings = sorted(
            self.progress_tracker.findings, key=lambda f: severity_order[f.severity]
        )

        # Display top 20 findings
        for finding in sorted_findings[:20]:
            severity_display = finding.severity.value[:4].upper()
            title = finding.title
            if len(title) > 40:
                title = title[:37] + "..."
            details = finding.details[:30] if finding.details else ""
            table.add_row(severity_display, title, details)


class SelfCorrectionPanel(Static):
    """Bottom-left panel showing self-correction events."""

    def __init__(self, progress_tracker: ProgressTracker, **kwargs: Any):
        super().__init__(**kwargs)
        self.progress_tracker = progress_tracker
        self.contradiction_count = 0

    def compose(self) -> ComposeResult:
        yield Label("SELF-CORRECT", classes="panel-title")
        yield Label(
            "[!] No contradictions yet",
            classes="status-label",
            id="contradiction-status",
        )
        yield Label(
            "  Monitoring...", classes="status-detail", id="contradiction-detail"
        )

    def on_mount(self) -> None:
        # Future: tail audit JSONL and highlight contradictions
        pass

    def add_contradiction(self, description: str) -> None:
        """Add a contradiction event."""
        self.contradiction_count += 1
        try:
            status_label = self.query_one("#contradiction-status", Label)
            detail_label = self.query_one("#contradiction-detail", Label)
            status_label.update(f"[!] CONTRADICT: {description}")
            detail_label.update(f"  Resolved {self.contradiction_count}x")
        except Exception:
            pass


class ReasoningPanel(Static):
    """Bottom-right panel showing reasoning trace."""

    def __init__(self, progress_tracker: ProgressTracker, **kwargs: Any):
        super().__init__(**kwargs)
        self.progress_tracker = progress_tracker

    def compose(self) -> ComposeResult:
        yield Label("REASONING", classes="panel-title")
        yield Static(
            "Waiting for analysis to start...",
            id="reasoning-text",
        )

    def update_reasoning(self, reasoning: str) -> None:
        """Update reasoning text."""
        try:
            reasoning_text = self.query_one("#reasoning-text", Static)
            reasoning_text.update(reasoning)
        except Exception:
            pass


class SystemResourcesPanel(Static):
    """Small bottom-left panel showing system resource usage."""

    def __init__(self, progress_tracker: ProgressTracker, **kwargs: Any):
        super().__init__(**kwargs)
        self.progress_tracker = progress_tracker

    def compose(self) -> ComposeResult:
        yield Label("SYSTEM", classes="panel-title", id="sys-title")
        yield Label("CPU:  --", classes="resource-item", id="sys-cpu")
        yield Label("RAM:  --", classes="resource-item", id="sys-ram")
        yield Label("Disk: --", classes="resource-item", id="sys-disk")
        yield Label("", classes="resource-spacer")
        yield Label("", classes="resource-warning", id="sys-warning")
        yield Label("", classes="resource-spacer")
        yield Label("[Press 'Esc' to cancel]", classes="resource-control")

    def update_resources(self) -> None:
        """Update resource display from progress tracker."""
        resources = self.progress_tracker.system_resources

        # Update CPU
        try:
            cpu_label = self.query_one("#sys-cpu", Label)
            cpu_label.update(f"CPU:  {resources.cpu_percent:.0f}%")
        except Exception:
            pass

        # Update RAM
        try:
            ram_label = self.query_one("#sys-ram", Label)
            ram_label.update(
                f"RAM:  {resources.ram_used_gb:.1f}/{resources.ram_total_gb:.0f}GB"
            )
        except Exception:
            pass

        # Update Disk
        try:
            disk_label = self.query_one("#sys-disk", Label)
            disk_label.update(f"Disk: {resources.disk_io_mb:.1f}MB/s")
        except Exception:
            pass

        # Update warning
        try:
            warning_label = self.query_one("#sys-warning", Label)
            if resources.has_warning and resources.warning_message:
                warning_label.update(f"⚠ {resources.warning_message}")
            else:
                warning_label.update("")
        except Exception:
            pass


class ProgressPanel(Static):
    """Collapsible progress panel for investigation status."""

    def __init__(self, progress_tracker: ProgressTracker, **kwargs: Any):
        super().__init__(**kwargs)
        self.is_collapsed = False
        self.progress_tracker = progress_tracker

    def compose(self) -> ComposeResult:
        if self.is_collapsed:
            yield from self._render_collapsed()
        else:
            yield from self._render_full()

    def _render_full(self) -> ComposeResult:
        """Render full progress panel."""
        yield Label("Investigation Progress", classes="progress-title")

        # Current phase
        phase_name = (
            self.progress_tracker.current_phase.display_name
            if self.progress_tracker.current_phase
            else "Idle"
        )
        yield Label(
            f"Current Phase: {phase_name}", classes="progress-phase", id="prog-phase"
        )

        # Progress bar and metrics
        pct = 0
        current = 0
        total = 0
        if self.progress_tracker.current_phase:
            pct = int(self.progress_tracker.current_phase.progress_pct)
            current = self.progress_tracker.current_phase.items_processed
            total = self.progress_tracker.current_phase.items_total

        elapsed = self.progress_tracker.elapsed_time
        eta = self.progress_tracker.estimated_time_remaining or "--:--:--"

        progress_text = f"{'█' * int(pct * 40 / 100)}{'░' * (40 - int(pct * 40 / 100))} {pct}% ({current}/{total} files)  │  Elapsed: {elapsed}  ETA: {eta}"
        yield Label(progress_text, classes="progress-bar-text", id="prog-bar")

        yield Label("")  # Spacer

        # Phase indicators
        phase_indicators = "Phases: "
        for phase in self.progress_tracker.phases:
            status_symbol = " "
            if phase.status == PhaseStatus.COMPLETE:
                status_symbol = "✓"
            elif phase.status == PhaseStatus.ACTIVE:
                status_symbol = "●"
            phase_indicators += f"[{status_symbol}] {phase.display_name}  "
        yield Label(phase_indicators, classes="progress-phases", id="prog-phases")

        yield Label("")  # Spacer

        # Findings counter
        findings = self.progress_tracker.findings_by_severity
        findings_text = f"Findings: Critical: {findings[FindingSeverity.CRITICAL]}  High: {findings[FindingSeverity.HIGH]}  Medium: {findings[FindingSeverity.MEDIUM]}  Low: {findings[FindingSeverity.LOW]}  Info: {findings[FindingSeverity.INFO]}"
        yield Label(findings_text, classes="progress-findings", id="prog-findings")

        yield Label("")  # Spacer

        # Recent activity
        yield Label("Recent Activity:", classes="progress-activity-title")
        activities = self.progress_tracker.activities[:3]  # Show last 3
        if activities:
            for activity in activities:
                yield Label(
                    f"• {activity.formatted_time} - {activity.message}",
                    classes="progress-activity-item",
                )
        else:
            yield Label("  No activity yet", classes="progress-activity-item")

        yield Label("")  # Spacer

        # Bottom controls
        yield Label("[p: Collapse]", classes="progress-controls")

    def _render_collapsed(self) -> ComposeResult:
        """Render collapsed progress panel."""
        # Compact single-line summary
        phase_name = (
            self.progress_tracker.current_phase.display_name
            if self.progress_tracker.current_phase
            else "Idle"
        )
        pct = (
            int(self.progress_tracker.current_phase.progress_pct)
            if self.progress_tracker.current_phase
            else 0
        )
        current = (
            self.progress_tracker.current_phase.items_processed
            if self.progress_tracker.current_phase
            else 0
        )
        total = (
            self.progress_tracker.current_phase.items_total
            if self.progress_tracker.current_phase
            else 0
        )
        elapsed = self.progress_tracker.elapsed_time
        eta = self.progress_tracker.estimated_time_remaining or "--:--:--"
        findings = self.progress_tracker.findings_by_severity

        summary = f"{phase_name}: {pct}% ({current}/{total})  │  Elapsed: {elapsed}  ETA: {eta}  │  Findings: C:{findings[FindingSeverity.CRITICAL]} H:{findings[FindingSeverity.HIGH]} M:{findings[FindingSeverity.MEDIUM]}"
        yield Label(summary, classes="progress-collapsed-summary")

        # Phase indicators and controls
        phase_text = ""
        for phase in self.progress_tracker.phases:
            short_name = phase.display_name[:4]
            status_symbol = " "
            if phase.status == PhaseStatus.COMPLETE:
                status_symbol = "✓"
            elif phase.status == PhaseStatus.ACTIVE:
                status_symbol = "●"
            phase_text += f"[{status_symbol}] {short_name} "

        controls = f"{phase_text}     [p: Expand]"
        yield Label(controls, classes="progress-collapsed-controls")

    def toggle_collapse(self) -> None:
        """Toggle between collapsed and full view."""
        self.is_collapsed = not self.is_collapsed
        self.remove_children()
        if self.is_collapsed:
            self.mount_all(self._render_collapsed())
        else:
            self.mount_all(self._render_full())
        self.refresh()


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
            yield Label(
                "- Click detected drives to navigate instantly", classes="help-item"
            )
            yield Label("- Ctrl+Click bookmarks to delete them", classes="help-item")
            yield Label(
                "- Type path and press Enter for manual navigation", classes="help-item"
            )
            yield Label(
                "- Click 'Bookmark Current' to save frequently used paths",
                classes="help-item",
            )

            yield Label("ANALYSIS SCREEN", classes="help-section")
            yield Label("a - Approve selected finding", classes="help-item")
            yield Label("r - Reject selected finding", classes="help-item")
            yield Label("d - Drill down for more details", classes="help-item")
            yield Label("e - Export findings to report", classes="help-item")
            yield Label(
                "p - Toggle progress panel (collapse/expand)", classes="help-item"
            )
            yield Label("b - Go back to previous screen", classes="help-item")

            yield Label("GLOBAL KEYBINDINGS", classes="help-section")
            yield Label("q - Quit application", classes="help-item")
            yield Label("? - Show this help screen", classes="help-item")

            yield Label(
                "\nPress any key to close this help screen", classes="help-item"
            )

        yield Footer()

    def on_key(self, event) -> None:
        """Close help on any key press."""
        self.app.pop_screen()


class SIFTDemoApp(App):
    """Textual app for SIFT Find Evil hackathon demo."""

    CSS = """
    AnalysisScreen {
        layout: grid;
        grid-size: 2 3;
        grid-rows: 1fr 1fr auto;
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

    /* System Resources Panel Styles */
    #system-resources-panel {
        border: solid $primary;
        padding: 1;
        row-span: 1;
        column-span: 1;
    }

    .resource-item {
        color: $text;
        padding: 0;
    }

    .resource-spacer {
        height: 1;
    }

    .resource-warning {
        color: $warning;
        text-style: bold;
    }

    .resource-control {
        color: $text-muted;
        text-style: italic;
    }

    /* Progress Panel Styles */
    #progress-panel {
        border: solid $accent;
        padding: 1;
        background: $surface-darken-1;
        row-span: 1;
        column-span: 1;
    }

    .progress-title {
        text-style: bold;
        color: $accent;
        text-align: center;
    }

    .progress-phase {
        color: $text;
        padding: 0 0 1 0;
    }

    .progress-bar-text {
        color: $success;
        text-style: bold;
    }

    .progress-phases {
        color: $text;
    }

    .progress-findings {
        color: $text;
    }

    .progress-activity-title {
        text-style: bold;
        color: $text-muted;
    }

    .progress-activity-item {
        color: $text-muted;
    }

    .progress-controls {
        color: $warning;
    }

    .progress-collapsed-summary {
        color: $text;
        text-style: bold;
    }

    .progress-collapsed-controls {
        color: $text-muted;
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
