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


class FileSelectionScreen(Screen):
    """File browser for selecting evidence files or synthetic scenarios."""

    CSS = """
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
        padding: 0 0 1 0;
    }

    #path-input {
        margin: 1 0;
    }

    .quick-nav {
        layout: horizontal;
        height: auto;
        margin: 1 0;
    }

    .quick-nav-button {
        width: 1fr;
        height: 3;
        margin: 0 1;
    }

    DirectoryTree {
        height: 1fr;
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
    """

    def __init__(self, **kwargs: Any):
        super().__init__(**kwargs)
        self.selected_path: Path | None = None
        self.current_tree_path = Path.cwd()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with VerticalScroll(id="file-container"):
            yield Label("SIFT FIND EVIL - SELECT EVIDENCE", classes="screen-title")
            yield Label("Navigate to evidence file or synthetic scenario directory:")
            yield Input(
                placeholder="Enter path or use tree below...",
                id="path-input"
            )

            # Quick navigation buttons
            with Horizontal(classes="quick-nav"):
                yield Button("Home", id="nav-home", classes="quick-nav-button")
                yield Button("/mnt", id="nav-mnt", classes="quick-nav-button")
                yield Button("/media", id="nav-media", classes="quick-nav-button")
                yield Button("Scenarios", id="nav-scenarios", classes="quick-nav-button")

            yield DirectoryTree(str(self.current_tree_path), id="evidence-tree")

            with Horizontal(classes="action-buttons"):
                yield Button("Cancel", id="cancel-btn", classes="action-button cancel-button")
                yield Button("Load Evidence", id="load-btn", classes="action-button")

        yield Footer()

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

        # Quick navigation buttons
        if button_id == "nav-home":
            self._navigate_to(Path.home())
        elif button_id == "nav-mnt":
            self._navigate_to(Path("/mnt"))
        elif button_id == "nav-media":
            self._navigate_to(Path("/media"))
        elif button_id == "nav-scenarios":
            scenarios_path = Path.cwd() / "scenarios" / "synthetic"
            if scenarios_path.exists():
                self._navigate_to(scenarios_path)
            else:
                self.app.notify("Scenarios directory not found", severity="warning")

        # Action buttons
        elif button_id == "load-btn":
            self._load_evidence()
        elif button_id == "cancel-btn":
            self.app.exit()

    def _navigate_to(self, path: Path) -> None:
        """Navigate the directory tree to a specific path."""
        if not path.exists():
            self.app.notify(f"Path not found: {path}", severity="error")
            return

        if not path.is_dir():
            self.app.notify(f"Not a directory: {path}", severity="error")
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
        self.app.sub_title = f"Case: {self.case_name}    Evidence: {evidence_name}    Mode: {mode_display}    ● ANALYZING"


class DetectorPanel(Static):
    """Left panel showing detector execution progress."""

    def compose(self) -> ComposeResult:
        yield Label("DETECTORS", classes="panel-title")
        yield DataTable(id="detector-table")

    def on_mount(self) -> None:
        table = self.query_one("#detector-table", DataTable)
        table.add_columns("Detector", "Status")
        table.cursor_type = "none"

        # Populate with sample detectors
        detectors = [
            ("NSRL filter", "✓"),
            ("Prefetch", "✓"),
            ("Memory", "●"),
            ("YARA scan", "●"),
            ("Timeline", "○"),
            ("Carving", "○"),
        ]
        for name, status in detectors:
            table.add_row(name, status)


class FindingsPanel(Static):
    """Top-right panel showing prioritized findings."""

    def compose(self) -> ComposeResult:
        yield Label("FINDINGS", classes="panel-title")
        yield DataTable(id="findings-table")

    def on_mount(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.add_columns("Sev", "Finding")
        table.cursor_type = "row"

        # Load findings from demo JSON
        findings_path = Path("demo/findings_sample.json")
        if findings_path.exists():
            findings = json.loads(findings_path.read_text())
            for finding in findings:
                severity = finding.get("severity", "medium").upper()[:4]
                title = finding.get("title", "Unknown")[:50]
                table.add_row(severity, title)
        else:
            # Fallback to ransomware demo
            findings_path = Path("analysis/demo_ransomware.json")
            if findings_path.exists():
                data = json.loads(findings_path.read_text())
                for exe in data.get("detected_executables", []):
                    severity = "CRIT" if "ransom" in exe else "HIGH"
                    table.add_row(severity, f"{exe}: mass encryption")


class SelfCorrectionPanel(Static):
    """Bottom-left panel showing self-correction events."""

    def compose(self) -> ComposeResult:
        yield Label("SELF-CORRECT", classes="panel-title")
        yield Label("⚠ CONTRADICT", classes="status-label")
        yield Label("  Resolved 3×", classes="status-detail")

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
            "→ Timestomping detected. SI can be modified,\n"
            "  FN is more reliable. Reduced confidence.",
            id="reasoning-text",
        )


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
        ("a", "approve", "Approve"),
        ("r", "reject", "Reject"),
        ("d", "drill", "Drill Down"),
        ("e", "export", "Export"),
        ("b", "back", "Back"),
        ("q", "quit", "Quit"),
    ]

    def on_mount(self) -> None:
        """Show file selection on startup."""
        self.push_screen(FileSelectionScreen())

    def action_approve(self) -> None:
        """Approve selected finding."""
        self.notify("✓ Finding approved")

    def action_reject(self) -> None:
        """Reject selected finding."""
        self.notify("✗ Finding rejected")

    def action_drill(self) -> None:
        """Drill down into selected finding."""
        self.notify("🔍 Drilling down...")

    def action_export(self) -> None:
        """Export findings to report."""
        self.notify("📄 Exporting report...")

    def action_back(self) -> None:
        """Go back to previous screen."""
        if len(self.screen_stack) > 1:
            self.pop_screen()
        else:
            self.notify("Already at first screen")


def main():
    """Run the SIFT Find Evil TUI demo."""
    app = SIFTDemoApp()
    app.title = "sift-find-evil"
    app.sub_title = "Professional DFIR Analysis Tool"
    app.run()


if __name__ == "__main__":
    main()
