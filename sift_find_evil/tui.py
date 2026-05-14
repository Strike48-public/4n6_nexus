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
    Footer,
    Header,
    Label,
    Static,
)


class CaseLoaderScreen(Screen):
    """Initial screen for selecting evidence and analysis type."""

    CSS = """
    CaseLoaderScreen {
        align: center middle;
    }

    #loader-container {
        width: 90%;
        max-width: 100;
        height: 90%;
        border: solid $primary;
        padding: 1 2;
        background: $surface;
    }

    .loader-title {
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

    .case-button {
        width: 100%;
        margin: 0;
        height: 3;
    }

    .case-description {
        color: $text-muted;
        padding: 0 2;
        margin-bottom: 1;
    }

    .quit-button {
        width: 100%;
        margin-top: 1;
        background: $error;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with VerticalScroll(id="loader-container"):
            yield Label("SIFT FIND EVIL - CASE LOADER", classes="loader-title")

            # Synthetic scenarios
            yield Label("📁 SYNTHETIC SCENARIOS (Demo-Ready)", classes="section-title")
            yield Button("🔴 Ransomware - Mass encryption",
                        id="synthetic_ransomware", classes="case-button")
            yield Label("  F1=1.00 | 3 findings | ~2s", classes="case-description")

            yield Button("⏱️  Timestomping - Timestamp manipulation",
                        id="synthetic_timestomp", classes="case-button")
            yield Label("  F1=1.00 | 4 findings | ~1s", classes="case-description")

            yield Button("🧠 Memory Intrusion - Volatility analysis",
                        id="synthetic_memory", classes="case-button")
            yield Label("  F1=1.00 | 5 findings | ~3s", classes="case-description")

            # Real evidence
            yield Label("💾 REAL FORENSIC IMAGES (Requires Mount)", classes="section-title")
            yield Button("📧 M57-Jean - Corporate espionage",
                        id="real_m57jean", classes="case-button")
            yield Label("  nps-2008-jean.E01 (4.2 GB) | ~45 min", classes="case-description")

            yield Button("💣 CIRCL 2023 - Wiped disk recovery",
                        id="real_circl", classes="case-button")
            yield Label("  circl-wiped-2023.dd (8 GB) | ~1.5 hrs", classes="case-description")

            # Analysis options
            yield Label("⚙️  ANALYSIS MODE", classes="section-title")
            yield Button("🚀 Quick Triage",
                        id="mode_quick", classes="case-button")
            yield Button("🔬 Full Analysis",
                        id="mode_full", classes="case-button")
            yield Button("🎯 Custom Selection",
                        id="mode_custom", classes="case-button")

            # Quit button
            yield Button("❌ Exit / Quit",
                        id="quit_app", classes="quit-button")

        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle case/mode selection."""
        button_id = event.button.id

        if button_id == "quit_app":
            # Quit the application
            self.app.exit()

        elif button_id and button_id.startswith("synthetic_"):
            # Load synthetic scenario
            scenario_map = {
                "synthetic_ransomware": "02_ransomware",
                "synthetic_timestomp": "03_timestomping",
                "synthetic_memory": "12_memory_intrusion",
            }
            scenario = scenario_map.get(button_id, "02_ransomware")
            self.app.push_screen(AnalysisScreen(
                case_name=scenario,
                evidence_type="synthetic",
                mode="quick"
            ))

        elif button_id and button_id.startswith("real_"):
            # Load real evidence
            case_map = {
                "real_m57jean": "M57-Jean",
                "real_circl": "CIRCL-2023",
            }
            case_name = case_map.get(button_id, "M57-Jean")
            self.app.notify(f"Loading {case_name}... (requires evidence mount)")
            self.app.push_screen(AnalysisScreen(
                case_name=case_name,
                evidence_type="real",
                mode="full"
            ))

        elif button_id and button_id.startswith("mode_"):
            # Just notify for now (mode selection would be implemented later)
            mode_map = {
                "mode_quick": "Quick Triage",
                "mode_full": "Full Analysis",
                "mode_custom": "Custom",
            }
            mode = mode_map.get(button_id, "Quick")
            self.app.notify(f"Mode: {mode} selected")


class AnalysisScreen(Screen):
    """Main analysis screen with four-panel layout."""

    def __init__(
        self,
        case_name: str = "Demo",
        evidence_type: str = "synthetic",
        mode: str = "quick",
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self.case_name = case_name
        self.evidence_type = evidence_type
        self.mode = mode

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
        evidence_file = "nps-2008-jean.E01" if self.case_name == "M57-Jean" else f"{self.case_name}.dd"
        self.app.sub_title = f"Case: {self.case_name}    Evidence: {evidence_file}    ● ANALYZING"


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
        ("c", "cases", "Case Loader"),
        ("q", "quit", "Quit"),
    ]

    def on_mount(self) -> None:
        """Show case loader on startup."""
        self.push_screen(CaseLoaderScreen())

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

    def action_cases(self) -> None:
        """Return to case loader."""
        self.push_screen(CaseLoaderScreen())


def main():
    """Run the SIFT Find Evil TUI demo."""
    app = SIFTDemoApp()
    app.title = "sift-find-evil"
    app.sub_title = "Case: M57-Jean    Evidence: nps-2008-jean.E01    ● ANALYZING"
    app.run()


if __name__ == "__main__":
    main()
