"""
Textual TUI for SIFT Find Evil Demo

Terminal User Interface showcasing autonomous detection, self-correction,
and forensic analysis workflows for hackathon demo.
"""

import json
from pathlib import Path
from typing import Any

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Label,
    Static,
)


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
    Screen {
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
        ("q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        """Compose the four-panel layout."""
        yield Header(show_clock=True)
        yield Container(DetectorPanel(), id="detector-panel")
        yield Container(FindingsPanel(), id="findings-panel")
        yield Container(SelfCorrectionPanel(), id="self-correction-panel")
        yield Container(ReasoningPanel(), id="reasoning-panel")
        yield Footer()

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


def main():
    """Run the SIFT Find Evil TUI demo."""
    app = SIFTDemoApp()
    app.title = "sift-find-evil"
    app.sub_title = "Case: M57-Jean    Evidence: nps-2008-jean.E01    ● ANALYZING"
    app.run()


if __name__ == "__main__":
    main()
