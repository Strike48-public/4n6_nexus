"""Test TUI components: theme, commands, progress indicators."""

import pytest

from sift_find_evil.tui import (
    Command,
    CommandPalette,
    filter_commands,
    get_command_by_id,
    OperationProgress,
    ProcessMeter,
    StatusSpinner,
    FORENSIC_THEME,
    TEXTUAL_CSS,
)
from sift_find_evil.tui.commands import FORENSIC_COMMANDS


class TestTheme:
    """Test forensic theme system."""

    def test_theme_has_all_colors(self):
        """Theme should have all required color categories."""
        # Backgrounds
        assert "bg_primary" in FORENSIC_THEME
        assert "bg_panel" in FORENSIC_THEME
        assert "bg_highlight" in FORENSIC_THEME

        # Text
        assert "text_primary" in FORENSIC_THEME
        assert "text_muted" in FORENSIC_THEME
        assert "text_dim" in FORENSIC_THEME

        # Evidence types
        assert "evidence_disk" in FORENSIC_THEME
        assert "evidence_memory" in FORENSIC_THEME
        assert "evidence_network" in FORENSIC_THEME

        # Detection states
        assert "detection_suspicious" in FORENSIC_THEME
        assert "detection_confirmed" in FORENSIC_THEME
        assert "detection_benign" in FORENSIC_THEME
        assert "detection_processing" in FORENSIC_THEME

    def test_textual_css_includes_variables(self):
        """Textual CSS should define color variables."""
        assert "$forensic-bg-primary" in TEXTUAL_CSS
        assert "$forensic-evidence-disk" in TEXTUAL_CSS
        assert "$forensic-detection-suspicious" in TEXTUAL_CSS


class TestCommands:
    """Test command system."""

    def test_all_commands_loaded(self):
        """Should load all forensic commands."""
        assert len(FORENSIC_COMMANDS) == 10

    def test_command_structure(self):
        """Commands should have required fields."""
        cmd = FORENSIC_COMMANDS[0]
        assert hasattr(cmd, "id")
        assert hasattr(cmd, "label")
        assert hasattr(cmd, "description")
        assert hasattr(cmd, "aliases")
        assert hasattr(cmd, "enabled")

    def test_filter_exact_match(self):
        """Exact match should return command first."""
        results = filter_commands("yara")
        assert len(results) > 0
        assert results[0].id == "yara"

    def test_filter_prefix_match(self):
        """Prefix match should work."""
        results = filter_commands("mem")
        assert len(results) > 0
        assert results[0].id == "memory"

    def test_filter_alias_match(self):
        """Alias matching should work."""
        results = filter_commands("scan")
        assert len(results) > 0
        assert results[0].id == "yara"

    def test_filter_empty_query(self):
        """Empty query should return all commands."""
        results = filter_commands("")
        assert len(results) == len(FORENSIC_COMMANDS)

    def test_filter_with_slash(self):
        """Query with leading slash should work."""
        results = filter_commands("/yara")
        assert len(results) > 0
        assert results[0].id == "yara"

    def test_get_command_by_id(self):
        """Should retrieve command by ID."""
        cmd = get_command_by_id("yara")
        assert cmd is not None
        assert cmd.id == "yara"
        assert cmd.label == "yara"

    def test_get_nonexistent_command(self):
        """Should return None for nonexistent command."""
        cmd = get_command_by_id("nonexistent")
        assert cmd is None


class TestOperationProgress:
    """Test OperationProgress widget."""

    def test_initialization(self):
        """Should initialize with correct values."""
        op = OperationProgress("YARA Scan", total=100, current=25)
        assert op.operation == "YARA Scan"
        assert op._total == 100
        assert op._current == 25

    def test_percent_complete(self):
        """Should calculate percentage correctly."""
        op = OperationProgress("Test", total=100, current=50)
        assert op.percent_complete == 50.0

    def test_is_complete(self):
        """Should detect completion."""
        op = OperationProgress("Test", total=100, current=100)
        assert op.is_complete

    def test_not_complete(self):
        """Should detect incomplete state."""
        op = OperationProgress("Test", total=100, current=50)
        assert not op.is_complete

    def test_zero_total(self):
        """Should handle zero total gracefully."""
        op = OperationProgress("Test", total=0, current=0)
        assert op.percent_complete == 100.0


class TestProcessMeter:
    """Test ProcessMeter widget."""

    def test_initialization(self):
        """Should initialize with steps."""
        steps = ["Step 1", "Step 2", "Step 3"]
        meter = ProcessMeter(steps)
        assert meter.steps == steps
        assert meter._current_step == 0

    def test_advance(self):
        """Should advance to next step."""
        meter = ProcessMeter(["Step 1", "Step 2"])
        assert meter._current_step == 0
        meter.advance()
        assert meter._current_step == 1

    def test_set_step(self):
        """Should set step by index."""
        meter = ProcessMeter(["Step 1", "Step 2", "Step 3"])
        meter.set_step(2)
        assert meter._current_step == 2

    def test_is_complete(self):
        """Should detect completion."""
        meter = ProcessMeter(["Step 1", "Step 2"])
        assert not meter.is_complete
        meter.advance()
        meter.advance()
        assert meter.is_complete

    def test_empty_steps(self):
        """Should handle empty steps list."""
        meter = ProcessMeter([])
        assert meter.render() == ""


class TestStatusSpinner:
    """Test StatusSpinner widget."""

    def test_initialization(self):
        """Should initialize with message."""
        spinner = StatusSpinner("Processing...")
        assert spinner.message == "Processing..."
        assert spinner._frame == 0

    def test_set_message(self):
        """Should update message."""
        spinner = StatusSpinner("Initial")
        spinner.set_message("Updated")
        assert spinner.message == "Updated"

    def test_has_frames(self):
        """Should have animation frames."""
        assert len(StatusSpinner.FRAMES) > 0


class TestCommandDataclass:
    """Test Command dataclass."""

    def test_command_creation(self):
        """Should create command with all fields."""
        cmd = Command(
            id="test",
            label="test",
            description="Test command",
            aliases=["t"],
            enabled=True,
        )
        assert cmd.id == "test"
        assert cmd.label == "test"
        assert cmd.description == "Test command"
        assert cmd.aliases == ["t"]
        assert cmd.enabled

    def test_command_defaults(self):
        """Should use default values."""
        cmd = Command(id="test", label="test", description="Test")
        assert cmd.aliases is None
        assert cmd.enabled is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
