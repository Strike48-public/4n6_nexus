"""Command palette modal for quick forensic operations."""

from textual import on
from textual.app import ComposeResult
from textual.containers import Container, VerticalScroll
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Input, Label, Static

from .commands import Command, filter_commands


class CommandItem(Static):
    """Single command in the palette list."""

    DEFAULT_CSS = """
    CommandItem {
        height: 3;
        padding: 0 2;
        color: $forensic-text-primary;
    }

    CommandItem.selected {
        background: $forensic-bg-highlight;
        border-left: thick $forensic-button-primary;
    }

    CommandItem .command-label {
        text-style: bold;
        color: $forensic-button-primary;
    }

    CommandItem .command-desc {
        color: $forensic-text-muted;
    }
    """

    def __init__(self, command: Command, **kwargs):
        """Initialize command item.

        Args:
            command: Command to display
            **kwargs: Additional widget arguments
        """
        super().__init__(**kwargs)
        self.command = command

    def compose(self) -> ComposeResult:
        """Compose command item."""
        # Show aliases if available
        aliases = f" ({', '.join(self.command.aliases)})" if self.command.aliases else ""
        yield Label(f"/{self.command.label}{aliases}", classes="command-label")
        yield Label(self.command.description, classes="command-desc")

    def on_click(self) -> None:
        """Handle click on command."""
        self.post_message(self.Selected(self.command))

    class Selected(Message):
        """Command was selected."""

        def __init__(self, command: Command):
            super().__init__()
            self.command = command


class CommandPalette(ModalScreen):
    """Modal command palette for quick actions."""

    DEFAULT_CSS = """
    CommandPalette {
        align: center middle;
    }

    #palette-container {
        width: 70;
        height: 25;
        border: thick $forensic-border-focus;
        background: $forensic-bg-panel;
        padding: 1;
    }

    #palette-input {
        margin: 0 0 1 0;
        border: solid $forensic-border-normal;
        background: $forensic-bg-primary;
        color: $forensic-text-primary;
    }

    #palette-input:focus {
        border: solid $forensic-border-focus;
    }

    #palette-title {
        text-style: bold;
        color: $forensic-text-heading;
        margin: 0 0 1 0;
    }

    #palette-list {
        height: 1fr;
        border: solid $forensic-border-normal;
        background: $forensic-bg-primary;
    }

    #palette-hint {
        color: $forensic-text-dim;
        margin: 1 0 0 0;
        text-align: center;
    }
    """

    BINDINGS = [
        ("escape", "dismiss", "Close"),
        ("up", "select_prev", "Previous"),
        ("down", "select_next", "Next"),
        ("enter", "execute", "Execute"),
    ]

    def __init__(self, **kwargs):
        """Initialize command palette."""
        super().__init__(**kwargs)
        self.commands: list[Command] = []
        self.selected_index = 0

    def compose(self) -> ComposeResult:
        """Compose command palette."""
        with Container(id="palette-container"):
            yield Label("Command Palette", id="palette-title")
            yield Input(
                placeholder="Type to search commands...",
                id="palette-input",
            )
            with VerticalScroll(id="palette-list"):
                # Will be populated by filter
                pass
            yield Label("↑↓ Navigate  Enter Execute  Esc Close", id="palette-hint")

    def on_mount(self) -> None:
        """Focus input when mounted."""
        self._update_commands("")
        self.query_one("#palette-input", Input).focus()

    @on(Input.Changed, "#palette-input")
    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle search query changes."""
        self._update_commands(event.value)

    def _update_commands(self, query: str) -> None:
        """Update filtered command list.

        Args:
            query: Search query
        """
        self.commands = filter_commands(query)
        self.selected_index = 0

        # Rebuild command list
        palette_list = self.query_one("#palette-list", VerticalScroll)
        palette_list.remove_children()

        for i, cmd in enumerate(self.commands):
            item = CommandItem(cmd, id=f"cmd-{cmd.id}")
            if i == self.selected_index:
                item.add_class("selected")
            palette_list.mount(item)

    def _update_selection(self) -> None:
        """Update visual selection."""
        # Remove all selections
        for item in self.query("#palette-list CommandItem"):
            item.remove_class("selected")

        # Add selection to current item
        if 0 <= self.selected_index < len(self.commands):
            cmd = self.commands[self.selected_index]
            item = self.query_one(f"#cmd-{cmd.id}", CommandItem)
            item.add_class("selected")
            item.scroll_visible()

    def action_select_prev(self) -> None:
        """Select previous command."""
        if self.commands:
            self.selected_index = (self.selected_index - 1) % len(self.commands)
            self._update_selection()

    def action_select_next(self) -> None:
        """Select next command."""
        if self.commands:
            self.selected_index = (self.selected_index + 1) % len(self.commands)
            self._update_selection()

    def action_execute(self) -> None:
        """Execute selected command."""
        if 0 <= self.selected_index < len(self.commands):
            selected_cmd = self.commands[self.selected_index]
            self.dismiss(selected_cmd)
        else:
            self.dismiss(None)

    def action_dismiss(self) -> None:
        """Close palette without executing."""
        self.dismiss(None)

    @on(CommandItem.Selected)
    def on_command_selected(self, event: CommandItem.Selected) -> None:
        """Handle command item click."""
        event.stop()
        self.dismiss(event.command)
