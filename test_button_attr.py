#!/usr/bin/env python3
"""Test button attribute persistence in Textual."""

from textual.app import App, ComposeResult
from textual.widgets import Button, Static, Header
from textual.containers import Container


class TestApp(App):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(id="button-container")

    def on_mount(self) -> None:
        container = self.query_one("#button-container")

        # Create button with custom attribute
        btn = Button("Click Me", id="test-btn")
        btn.custom_index = 42
        container.mount(btn)

        # Check if attribute exists
        print(f"After mount: hasattr={hasattr(btn, 'custom_index')}, value={getattr(btn, 'custom_index', 'N/A')}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button = event.button
        print(f"Button clicked: id={button.id}")
        print(f"Has custom_index: {hasattr(button, 'custom_index')}")
        if hasattr(button, 'custom_index'):
            print(f"custom_index value: {button.custom_index}")
            self.exit()
        else:
            print("ERROR: custom_index attribute missing!")
            self.exit(1)


if __name__ == "__main__":
    app = TestApp()
    app.run()
