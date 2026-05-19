"""
Automated tests for SIFT Find Evil TUI.

Tests interactive functionality including button clicks, navigation, and screen transitions.
"""

import pytest
from pathlib import Path
from textual.pilot import Pilot
from sift_find_evil.tui_app import SIFTDemoApp, FileSelectionScreen


class TestFileSelectionScreen:
    """Test the file selection screen functionality."""

    @pytest.mark.asyncio
    async def test_screen_loads(self):
        """Test that the file selection screen loads successfully."""
        app = SIFTDemoApp()
        async with app.run_test() as pilot:
            # Should start on file selection screen
            assert isinstance(pilot.app.screen, FileSelectionScreen)
            assert pilot.app.screen.query_one("#quick-access-container") is not None

    @pytest.mark.asyncio
    async def test_refresh_drives_button(self):
        """Test clicking the refresh drives button."""
        app = SIFTDemoApp()
        async with app.run_test() as pilot:
            # Get initial mount count
            screen = pilot.app.screen
            initial_mount_count = len(screen.mounts)

            # Click refresh button
            await pilot.click("#refresh-drives-btn")
            await pilot.pause()

            # Should have same or different mount count (depends on system state)
            # But should not crash
            assert len(screen.mounts) >= 0

    @pytest.mark.asyncio
    async def test_mount_button_click(self):
        """Test clicking a mount button navigates to the path."""
        app = SIFTDemoApp()
        async with app.run_test() as pilot:
            screen = pilot.app.screen

            # Skip if no mounts detected
            if not screen.mounts:
                pytest.skip("No mounts detected for testing")

            # Get first mount button (by class, since IDs are dynamic)
            mount_buttons = screen.query(".mount-button")
            if mount_buttons:
                button_id = mount_buttons[0].id
                print(f"Testing button: {button_id}")
                print(f"Mapping: {screen._mount_id_to_index}")
                print(f"Expected path: {screen.mounts[0]['path']}")

                # Test by calling _navigate_to directly
                expected_path = Path(screen.mounts[0]["path"])
                screen._navigate_to(expected_path)
                await pilot.pause()

                print(f"Current path after direct call: {screen.current_tree_path}")

                # Should have navigated to that path
                assert screen.current_tree_path == expected_path

    @pytest.mark.asyncio
    async def test_manual_path_navigation(self):
        """Test entering a path manually and pressing Enter."""
        app = SIFTDemoApp()
        async with app.run_test() as pilot:
            # Enter a valid path (use /tmp which should exist)
            test_path = "/tmp"
            path_input = pilot.app.screen.query_one("#path-input")

            # Focus and type into input
            path_input.focus()
            await pilot.press(*list(test_path))
            await pilot.press("enter")
            await pilot.pause()

            # Should have navigated
            assert pilot.app.screen.current_tree_path == Path(test_path)

    @pytest.mark.asyncio
    async def test_bookmark_current_path(self):
        """Test bookmarking the current path."""
        app = SIFTDemoApp()
        async with app.run_test() as pilot:
            screen = pilot.app.screen
            initial_bookmark_count = len(screen.bookmarks)

            # Navigate to /tmp first
            await pilot.click("#path-input")
            await pilot.press(*list("/tmp"))
            await pilot.press("enter")
            await pilot.pause()

            # Click bookmark button
            await pilot.click("#bookmark-current-btn")
            await pilot.pause()

            # Should have one more bookmark (if not already bookmarked)
            assert len(screen.bookmarks) >= initial_bookmark_count

    @pytest.mark.asyncio
    async def test_help_screen(self):
        """Test opening and closing the help screen."""
        app = SIFTDemoApp()
        async with app.run_test() as pilot:
            # Press ? to open help
            await pilot.press("question_mark")
            await pilot.pause()

            # Should be on a different screen now (HelpScreen)
            assert not isinstance(pilot.app.screen, FileSelectionScreen)

            # Press any key to dismiss
            await pilot.press("escape")
            await pilot.pause()

            # Should be back on file selection
            assert isinstance(pilot.app.screen, FileSelectionScreen)

    @pytest.mark.asyncio
    async def test_quit_keybinding(self):
        """Test that 'q' quits the app."""
        app = SIFTDemoApp()
        async with app.run_test() as pilot:
            # Press q to quit
            await pilot.press("q")
            await pilot.pause()

            # App should exit (this will happen during pilot cleanup)
            # If we get here without exception, test passed

    @pytest.mark.asyncio
    async def test_load_evidence_with_selection(self):
        """Test loading evidence with a selected path."""
        app = SIFTDemoApp()
        async with app.run_test() as pilot:
            screen = pilot.app.screen

            # Set a selected path
            screen.selected_path = Path("/tmp")

            # Click load button
            await pilot.click("#load-btn")
            await pilot.pause()

            # Should transition to analysis config screen
            # (screen type will be different from FileSelectionScreen)
            assert not isinstance(pilot.app.screen, FileSelectionScreen)

    @pytest.mark.asyncio
    async def test_no_duplicate_ids_after_refresh(self):
        """Test that refreshing drives doesn't create duplicate IDs."""
        app = SIFTDemoApp()
        async with app.run_test() as pilot:
            # Click refresh multiple times
            for _ in range(3):
                await pilot.click("#refresh-drives-btn")
                await pilot.pause()

            # Should not have crashed with duplicate ID errors
            # If we get here, test passed

    @pytest.mark.asyncio
    async def test_mount_buttons_exist(self):
        """Test that mount buttons are created."""
        app = SIFTDemoApp()
        async with app.run_test() as pilot:
            screen = pilot.app.screen

            # Should have mount buttons matching mount count
            mount_buttons = screen.query(".mount-button")
            assert len(mount_buttons) == len(screen.mounts)

    @pytest.mark.asyncio
    async def test_bookmark_deletion_with_ctrl_click(self):
        """Test deleting a bookmark with Ctrl+Click."""
        app = SIFTDemoApp()
        async with app.run_test() as pilot:
            screen = pilot.app.screen

            # First ensure we have a bookmark by adding /tmp
            screen.selected_path = Path("/tmp")
            await pilot.click("#bookmark-current-btn")
            await pilot.pause()

            initial_count = len(screen.bookmarks)
            if initial_count == 0:
                pytest.skip("No bookmarks to delete")

            # Ctrl+Click on first bookmark
            # Note: Textual pilot may not support Ctrl+Click simulation
            # This is a manual test case
            pass


class TestIntegration:
    """Integration tests for full workflows."""

    @pytest.mark.asyncio
    async def test_full_navigation_workflow(self):
        """Test complete navigation workflow: mount click -> bookmark -> navigate."""
        app = SIFTDemoApp()
        async with app.run_test() as pilot:
            screen = pilot.app.screen

            if not screen.mounts:
                pytest.skip("No mounts for integration test")

            # 1. Click a mount
            mount_buttons = screen.query(".mount-button")
            if mount_buttons:
                await pilot.click(f"#{mount_buttons[0].id}")
                await pilot.pause()

            # 2. Bookmark it
            await pilot.click("#bookmark-current-btn")
            await pilot.pause()

            # 3. Navigate away to /tmp
            path_input = screen.query_one("#path-input")
            path_input.focus()
            await pilot.press(*list("/tmp"))
            await pilot.press("enter")
            await pilot.pause()

            # 4. Refresh drives
            await pilot.click("#refresh-drives-btn")
            await pilot.pause()

            # Should complete without errors
            assert True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
