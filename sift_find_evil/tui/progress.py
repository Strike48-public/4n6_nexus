"""Progress indicators for TUI operations."""

from textual.app import ComposeResult
from textual.containers import Container
from textual.widgets import Label, ProgressBar, Static


class OperationProgress(Container):
    """Progress indicator for long-running forensic operations."""

    DEFAULT_CSS = """
    OperationProgress {
        height: 5;
        border: solid $forensic-border-normal;
        padding: 1;
        margin: 0 0 1 0;
    }

    OperationProgress .progress-label {
        color: $forensic-text-primary;
        text-style: bold;
    }

    OperationProgress .progress-detail {
        color: $forensic-text-muted;
        margin: 0 0 1 0;
    }

    OperationProgress ProgressBar {
        margin: 0;
    }

    OperationProgress .progress-bar-complete {
        color: $forensic-progress-complete;
    }
    """

    def __init__(
        self,
        operation: str,
        total: int = 100,
        current: int = 0,
        detail: str = "",
        **kwargs,
    ):
        """Initialize progress indicator.

        Args:
            operation: Operation name (e.g., "YARA Scan", "Analyzing")
            total: Total units of work
            current: Current progress
            detail: Additional detail text
            **kwargs: Additional container arguments
        """
        super().__init__(**kwargs)
        self.operation = operation
        self._total = total
        self._current = current
        self._detail = detail

    def compose(self) -> ComposeResult:
        """Compose progress indicator widgets."""
        yield Label(self.operation, classes="progress-label")
        yield Label(self._detail, classes="progress-detail", id="progress-detail")
        yield ProgressBar(total=self._total, show_eta=False, id="progress-bar")

    def update_progress(self, current: int, detail: str = "") -> None:
        """Update progress.

        Args:
            current: Current progress value
            detail: Optional detail text
        """
        self._current = current
        progress_bar = self.query_one("#progress-bar", ProgressBar)
        progress_bar.update(progress=current)

        if detail:
            self._detail = detail
            detail_label = self.query_one("#progress-detail", Label)
            detail_label.update(detail)

        # Update styling when complete
        if current >= self._total:
            progress_bar.add_class("progress-bar-complete")

    @property
    def is_complete(self) -> bool:
        """Check if operation is complete."""
        return self._current >= self._total

    @property
    def percent_complete(self) -> float:
        """Get completion percentage."""
        if self._total == 0:
            return 100.0
        return (self._current / self._total) * 100


class ProcessMeter(Static):
    """Compact process meter showing step-by-step progress.

    Example:
        [1/5] Loading evidence ████████░░░░ 40%
    """

    DEFAULT_CSS = """
    ProcessMeter {
        height: 1;
        color: $forensic-text-primary;
    }

    ProcessMeter.complete {
        color: $forensic-progress-complete;
    }
    """

    def __init__(
        self,
        steps: list[str],
        current_step: int = 0,
        **kwargs,
    ):
        """Initialize process meter.

        Args:
            steps: List of step names
            current_step: Current step index (0-based)
            **kwargs: Additional widget arguments
        """
        super().__init__(**kwargs)
        self.steps = steps
        self._current_step = current_step

    def render(self) -> str:
        """Render process meter."""
        if not self.steps:
            return ""

        total = len(self.steps)
        current = min(self._current_step, total - 1)
        step_name = self.steps[current] if current < total else "Complete"

        # Progress bar (12 blocks)
        bar_length = 12
        filled = int((current / total) * bar_length)
        bar = "█" * filled + "░" * (bar_length - filled)

        # Percentage
        percent = int((current / total) * 100)

        return f"[{current + 1}/{total}] {step_name} {bar} {percent}%"

    def advance(self, step_name: str | None = None) -> None:
        """Advance to next step.

        Args:
            step_name: Optional override for step name
        """
        self._current_step += 1
        if self._current_step >= len(self.steps):
            self.add_class("complete")
        self.refresh()

    def set_step(self, step_index: int) -> None:
        """Set current step by index.

        Args:
            step_index: Step index (0-based)
        """
        self._current_step = max(0, min(step_index, len(self.steps) - 1))
        if self._current_step >= len(self.steps):
            self.add_class("complete")
        self.refresh()

    @property
    def is_complete(self) -> bool:
        """Check if all steps are complete."""
        return self._current_step >= len(self.steps)


class StatusSpinner(Static):
    """Animated spinner for indeterminate operations."""

    DEFAULT_CSS = """
    StatusSpinner {
        height: 1;
        color: $forensic-detection-processing;
    }
    """

    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, message: str = "Processing...", **kwargs):
        """Initialize spinner.

        Args:
            message: Status message to display
            **kwargs: Additional widget arguments
        """
        super().__init__(**kwargs)
        self.message = message
        self._frame = 0

    def on_mount(self) -> None:
        """Start animation when mounted."""
        self.set_interval(0.1, self._animate)

    def _animate(self) -> None:
        """Animate spinner frame."""
        self._frame = (self._frame + 1) % len(self.FRAMES)
        self.update(f"{self.FRAMES[self._frame]} {self.message}")

    def set_message(self, message: str) -> None:
        """Update spinner message.

        Args:
            message: New message
        """
        self.message = message
