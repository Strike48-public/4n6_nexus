"""TUI theme with semantic forensic colors."""

FORENSIC_THEME = {
    # Backgrounds
    "bg_primary": "#0a0a0a",
    "bg_panel": "#1a1a1a",
    "bg_highlight": "#2a2a2a",
    "bg_input": "#161616",

    # Text
    "text_primary": "#e0e0e0",
    "text_muted": "#808080",
    "text_dim": "#505050",
    "text_heading": "#ffffff",

    # Evidence types
    "evidence_disk": "#5c9cf5",      # Blue for disk images
    "evidence_memory": "#9c5cf5",    # Purple for memory dumps
    "evidence_network": "#5cf59c",   # Green for network captures
    "evidence_registry": "#f59c5c",  # Orange for registry
    "evidence_timeline": "#f5f55c",  # Yellow for timeline

    # Detection states
    "detection_suspicious": "#f5a542",  # Orange
    "detection_confirmed": "#f54242",   # Red - malicious
    "detection_benign": "#42f554",      # Green - clean
    "detection_unknown": "#808080",     # Gray - uncertain
    "detection_processing": "#5c9cf5",  # Blue - in progress

    # Timeline events
    "timeline_before": "#5c9cf5",    # Blue - before IOC
    "timeline_ioc": "#f54242",       # Red - IOC event
    "timeline_after": "#f5a542",     # Orange - after IOC

    # UI elements
    "border_normal": "#333333",
    "border_focus": "#5c9cf5",
    "border_error": "#f54242",

    "button_primary": "#5c9cf5",
    "button_success": "#42f554",
    "button_warning": "#f5a542",
    "button_danger": "#f54242",

    # Progress indicators
    "progress_bg": "#1a1a1a",
    "progress_fill": "#5c9cf5",
    "progress_complete": "#42f554",

    # Diff/comparison
    "diff_added": "#1e3a1e",
    "diff_added_fg": "#8adf8a",
    "diff_removed": "#3a1e1e",
    "diff_removed_fg": "#df8a8a",
    "diff_context": "#161616",
}

# Textual CSS color mappings
TEXTUAL_CSS = f"""
$forensic-bg-primary: {FORENSIC_THEME['bg_primary']};
$forensic-bg-panel: {FORENSIC_THEME['bg_panel']};
$forensic-bg-highlight: {FORENSIC_THEME['bg_highlight']};

$forensic-text-primary: {FORENSIC_THEME['text_primary']};
$forensic-text-muted: {FORENSIC_THEME['text_muted']};
$forensic-text-dim: {FORENSIC_THEME['text_dim']};

$forensic-evidence-disk: {FORENSIC_THEME['evidence_disk']};
$forensic-evidence-memory: {FORENSIC_THEME['evidence_memory']};
$forensic-evidence-network: {FORENSIC_THEME['evidence_network']};

$forensic-detection-suspicious: {FORENSIC_THEME['detection_suspicious']};
$forensic-detection-confirmed: {FORENSIC_THEME['detection_confirmed']};
$forensic-detection-benign: {FORENSIC_THEME['detection_benign']};
$forensic-detection-processing: {FORENSIC_THEME['detection_processing']};

$forensic-border-normal: {FORENSIC_THEME['border_normal']};
$forensic-border-focus: {FORENSIC_THEME['border_focus']};

$forensic-button-primary: {FORENSIC_THEME['button_primary']};
$forensic-button-success: {FORENSIC_THEME['button_success']};
$forensic-button-warning: {FORENSIC_THEME['button_warning']};
$forensic-button-danger: {FORENSIC_THEME['button_danger']};

$forensic-progress-bg: {FORENSIC_THEME['progress_bg']};
$forensic-progress-fill: {FORENSIC_THEME['progress_fill']};
$forensic-progress-complete: {FORENSIC_THEME['progress_complete']};
"""
