"""Slash command palette for forensic operations."""

from dataclasses import dataclass


@dataclass
class Command:
    """Represents a slash command."""

    id: str
    label: str
    description: str
    aliases: list[str] | None = None
    enabled: bool = True


FORENSIC_COMMANDS = [
    Command(
        id="help",
        label="help",
        description="Show keyboard shortcuts and commands",
        aliases=["h", "?"],
    ),
    Command(
        id="timeline",
        label="timeline",
        description="Generate artifact timeline view",
        aliases=["time", "tl"],
    ),
    Command(
        id="yara",
        label="yara",
        description="Run YARA malware scan",
        aliases=["scan", "malware", "y"],
    ),
    Command(
        id="memory",
        label="memory",
        description="Memory forensics analysis",
        aliases=["mem", "volatility", "vol"],
    ),
    Command(
        id="export",
        label="export",
        description="Export findings to report",
        aliases=["save", "report", "out"],
    ),
    Command(
        id="filter",
        label="filter",
        description="Filter artifacts by type/date",
        aliases=["find", "search", "f"],
    ),
    Command(
        id="refresh",
        label="refresh",
        description="Refresh evidence sources",
        aliases=["reload", "r"],
    ),
    Command(
        id="bookmark",
        label="bookmark",
        description="Bookmark current path",
        aliases=["bm", "mark"],
    ),
    Command(
        id="analyze",
        label="analyze",
        description="Run full detection analysis",
        aliases=["detect", "run", "a"],
    ),
    Command(
        id="quit",
        label="quit",
        description="Exit application",
        aliases=["exit", "q"],
    ),
]


def filter_commands(query: str) -> list[Command]:
    """Filter commands by fuzzy search.

    Args:
        query: Search query (with or without leading '/')

    Returns:
        Filtered and scored list of commands
    """
    # Normalize query
    normalized = query.strip().lower().lstrip("/")
    if not normalized:
        return FORENSIC_COMMANDS

    # Score each command
    scored = []
    for cmd in FORENSIC_COMMANDS:
        if not cmd.enabled:
            continue

        score = _score_command(cmd, normalized)
        if score != float("inf"):
            scored.append((score, cmd))

    # Sort by score and return commands
    scored.sort(key=lambda x: x[0])
    return [cmd for _, cmd in scored]


def _score_command(cmd: Command, query: str) -> float:
    """Score a command against a query.

    Lower score = better match.
    Returns inf if no match.
    """
    # Collect all searchable fields
    fields = [cmd.id, cmd.label]
    if cmd.aliases:
        fields.extend(cmd.aliases)

    # Check for exact match
    for field in fields:
        if field.lower() == query:
            return 0.0

    # Check for prefix match
    for field in fields:
        if field.lower().startswith(query):
            return 1.0

    # Check for substring match
    for field in fields:
        if query in field.lower():
            return 2.0

    # Check description
    if query in cmd.description.lower():
        return 3.0

    return float("inf")


def get_command_by_id(command_id: str) -> Command | None:
    """Get command by ID.

    Args:
        command_id: Command identifier

    Returns:
        Command if found, None otherwise
    """
    for cmd in FORENSIC_COMMANDS:
        if cmd.id == command_id:
            return cmd
    return None
