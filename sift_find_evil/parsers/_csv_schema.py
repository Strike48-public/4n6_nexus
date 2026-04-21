"""CSV schema-validation helper shared by the CSV-backed parsers (SFE-2lr).

The ``MFTParser``, ``PrefetchParser``, and ``EventLogParser`` all accept
``csv.DictReader``-style files and quietly tolerated rows without the columns
they actually read — producing empty/default entries instead of raising. That
masked the SFE-a1w scenario-fixture bug. This helper centralises the check so
every parser rejects a schema mismatch with a clear, single-origin error
message.

Each required-column entry can be either:
  * a plain string — the column must appear verbatim in the header, or
  * a tuple of strings — at least one of the alternatives must appear
    (used for MFT's two historical column schemes).
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Sequence, Union

RequiredColumn = Union[str, Sequence[str]]


def require_columns(
    reader: csv.DictReader,
    required: Sequence[RequiredColumn],
    csv_path: Path,
    label: str,
) -> None:
    """Raise ``ValueError`` if ``reader.fieldnames`` is missing any required column.

    The check runs after ``DictReader`` has consumed the header line, so calling
    it before the row loop is enough to reject malformed inputs without
    touching the data rows.

    Args:
        reader: A ``csv.DictReader`` whose header has already been read (this
            happens lazily on first access to ``fieldnames``, which this call
            triggers).
        required: Sequence of required column names. An element may be a tuple
            of alternatives, in which case any one match satisfies the
            requirement.
        csv_path: Path to the CSV, included in the error message to help
            operators identify the offending file.
        label: Human-readable parser label (e.g. ``"Prefetch"``) used in the
            error message.

    Raises:
        ValueError: If the CSV is empty (no header line), or if any required
            column (or alternative set) is absent from the header.
    """
    fieldnames = reader.fieldnames
    if not fieldnames:
        raise ValueError(
            f"{label} CSV has no header row (empty or malformed file): {csv_path}"
        )

    present = set(fieldnames)
    missing: list[str] = []
    for entry in required:
        if isinstance(entry, str):
            if entry not in present:
                missing.append(entry)
        else:
            if not any(alt in present for alt in entry):
                missing.append(" | ".join(entry))

    if missing:
        raise ValueError(
            f"{label} CSV {csv_path} is missing required column(s): "
            f"{', '.join(missing)}. Found columns: {sorted(present)}"
        )
