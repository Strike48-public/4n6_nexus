"""Cross-artifact timeline correlation.

Provides stdlib-only (sqlite3) time-windowed correlation across forensic
artifact sources, plus surfacing of UNRESOLVED contradictions for a human or
LLM verifier to adjudicate. Nothing here auto-resolves a contradiction.
"""

from .hidden_process import detect_hidden_linux_processes
from .cross_source import (
    CrossSourceDiscrepancy,
    CrossSourceInput,
    DiscrepancyType,
    correlate_cross_source,
    names_reconcile,
    normalize_eprocess_name,
)
from .sql_artifact import ArtifactCorroboration, correlate_artifacts
from .sql_timeline import (
    Correlation,
    RuleRejectedError,
    correlate_timeline,
    find_co_occurrences,
    validate_rule_string,
)

__all__ = [
    "Correlation",
    "RuleRejectedError",
    "correlate_timeline",
    "find_co_occurrences",
    "validate_rule_string",
    "CrossSourceDiscrepancy",
    "CrossSourceInput",
    "DiscrepancyType",
    "correlate_cross_source",
    "names_reconcile",
    "normalize_eprocess_name",
    "ArtifactCorroboration",
    "correlate_artifacts",
    "detect_hidden_linux_processes",
]
