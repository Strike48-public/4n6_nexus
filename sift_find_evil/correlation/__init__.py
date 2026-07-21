"""Cross-artifact timeline correlation.

Provides stdlib-only (sqlite3) time-windowed correlation across forensic
artifact sources, plus surfacing of UNRESOLVED contradictions for a human or
LLM verifier to adjudicate. Nothing here auto-resolves a contradiction.
"""

from .sql_timeline import (
    Correlation,
    RuleRejectedError,
    correlate_timeline,
    find_contradictions,
    validate_rule_string,
)

__all__ = [
    "Correlation",
    "RuleRejectedError",
    "correlate_timeline",
    "find_contradictions",
    "validate_rule_string",
]
