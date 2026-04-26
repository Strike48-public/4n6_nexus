"""Finding primitives shared across detectors.

The taxonomy in `categories` lets every detector tag its output with a
case-agnostic label so downstream acceptance tests can assert on *what* the
engine found without knowing *which case* the image belongs to.

The `Finding` dataclass represents a complete forensic finding with evidence,
confidence scoring, and reasoning chains. It was moved from self_correction/
to findings/ to enable clean separation between Community (core detection) and
Enterprise (self-correction) editions.
"""

from .categories import FindingCategory
from .finding import Finding

__all__ = ["FindingCategory", "Finding"]
