"""Finding primitives shared across detectors.

The taxonomy in `categories` lets every detector tag its output with a
case-agnostic label so downstream acceptance tests can assert on *what* the
engine found without knowing *which case* the image belongs to.
"""

from .categories import FindingCategory

__all__ = ["FindingCategory"]
