"""Coverage and completeness auditing for DFIR analysis runs.

This package distinguishes 'looked and found nothing' from 'could not
look', so that the absence of findings for an unevaluated artifact class
is never mistaken for evidence of a clean system.
"""

from sift_find_evil.coverage.audit import (
    ARTIFACT_CATALOG,
    CoverageReport,
    assess_coverage,
)

__all__ = ["ARTIFACT_CATALOG", "CoverageReport", "assess_coverage"]
