"""Security utilities for the 4n6 Nexus detection engine.

Currently provides correlation-preserving credential redaction so that
sensitive material can be scrubbed from findings, logs, and exports while
still allowing analysts to correlate repeated occurrences of the same
secret via stable HMAC-derived tags.
"""

from sift_find_evil.security.redact import RedactionError, redact_tree

__all__ = ["RedactionError", "redact_tree"]
