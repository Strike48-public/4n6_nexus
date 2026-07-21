"""Correlation-preserving credential redaction.

This module scrubs credential material from arbitrary dict/list/scalar trees.
Each redacted secret is replaced by an HMAC-tagged placeholder of the form
``[REDACTED:<tag>]`` where ``tag`` is derived from the matched value with a
caller-supplied key. Because the tag is deterministic for a given key, the
same secret always maps to the same placeholder, preserving correlation
across findings while the plaintext value is discarded.

Hard guards protect against pathological inputs:

* ``MAX_DEPTH`` bounds recursion depth (fail-closed on deeper trees).
* ``MAX_VALUE_BYTES`` caps the size of any single scalar considered.
* ``MAX_REGEX_INPUT_BYTES`` short-circuits large values to an ``OVERSIZE``
  tag without running regexes (ReDoS mitigation).
* Keys shorter than ``MIN_KEY_BYTES`` are rejected with ``ValueError``.
* Any uncaught error during redaction raises :class:`RedactionError`
  rather than risking emission of unredacted output (fail-closed).
"""

import hmac
import re
from hashlib import sha256
from typing import Any, Final, Pattern

MAX_DEPTH: Final[int] = 32
MAX_VALUE_BYTES: Final[int] = 1_000_000
MAX_REGEX_INPUT_BYTES: Final[int] = 65_536
MIN_KEY_BYTES: Final[int] = 32
TAG_LEN: Final[int] = 16

OVERSIZE_PLACEHOLDER: Final[str] = "[REDACTED:OVERSIZE]"


class RedactionError(Exception):
    """Raised when redaction fails, guaranteeing no unredacted output leaks."""


# Ordered credential patterns. Each is applied against candidate string values.
# Patterns intentionally avoid unbounded backtracking constructs to limit
# ReDoS exposure; the MAX_REGEX_INPUT_BYTES guard is the primary defense.
_CREDENTIAL_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    # PEM private-key blocks (multiline).
    re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        r".*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        re.DOTALL,
    ),
    # AWS access key IDs.
    re.compile(r"AKIA[0-9A-Z]{16}"),
    # Bearer tokens.
    re.compile(r"Bearer\s+[A-Za-z0-9._\-]{16,}"),
    # key=value style assignments for common secret-bearing keys.
    re.compile(
        r"(?i)(?:api[_-]?key|secret|password|passwd|token)\s*[=:]\s*[^\s\"']{6,}",
    ),
    # Long hex secrets (32+ hex chars).
    re.compile(r"\b[0-9a-fA-F]{32,}\b"),
)


def _tag(key: bytes, matched: str) -> str:
    """Return a stable HMAC-SHA256 tag placeholder for a matched secret.

    Args:
        key: Caller-supplied HMAC key (already validated for length).
        matched: The secret substring that matched a credential pattern.

    Returns:
        A placeholder string ``[REDACTED:<tag>]`` where ``tag`` is the first
        ``TAG_LEN`` hex characters of ``HMAC-SHA256(key, matched)``.
    """
    digest = hmac.new(key, matched.encode("utf-8", "surrogatepass"), sha256).hexdigest()
    return f"[REDACTED:{digest[:TAG_LEN]}]"


def _redact_string(value: str, key: bytes) -> str:
    """Redact all credential matches within a single string value.

    Values exceeding ``MAX_REGEX_INPUT_BYTES`` are replaced wholesale with the
    oversize placeholder without running any regex (ReDoS guard).
    """
    if len(value.encode("utf-8", "surrogatepass")) > MAX_REGEX_INPUT_BYTES:
        return OVERSIZE_PLACEHOLDER

    redacted = value
    for pattern in _CREDENTIAL_PATTERNS:
        redacted = pattern.sub(
            lambda match: _tag(key, match.group(0)),
            redacted,
        )
    return redacted


def _redact_node(node: Any, key: bytes, depth: int) -> Any:
    """Recursively redact a node, returning a new (never mutated) structure."""
    if depth > MAX_DEPTH:
        raise RedactionError(f"maximum redaction depth {MAX_DEPTH} exceeded")

    if isinstance(node, dict):
        return {k: _redact_node(v, key, depth + 1) for k, v in node.items()}

    if isinstance(node, (list, tuple)):
        redacted = [_redact_node(item, key, depth + 1) for item in node]
        return type(node)(redacted) if isinstance(node, tuple) else redacted

    if isinstance(node, str):
        if len(node.encode("utf-8", "surrogatepass")) > MAX_VALUE_BYTES:
            return OVERSIZE_PLACEHOLDER
        return _redact_string(node, key)

    # Non-string scalars (int, float, bool, None) pass through unchanged.
    return node


def redact_tree(obj: Any, key: bytes) -> Any:
    """Redact credentials from an arbitrary dict/list/scalar tree.

    The input is never mutated; a new structure is returned. Repeated
    occurrences of the same secret map to identical placeholders so analysts
    can still correlate them.

    Args:
        obj: Arbitrary tree of dicts, lists, tuples, and scalars.
        key: HMAC key used to derive correlation tags. Must be at least
            ``MIN_KEY_BYTES`` bytes.

    Returns:
        A redacted copy of ``obj``.

    Raises:
        ValueError: If ``key`` is shorter than ``MIN_KEY_BYTES`` bytes.
        RedactionError: If redaction fails for any reason (fail-closed).
    """
    if not isinstance(key, (bytes, bytearray)) or len(key) < MIN_KEY_BYTES:
        raise ValueError(f"redaction key must be at least {MIN_KEY_BYTES} bytes")

    key_bytes = bytes(key)
    try:
        return _redact_node(obj, key_bytes, depth=0)
    except RedactionError:
        raise
    except Exception as exc:  # noqa: BLE001 - fail-closed by design
        raise RedactionError("redaction failed; refusing to emit output") from exc
