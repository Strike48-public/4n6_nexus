"""Content-addressed, offline-replayable cache for navigation steps (SFE-bosf).

A sibling of :mod:`sift_find_evil.self_correction.judge_cache`. The store shape is
intentionally the same (a hostile auditor re-checks a pinned step offline exactly
as they re-check a pinned judge verdict), but the two are NOT the same cache: the
judge key is derived from ``ground_truth + agent_finding + model + prompt`` and its
value is a "verdict"; the navigation key is derived from a navigation REQUEST and
its value is a "next step". Folding navigation into the judge cache would couple it
to the self-correction engine for no gain. Rule of three: judge is cache #1,
navigation #2 -- a shared base is worth extracting only if a third appears.

Both hash through the shared :mod:`sift_find_evil.canonical` serializer, so a
navigation key can never drift from the audit chain's / receipts' canonical form.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Callable, Optional

from ..canonical import canonical_bytes

# Key-schema version. Bump when the keyed-input set changes so entries written
# under a different content contract can never be served.
_KEY_VERSION = "nav-v1"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_nav_key(request: Any, model_id: str, prompt_template: str) -> str:
    """Content-address a navigation call: SHA-256 over its three defining inputs.

    Args:
        request: The navigation request (content only -- the whole request dict is
            canonicalized; a per-run finding id inside it is just more content and
            is deliberately NOT special-cased, so two requests that differ only by
            such an id still key identically).
        model_id: The proposing model snapshot (e.g. ``matrix-studio``).
        prompt_template: The verbatim prompt template driving the proposal.

    Returns:
        A 64-char SHA-256 hex digest. Byte-identical inputs -> identical key; any
        change to the request content, model id, or prompt -> a different key.
    """
    # Each component is pre-hashed to a fixed-width digest before the '|' join, so
    # no free-form field (e.g. a model id containing '|') can shift a boundary and
    # forge a collision with a different input tuple.
    parts = "|".join(
        (
            _KEY_VERSION,
            _sha(canonical_bytes(request)),
            _sha(model_id.encode("utf-8")),
            _sha(prompt_template.encode("utf-8")),
        )
    )
    return _sha(parts.encode("utf-8"))


class NavigationCache:
    """A content-addressed, JSON-persisted store of navigation steps.

    Each entry maps a :func:`make_nav_key` digest to ``{"step", "prompt_hash"}``.
    The recorded ``prompt_hash`` lets a replay detect that the prompt template
    changed and recompute rather than silently serving a step produced under a
    different prompt.
    """

    def __init__(self, path: Optional[Path] = None):
        """Create a cache, optionally backed by a JSON file at ``path``.

        A cache with no path is in-memory only; calling :meth:`save` on it raises.
        """
        self.path = Path(path) if path is not None else None
        self._store: dict[str, dict] = {}

    # -- lookups -------------------------------------------------------------

    def contains(self, key: str) -> bool:
        """True if ``key`` has a cached step (even a falsy one)."""
        return key in self._store

    def get(self, key: str) -> Optional[Any]:
        """Return the cached step for ``key``, or ``None`` if never cached.

        A stored falsy step (``{}``) is returned as-is; use :meth:`contains` to
        distinguish a real miss from a falsy hit.
        """
        entry = self._store.get(key)
        return entry["step"] if entry is not None else None

    def prompt_hash(self, key: str) -> Optional[str]:
        """Return the prompt-template hash recorded with ``key``'s step."""
        entry = self._store.get(key)
        return entry["prompt_hash"] if entry is not None else None

    # -- mutation ------------------------------------------------------------

    def put(self, key: str, step: Any, prompt_hash: str) -> None:
        """Store ``step`` under ``key``, recording the prompt-template hash."""
        self._store[key] = {"step": step, "prompt_hash": prompt_hash}

    def get_or_compute(
        self,
        key: str,
        compute: Callable[[], Any],
        prompt_hash: str,
    ) -> Any:
        """Return the cached step, or compute + cache it on a miss.

        A cached step is served ONLY when its recorded ``prompt_hash`` matches the
        caller's -- a prompt-template change forces a recompute so a stale step is
        never reused. On a genuine hit, ``compute`` is never called, which is what
        lets a committed cache replay offline with no live model.
        """
        entry = self._store.get(key)
        if entry is not None and entry["prompt_hash"] == prompt_hash:
            return entry["step"]
        step = compute()
        self.put(key, step, prompt_hash)
        return step

    # -- persistence ---------------------------------------------------------

    def load(self) -> None:
        """Load the store from ``path``. A missing file yields an empty cache."""
        if self.path is None or not self.path.is_file():
            return
        import json

        with self.path.open(encoding="utf-8") as handle:
            data = json.load(handle)
        # Only accept the mapping shape we wrote; anything else is ignored rather
        # than corrupting the in-memory store.
        if isinstance(data, dict):
            self._store = {
                str(k): v
                for k, v in data.items()
                if isinstance(v, dict) and "step" in v and "prompt_hash" in v
            }

    def save(self) -> None:
        """Persist the store to ``path`` atomically (temp file then replace).

        Raises:
            ValueError: if the cache has no path (in-memory only).
        """
        if self.path is None:
            raise ValueError(
                "NavigationCache has no path; cannot save an in-memory cache."
            )
        import json

        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(self._store, sort_keys=True, indent=2), encoding="utf-8"
        )
        os.replace(tmp, self.path)
