"""Content-addressed LLM verdict/judge cache (SFE-y3qc, gallery idea #34).

Every LLM verifier/judge call is cached under a key derived from the SHA-256 of
the CONTENT of its inputs -- the ground-truth record, the agent finding, the
model id, and the prompt template -- NOT from a finding ID. Finding IDs (``F-001``)
are per-run positional labels that collide across runs; keying a cache by them
once served a verdict computed for a *different* finding. Content-addressing makes
that class of bug structurally impossible: two calls collide only when their
inputs are byte-identical.

Why a committed cache and not just ``temperature=0``: a zero-temperature model is
near-deterministic, not bit-deterministic, so it cannot guarantee an exact rerun.
The committed cache IS the guarantee -- with it, an entire investigation replays
bit-identically in CI with no API key and no live judge.

Two products:

  * ``make_cache_key`` -- the content-addressed key for a judge call.
  * ``finding_receipt`` -- a per-finding content hash binding a verdict to exactly
    the finding bytes + tool outputs + evidence image that produced it.

Both hash through the shared :mod:`sift_find_evil.canonical` serializer, so a
cache key can never drift from the audit chain's / receipts' canonical form.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Callable, Optional

from ..canonical import canonical_bytes

# Cache-key schema version. Bump when the keyed-input set changes so old cache
# entries (which encoded a different content contract) can never be served.
_KEY_VERSION = "v1"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_cache_key(
    ground_truth: Any,
    agent_finding: Any,
    model_id: str,
    prompt_template: str,
) -> str:
    """Content-address a judge call: SHA-256 over its four defining inputs.

    Args:
        ground_truth: The ground-truth / reference record shown to the judge.
        agent_finding: The analyst finding being judged (content only -- do NOT
            include a per-run finding id; that is what collides across runs).
        model_id: The judging model snapshot (e.g. ``claude-opus-4-8``).
        prompt_template: The verbatim prompt template driving the judge.

    Returns:
        A 64-char SHA-256 hex digest. Byte-identical inputs -> identical key;
        any change to any input -> a different key.
    """
    # Every component is pre-hashed to a fixed-width digest before joining, so no
    # free-form field (e.g. a model id containing the '|' delimiter) can shift a
    # boundary and forge a collision with a different input tuple.
    parts = "|".join(
        (
            _KEY_VERSION,
            _sha(canonical_bytes(ground_truth)),
            _sha(canonical_bytes(agent_finding)),
            _sha(model_id.encode("utf-8")),
            _sha(prompt_template.encode("utf-8")),
        )
    )
    return _sha(parts.encode("utf-8"))


def finding_receipt(
    finding_content: Any,
    tool_outputs: Any,
    image_sha: str,
) -> str:
    """A per-finding content-hash receipt: SHA-256 over its grounding bytes.

    Binds a finding to exactly the content, the tool outputs it cites, and the
    evidence image it was derived from. Any post-hoc edit to any of the three
    changes the receipt, so a tampered or hallucinated finding cannot keep a
    receipt that still verifies. Stored in the (chained) audit log.

    Args:
        finding_content: The finding body (any JSON-serializable value).
        tool_outputs: The tool outputs/ids the finding cites.
        image_sha: SHA-256 of the evidence image the run analyzed.

    Returns:
        A 64-char SHA-256 hex digest over the canonical encoding of all three.
    """
    return _sha(
        canonical_bytes(
            {
                "finding": finding_content,
                "tool_outputs": tool_outputs,
                "image_sha": image_sha,
            }
        )
    )


class JudgeCache:
    """A content-addressed, JSON-persisted store of judge verdicts.

    Each entry maps a ``make_cache_key`` digest to ``{"verdict", "prompt_hash"}``.
    The recorded ``prompt_hash`` lets a replay detect that the prompt template
    changed and recompute rather than silently serving a verdict produced under a
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
        """True if ``key`` has a cached verdict (even a falsy one)."""
        return key in self._store

    def get(self, key: str) -> Optional[Any]:
        """Return the cached verdict for ``key``, or ``None`` if never cached.

        A stored falsy verdict (``{}``) is returned as-is; use :meth:`contains`
        to distinguish a real miss from a falsy hit.
        """
        entry = self._store.get(key)
        return entry["verdict"] if entry is not None else None

    def prompt_hash(self, key: str) -> Optional[str]:
        """Return the prompt-template hash recorded with ``key``'s verdict."""
        entry = self._store.get(key)
        return entry["prompt_hash"] if entry is not None else None

    # -- mutation ------------------------------------------------------------

    def put(self, key: str, verdict: Any, prompt_hash: str) -> None:
        """Store ``verdict`` under ``key``, recording the prompt-template hash."""
        self._store[key] = {"verdict": verdict, "prompt_hash": prompt_hash}

    def get_or_compute(
        self,
        key: str,
        compute: Callable[[], Any],
        prompt_hash: str,
    ) -> Any:
        """Return the cached verdict, or compute + cache it on a miss.

        A cached verdict is served ONLY when its recorded ``prompt_hash`` matches
        the caller's -- a prompt-template change forces a recompute so a stale
        verdict is never reused. On a genuine hit, ``compute`` is never called,
        which is what lets a committed cache replay offline with no live judge.
        """
        entry = self._store.get(key)
        if entry is not None and entry["prompt_hash"] == prompt_hash:
            return entry["verdict"]
        verdict = compute()
        self.put(key, verdict, prompt_hash)
        return verdict

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
                if isinstance(v, dict) and "verdict" in v and "prompt_hash" in v
            }

    def save(self) -> None:
        """Persist the store to ``path`` atomically (temp file then replace).

        Raises:
            ValueError: if the cache has no path (in-memory only).
        """
        if self.path is None:
            raise ValueError("JudgeCache has no path; cannot save an in-memory cache.")
        import json

        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(self._store, sort_keys=True, indent=2), encoding="utf-8"
        )
        os.replace(tmp, self.path)
