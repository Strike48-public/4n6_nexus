"""The frozen navigation-request corpus for the record-replay cache (SFE-9v95).

The corpus is a FIXED, committed set of navigation requests
(``{category, severity, action_id, prompt, finding}`` -- PR-1's Rust
NavigationRequest contract) that both the out-of-band recorder
(``scripts/record-navigation-cache.py``) and the offline replay test load
byte-identically.

Why a frozen snapshot and not a live re-derivation: :func:`make_nav_key`
content-addresses the WHOLE request, finding included, and the engine's real
findings carry a wall-clock ``detected_at`` (top-level and inside each
``contradiction``) that changes every run. So a finding derived fresh at replay
time would key differently from one captured at record time and the committed
cache would always miss. The corpus is therefore captured once from the real
engine, its volatile ``detected_at`` stripped, and pinned here as JSON -- a
fixture, exactly like ``tests/fixtures/judge_cache/02_ransomware.json``. The
findings are otherwise the engine's verbatim output (real titles, real
``artifact_sources``, real reasoning chains), so a recorded step grounds in the
same evidence a live GUI click would hand the Navigator.

The action_id/prompt pairs mirror the primary action per category in
``ui/crates/tools/src/registry/actions.rs::suggested_actions`` (the source of
truth for what the GUI's suggested-action buttons emit).
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

# The committed corpus asset lives beside this module so it ships with the
# package (importable regardless of cwd) and is reviewable in git.
_CORPUS_PATH = Path(__file__).with_name("recording_corpus.json")


@lru_cache(maxsize=1)
def load_recording_corpus() -> list[dict[str, Any]]:
    """Return the frozen navigation-request corpus as a list of request dicts.

    Each entry is a full navigation request plus a ``scenario`` label:
    ``{scenario, category, severity, action_id, prompt, finding}``. The list is
    cached so repeated callers (recorder + tests) share one parse and one set of
    dict objects. Callers MUST NOT mutate the returned structures.
    """
    with _CORPUS_PATH.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list) or not data:
        raise ValueError(
            f"navigation recording corpus at {_CORPUS_PATH} is empty/invalid"
        )
    # Validate each entry's shape up front: a malformed corpus should fail loudly
    # here, not partway through a (billed) live recording run.
    required = ("scenario", "category", "severity", "action_id", "prompt", "finding")
    for i, entry in enumerate(data):
        if not isinstance(entry, dict):
            raise ValueError(f"corpus entry {i} at {_CORPUS_PATH} is not an object")
        missing = [k for k in required if k not in entry]
        if missing:
            raise ValueError(
                f"corpus entry {i} at {_CORPUS_PATH} missing keys: {missing}"
            )
    return data


def corpus_request(entry: dict[str, Any]) -> dict[str, Any]:
    """Project a corpus entry down to the base request contract fields.

    Strips the ``scenario`` label (a corpus-only annotation, never part of the
    request identity), returning ``{category, severity, action_id, prompt,
    finding}``. This is the CLIENT-side contract; for the exact bytes the SERVER
    keys on (which also carry ``model_id``), use :func:`keyed_request`.
    """
    return {
        k: entry[k] for k in ("category", "severity", "action_id", "prompt", "finding")
    }


def keyed_request(entry: dict[str, Any], model_id: str) -> dict[str, Any]:
    """Return the request dict EXACTLY as the server content-addresses it.

    ``handle_navigate_request`` keys on every request param except ``live_answer``
    -- and that param set INCLUDES ``model_id`` (the Rust GUI sends
    ``model_id="matrix-studio"`` on the live path). So the recorded key and the
    replay lookup must both fold ``model_id`` into the request, or a recorded live
    step keyed without it would never be served. Recorder and replay test both go
    through here so they can never drift from the server's shaping.
    """
    return {**corpus_request(entry), "model_id": model_id}
