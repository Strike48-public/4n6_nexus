"""DFIR navigation engine (SFE-vq6q PR-2).

Proposes the next forensic step for a finding, cache-first and offline-replayable.
The recorded/hermetic half: no live model call, no network, no SDK. The gated-live
path (routing through Prospector Studio) is wired in PR-3 via ``live_fn``.
"""

from .cache import NavigationCache, make_nav_key
from .engine import NAV_PROMPT_TEMPLATE, propose_next_step
from .recording_corpus import corpus_request, keyed_request, load_recording_corpus

__all__ = [
    "NavigationCache",
    "make_nav_key",
    "propose_next_step",
    "NAV_PROMPT_TEMPLATE",
    "load_recording_corpus",
    "corpus_request",
    "keyed_request",
]
