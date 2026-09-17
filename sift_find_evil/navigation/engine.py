"""Navigation engine: propose the next forensic step for a finding (SFE-bosf).

C-hybrid, recorded half. :func:`propose_next_step` looks the step up in a
content-addressed :class:`NavigationCache`; on a miss it calls a supplied
``live_fn`` if present, else falls back to a DETERMINISTIC, GROUNDED proposer.

In CI ``live_fn`` is always ``None`` (the default), so CI makes zero live calls
and a committed cache replays an investigation bit-identically. The gated-live
path -- routing through Prospector Studio -- is wired in PR-3 by passing a real
``live_fn``; this module imports no network/SDK dependency and never will. Every
live result passes through :func:`_validate_live_grounding` before it can be
cached, so a hallucinated citation is dropped rather than pinned into a replay.

The deterministic proposer is the no-fabrication core: it composes the next step
ONLY from strings the finding already carries (its title, category, and its own
``artifact_sources``). It never invents an artifact, a host, or a conclusion, so
its output is safe to pin and re-check offline.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Callable, Optional

from .cache import NavigationCache, make_nav_key

_LOG = logging.getLogger(__name__)

# The prompt template the (future) live proposer runs under, and the key input
# that versions the cache: change the template -> the recorded prompt_hash
# mismatches -> cached steps recompute rather than being served stale.
NAV_PROMPT_TEMPLATE = (
    "You are a DFIR navigation assistant. Given a confirmed finding and the "
    "investigator's chosen next action, propose the single next forensic step. "
    "Ground every statement in the finding's own artifact sources; never assert "
    "an artifact, host, or conclusion the finding does not already support."
)

# Per-category rationale for why the chosen action follows. Keyed on the engine's
# FindingCategory values (sift_find_evil/findings/categories.py). An absent/unknown
# category degrades to a generic, still-grounded default -- it never fabricates.
_CATEGORY_RATIONALE = {
    "process_injection": "Injected code hides its origin; the next step walks back to the injector.",
    "credential_theft": "Stolen credentials enable lateral reuse; trace where they were used next.",
    "credential_access": "Credential access precedes escalation; confirm what the access unlocked.",
    "persistence": "Persistence survives reboot; enumerate every autostart it may have seeded.",
    "lateral_movement": "Lateral movement chains hosts; follow the session to its next hop.",
    "data_exfiltration": "Exfiltration has a destination and a volume; quantify both.",
    "command_and_control": "C2 has a cadence and an endpoint; characterize the channel.",
    "timeline_tampering": "Tampered timestamps hide sequence; corroborate against an untamped source.",
    "anti_forensics": "Anti-forensics destroys evidence; look for what the wipe missed.",
    "malware_classification": "A classified sample has known behaviors; pivot on its indicators.",
    "reconnaissance": "Recon precedes action; identify what the enumeration targeted.",
    "execution": "Execution leaves parent/child and load artifacts; reconstruct the launch chain.",
}
_DEFAULT_RATIONALE = (
    "Follow the chosen action to develop this finding using its cited evidence."
)


def prompt_hash(template: str) -> str:
    """SHA-256 hex of a prompt template -- the value recorded with a cached step
    so a template change forces a recompute rather than serving a stale step."""
    return hashlib.sha256(template.encode("utf-8")).hexdigest()


def _grounding(finding: Any) -> list:
    """Echo the finding's own artifact sources -- never invent one.

    Returns the finding's ``artifact_sources`` list verbatim when present and
    well-shaped, else an empty list. The empty case is deliberate: a step with no
    grounding must SAY so (``grounded_in: []``), not manufacture a source to look
    grounded. This is the no-fabrication invariant guarded by the tests.
    """
    if not isinstance(finding, dict):
        return []
    sources = finding.get("artifact_sources")
    if isinstance(sources, list):
        return [s for s in sources if isinstance(s, str)]
    return []


def _validate_live_grounding(step: Any, finding: Any) -> dict:
    """Coerce a live step's ``grounded_in`` down to the finding's real sources.

    The no-fabrication seam for the gated-live path (SFE-vq6q PR-3): a live model
    may cite an artifact the finding does not carry. Such a source must never be
    pinned into the replay cache, so before caching we keep only the citations that
    are genuinely a SUBSET of the finding's own ``artifact_sources`` -- preserving
    the model's order and an honest, focused subset, but dropping anything invented.

    Anything untrustworthy collapses safely: a malformed (non-list) grounding, or a
    finding with no sources at all, coerces to the finding's real sources (``[]``
    when it has none). A dropped or coerced source is logged for the audit trail; a
    step that is not a dict is returned unchanged (nothing to validate).
    """
    if not isinstance(step, dict):
        return step

    real = _grounding(finding)
    claimed = step.get("grounded_in")

    if isinstance(claimed, list):
        allowed = set(real)
        # A clean citation (every entry is one of the finding's real sources) is
        # trusted verbatim -- this preserves the model's order and an honest,
        # focused subset. But the moment ANY entry is fabricated, the whole citation
        # is treated as untrustworthy and replaced with the finding's authoritative
        # sources; we do not keep the model's partial selection from a proven-
        # fabricating source (per SFE-vq6q PR-3 AC #1: "coerce to the real sources").
        dropped = [s for s in claimed if not (isinstance(s, str) and s in allowed)]
        if not dropped:
            return step
        _LOG.warning(
            "navigation: dropped %d ungrounded live citation(s) %r; coerced to the "
            "finding's real sources",
            len(dropped),
            dropped,
        )
        grounded = list(real)
    else:
        # A grounding that is not even a list is not trustworthy -- normalize to the
        # finding's real sources rather than pinning a shape-violating value.
        _LOG.warning(
            "navigation: live grounded_in was %s, not a list; coerced to the "
            "finding's real sources",
            type(claimed).__name__,
        )
        grounded = list(real)

    return {**step, "grounded_in": grounded}


def _deterministic_step(request: Any) -> dict:
    """Compose a grounded next step from only what the request already carries.

    Purely a function of the request content -> fully reproducible, so this is what
    a committed cache replays in CI. Introduces no new claim: the summary quotes the
    action's own prompt, the rationale is a fixed per-category string, and the
    grounding echoes the finding's own artifact sources.
    """
    req = request if isinstance(request, dict) else {}
    finding = req.get("finding")
    finding = finding if isinstance(finding, dict) else {}

    prompt = str(req.get("prompt", ""))
    category = str(finding.get("category", "")) or str(req.get("category", ""))
    title = str(finding.get("title", "")).strip()

    subject = f' for "{title}"' if title else ""
    summary = f"Next step{subject}: {prompt}".strip()
    rationale = _CATEGORY_RATIONALE.get(category, _DEFAULT_RATIONALE)

    return {
        "summary": summary,
        "rationale": rationale,
        "grounded_in": _grounding(finding),
        "source": "deterministic",
    }


def propose_next_step(
    request: Any,
    model_id: str,
    cache: NavigationCache,
    live_fn: Optional[Callable[[Any], dict]] = None,
) -> dict:
    """Propose the next forensic step for a navigation request.

    Cache-first: returns the pinned step on a hit (no compute, no live call). On a
    miss, computes via ``live_fn`` when supplied, else via the deterministic
    grounded proposer, then caches the result under the content-addressed key.

    Args:
        request: The navigation request (``{category, severity, action_id, prompt,
            finding}`` -- PR-1's Rust NavigationRequest contract).
        model_id: The proposing model snapshot; part of the cache key.
        cache: The :class:`NavigationCache` to read/write.
        live_fn: Optional live proposer (PR-3 passes the Studio-routed path). MUST
            be ``None`` on every CI path so CI stays hermetic. When ``None``, a
            cache miss falls back to the deterministic proposer.

    Returns:
        The step dict: ``{summary, rationale, grounded_in, source}``.
    """
    key = make_nav_key(request, model_id, NAV_PROMPT_TEMPLATE)
    ph = prompt_hash(NAV_PROMPT_TEMPLATE)

    def compute() -> dict:
        if live_fn is not None:
            # No-fabrication seam: a live citation is validated against the
            # finding's own sources BEFORE it can be pinned, so a hallucinated
            # grounding never enters the cache or an offline replay.
            req = request if isinstance(request, dict) else {}
            return _validate_live_grounding(live_fn(request), req.get("finding"))
        return _deterministic_step(request)

    return cache.get_or_compute(key, compute, prompt_hash=ph)
