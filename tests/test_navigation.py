"""Tests for the DFIR navigation engine + record-replay cache (SFE-bosf, PR-2 of
SFE-vq6q).

The navigation engine proposes the next forensic step for a finding. It mirrors
the content-addressed, offline-replayable design of the judge cache
(``sift_find_evil/self_correction/judge_cache.py``): a step is keyed by the
SHA-256 of the CONTENT of the request + model id + prompt template, so a committed
cache replays an investigation bit-identically with no live model and no network.

The recorded half (this PR) has TWO honesty invariants under test:
  * ZERO live calls in CI -- ``propose_next_step`` with ``live_fn=None`` (the CI
    default) never reaches out; a committed cache replays offline.
  * NO fabrication -- the deterministic proposer's ``grounded_in`` echoes only the
    finding's own ``artifact_sources``; it never invents an artifact.

RED-first: the ``sift_find_evil.navigation`` package does not exist before this PR.
"""

from __future__ import annotations

import pytest

from sift_find_evil.navigation import (
    NAV_PROMPT_TEMPLATE,
    NavigationCache,
    make_nav_key,
    propose_next_step,
)
from sift_find_evil.navigation.engine import prompt_hash

# A request shaped like PR-1's Rust NavigationRequest contract. The `finding` is a
# Finding.to_dict() subset with the fields the grounded proposer reads.
_FINDING = {
    "title": "Injected region in lsass.exe",
    "category": "process_injection",
    "severity": "critical",
    "confidence": 0.92,
    "reasoning_chain": ["malfind flagged RWX region", "no backing file"],
    "artifact_sources": ["memory:malfind", "memory:pslist"],
}
_REQUEST = {
    "category": "process_injection",
    "severity": "critical",
    "action_id": "pi_parent",
    "prompt": "Trace the parent/child process tree for this injected process.",
    "finding": _FINDING,
}
_MODEL = "matrix-studio"
_PROMPT = NAV_PROMPT_TEMPLATE


# -- make_nav_key ----------------------------------------------------------


def test_nav_key_is_deterministic_and_hex():
    k1 = make_nav_key(_REQUEST, _MODEL, _PROMPT)
    k2 = make_nav_key(_REQUEST, _MODEL, _PROMPT)
    assert k1 == k2
    assert len(k1) == 64


def test_nav_key_is_dict_order_independent():
    reordered = {
        "prompt": _REQUEST["prompt"],
        "finding": _REQUEST["finding"],
        "action_id": _REQUEST["action_id"],
        "severity": _REQUEST["severity"],
        "category": _REQUEST["category"],
    }
    assert make_nav_key(_REQUEST, _MODEL, _PROMPT) == make_nav_key(
        reordered, _MODEL, _PROMPT
    )


def test_nav_key_changes_with_request_content():
    other = dict(_REQUEST, action_id="pi_dump")
    assert make_nav_key(_REQUEST, _MODEL, _PROMPT) != make_nav_key(
        other, _MODEL, _PROMPT
    )


def test_nav_key_changes_with_model_id():
    assert make_nav_key(_REQUEST, _MODEL, _PROMPT) != make_nav_key(
        _REQUEST, "some-other-model", _PROMPT
    )


def test_nav_key_changes_with_prompt_template():
    assert make_nav_key(_REQUEST, _MODEL, _PROMPT) != make_nav_key(
        _REQUEST, _MODEL, _PROMPT + " Be terse."
    )


def test_delimiter_in_model_id_cannot_forge_a_collision():
    # Every keyed component is pre-hashed before the '|' join, so a delimiter in
    # the model id cannot shift a field boundary to collide with a different tuple.
    assert make_nav_key(_REQUEST, "m|x", _PROMPT) != make_nav_key(
        _REQUEST, "m", "x|" + _PROMPT
    )


def test_nav_key_is_content_only_no_hidden_identity():
    # Content-addressing discipline (as judge_cache): the key is a pure function of
    # the request CONTENT, so a rebuilt-from-scratch request with byte-identical
    # content keys the same and can never serve a step keyed by a per-run label.
    # The request/finding contract carries NO id field (Finding.to_dict emits none,
    # verified), so unlike judge_cache we neither receive nor strip one -- the key
    # is content-only by construction, not by scrubbing. This guards that the key
    # never quietly starts folding in something outside the request content.
    rebuilt_finding = {
        "artifact_sources": list(_FINDING["artifact_sources"]),
        "reasoning_chain": list(_FINDING["reasoning_chain"]),
        "confidence": _FINDING["confidence"],
        "severity": _FINDING["severity"],
        "category": _FINDING["category"],
        "title": _FINDING["title"],
    }
    rebuilt = {
        "finding": rebuilt_finding,
        "prompt": _REQUEST["prompt"],
        "action_id": _REQUEST["action_id"],
        "severity": _REQUEST["severity"],
        "category": _REQUEST["category"],
    }
    assert make_nav_key(rebuilt, _MODEL, _PROMPT) == make_nav_key(
        _REQUEST, _MODEL, _PROMPT
    )


# -- NavigationCache get/put -----------------------------------------------


def test_miss_then_hit():
    cache = NavigationCache()
    key = make_nav_key(_REQUEST, _MODEL, _PROMPT)
    assert cache.get(key) is None
    cache.put(key, {"summary": "trace parent"}, prompt_hash="ph1")
    assert cache.get(key) == {"summary": "trace parent"}


def test_falsy_cached_step_is_a_hit_not_a_miss():
    cache = NavigationCache()
    key = make_nav_key(_REQUEST, _MODEL, _PROMPT)
    cache.put(key, {}, prompt_hash="ph1")
    assert cache.contains(key) is True
    assert cache.get(key) == {}


def test_get_or_compute_computes_once_then_serves_cached():
    cache = NavigationCache()
    calls = {"n": 0}

    def compute():
        calls["n"] += 1
        return {"summary": "computed"}

    key = make_nav_key(_REQUEST, _MODEL, _PROMPT)
    v1 = cache.get_or_compute(key, compute, prompt_hash="ph1")
    v2 = cache.get_or_compute(key, compute, prompt_hash="ph1")
    assert v1 == v2 == {"summary": "computed"}
    assert calls["n"] == 1


def test_get_or_compute_never_calls_compute_on_hit():
    cache = NavigationCache()
    key = make_nav_key(_REQUEST, _MODEL, _PROMPT)
    cache.put(key, {"summary": "pinned"}, prompt_hash="ph1")

    def compute():
        raise AssertionError("must not compute on a cache hit")

    assert cache.get_or_compute(key, compute, prompt_hash="ph1") == {
        "summary": "pinned"
    }


def test_put_records_prompt_hash():
    cache = NavigationCache()
    key = make_nav_key(_REQUEST, _MODEL, _PROMPT)
    cache.put(key, {"summary": "x"}, prompt_hash="ph-xyz")
    assert cache.prompt_hash(key) == "ph-xyz"


def test_get_or_compute_recomputes_when_prompt_hash_changed():
    cache = NavigationCache()
    key = make_nav_key(_REQUEST, _MODEL, _PROMPT)
    cache.put(key, {"summary": "stale"}, prompt_hash="OLD")
    result = cache.get_or_compute(key, lambda: {"summary": "fresh"}, prompt_hash="NEW")
    assert result == {"summary": "fresh"}
    assert cache.prompt_hash(key) == "NEW"


# -- persistence -----------------------------------------------------------


def test_save_and_load_round_trip(tmp_path):
    path = tmp_path / "nav_cache.json"
    cache = NavigationCache(path=path)
    key = make_nav_key(_REQUEST, _MODEL, _PROMPT)
    cache.put(key, {"summary": "trace parent"}, prompt_hash="ph1")
    cache.save()

    reloaded = NavigationCache(path=path)
    reloaded.load()
    assert reloaded.get(key) == {"summary": "trace parent"}
    assert reloaded.prompt_hash(key) == "ph1"


def test_load_missing_file_is_empty_not_error(tmp_path):
    cache = NavigationCache(path=tmp_path / "nope.json")
    cache.load()  # must not raise
    assert cache.get(make_nav_key(_REQUEST, _MODEL, _PROMPT)) is None


def test_save_is_atomic_leaves_no_tmp(tmp_path):
    path = tmp_path / "nav_cache.json"
    cache = NavigationCache(path=path)
    cache.put(make_nav_key(_REQUEST, _MODEL, _PROMPT), {"s": "x"}, prompt_hash="p")
    cache.save()
    leftovers = [p.name for p in tmp_path.iterdir() if p.name != "nav_cache.json"]
    assert leftovers == []


def test_save_without_path_raises():
    cache = NavigationCache()  # in-memory only
    cache.put(make_nav_key(_REQUEST, _MODEL, _PROMPT), {"s": "x"}, prompt_hash="p")
    with pytest.raises(ValueError):
        cache.save()


# -- propose_next_step: the deterministic grounded proposer ----------------


def test_propose_offline_returns_deterministic_step_grounded_in_the_finding():
    # live_fn=None (the CI default): no live call, a deterministic step whose
    # grounding echoes ONLY the finding's own artifact_sources.
    cache = NavigationCache()
    step = propose_next_step(_REQUEST, model_id=_MODEL, cache=cache)
    assert step["source"] == "deterministic"
    assert step["grounded_in"] == _FINDING["artifact_sources"]
    # The summary references the action's own prompt text (verbatim, not invented).
    assert _REQUEST["prompt"] in step["summary"] or _REQUEST["action_id"] in str(step)


def test_proposer_never_fabricates_grounding_when_the_finding_has_none():
    # A finding carrying no artifact_sources must yield grounded_in == [] — the
    # proposer must NOT invent a source to look grounded. This is the
    # no-fabrication invariant; breaking it (appending any literal) reddens here.
    finding = {k: v for k, v in _FINDING.items() if k != "artifact_sources"}
    request = dict(_REQUEST, finding=finding)
    step = propose_next_step(request, model_id=_MODEL, cache=NavigationCache())
    assert step["grounded_in"] == []


def test_committed_cache_replays_offline_without_a_live_call(tmp_path):
    # The whole point of the recorded half: a committed cache reproduces the step
    # with NO live model available. A fresh process loads the file and replays.
    path = tmp_path / "committed_nav.json"
    producer = NavigationCache(path=path)
    propose_next_step(_REQUEST, model_id=_MODEL, cache=producer)
    producer.save()

    replay = NavigationCache(path=path)
    replay.load()

    def exploding_live(_request):
        raise AssertionError("offline replay must not call the live model")

    step = propose_next_step(
        _REQUEST, model_id=_MODEL, cache=replay, live_fn=exploding_live
    )
    assert step["source"] == "deterministic"
    assert step["grounded_in"] == _FINDING["artifact_sources"]


def test_live_fn_is_used_on_a_miss_when_provided_and_cached():
    # When a live_fn is supplied (PR-3 wires the real Matrix/Studio path), a miss
    # calls it, tags the step live, and caches it. No network here -- a fake fn.
    cache = NavigationCache()
    calls = {"n": 0}

    def fake_live(request):
        calls["n"] += 1
        return {
            "summary": "live proposal",
            "rationale": "from the model",
            "grounded_in": request["finding"]["artifact_sources"],
            "source": "live",
        }

    step = propose_next_step(_REQUEST, model_id=_MODEL, cache=cache, live_fn=fake_live)
    assert calls["n"] == 1
    assert step["source"] == "live"
    # Cached: a second call with the same request serves the cache, not the fn.
    step2 = propose_next_step(_REQUEST, model_id=_MODEL, cache=cache, live_fn=fake_live)
    assert calls["n"] == 1
    assert step2 == step


def test_prompt_hash_is_stable_for_the_template():
    assert prompt_hash(NAV_PROMPT_TEMPLATE) == prompt_hash(NAV_PROMPT_TEMPLATE)
    assert prompt_hash(NAV_PROMPT_TEMPLATE) != prompt_hash(NAV_PROMPT_TEMPLATE + " x")


# -- live-grounding validation seam (SFE-vq6q PR-3, AC #1) -----------------
# A live proposer may cite an artifact the finding does not carry. Such a
# hallucinated source must NEVER be pinned into the replay cache: before caching
# a live result, grounded_in is validated as a SUBSET of the finding's real
# artifact_sources and coerced to the finding's real sources otherwise. These
# guard that invariant -- each goes RED if the seam in propose_next_step's live
# branch is removed (the pre-PR-3 baseline returned live_fn's output verbatim).


def _fabricating_live(request):
    # A live model that invents a source the finding does not carry.
    return {
        "summary": "live proposal",
        "rationale": "from the model",
        "grounded_in": ["memory:malfind", "network:INVENTED_C2"],
        "source": "live",
    }


def test_live_fabricated_grounding_is_coerced_to_the_findings_real_sources():
    step = propose_next_step(
        _REQUEST, model_id=_MODEL, cache=NavigationCache(), live_fn=_fabricating_live
    )
    # The invented source is gone; grounding is exactly the finding's real sources.
    assert step["grounded_in"] == _FINDING["artifact_sources"]
    assert "network:INVENTED_C2" not in step["grounded_in"]
    # It is still tagged live -- provenance of the PROPOSAL is unchanged; only its
    # (untrustworthy) citation was corrected.
    assert step["source"] == "live"


def test_fabricated_live_grounding_is_never_pinned_in_the_cache():
    # The core invariant: the coerced step -- not the raw fabrication -- is what
    # gets cached, so a later hit (and any offline replay) can never serve the
    # hallucinated source. Guard-check: deleting the seam reddens here.
    cache = NavigationCache()
    propose_next_step(_REQUEST, model_id=_MODEL, cache=cache, live_fn=_fabricating_live)
    key = make_nav_key(_REQUEST, _MODEL, _PROMPT)
    pinned = cache.get(key)
    assert pinned["grounded_in"] == _FINDING["artifact_sources"]
    assert "network:INVENTED_C2" not in pinned["grounded_in"]


def test_fabricated_live_grounding_never_survives_offline_replay(tmp_path):
    # End-to-end no-fabrication guarantee: produce with a fabricating live_fn, save,
    # then replay in a fresh cache with the live model made unavailable. The pinned
    # step must carry only real sources.
    path = tmp_path / "committed_nav.json"
    producer = NavigationCache(path=path)
    propose_next_step(
        _REQUEST, model_id=_MODEL, cache=producer, live_fn=_fabricating_live
    )
    producer.save()

    replay = NavigationCache(path=path)
    replay.load()

    def exploding_live(_request):
        raise AssertionError("offline replay must not call the live model")

    step = propose_next_step(
        _REQUEST, model_id=_MODEL, cache=replay, live_fn=exploding_live
    )
    assert step["grounded_in"] == _FINDING["artifact_sources"]
    assert "network:INVENTED_C2" not in step["grounded_in"]


def test_live_grounding_that_is_a_clean_subset_is_preserved():
    # A live proposer is allowed to cite FEWER sources than the finding carries --
    # an honest subset is not fabrication and must pass through unchanged (we must
    # not over-write a legitimate, focused citation with the full list).
    def focused_live(request):
        return {
            "summary": "s",
            "rationale": "r",
            "grounded_in": ["memory:malfind"],  # a real subset of the finding's two
            "source": "live",
        }

    step = propose_next_step(
        _REQUEST, model_id=_MODEL, cache=NavigationCache(), live_fn=focused_live
    )
    assert step["grounded_in"] == ["memory:malfind"]


def test_live_grounding_preserves_model_order_for_a_multi_element_subset():
    # The docstring promises "preserving the model's order". A single-element
    # subset can't prove that -- a guard that sorted or reordered an honest 2+
    # element subset would pass a 1-element assertion. Cite both real sources in
    # the REVERSE of the finding's order; an order-preserving guard returns them
    # in the model's order, a sorting/reordering guard would not.
    reversed_real = list(reversed(_FINDING["artifact_sources"]))
    assert reversed_real != _FINDING["artifact_sources"]  # guard the guard

    def ordered_live(request):
        return {
            "summary": "s",
            "rationale": "r",
            "grounded_in": reversed_real,
            "source": "live",
        }

    step = propose_next_step(
        _REQUEST, model_id=_MODEL, cache=NavigationCache(), live_fn=ordered_live
    )
    assert step["grounded_in"] == reversed_real


def test_live_non_string_list_entries_are_treated_as_fabrication():
    # An LLM can emit non-string junk (ints, None, nested) in the list. Any such
    # entry is not one of the finding's real sources, so the whole citation is
    # untrustworthy and coerces to the finding's authoritative sources.
    def junk_live(request):
        return {
            "summary": "s",
            "rationale": "r",
            "grounded_in": ["memory:malfind", 123, None],
            "source": "live",
        }

    step = propose_next_step(
        _REQUEST, model_id=_MODEL, cache=NavigationCache(), live_fn=junk_live
    )
    assert step["grounded_in"] == _FINDING["artifact_sources"]


def test_live_non_dict_step_is_returned_unchanged():
    # The documented passthrough branch: a live_fn that returns a non-dict has
    # nothing to validate and is returned as-is (no crash, no coercion). Guards
    # the branch the docstring promises but no other test exercises.
    def scalar_live(request):
        return "not a dict"

    step = propose_next_step(
        _REQUEST, model_id=_MODEL, cache=NavigationCache(), live_fn=scalar_live
    )
    assert step == "not a dict"


def test_live_grounding_is_coerced_to_empty_when_the_finding_has_no_sources():
    # A finding with no artifact_sources cannot ground anything; a live citation is
    # by definition fabricated and must collapse to [].
    finding = {k: v for k, v in _FINDING.items() if k != "artifact_sources"}
    request = dict(_REQUEST, finding=finding)
    step = propose_next_step(
        request, model_id=_MODEL, cache=NavigationCache(), live_fn=_fabricating_live
    )
    assert step["grounded_in"] == []


def test_live_non_list_grounding_is_coerced_to_the_real_sources():
    # A malformed grounding (not a list) is not trustworthy -- normalize it to the
    # finding's real sources rather than pinning a shape-violating value.
    def malformed_live(request):
        return {
            "summary": "s",
            "rationale": "r",
            "grounded_in": "memory:malfind",  # a bare string, not a list
            "source": "live",
        }

    step = propose_next_step(
        _REQUEST, model_id=_MODEL, cache=NavigationCache(), live_fn=malformed_live
    )
    assert step["grounded_in"] == _FINDING["artifact_sources"]
