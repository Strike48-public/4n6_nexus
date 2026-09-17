"""Tests for the content-addressed LLM judge cache (gallery idea #34, SFE-y3qc).

Every LLM verifier/judge call is cached under a key derived from the SHA-256 of
the CONTENT of its inputs -- ground-truth + agent finding + model id + prompt
template -- NOT from finding IDs (which collide across runs and once served a
stale verdict for a different finding). This gives:

  * bit-identical replay of an entire investigation with no API key (the cache,
    committed, is the source of truth -- temperature=0 is only near-deterministic);
  * a per-finding content-hash receipt binding the verdict to exactly the bytes
    that produced it.

The cache is pure/deterministic apart from its JSON persistence. RED-first: the
module did not exist before.
"""

import pytest

from sift_find_evil.self_correction.judge_cache import (
    JudgeCache,
    finding_receipt,
    make_cache_key,
)

_GT = {"executable": "evil.exe", "verdict": "malicious"}
_AGENT = {"finding_id": "F-001", "claim": "evil.exe executed at 03:00"}
_MODEL = "claude-opus-4-8"
_PROMPT = "You are a forensic verifier. Refute or sustain the claim."


# -- make_cache_key --------------------------------------------------------


def test_cache_key_is_deterministic():
    k1 = make_cache_key(_GT, _AGENT, _MODEL, _PROMPT)
    k2 = make_cache_key(_GT, _AGENT, _MODEL, _PROMPT)
    assert k1 == k2
    assert len(k1) == 64  # sha256 hex


def test_cache_key_is_dict_order_independent():
    # Canonical (sorted-key) serialization: the same content in a different dict
    # order is the same key.
    gt_reordered = {"verdict": "malicious", "executable": "evil.exe"}
    assert make_cache_key(_GT, _AGENT, _MODEL, _PROMPT) == make_cache_key(
        gt_reordered, _AGENT, _MODEL, _PROMPT
    )


def test_cache_key_changes_with_ground_truth():
    other_gt = {"executable": "evil.exe", "verdict": "benign"}
    assert make_cache_key(_GT, _AGENT, _MODEL, _PROMPT) != make_cache_key(
        other_gt, _AGENT, _MODEL, _PROMPT
    )


def test_cache_key_changes_with_agent_finding():
    other = {"finding_id": "F-001", "claim": "evil.exe executed at 04:00"}
    assert make_cache_key(_GT, _AGENT, _MODEL, _PROMPT) != make_cache_key(
        _GT, other, _MODEL, _PROMPT
    )


def test_cache_key_changes_with_model_id():
    assert make_cache_key(_GT, _AGENT, _MODEL, _PROMPT) != make_cache_key(
        _GT, _AGENT, "claude-sonnet-5", _PROMPT
    )


def test_cache_key_changes_with_prompt_template():
    assert make_cache_key(_GT, _AGENT, _MODEL, _PROMPT) != make_cache_key(
        _GT, _AGENT, _MODEL, _PROMPT + " Be strict."
    )


def test_delimiter_in_model_id_cannot_forge_a_collision():
    # Every keyed component is pre-hashed before joining, so a '|' inside the
    # model id cannot shift a field boundary to collide with a different tuple.
    assert make_cache_key(_GT, _AGENT, "m|x", _PROMPT) != make_cache_key(
        _GT, _AGENT, "m", "x|" + _PROMPT
    )
    # And the model id still deterministically participates in the key.
    assert make_cache_key(_GT, _AGENT, "m|x", _PROMPT) == make_cache_key(
        _GT, _AGENT, "m|x", _PROMPT
    )


def test_cache_key_does_not_depend_on_finding_id():
    # THE bug this design fixes: two findings with the SAME content but DIFFERENT
    # ids must share a key (content-addressed), so a run cannot serve a stale
    # verdict keyed by a colliding id. Here id is not part of the keyed content.
    gt_a = {"executable": "evil.exe", "verdict": "malicious"}
    agent_a = {"claim": "evil.exe executed at 03:00"}  # no id
    k = make_cache_key(gt_a, agent_a, _MODEL, _PROMPT)
    # Same content, asked twice, is the same key regardless of any external id.
    assert k == make_cache_key(dict(gt_a), dict(agent_a), _MODEL, _PROMPT)


# -- finding_receipt -------------------------------------------------------


def test_finding_receipt_is_deterministic_and_hex():
    r1 = finding_receipt(_AGENT, tool_outputs=["evt-1", "evt-2"], image_sha="abc123")
    r2 = finding_receipt(_AGENT, tool_outputs=["evt-1", "evt-2"], image_sha="abc123")
    assert r1 == r2
    assert len(r1) == 64


def test_finding_receipt_changes_with_any_input():
    base = finding_receipt(_AGENT, tool_outputs=["evt-1"], image_sha="abc123")
    assert base != finding_receipt(
        {"finding_id": "F-002"}, tool_outputs=["evt-1"], image_sha="abc123"
    )
    assert base != finding_receipt(_AGENT, tool_outputs=["evt-9"], image_sha="abc123")
    assert base != finding_receipt(_AGENT, tool_outputs=["evt-1"], image_sha="deadbeef")


# -- JudgeCache get/put ----------------------------------------------------


def test_miss_then_hit():
    cache = JudgeCache()
    key = make_cache_key(_GT, _AGENT, _MODEL, _PROMPT)
    assert cache.get(key) is None
    cache.put(key, {"outcome": "sustained"}, prompt_hash="ph1")
    assert cache.get(key) == {"outcome": "sustained"}


def test_falsy_cached_verdict_is_a_hit_not_a_miss():
    # A cached verdict that is falsy ({}), or an explicit stored None, must be
    # distinguishable from "never cached". get() returns a sentinel-safe value,
    # so use `contains` to tell a real miss from a falsy hit.
    cache = JudgeCache()
    key = make_cache_key(_GT, _AGENT, _MODEL, _PROMPT)
    cache.put(key, {}, prompt_hash="ph1")
    assert cache.contains(key) is True
    assert cache.get(key) == {}


def test_get_or_compute_computes_on_miss_then_caches():
    cache = JudgeCache()
    calls = {"n": 0}

    def compute():
        calls["n"] += 1
        return {"outcome": "dismissed"}

    key = make_cache_key(_GT, _AGENT, _MODEL, _PROMPT)
    v1 = cache.get_or_compute(key, compute, prompt_hash="ph1")
    v2 = cache.get_or_compute(key, compute, prompt_hash="ph1")
    assert v1 == v2 == {"outcome": "dismissed"}
    assert calls["n"] == 1  # computed once, served from cache the second time


def test_get_or_compute_offline_never_calls_the_judge_on_hit():
    cache = JudgeCache()
    key = make_cache_key(_GT, _AGENT, _MODEL, _PROMPT)
    cache.put(key, {"outcome": "sustained"}, prompt_hash="ph1")

    def compute():
        raise AssertionError("live judge must not be called on a cache hit")

    assert cache.get_or_compute(key, compute, prompt_hash="ph1") == {
        "outcome": "sustained"
    }


def test_put_records_prompt_hash_for_audit():
    cache = JudgeCache()
    key = make_cache_key(_GT, _AGENT, _MODEL, _PROMPT)
    cache.put(key, {"outcome": "sustained"}, prompt_hash="ph-xyz")
    assert cache.prompt_hash(key) == "ph-xyz"


# -- persistence -----------------------------------------------------------


def test_save_and_load_round_trip(tmp_path):
    path = tmp_path / "judge_cache.json"
    cache = JudgeCache(path=path)
    key = make_cache_key(_GT, _AGENT, _MODEL, _PROMPT)
    cache.put(key, {"outcome": "sustained"}, prompt_hash="ph1")
    cache.save()

    reloaded = JudgeCache(path=path)
    reloaded.load()
    assert reloaded.get(key) == {"outcome": "sustained"}
    assert reloaded.prompt_hash(key) == "ph1"


def test_load_missing_file_is_empty_not_error(tmp_path):
    cache = JudgeCache(path=tmp_path / "does_not_exist.json")
    cache.load()  # must not raise
    assert cache.get(make_cache_key(_GT, _AGENT, _MODEL, _PROMPT)) is None


def test_committed_cache_replays_offline_without_recompute(tmp_path):
    # The whole point: a committed cache reproduces the investigation with no live
    # judge available. Simulate a fresh process loading the committed file.
    path = tmp_path / "committed.json"
    producer = JudgeCache(path=path)
    key = make_cache_key(_GT, _AGENT, _MODEL, _PROMPT)
    producer.get_or_compute(key, lambda: {"outcome": "sustained"}, prompt_hash="ph1")
    producer.save()

    replay = JudgeCache(path=path)
    replay.load()

    def no_judge():
        raise AssertionError("offline replay must not call the judge")

    assert replay.get_or_compute(key, no_judge, prompt_hash="ph1") == {
        "outcome": "sustained"
    }


def test_save_is_atomic_leaves_no_tmp(tmp_path):
    path = tmp_path / "judge_cache.json"
    cache = JudgeCache(path=path)
    cache.put(make_cache_key(_GT, _AGENT, _MODEL, _PROMPT), {"o": "x"}, prompt_hash="p")
    cache.save()
    # Atomic write must not leave a stray temp file behind.
    leftovers = [p.name for p in tmp_path.iterdir() if p.name != "judge_cache.json"]
    assert leftovers == []


def test_save_without_path_raises():
    cache = JudgeCache()  # in-memory only
    cache.put(make_cache_key(_GT, _AGENT, _MODEL, _PROMPT), {"o": "x"}, prompt_hash="p")
    with pytest.raises(ValueError):
        cache.save()


# -- stale-verdict guard ---------------------------------------------------


def test_get_or_compute_recomputes_when_prompt_hash_changed(tmp_path):
    # A verdict cached under one prompt template must NOT be served for a
    # different template: the recorded prompt_hash mismatching forces recompute,
    # closing the stale-verdict hole.
    cache = JudgeCache()
    key = make_cache_key(_GT, _AGENT, _MODEL, _PROMPT)
    cache.put(key, {"outcome": "stale"}, prompt_hash="OLD")

    def compute():
        return {"outcome": "fresh"}

    result = cache.get_or_compute(key, compute, prompt_hash="NEW")
    assert result == {"outcome": "fresh"}
    assert cache.prompt_hash(key) == "NEW"
