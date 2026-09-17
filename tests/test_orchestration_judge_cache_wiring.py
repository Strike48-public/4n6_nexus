"""Tests that the content-addressed judge cache is WIRED into the orchestrator.

The ``JudgeCache`` + ``make_cache_key`` + ``finding_receipt`` primitives landed
as unit-tested modules (SFE-y3qc / PR #76). This proves the live orchestrator
actually:

  * routes every adversarial (judge/falsifier) call through the cache, keyed by
    finding CONTENT (never the per-run ``F-NNN`` id);
  * replays an entire investigation from a COMMITTED cache with no live judge --
    every verdict served from cache, zero recomputes -- and the served verdicts
    are bit-identical to a fresh run (regression guard against verdict drift);
  * attaches a per-finding ``content_receipt`` into the chained audit log.

RED-first: before this change the orchestrator computed every verdict live and
emitted no content receipt, so the constructor took no ``judge_cache`` and
``FindingEmitted`` carried no ``content_receipt``.
"""

from __future__ import annotations

import json
from pathlib import Path


from sift_find_evil.orchestration import InvestigationOrchestrator
from sift_find_evil.self_correction.judge_cache import JudgeCache

# The committed replay cache produced by scripts/build-judge-cache.py. Loading it
# lets CI replay the whole demo investigation offline (no API key, no live judge).
_COMMITTED_CACHE = (
    Path(__file__).parent / "fixtures" / "judge_cache" / "02_ransomware.json"
)


def _run(tmp_path, cache: JudgeCache | None = None, name: str = "audit"):
    orch = InvestigationOrchestrator(
        case_id="INC-JC-001",
        audit_path=tmp_path / f"{name}.jsonl",
        judge_cache=cache,
    )
    report = orch.run_demo_investigation()
    return orch, report


def _rulings_by_key(report: dict) -> dict:
    """Map each finding's stable id -> its adversarial ruling dict.

    ``finding_id`` (F-NNN) is deterministic across runs because analyst order and
    detector output order are fixed, so it is a sound cross-run join key here.
    """
    return {item["finding_id"]: item["adversarial"] for item in report["case_findings"]}


# -- the cache is actually consulted ---------------------------------------


def test_adversarial_pass_populates_the_judge_cache(tmp_path):
    cache = JudgeCache()
    orch, report = _run(tmp_path, cache)
    assert report["case_findings"], "demo must emit findings"
    # Every finding's verdict went through the cache, so the store is populated.
    assert cache._store, "adversarial pass did not route through the judge cache"
    # First run computes each distinct judge call at least once.
    assert orch._judge_computes >= 1


def test_second_run_serves_every_verdict_from_cache_no_recompute(tmp_path):
    # Populate a cache with a first orchestrator...
    cache = JudgeCache()
    _run(tmp_path, cache, name="first")
    # ...then a FRESH orchestrator sharing that cache must recompute nothing:
    # this is the offline-replay property (no live judge is ever called).
    orch2, _ = _run(tmp_path, cache, name="second")
    assert orch2._judge_computes == 0, (
        "second run recomputed a verdict the cache already held "
        f"({orch2._judge_computes} live-judge calls on replay)"
    )


def test_verdicts_are_bit_identical_across_runs(tmp_path):
    _, r1 = _run(tmp_path, JudgeCache(), name="a")
    _, r2 = _run(tmp_path, JudgeCache(), name="b")
    assert _rulings_by_key(r1) == _rulings_by_key(r2)


# -- committed cache replays the investigation offline ---------------------


def test_committed_cache_exists():
    assert _COMMITTED_CACHE.is_file(), (
        f"committed replay cache missing at {_COMMITTED_CACHE}; "
        "regenerate with: python scripts/build-judge-cache.py"
    )


def test_committed_cache_replays_offline_with_zero_recompute(tmp_path):
    cache = JudgeCache(path=_COMMITTED_CACHE)
    cache.load()
    assert cache._store, "committed cache is empty"
    orch = InvestigationOrchestrator(
        case_id="INC-JC-REPLAY",
        audit_path=tmp_path / "replay.jsonl",
        judge_cache=cache,
    )
    report = orch.run_demo_investigation()
    # The whole investigation replayed from the committed file: no live judge.
    assert orch._judge_computes == 0, (
        "committed cache is stale/incomplete; a live judge was invoked "
        f"{orch._judge_computes} time(s). Regenerate scripts/build-judge-cache.py"
    )
    assert report["case_findings"]


def test_committed_cache_matches_a_fresh_run_bit_identical(tmp_path):
    # Guards against silent staleness: if the engine's verdicts drift, the
    # committed cache no longer matches a fresh computation and this fails.
    fresh = JudgeCache()
    _run(tmp_path, fresh, name="fresh")

    committed = JudgeCache(path=_COMMITTED_CACHE)
    committed.load()
    assert fresh._store == committed._store, (
        "committed judge cache is out of date; regenerate with "
        "python scripts/build-judge-cache.py"
    )


# -- content-addressing: key excludes the per-run finding id ---------------


def test_finding_content_projection_ignores_per_run_id_and_timestamp():
    from types import SimpleNamespace
    from datetime import datetime

    from sift_find_evil.findings.categories import FindingCategory
    from sift_find_evil.findings.finding import Finding

    a = Finding(
        title="t",
        description="d",
        finding_type="behavior",
        severity="high",
        category=FindingCategory.EXECUTION,
        evidence={"executable": "evil.exe"},
        reasoning_chain=["x"],
        artifact_sources=["mft", "prefetch"],
        detected_at=datetime(2020, 1, 1),
    )
    b = Finding(
        title="t",
        description="d",
        finding_type="behavior",
        severity="high",
        category=FindingCategory.EXECUTION,
        evidence={"executable": "evil.exe"},
        reasoning_chain=["x"],
        artifact_sources=["prefetch", "mft"],  # different ORDER, same set
        detected_at=datetime(2024, 9, 9),  # different timestamp
    )
    proj = InvestigationOrchestrator._finding_content
    assert proj(a) == proj(b), "content projection must ignore id/time/source-order"

    # The projection must still tolerate the SimpleNamespace shape the existing
    # seat-falsifier unit test feeds through _adversarial_pass (no title/etc).
    shim = SimpleNamespace(
        reasoning_chain=["a shimcache entry"],
        description="shimcache entry",
        artifact_sources=["shimcache"],
    )
    projected = proj(shim)  # must not raise
    assert projected["artifact_sources"] == ["shimcache"]


def test_finding_content_distinguishes_different_asserted_identity_values():
    """Two findings with the SAME claim/severity/sources but DIFFERENT asserted
    identity values (an IP/PID the entailment falsifier re-derives) must NOT
    collide to the same cache key.

    The adversarial verdict depends on whether each finding's OWN asserted value
    is entailed by its claim text, so a projection that drops the evidence
    identity anchors would let two findings that get DIFFERENT verdicts share a
    key -- the second served the first's wrong verdict. That is precisely the
    content-addressing failure this design exists to prevent.
    """
    from types import SimpleNamespace

    proj = InvestigationOrchestrator._finding_content
    a = SimpleNamespace(
        reasoning_chain=["outbound connection observed"],
        description="c2",
        severity="high",
        artifact_sources=["pcap"],
        evidence={"dst_ip": "1.2.3.4"},
    )
    b = SimpleNamespace(
        reasoning_chain=["outbound connection observed"],  # SAME claim
        description="c2",
        severity="high",
        artifact_sources=["pcap"],
        evidence={"dst_ip": "8.8.8.8"},  # DIFFERENT asserted IP
    )
    assert proj(a) != proj(
        b
    ), "findings asserting different identity anchors must not share a cache key"


def test_finding_content_ignores_evidence_fields_that_do_not_affect_the_verdict():
    """Only the RE-DERIVED identity anchors matter -- unrelated evidence keys
    (which never reach the falsifier) must not perturb the key, or the cache
    would miss on findings that get an identical verdict."""
    from types import SimpleNamespace

    proj = InvestigationOrchestrator._finding_content
    a = SimpleNamespace(
        reasoning_chain=["x"],
        severity="high",
        artifact_sources=["mft"],
        evidence={"dst_ip": "1.2.3.4", "note": "alpha"},
    )
    b = SimpleNamespace(
        reasoning_chain=["x"],
        severity="high",
        artifact_sources=["mft"],
        evidence={"dst_ip": "1.2.3.4", "note": "omega"},  # irrelevant field differs
    )
    assert proj(a) == proj(b)


# -- per-finding content receipt in the audit log --------------------------


def test_finding_emitted_entries_carry_a_content_receipt(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    orch = InvestigationOrchestrator(case_id="INC-JC-R", audit_path=audit_path)
    orch.run_demo_investigation()

    receipts = []
    for line in audit_path.read_text().splitlines():
        entry = json.loads(line)
        if entry.get("action") == "finding_emitted":
            details = entry.get("details", {})
            assert "content_receipt" in details, "finding logged without receipt"
            receipt = details["content_receipt"]
            assert isinstance(receipt, str) and len(receipt) == 64
            int(receipt, 16)  # must be hex
            receipts.append(receipt)

    assert receipts, "no finding_emitted entries found"
    # Distinct findings must not all share one receipt (content-sensitive).
    assert len(set(receipts)) > 1


def test_content_receipt_survives_finding_emitted_round_trip():
    from sift_find_evil.audit.models import FindingEmitted

    fe = FindingEmitted(
        finding_id="F-001",
        category="malware_execution",
        severity="high",
        confidence=0.9,
        produced_by="disk_analyst",
        content_receipt="a" * 64,
    )
    restored = FindingEmitted.from_dict(fe.to_dict())
    assert restored.content_receipt == "a" * 64


# -- backward compatibility -------------------------------------------------


def test_default_orchestrator_still_runs_without_a_cache(tmp_path):
    # No judge_cache passed: an in-memory cache is used, behavior unchanged.
    orch = InvestigationOrchestrator(
        case_id="INC-JC-DEFAULT", audit_path=tmp_path / "audit.jsonl"
    )
    report = orch.run_demo_investigation()
    assert report["case_findings"]
    outcomes = {i["adversarial"]["outcome"] for i in report["case_findings"]}
    assert "sustained" in outcomes
