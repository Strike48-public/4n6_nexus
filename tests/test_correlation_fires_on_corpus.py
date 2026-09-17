"""SFE-1fkn: same-actor cross-source correlation FIRES on the real corpus.

The hostile audit reverted correlation 3->2 because the capability was wired into
the shared hardening pipeline (and unit-tested) but produced ZERO output on the
16 real recall scenarios: no fixture had a same-actor multi-source overlap, and
two latent bugs made the join impossible even if one did:

  1. timeline timestamps carry a `` UTC`` suffix, which SQLite ``julianday()``
     cannot parse -> the time-window predicate is NULL -> never matches.
  2. the actor join was raw-string equality, so a memory-truncated / path-form
     process name would not equal its full-name counterpart.

This proves the fix end-to-end: 12_memory_intrusion's injected ``powershell.exe``
(malfind, memory) is the SAME actor beaconing to C2 (netscan, memory), so a real
recall run now emits >=1 correlation. F1 is unaffected (correlation is additive
HardeningReport metadata; the overlap is a true artifact, not a new finding).
"""

from __future__ import annotations

from pathlib import Path

import tests.scenario_harness as h
from sift_find_evil.correlation.assemble import _timeline_events
from sift_find_evil.hardening import harden_findings
from sift_find_evil.findings import Finding, FindingCategory

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _memory_scenario() -> h.ScenarioExpectation:
    for expectation in h.discover_scenarios(_REPO_ROOT):
        if expectation.name == "12_memory_intrusion":
            return expectation
    raise AssertionError("12_memory_intrusion scenario not found")


# --- end-to-end: correlation fires on the real scored corpus ---------------


def test_memory_scenario_emits_at_least_one_cross_source_correlation() -> None:
    result = h.run_scenario(_memory_scenario())
    assert result.hardening.correlations, (
        "expected >=1 cross-source correlation on the real recall corpus "
        "(same actor seen by malfind and netscan)"
    )


def test_correlation_links_malfind_and_netscan_on_the_injected_process() -> None:
    result = h.run_scenario(_memory_scenario())
    sources = {
        frozenset((c["a"]["source"], c["b"]["source"]))
        for c in result.hardening.correlations
    }
    assert frozenset(("malfind", "netscan")) in sources, (
        "expected the injected process (malfind) to correlate with its C2 "
        f"connection (netscan); saw source pairs {sources}"
    )


def test_memory_scenario_f1_is_unaffected_by_the_overlap() -> None:
    # The correlation overlap must not add/drop a scored finding.
    result = h.run_scenario(_memory_scenario())
    assert len(result.false_positives) == 0
    assert len(result.false_negatives) == 0
    assert result.findings_count == 27


# --- mutation guard: without the overlap, correlation goes to zero ---------


def test_stripping_the_overlap_actor_yields_zero_correlations() -> None:
    # If the two sources named DIFFERENT actors (the pre-fix state), the join
    # must not fire. This guards that the correlation is genuine, not spurious.
    result = h.run_scenario(_memory_scenario())
    findings = result.findings
    # Rewrite every netscan timeline actor to a unique non-overlapping name.
    for finding in findings:
        tl = (finding.evidence or {}).get("timeline")
        if isinstance(tl, dict) and tl.get("source") == "netscan":
            tl["actor"] = "unrelated_stub.exe"
    report = harden_findings(
        findings,
        image_sha256="a" * 64,
        receipt_key=b"k" * 32,
    )
    assert (
        report.correlations == []
    ), "correlation must vanish once the shared actor is removed"


# --- unit: hardening timeline normalization (the two latent-bug fixes) -----


def _tl_finding(source: str, actor: str, ts: str, etype: str) -> Finding:
    return Finding(
        title=f"{source}:{actor}",
        description="d",
        finding_type="behavior",
        severity="high",
        category=FindingCategory.PROCESS_INJECTION,
        evidence={
            "timeline": {
                "ts": ts,
                "source": source,
                "actor": actor,
                "target": "",
                "type": etype,
            }
        },
    )


def test_timeline_events_strip_utc_suffix_so_julianday_can_parse() -> None:
    events = _timeline_events(
        [_tl_finding("malfind", "evil.exe", "2026-04-22 10:05:10.000000 UTC", "x")]
    )
    assert len(events) == 1
    assert "UTC" not in events[0]["ts"]
    assert events[0]["ts"] == "2026-04-22 10:05:10.000000"


def test_timeline_events_canonicalize_the_actor_join_key() -> None:
    # A memory-truncated name and its full form must produce the SAME actor key,
    # or a genuine same-process overlap across sources would not join.
    truncated = _timeline_events(
        [_tl_finding("malfind", "crypt_engine.ex", "2026-04-22T10:00:00", "x")]
    )
    full = _timeline_events(
        [_tl_finding("netscan", r"C:\a\crypt_engine.exe", "2026-04-22T10:00:00", "y")]
    )
    assert truncated[0]["actor"] == full[0]["actor"]


def test_aggregate_surfaces_a_nonzero_cross_source_correlation_count() -> None:
    # The report must SHOW correlation is load-bearing on the real corpus, not
    # only exercised by a unit test (the audit's exact complaint).
    results = [h.run_scenario(s) for s in h.discover_scenarios(_REPO_ROOT)]
    agg = h.aggregate(results)
    assert agg["cross_source_correlations"] >= 1
    # And it stays an overlay: P/R/F1 remain perfect.
    assert agg["f1"] == 1.0
    assert agg["false_positives"] == 0 and agg["false_negatives"] == 0


def test_utc_suffixed_same_actor_events_correlate_end_to_end() -> None:
    # The regression the audit found: two sources, same actor, `` UTC`` suffix.
    # Before the fix julianday() returned NULL and this produced zero.
    findings = [
        _tl_finding("malfind", "evil.exe", "2026-04-22 10:00:00.000000 UTC", "inject"),
        _tl_finding("netscan", "evil.exe", "2026-04-22 10:00:01.000000 UTC", "c2"),
    ]
    report = harden_findings(findings, image_sha256="a" * 64, receipt_key=b"k" * 32)
    assert report.correlations, "UTC-suffixed same-actor events must correlate"
