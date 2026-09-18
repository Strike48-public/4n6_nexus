"""Independent challenger activates from each finding's own source_span (SFE-fibx.6).

The shipping ``analyze --harden`` path called ``harden_findings`` WITHOUT
``evidence_texts``, so ``_adversarial_ruling`` always fell to the null falsifier
and every finding was trivially SURVIVED -- the "adversarial ruling" in the
hardened report challenged nothing (a vacuous pass, same class as the RFC-5737
bug in SFE-fibx.3).

The fix: when a caller supplies no ``evidence_texts`` entry for a finding,
``harden_findings`` falls back to that finding's own ``evidence['source_span']``
(the exact tool-output record it was derived from, SFE-fsno). This activates the
already-built independent ``EntailmentFalsifier`` on the shipping path.

Non-vacuousness (the load-bearing property): each finding is challenged against
ITS OWN span, never a merged corpus blob. A correctly-attributed anchor is in its
own span (SURVIVES); a hallucinated or misattributed anchor is absent from its own
span (FALSIFIED -> dismissed). A merged-blob check would pass vacuously because
every anchor appears somewhere in the corpus.
"""

from sift_find_evil.findings import Finding, FindingCategory
from sift_find_evil.hardening import harden_findings

KEY = b"k" * 32
IMAGE = "a" * 64


def _net_finding(foreign_addr="203.0.113.9", source_span=None, sources=None):
    """A single-source network finding asserting a foreign_addr anchor.

    A single artifact source is deliberate: with >=2 corroborating sources the
    adjudicator sustains on corroboration and the falsifier outcome is masked, so
    the independence signal would not be observable. One source isolates it.
    """
    evidence = {"foreign_addr": foreign_addr}
    if source_span is not None:
        evidence["source_span"] = source_span
    return Finding(
        title=f"C2 to {foreign_addr}",
        description="hardcoded-IP C2 candidate",
        finding_type="indicator",
        severity="high",
        category=FindingCategory.COMMAND_AND_CONTROL,
        evidence=evidence,
        confidence=0.85,
        reasoning_chain=[f"TCP conversation to {foreign_addr} with no DNS lookup"],
        artifact_sources=sources or ["pcap"],
    )


def _harden(findings, **kwargs):
    """Harden and return the JSON-serializable report dict (the CLI-visible shape)."""
    return harden_findings(
        findings, image_sha256=IMAGE, receipt_key=KEY, **kwargs
    ).to_dict()


def _rule(report, index=0):
    return report["hardened"][index]["adversarial"]


def test_hallucinated_anchor_absent_from_own_span_is_dismissed():
    """The anchor the finding asserts does NOT appear in its own source_span ->
    the independent falsifier refutes it -> dismissed. Before this fix the
    shipping path passed no evidence_texts, so it SURVIVED vacuously."""
    f = _net_finding(
        foreign_addr="203.0.113.9",
        # The row the finding was "derived from" mentions a DIFFERENT address:
        # the asserted anchor is not re-derivable from its own provenance.
        source_span='{"foreign_addr": "198.51.100.2", "pid": "1044"}',
    )
    report = _harden([f])
    rule = _rule(report)
    assert rule["outcome"] == "dismissed"
    assert rule["falsifier_status"] == "falsified"
    # Independence was actually claimed (not the null-falsifier fallback).
    assert rule["falsifier_family"] == "entailment-rederivation"
    assert rule["architectural_distance"] == 1.0


def test_correctly_attributed_anchor_in_its_span_survives():
    """The asserted anchor IS present in the finding's own span -> re-derivable ->
    the falsifier cannot kill it. A single-source finding survives-but-uncorroborated
    is remanded (not dismissed): the point here is it is NOT falsified."""
    f = _net_finding(
        foreign_addr="203.0.113.9",
        source_span='{"foreign_addr": "203.0.113.9", "pid": "1044"}',
    )
    report = _harden([f])
    rule = _rule(report)
    assert rule["falsifier_status"] == "survived"
    assert rule["outcome"] != "dismissed"
    assert rule["falsifier_family"] == "entailment-rederivation"


def test_explicit_evidence_texts_still_wins_over_span_fallback():
    """A caller that DOES supply evidence_texts keeps control: the explicit text is
    used, not the finding's span. Here the span would survive but the explicit text
    omits the anchor -> dismissed, proving the explicit map took precedence."""
    f = _net_finding(
        foreign_addr="203.0.113.9",
        source_span='{"foreign_addr": "203.0.113.9"}',  # would survive
    )
    report = _harden(
        [f],
        evidence_texts={f.title: "an unrelated span with no matching anchor"},
    )
    assert _rule(report)["outcome"] == "dismissed"


def test_no_span_and_no_evidence_text_stays_null_falsifier():
    """A finding with neither a span nor an explicit evidence text claims NO
    independence (honest): it must not be dismissed for lack of a signal, and the
    family must stay the null fallback rather than falsely claim re-derivation."""
    f = _net_finding(foreign_addr="203.0.113.9", source_span=None)
    report = _harden([f])
    rule = _rule(report)
    assert rule["outcome"] != "dismissed"
    assert rule["falsifier_family"] != "entailment-rederivation"


def test_span_fallback_does_not_mutate_the_scored_finding_set():
    """Additive-overlay invariant: activating the falsifier never adds, drops, or
    mutates a finding, so F1 is unaffected even when a finding is dismissed in the
    hardened ruling."""
    f = _net_finding(
        foreign_addr="203.0.113.9",
        source_span='{"foreign_addr": "198.51.100.2"}',  # -> dismissed ruling
    )
    report = _harden([f])
    assert report["finding_count"] == 1
    assert len(report["hardened"]) == 1
    # The scored finding is unchanged: its anchor and identity survive the dismissal.
    assert report["hardened"][0]["finding"]["evidence"]["foreign_addr"] == "203.0.113.9"
