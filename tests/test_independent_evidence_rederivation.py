"""Move A: the falsifier re-derives against RAW EVIDENCE, not the finding narrative.

Defect this fixes: the first cut wired the EntailmentFalsifier with
``evidence_text = " ".join(finding.reasoning_chain)`` - i.e. it checked a
finding's asserted values against the finding's OWN narrative. That is a
self-consistency check, not independent verification: a hallucinated IP that the
analyst also wrote into its reasoning would pass.

The fix: re-derive asserted anchors against the RAW evidence text the detector
actually consumed (the fixture/tool output), supplied out-of-band. An anchor
absent from the raw evidence is FALSIFIED even if the finding's own narrative
mentions it. This is genuine independence.
"""

from sift_find_evil.findings import Finding, FindingCategory
from sift_find_evil.hardening import harden_findings

KEY = b"k" * 32
IMAGE = "a" * 64


def _net_finding(dst_ip, narrative_ip=None):
    """A network finding asserting dst_ip; its narrative cites narrative_ip."""
    cited = narrative_ip or dst_ip
    return Finding(
        title=f"C2 to {dst_ip}",
        description="hardcoded-ip c2",
        finding_type="behavior",
        severity="high",
        category=FindingCategory.COMMAND_AND_CONTROL,
        evidence={"dst_ip": dst_ip},
        confidence=0.9,
        reasoning_chain=[f"conversation to external IP {cited} with no DNS"],
        artifact_sources=["pcap_conversations", "pcap_dns"],
    )


def test_hallucinated_ip_killed_even_when_finding_narrative_agrees():
    # The analyst asserts AND narrates 10.9.9.9 - a self-consistent hallucination.
    # The RAW evidence only contains 203.0.113.66. Independent re-derivation must
    # still FALSIFY it, which a narrative-only check (the old bug) would not.
    f = _net_finding("10.9.9.9", narrative_ip="10.9.9.9")
    raw_evidence = {f.title: "tshark conv: endpoint_b_ip=203.0.113.66 port=4444"}
    report = harden_findings(
        [f], image_sha256=IMAGE, receipt_key=KEY, evidence_texts=raw_evidence
    )
    item = report.hardened[0]
    assert item["adversarial"]["falsifier_status"] == "falsified"
    assert item["adversarial"]["outcome"] == "dismissed"
    assert item["adversarial"]["falsifier_family"] == "entailment-rederivation"


def test_grounded_ip_survives_against_raw_evidence():
    f = _net_finding("203.0.113.66")
    raw_evidence = {f.title: "tshark conv: endpoint_b_ip=203.0.113.66 port=4444"}
    report = harden_findings(
        [f], image_sha256=IMAGE, receipt_key=KEY, evidence_texts=raw_evidence
    )
    item = report.hardened[0]
    assert item["adversarial"]["falsifier_status"] == "survived"


def test_without_raw_evidence_no_independence_claim():
    # When no raw evidence is supplied for a finding, the pipeline must NOT claim
    # independent re-derivation - it falls back (no entailment-rederivation family).
    f = _net_finding("203.0.113.66")
    report = harden_findings([f], image_sha256=IMAGE, receipt_key=KEY)
    item = report.hardened[0]
    assert item["adversarial"]["falsifier_family"] != "entailment-rederivation"


def test_adversarial_ruling_present_on_every_hardened_finding():
    # Move A also puts the adversarial pass on the SHARED pipeline (was orchestrator
    # only), so every hardened finding carries a ruling.
    findings = [_net_finding("203.0.113.66"), _net_finding("1.1.1.1")]
    raw = {
        findings[0].title: "endpoint_b_ip=203.0.113.66",
        findings[1].title: "endpoint_b_ip=1.1.1.1",
    }
    report = harden_findings(
        findings, image_sha256=IMAGE, receipt_key=KEY, evidence_texts=raw
    )
    for item in report.hardened:
        assert "adversarial" in item
        assert item["adversarial"]["outcome"] in {
            "sustained",
            "dismissed",
            "remanded",
            "flagged_human",
        }


def test_finding_count_unchanged_by_adversarial_pass():
    findings = [_net_finding("203.0.113.66"), _net_finding("1.1.1.1")]
    report = harden_findings(findings, image_sha256=IMAGE, receipt_key=KEY)
    assert report.finding_count == 2
    assert len(report.hardened) == 2


def test_pid_anchor_re_derived_against_raw_evidence():
    # A memory finding asserting a PID: the PID must appear in the raw evidence.
    f = Finding(
        title="hidden process PID 6666",
        description="dkom hidden process",
        finding_type="behavior",
        severity="high",
        category=FindingCategory.PROCESS_INJECTION,
        evidence={"pid": 6666, "process": "rootkit.exe"},
        confidence=0.9,
        reasoning_chain=["netscan socket owned by PID 6666"],
        artifact_sources=["netscan", "pslist"],
    )
    # Raw evidence contains the PID -> survives.
    ok = harden_findings(
        [f],
        image_sha256=IMAGE,
        receipt_key=KEY,
        evidence_texts={f.title: "pslist row: PID 6666 rootkit.exe"},
    )
    assert ok.hardened[0]["adversarial"]["falsifier_status"] == "survived"
    # Raw evidence lacks the PID -> hallucinated PID is falsified.
    bad = harden_findings(
        [f],
        image_sha256=IMAGE,
        receipt_key=KEY,
        evidence_texts={f.title: "pslist row: PID 1234 explorer.exe"},
    )
    assert bad.hardened[0]["adversarial"]["falsifier_status"] == "falsified"
