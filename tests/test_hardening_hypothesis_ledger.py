"""The hardened report carries the self-correction retraction ledger (SFE-fibx.1).

The hypothesis-ledger candidate-elimination trail (a SUPPORTS->REFUTES retraction
logged as an unforgeable ``SelfCorrection``) was produced ONLY by the demo
orchestrator (``run_demo_investigation``) and never reached any shipping surface:
``HardeningReport`` carried no ledger, so ``analyze --harden`` — the custody
artifact a human reads — showed nothing of the engine's self-correction.

This wires the same read-only overlay onto the shipping ``harden_findings`` path,
so a retraction is a first-class field of the hardened report. The overlay never
touches ``evidence['executable']`` (the detection scoring key), so F1 is
unaffected.

RED-first: before this change ``HardeningReport`` has no ``hypothesis_ledger``.
"""

from sift_find_evil.findings import Finding, FindingCategory
from sift_find_evil.hardening import harden_findings
from sift_find_evil.self_correction.confidence_scorer import Resolution

KEY = b"k" * 32
IMAGE = "a" * 64


def _confirmed_finding(title="evil.exe executed"):
    """A normal true-positive finding: no exonerating resolution -> stays SUPPORTS."""
    return Finding(
        title=title,
        description="d",
        finding_type="indicator",
        severity="high",
        category=FindingCategory.EXECUTION,
        evidence={"executable": "evil.exe"},
        confidence=0.9,
        reasoning_chain=["a socket to 1.2.3.4 was observed"],
        artifact_sources=["MFT", "Prefetch"],
    )


def _exonerated_finding(title="8.8.8.8 c2 beacon"):
    """A finding the engine EXONERATED (benign-infra direct IP) -> SUPPORTS->REFUTES.

    Mirrors the engine's real exoneration (self_correction/engine.py:585,
    ``known_benign_direct_ip_infrastructure``): a Resolution flagged
    ``is_exonerating=True`` is the sole trigger the ledger reads.
    """
    return Finding(
        title=title,
        description="beacon to a direct IP later cleared as benign infrastructure",
        finding_type="indicator",
        severity="high",
        category=FindingCategory.COMMAND_AND_CONTROL,
        evidence={"foreign_addr": "8.8.8.8"},
        confidence=0.6,
        reasoning_chain=["periodic connection to 8.8.8.8"],
        artifact_sources=["PCAP"],
        resolutions=[
            Resolution(
                contradiction_type="direct_ip_no_dns",
                resolution_method="known_benign_direct_ip_infrastructure",
                confidence_recovery=0.0,
                evidence={"note": "8.8.8.8 is a well-known public DNS resolver"},
                is_exonerating=True,
            )
        ],
    )


def test_hardened_report_carries_a_hypothesis_ledger():
    report = harden_findings(
        [_confirmed_finding()], image_sha256=IMAGE, receipt_key=KEY
    )
    ledger = report.to_dict()["hypothesis_ledger"]
    # A confirmed-only run still emits the ledger structure (empty trail is honest,
    # not a bug): the section exists so a reader knows self-correction ran.
    assert ledger["self_correction_count"] == 0
    assert ledger["retracted"] == []
    assert ledger["correction_trail"] == []


def test_exonerated_finding_appears_as_a_retraction_in_the_hardened_report():
    report = harden_findings(
        [_confirmed_finding(), _exonerated_finding()],
        image_sha256=IMAGE,
        receipt_key=KEY,
    )
    ledger = report.to_dict()["hypothesis_ledger"]
    # The exonerated subject is a logged SUPPORTS->REFUTES self-correction.
    assert ledger["self_correction_count"] == 1
    assert len(ledger["retracted"]) == 1
    trail = ledger["correction_trail"]
    assert len(trail) == 1
    entry = trail[0]
    assert entry["from_verdict"] == "supports"
    assert entry["to_verdict"] == "refutes"
    # The retraction cites the exonerating method (grounded, not free-text).
    assert "known_benign_direct_ip_infrastructure" in entry["reason"]
    # And it names a triggering execution id (a correction must cite its trigger).
    assert entry["trigger_exec_id"]


def test_ledger_overlay_does_not_mutate_the_scored_findings():
    """F1 guard: the overlay must not touch the detection scoring key."""
    findings = [_exonerated_finding()]
    harden_findings(findings, image_sha256=IMAGE, receipt_key=KEY)
    # evidence['executable']/foreign_addr and the finding list are untouched.
    assert findings[0].evidence["foreign_addr"] == "8.8.8.8"
    assert len(findings) == 1
