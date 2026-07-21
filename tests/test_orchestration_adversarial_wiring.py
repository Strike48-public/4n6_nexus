"""Tests that adversarial verification is WIRED into the live orchestrator.

The adversarial adjudicator + refutation seats landed as unit-tested modules;
this proves the standalone orchestrator actually runs a deterministic adversarial
pass over every finding and records the adjudicated outcome. In the standalone
(no-model) path the falsifier is deterministic: the refutation seats act as a
model-free adversary that FALSIFIES a finding whose interpretation over-reads its
tool, and SURVIVES one that is correctly scoped.

RED-first: the orchestrator did not run an adversarial pass before this change.
"""

import pytest

from sift_find_evil.orchestration import InvestigationOrchestrator


@pytest.fixture
def report(tmp_path):
    orch = InvestigationOrchestrator(
        case_id="INC-ADV-001", audit_path=tmp_path / "audit.jsonl"
    )
    return orch.run_demo_investigation()


def test_every_finding_carries_an_adversarial_adjudication(report):
    assert report["case_findings"], "demo must emit findings"
    for item in report["case_findings"]:
        assert "adversarial" in item, f"{item['finding_id']} not adjudicated"
        adv = item["adversarial"]
        assert adv["outcome"] in {
            "sustained",
            "dismissed",
            "remanded",
            "flagged_human",
        }
        assert adv["falsifier_status"] in {"survived", "falsified", "inconclusive"}


def test_demo_findings_survive_and_sustain(report):
    # The demo's findings are correctly tool-scoped and multi-source, so the
    # deterministic falsifier should not kill them - they sustain.
    outcomes = {item["adversarial"]["outcome"] for item in report["case_findings"]}
    assert "dismissed" not in outcomes
    assert "sustained" in outcomes


def test_integrity_block_reports_adversarial_summary(report):
    integ = report["integrity"]
    assert "adversarial_sustained" in integ
    assert integ["adversarial_sustained"] >= 1


def test_seat_falsifier_dismisses_a_single_source_over_read():
    """The model-free falsifier kills a single-source finding that over-reads its tool.

    Exercises the _SeatFalsifier path (single-source) end to end via the
    orchestrator's _adversarial_pass, which the multi-source demo findings skip.
    """
    from types import SimpleNamespace

    from sift_find_evil.orchestration import InvestigationOrchestrator
    from sift_find_evil.self_correction.adversarial import RulesAdjudicator

    orch = InvestigationOrchestrator.__new__(InvestigationOrchestrator)
    # A shimcache-only (single-source) finding whose interpretation claims the
    # program "executed" - which shimcache alone cannot establish.
    finding = SimpleNamespace(
        reasoning_chain=["the program executed from C:/temp/x.exe"],
        description="shimcache entry",
        artifact_sources=["shimcache"],
    )
    verification = SimpleNamespace(verdict="confirmed", finding_id="F-999")
    ruling = orch._adversarial_pass(
        finding, verification, "disk_analyst", RulesAdjudicator()
    )
    assert ruling["outcome"] == "dismissed"
    assert ruling["falsifier_status"] == "falsified"
    assert ruling["falsifier_family"] == "deterministic-seats"

    # A single-source finding that is correctly scoped SURVIVES the seat check
    # (it does not over-read its tool) - remanded for lack of corroboration,
    # never sustained on one source, never wrongly dismissed.
    scoped = SimpleNamespace(
        reasoning_chain=["a shimcache entry for x.exe was present"],
        description="shimcache entry",
        artifact_sources=["shimcache"],
    )
    ruling2 = orch._adversarial_pass(
        scoped, verification, "disk_analyst", RulesAdjudicator()
    )
    assert ruling2["falsifier_status"] == "survived"
    assert ruling2["outcome"] == "remanded"


def test_receipt_key_from_env_and_file_evidence(tmp_path, monkeypatch):
    """Cover the env-supplied receipt key + single-file evidence-image branches."""
    from sift_find_evil.orchestration import (
        _evidence_image_sha256,
        _resolve_receipt_key,
    )

    monkeypatch.setenv("SFE_RECEIPT_HMAC_KEY", "x" * 40)
    assert _resolve_receipt_key() == (b"x" * 40)

    img = tmp_path / "image.dd"
    img.write_bytes(b"evidence-bytes")
    digest = _evidence_image_sha256(img)
    assert len(digest) == 64
