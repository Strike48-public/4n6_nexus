"""Tests for the randomized adversarial recall harness (SFE-fibx.3).

The frozen-16-scenario F1=1.00 number is by-construction: the detectors were
authored against those exact fixture names. This harness proves recall against
*procedurally generated* fixtures with randomized names + RFC-5737 IPs, so a
detector that memorized the 16 names would fail here. Everything is deterministic
and LLM-free: a fixed seed reproduces the exact same score, so it is CI-gateable.
"""

from __future__ import annotations

import ipaddress
import random

from sift_find_evil.benchmark.red_team import (
    RedTeamObservation,
    extract_observation,
    plant_causality_violation,
    plant_false_ioc,
    plant_memory_c2,
    plant_negative_control,
    run_red_team,
    score_iteration,
)


# ─── Planters produce structurally-valid, randomized fixtures ────────────────


def test_causality_planter_is_deterministic_under_seed() -> None:
    """Same seed → identical planted fixtures (required for a CI-gateable score)."""
    a = plant_causality_violation(random.Random(7))
    b = plant_causality_violation(random.Random(7))
    assert a.fixtures == b.fixtures
    assert a.malicious == b.malicious


def test_causality_planter_uses_randomized_nonfixture_names() -> None:
    """Planted names must not be any of the committed-16 fixture names.

    If the harness reused ``ransom_note.exe`` it would prove nothing about
    generalization. Names are random hex tokens; assert they differ across seeds.
    """
    committed = {"ransom_note.exe", "crypt_engine.exe", "persist.exe"}
    names = plant_causality_violation(random.Random(1)).malicious
    assert names.isdisjoint(committed)
    other = plant_causality_violation(random.Random(2)).malicious
    assert names != other  # different seed → different names


def test_causality_planter_embeds_rfc5737_c2_ip() -> None:
    """The planted C2 IP is a documentation-range (RFC-5737) address.

    Real-world IPs stand out against TEST-NET planting, which is exactly the
    hallucination heuristic the scorer relies on.
    """
    planted = plant_causality_violation(random.Random(3))
    assert planted.planted_ips
    for ip in planted.planted_ips:
        assert (
            ipaddress.ip_address(ip) in ipaddress.ip_network("192.0.2.0/24")
            or (ipaddress.ip_address(ip) in ipaddress.ip_network("198.51.100.0/24"))
            or (ipaddress.ip_address(ip) in ipaddress.ip_network("203.0.113.0/24"))
        )


# ─── The REAL engine detects the randomized violation (anti-overfit core) ────


def test_engine_flags_randomly_named_causality_violation() -> None:
    """Recall=1.0 over a freshly-generated causality scenario the engine never saw."""
    planted = plant_causality_violation(random.Random(11))
    observed = _run_engine(planted)
    score = score_iteration(planted, observed, forbidden_markers=frozenset())
    assert score.recall == 1.0
    assert not score.missed
    assert not score.false_positives


def test_engine_does_not_flag_negative_control() -> None:
    """A benign scenario (no structural violation) yields zero flagged executables."""
    planted = plant_negative_control(random.Random(12))
    observed = _run_engine(planted)
    score = score_iteration(planted, observed, forbidden_markers=frozenset())
    assert not score.false_positives
    assert score.recall == 1.0  # nothing to find → recall is vacuously perfect


def test_engine_does_not_anchor_on_suspicious_name_without_structure() -> None:
    """TRUDI-style planted false IOC: a suspicious NAME with benign STRUCTURE.

    The deterministic engine fires on structure, not on how evil a name looks,
    so it must NOT flag a ``svch0st``-style exe that was modified *before* it ran.
    """
    planted = plant_false_ioc(random.Random(13))
    assert planted.malicious == frozenset()  # nothing should be flagged
    observed = _run_engine(planted)
    score = score_iteration(planted, observed, forbidden_markers=frozenset())
    assert not score.false_positives


# ─── Hallucination: no non-planted IP, no cross-iteration pollution ──────────


def test_memory_c2_ip_is_surfaced_and_not_fabricated_on_a_real_run() -> None:
    """The memory planter exercises a REAL engine path that surfaces an IPv4.

    This is what makes the RFC-5737 hallucination heuristic load-bearing on a
    real run (not just the grader-calibration meta-test): the planted C2 IP MUST
    be surfaced (recall), and no OTHER routable IPv4 may appear (no fabrication).
    """
    planted = plant_memory_c2(random.Random(14))
    (c2,) = tuple(planted.expected_ips)
    observed = _run_engine(planted)
    assert c2 in observed.ipv4s  # the engine really did surface the planted IP
    score = score_iteration(planted, observed, forbidden_markers=frozenset())
    assert score.recall == 1.0
    assert not score.missed
    assert not score.hallucinated_ips


def test_cross_iteration_marker_pollution_is_detected() -> None:
    """An earlier iteration's unique marker surfacing later ⇒ leaked global state.

    Simulated by scoring an observation that (wrongly) flags a prior iteration's
    random name; the scorer must surface it as pollution.
    """
    planted = plant_negative_control(random.Random(15))
    leaked = "zzleaked_marker.exe"
    polluted = RedTeamObservation(
        flagged=frozenset({leaked}),
        ipv4s=frozenset(),
    )
    score = score_iteration(planted, polluted, forbidden_markers=frozenset({leaked}))
    assert leaked in score.polluted_markers


# ─── Grader calibration: the scorer must FAIL when it should ─────────────────


def test_grader_calibration_fails_on_missed_marker() -> None:
    """Prove the scorer reports a miss when a planted marker is absent from output.

    A grader stuck-on-PASS is worse than no grader; this is the meta-test that
    proves ours is not.
    """
    planted = plant_causality_violation(random.Random(16))
    empty = RedTeamObservation(flagged=frozenset(), ipv4s=frozenset())
    score = score_iteration(planted, empty, forbidden_markers=frozenset())
    assert score.recall < 1.0
    assert score.missed == planted.malicious


def test_grader_calibration_flags_non_planted_ip() -> None:
    """Prove the scorer flags an IP that was never planted as a hallucination."""
    planted = plant_negative_control(random.Random(17))
    fabricated = RedTeamObservation(
        flagged=frozenset(),
        ipv4s=frozenset({"8.34.211.9"}),  # public, not planted, not noise
    )
    score = score_iteration(planted, fabricated, forbidden_markers=frozenset())
    assert "8.34.211.9" in score.hallucinated_ips


def test_grader_calibration_flags_fabricated_rfc5737_ip() -> None:
    """Prove the scorer flags a NON-planted RFC-5737 IP as a hallucination.

    This is the load-bearing calibration the harness's premise depends on: the
    planters fabricate C2 only in RFC-5737 space, so the scorer MUST flag an
    RFC-5737 IP that was not planted. Python's ``ipaddress`` classifies RFC-5737
    as private, so without the explicit exclusion in ``_is_defensible_noise`` a
    detector that fabricated ``198.51.100.x`` would score clean (the exact
    vacuous-pass this test guards against).
    """
    planted = plant_negative_control(random.Random(17))
    fabricated = RedTeamObservation(
        flagged=frozenset(),
        ipv4s=frozenset({"198.51.100.199"}),  # RFC-5737, not in planted_ips
    )
    score = score_iteration(planted, fabricated, forbidden_markers=frozenset())
    assert "198.51.100.199" in score.hallucinated_ips


def test_grader_calibration_passes_on_good_output() -> None:
    """The mirror of the two FAIL tests: a correct observation scores clean."""
    planted = plant_causality_violation(random.Random(18))
    good = RedTeamObservation(
        flagged=planted.malicious,
        ipv4s=planted.planted_ips,
    )
    score = score_iteration(planted, good, forbidden_markers=frozenset())
    assert score.recall == 1.0
    assert not score.false_positives
    assert not score.hallucinated_ips
    assert not score.polluted_markers


# ─── The loop aggregates and is deterministic ────────────────────────────────


def test_run_red_team_is_deterministic_and_clean() -> None:
    """A seeded multi-iteration run reproduces exactly and reports a perfect pass."""
    report_a = run_red_team(iterations=9, seed=99)
    report_b = run_red_team(iterations=9, seed=99)
    assert report_a.to_dict() == report_b.to_dict()
    assert report_a.iterations == 9
    assert report_a.mean_recall == 1.0
    assert report_a.total_false_positives == 0
    assert report_a.total_hallucinated_ips == 0
    assert report_a.total_polluted_markers == 0
    assert report_a.passed is True


def test_ci_budget_run_passes() -> None:
    """The exact seeded budget CI gates on scores a clean pass.

    This is the regression net itself: if a downstream detector change (schema v2,
    verifier gate, anti-anchoring) breaks recall on randomized inputs or introduces
    an over-call, this goes red — which is the whole point of sequencing it first.
    """
    from sift_find_evil.benchmark.red_team import _CI_ITERATIONS, _CI_SEED

    report = run_red_team(iterations=_CI_ITERATIONS, seed=_CI_SEED)
    assert report.passed, report.to_dict()
    assert report.attack_classes_seen == {
        "causality_violation",
        "negative_control",
        "false_ioc",
        "memory_c2",
    }


def test_run_red_team_covers_every_attack_class() -> None:
    """Over enough iterations the loop exercises all four planter classes."""
    report = run_red_team(iterations=12, seed=5)
    assert report.attack_classes_seen == {
        "causality_violation",
        "negative_control",
        "false_ioc",
        "memory_c2",
    }


def test_cli_main_prints_report_and_exits_zero_on_pass(capsys) -> None:
    """The CI entry point prints the JSON report and does not exit on a clean run."""
    from sift_find_evil.benchmark import red_team

    red_team.main()  # must NOT raise SystemExit on the seeded clean budget
    out = capsys.readouterr().out
    assert '"passed": true' in out
    assert "RED-TEAM PASS" in out


def test_cli_main_exits_nonzero_when_a_run_fails(monkeypatch) -> None:
    """A failing report makes ``main`` exit non-zero — the CI gate actually gates."""
    import pytest

    from sift_find_evil.benchmark import red_team
    from sift_find_evil.benchmark.red_team import RedTeamReport

    failing = RedTeamReport(
        iterations=1,
        seed=0,
        mean_recall=0.0,
        total_false_positives=1,
        total_hallucinated_ips=0,
        total_polluted_markers=0,
        attack_classes_seen=frozenset({"causality_violation"}),
        per_iteration=(),
    )
    monkeypatch.setattr(red_team, "run_red_team", lambda **_: failing)
    with pytest.raises(SystemExit) as exc:
        red_team.main()
    assert exc.value.code == 1


# ─── helper: run the REAL engine over a planted scenario ─────────────────────


def _run_engine(planted) -> RedTeamObservation:
    """Materialize the planted fixtures to a tmp dir, run the engine, observe."""
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        return extract_observation(planted, Path(tmp))
