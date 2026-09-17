"""Report-blocking gate (SFE-fibx.5 PR-D).

The composing gate: it reads the already-computed adversarial ruling per finding,
applies the kill-chain-coherence protection (a member of a coherent 3+-phase
chain is harder to dismiss), folds in the coverage audit, and produces a single
gate verdict the emitters enforce (stamp + non-zero exit; the report still ships
-- degrade, not refuse).

Calibration (measured across the 16 scored scenarios): findings are overwhelmingly
single-source ``remanded`` (110) with a few ``sustained`` (13) and zero
``dismissed`` / zero coherent chains. So ``remanded`` is the NORMAL case and must
NOT trip the gate; the gate blocks on a genuinely bad state (a ``dismissed``
finding = a hallucinated identity anchor that no chain vouches for).
"""

from __future__ import annotations

from sift_find_evil.self_correction.gate import build_gate


def _hardened_entry(techniques=None, outcome="sustained", executable="evil.exe"):
    """A hardened-report entry shaped like harden_findings emits.

    Only the fields the gate reads are populated: the finding's techniques +
    evidence (for kill-chain phase and canonical-entity grouping) and the
    adversarial outcome.
    """
    return {
        "finding": {
            "title": f"finding for {executable}",
            "techniques": list(techniques or []),
            "evidence": {"executable": executable},
        },
        "adversarial": {"outcome": outcome},
    }


# Techniques spanning distinct kill-chain tactics (see mitre_guardrail.CATALOG):
_PERSISTENCE = "T1547"  # Persistence
_DEFENSE_EVASION = "T1055"  # Defense Evasion
_C2 = "T1071"  # Command and Control


# ---------------------------------------------------------------------------
# happy path: the normal corpus shape must PASS
# ---------------------------------------------------------------------------


def test_all_sustained_passes():
    hardened = [_hardened_entry(outcome="sustained", executable="a.exe")]
    v = build_gate(hardened, coverage={}, negatives=[])
    assert v.verdict == "PASS"


def test_remanded_alone_does_not_trip_the_gate():
    # remanded (survived-but-uncorroborated) is the NORMAL single-source case;
    # it must not flag, or the gate is noise on every clean scenario.
    hardened = [
        _hardened_entry(outcome="remanded", executable="a.exe"),
        _hardened_entry(outcome="remanded", executable="b.exe"),
    ]
    v = build_gate(hardened, coverage={}, negatives=[])
    assert v.verdict == "PASS"


def test_empty_report_passes():
    assert build_gate([], coverage={}, negatives=[]).verdict == "PASS"


# ---------------------------------------------------------------------------
# dismissed -> BLOCKED (hallucinated anchor, no chain vouches for it)
# ---------------------------------------------------------------------------


def test_dismissed_without_chain_blocks():
    hardened = [_hardened_entry(outcome="dismissed", executable="ghost.exe")]
    v = build_gate(hardened, coverage={}, negatives=[])
    assert v.verdict == "BLOCKED"
    assert any("ghost.exe" in r for r in v.reasons)


def test_blocked_dominates_other_findings():
    hardened = [
        _hardened_entry(outcome="sustained", executable="a.exe"),
        _hardened_entry(outcome="dismissed", executable="ghost.exe"),
        _hardened_entry(outcome="remanded", executable="b.exe"),
    ]
    v = build_gate(hardened, coverage={}, negatives=[])
    assert v.verdict == "BLOCKED"


# ---------------------------------------------------------------------------
# kill-chain coherence: a dismissed member of a coherent chain escalates to
# NEEDS_HUMAN (harder to dismiss), not silently BLOCKED
# ---------------------------------------------------------------------------


def test_dismissed_chain_member_escalates_to_needs_human_not_blocked():
    # Three findings on the SAME subject spanning 3 kill-chain phases -> coherent
    # chain. One is dismissed; because it is chain-protected, the gate escalates
    # to human review rather than accepting the dismissal as a hard block.
    subject = "crypt.exe"
    hardened = [
        _hardened_entry(
            techniques=[_PERSISTENCE], outcome="sustained", executable=subject
        ),
        _hardened_entry(
            techniques=[_DEFENSE_EVASION], outcome="sustained", executable=subject
        ),
        _hardened_entry(techniques=[_C2], outcome="dismissed", executable=subject),
    ]
    v = build_gate(hardened, coverage={}, negatives=[])
    assert v.verdict == "NEEDS_HUMAN"
    assert any("chain" in r.lower() for r in v.reasons)


def test_dismissed_non_chain_member_still_blocks_even_when_a_chain_exists():
    # A coherent chain exists on subject X, but the DISMISSED finding is on an
    # unrelated subject Y with no chain -> it is not protected -> BLOCKED.
    x = "chain.exe"
    hardened = [
        _hardened_entry(techniques=[_PERSISTENCE], outcome="sustained", executable=x),
        _hardened_entry(
            techniques=[_DEFENSE_EVASION], outcome="sustained", executable=x
        ),
        _hardened_entry(techniques=[_C2], outcome="sustained", executable=x),
        _hardened_entry(techniques=[_C2], outcome="dismissed", executable="lone.exe"),
    ]
    v = build_gate(hardened, coverage={}, negatives=[])
    assert v.verdict == "BLOCKED"


def test_chain_protection_requires_same_subject_grouping():
    # Three dismissed findings each in a different phase but on THREE DIFFERENT
    # subjects do NOT form a per-subject coherent chain -> each is unprotected ->
    # BLOCKED (this is the PR-A caller-contract: group by canonical_entity first).
    hardened = [
        _hardened_entry(
            techniques=[_PERSISTENCE], outcome="dismissed", executable="a.exe"
        ),
        _hardened_entry(
            techniques=[_DEFENSE_EVASION], outcome="dismissed", executable="b.exe"
        ),
        _hardened_entry(techniques=[_C2], outcome="dismissed", executable="c.exe"),
    ]
    v = build_gate(hardened, coverage={}, negatives=[])
    assert v.verdict == "BLOCKED"


# ---------------------------------------------------------------------------
# coverage gaps -> NEEDS_HUMAN advisory (never blocks)
# ---------------------------------------------------------------------------


def test_not_examined_coverage_gap_is_advisory_not_blocking():
    # A coverage gap flags but does NOT change the verdict or force a non-zero
    # exit -- a deliberately-partial run is normal; gating every one is noise.
    hardened = [_hardened_entry(outcome="sustained", executable="a.exe")]
    coverage = {
        "uncited": [],
        "not_examined": ["memory", "registry"],
        "supplied": ["disk"],
    }
    v = build_gate(hardened, coverage=coverage, negatives=[])
    assert v.verdict == "PASS"  # advisory, not blocking
    assert any("memory" in a or "registry" in a for a in v.advisories)
    # The gap is NOT in the (exit-worthy) reasons.
    assert not any("Coverage gap" in r for r in v.reasons)


def test_coverage_gap_does_not_override_a_block():
    hardened = [_hardened_entry(outcome="dismissed", executable="ghost.exe")]
    coverage = {"uncited": [], "not_examined": ["memory"], "supplied": ["disk"]}
    v = build_gate(hardened, coverage=coverage, negatives=[])
    assert v.verdict == "BLOCKED"  # finding-level block still wins
    assert any("memory" in a for a in v.advisories)  # gap still flagged


def test_clean_coverage_passes():
    hardened = [_hardened_entry(outcome="sustained", executable="a.exe")]
    coverage = {"uncited": [], "not_examined": [], "supplied": ["disk", "memory"]}
    v = build_gate(hardened, coverage=coverage, negatives=[]).verdict
    assert v == "PASS"


# ---------------------------------------------------------------------------
# verdict shape + determinism
# ---------------------------------------------------------------------------


def test_verdict_is_serializable_and_frozen():
    import pytest

    v = build_gate([_hardened_entry(outcome="dismissed")], coverage={}, negatives=[])
    d = v.to_dict()
    assert set(d) == {"verdict", "reasons", "blocked_findings", "advisories"}
    assert d["verdict"] == "BLOCKED"
    with pytest.raises((AttributeError, TypeError)):
        v.verdict = "PASS"  # type: ignore[misc]


def test_build_gate_is_deterministic():
    hardened = [
        _hardened_entry(outcome="dismissed", executable="g.exe"),
        _hardened_entry(outcome="remanded", executable="b.exe"),
    ]
    assert (
        build_gate(hardened, coverage={}, negatives=[]).to_dict()
        == build_gate(hardened, coverage={}, negatives=[]).to_dict()
    )


def test_build_gate_does_not_mutate_inputs():
    hardened = [_hardened_entry(outcome="dismissed", executable="g.exe")]
    import copy

    snapshot = copy.deepcopy(hardened)
    build_gate(hardened, coverage={}, negatives=[])
    assert hardened == snapshot


# ---------------------------------------------------------------------------
# CLI enforcement: _exit_on_gate turns a non-PASS verdict into a non-zero exit
# ---------------------------------------------------------------------------


def test_exit_on_gate_blocks_with_nonzero():
    import pytest

    from sift_find_evil.cli import _GATE_EXIT_CODE, _exit_on_gate

    with pytest.raises(SystemExit) as exc:
        _exit_on_gate("BLOCKED")
    assert exc.value.code == _GATE_EXIT_CODE


def test_exit_on_gate_needs_human_with_nonzero():
    import pytest

    from sift_find_evil.cli import _GATE_EXIT_CODE, _exit_on_gate

    with pytest.raises(SystemExit) as exc:
        _exit_on_gate("NEEDS_HUMAN")
    assert exc.value.code == _GATE_EXIT_CODE


def test_exit_on_gate_pass_and_none_are_noops():
    from sift_find_evil.cli import _exit_on_gate

    # Neither raises: a PASS or a no-harden (None) run exits normally.
    assert _exit_on_gate("PASS") is None
    assert _exit_on_gate(None) is None


def test_build_gate_degrades_on_malformed_entries():
    # Out-of-contract shapes must not crash the gate (defense in depth: a
    # well-formed run always carries dict evidence, but the gate is trust-critical
    # so it degrades rather than raising AttributeError).
    malformed = [
        {"finding": {"title": "no-adv", "evidence": {}}},  # missing adversarial
        {"adversarial": {"outcome": "dismissed"}},  # missing finding
        {
            "finding": {"title": "t", "evidence": "not-a-dict"},
            "adversarial": {"outcome": "sustained"},
        },
        {
            "finding": {"title": "t2", "evidence": [1, 2], "techniques": None},
            "adversarial": {"outcome": "dismissed"},
        },
    ]
    # Should not raise; verdict is a valid value.
    v = build_gate(malformed, coverage=None, negatives=[])
    assert v.verdict in {"PASS", "NEEDS_HUMAN", "BLOCKED"}
