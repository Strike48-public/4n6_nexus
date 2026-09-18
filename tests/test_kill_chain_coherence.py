"""Kill-chain coherence primitive (SFE-fibx.5 PR-A).

The rule: a finding that is a member of a
coherent 3+-phase kill chain is HARDER to dismiss than a lone weak finding,
because the convergent chain corroborates it. This tests the pure, model-free
substrate that computes chain membership; the verdict adjustment that consumes
it is PR-D (the blocking gate).
"""

from __future__ import annotations

import pytest

from sift_find_evil.reporting.mitre_guardrail import CATALOG
from sift_find_evil.self_correction.kill_chain import (
    MIN_CHAIN_PHASES,
    TACTIC_PHASE_ORDER,
    assess_chain,
    finding_tactics,
    is_protected,
)


class _Finding:
    """Minimal duck-typed finding: only ``mitre_techniques()`` is consulted."""

    def __init__(self, techniques: list[str]):
        self._techniques = list(techniques)

    def mitre_techniques(self) -> list[str]:
        return list(self._techniques)


# Techniques whose tactics span the kill chain (verified against CATALOG below):
#   T1547 -> Persistence, T1055 -> Defense Evasion, T1071 -> Command and Control,
#   T1486 -> Impact, T1003 -> Credential Access, T1021 -> Lateral Movement.
_PERSISTENCE = "T1547"
_DEFENSE_EVASION = "T1055"
_C2 = "T1071"
_IMPACT = "T1486"
_CRED_ACCESS = "T1003"
_LATERAL = "T1021"


# ---------------------------------------------------------------------------
# finding_tactics
# ---------------------------------------------------------------------------


def test_finding_tactics_maps_techniques_to_tactics():
    f = _Finding([_PERSISTENCE, _C2])
    assert finding_tactics(f) == frozenset({"Persistence", "Command and Control"})


def test_finding_tactics_empty_when_no_techniques():
    assert finding_tactics(_Finding([])) == frozenset()


def test_finding_tactics_drops_technique_with_uncatalogued_tactic():
    # A syntactically valid id absent from CATALOG has tactic "unknown", which is
    # not a kill-chain phase -> it contributes nothing to the chain.
    assert finding_tactics(_Finding(["T9999"])) == frozenset()


def test_finding_tactics_accepts_dict_shape():
    # to_dict() shape (what confirmed_matrix consumes) must also resolve.
    d = {"techniques": [_IMPACT], "title": "x"}
    assert finding_tactics(d) == frozenset({"Impact"})


def test_finding_tactics_dict_honors_legacy_evidence_keys():
    """A dict carrying techniques ONLY under legacy evidence keys resolves them.

    Guards the object/dict asymmetry: the object path (mitre_techniques()) honors
    evidence['mitre_attack']/['mitre_technique']/['mitre'], so the dict path must
    too -- otherwise a legacy finding keeps its kill-chain phase as an object but
    silently loses it as a to_dict()-shaped dict (the shape the report/hardening
    path passes). Both shapes of the SAME finding must resolve identically.
    """
    legacy_dict = {"evidence": {"mitre_attack": [_PERSISTENCE]}, "title": "legacy"}
    assert finding_tactics(legacy_dict) == frozenset({"Persistence"})

    class _LegacyFinding:
        """Object whose techniques live only under a legacy evidence key."""

        def __init__(self):
            self.evidence = {"mitre_attack": [_PERSISTENCE]}

        def mitre_techniques(self):
            # Mirror Finding.mitre_techniques(): field-first, then legacy keys.
            return list(self.evidence.get("mitre_attack", []))

    assert finding_tactics(_LegacyFinding()) == finding_tactics(legacy_dict)


def test_finding_tactics_returns_empty_for_non_duck_typed_object():
    """A value that is neither a mitre_techniques()-bearing object nor a dict.

    Exercises the defensive final ``return []`` fallback so a malformed input
    yields no tactics rather than raising.
    """

    class _Bare:
        pass

    assert finding_tactics(_Bare()) == frozenset()


def test_finding_tactics_drops_technique_with_novel_tactic_not_in_phase_order(
    monkeypatch,
):
    """A technique whose tactic is NOT in TACTIC_PHASE_ORDER is dropped, not kept.

    Exercises the ``if tactic in TACTIC_PHASE_ORDER`` guard directly: it is the
    filter that keeps ``assess_chain``'s ``TACTIC_PHASE_ORDER[t]`` sort key from
    raising KeyError if the CATALOG ever gains a tactic the ordering does not yet
    know (the drift scenario the guard defends). Simulate it by injecting a
    catalogued technique with a novel tactic; the finding must occupy no phase,
    and assess_chain must not crash.
    """
    import sift_find_evil.self_correction.kill_chain as kc

    monkeypatch.setitem(
        kc.CATALOG, "T4242", {"name": "Fake", "tactic": "Nonexistent Tactic"}
    )
    f = _Finding(["T4242"])
    assert finding_tactics(f) == frozenset()
    # And it must not crash the chain sort (the guard's whole point).
    assert assess_chain([f]).phase_count == 0


# ---------------------------------------------------------------------------
# assess_chain
# ---------------------------------------------------------------------------


def test_three_distinct_phases_is_coherent():
    findings = [
        _Finding([_PERSISTENCE]),
        _Finding([_DEFENSE_EVASION]),
        _Finding([_C2]),
    ]
    a = assess_chain(findings)
    assert a.phase_count == 3
    assert a.is_coherent is True


def test_two_distinct_phases_is_not_coherent():
    a = assess_chain([_Finding([_PERSISTENCE]), _Finding([_C2])])
    assert a.phase_count == 2
    assert a.is_coherent is False


def test_many_findings_one_phase_is_not_a_chain():
    # Convergent findings that all sit in the SAME phase are not a multi-phase
    # chain -- the coherence rule protects a chain that SPANS phases.
    a = assess_chain([_Finding([_C2]), _Finding([_C2]), _Finding([_C2])])
    assert a.phase_count == 1
    assert a.is_coherent is False


def test_empty_findings_is_not_coherent():
    a = assess_chain([])
    assert a.phase_count == 0
    assert a.is_coherent is False


def test_assess_chain_judges_only_the_group_it_is_given():
    """Caller contract: assess_chain spans-phases over EXACTLY its input set.

    It intentionally does not know about subjects/entities/hosts -- three
    findings spanning three phases are "coherent" whether or not they belong to
    one subject. The consumer (PR-D gate) is responsible for grouping by
    canonical entity BEFORE calling this, so coherence means "one subject shows a
    multi-phase chain". This test pins the primitive's schema-agnostic contract
    so a future change that silently adds entity-awareness here (and breaks the
    documented division of labor) is caught.
    """
    three_phase_group = [
        _Finding([_PERSISTENCE]),
        _Finding([_DEFENSE_EVASION]),
        _Finding([_C2]),
    ]
    assert assess_chain(three_phase_group).is_coherent is True


def test_phases_returned_in_kill_chain_order_regardless_of_input_order():
    # Input deliberately reverse-ordered; output must be canonical kill-chain
    # order (Cred Access before Lateral Movement before C2 before Impact).
    findings = [
        _Finding([_IMPACT]),
        _Finding([_C2]),
        _Finding([_LATERAL]),
        _Finding([_CRED_ACCESS]),
    ]
    a = assess_chain(findings)
    order = [TACTIC_PHASE_ORDER[t] for t in a.phases]
    assert order == sorted(order)
    assert a.phases == (
        "Credential Access",
        "Lateral Movement",
        "Command and Control",
        "Impact",
    )


def test_assessment_to_dict_is_serializable():
    a = assess_chain([_Finding([_PERSISTENCE]), _Finding([_DEFENSE_EVASION])])
    d = a.to_dict()
    assert d == {
        "phases": ["Persistence", "Defense Evasion"],
        "phase_count": 2,
        "is_coherent": False,
    }


# ---------------------------------------------------------------------------
# is_protected
# ---------------------------------------------------------------------------


def test_chain_member_is_protected_when_chain_coherent():
    findings = [
        _Finding([_PERSISTENCE]),
        _Finding([_DEFENSE_EVASION]),
        _Finding([_C2]),
    ]
    a = assess_chain(findings)
    for f in findings:
        assert is_protected(f, a) is True


def test_finding_with_no_tactic_is_not_protected_even_in_coherent_chain():
    chain = [_Finding([_PERSISTENCE]), _Finding([_DEFENSE_EVASION]), _Finding([_C2])]
    a = assess_chain(chain)
    orphan = _Finding([])  # no techniques -> not a chain member
    assert is_protected(orphan, a) is False


def test_no_protection_when_chain_not_coherent():
    findings = [_Finding([_PERSISTENCE]), _Finding([_C2])]  # only 2 phases
    a = assess_chain(findings)
    for f in findings:
        assert is_protected(f, a) is False


# ---------------------------------------------------------------------------
# ordering integrity + determinism
# ---------------------------------------------------------------------------


def test_tactic_order_is_monotonic_recon_before_impact():
    assert TACTIC_PHASE_ORDER["Reconnaissance"] < TACTIC_PHASE_ORDER["Execution"]
    assert TACTIC_PHASE_ORDER["Execution"] < TACTIC_PHASE_ORDER["Persistence"]
    assert TACTIC_PHASE_ORDER["Persistence"] < TACTIC_PHASE_ORDER["Impact"]
    assert TACTIC_PHASE_ORDER["Command and Control"] < TACTIC_PHASE_ORDER["Impact"]


def test_min_chain_phases_default_is_three():
    assert MIN_CHAIN_PHASES == 3


def test_every_catalogued_tactic_is_orderable():
    """Drift guard: every tactic the MITRE CATALOG can emit must have a phase.

    If a new technique introduces a tactic string absent from
    TACTIC_PHASE_ORDER, that tactic would silently drop out of every chain and
    weaken the coherence protection. This fails loudly so the ordering is kept
    in lockstep with the single-source technique->tactic CATALOG.
    """
    catalog_tactics = {meta["tactic"] for meta in CATALOG.values()}
    missing = catalog_tactics - set(TACTIC_PHASE_ORDER)
    assert not missing, f"tactics missing from TACTIC_PHASE_ORDER: {missing}"


def test_assessment_is_deterministic():
    findings = [_Finding([_C2]), _Finding([_PERSISTENCE]), _Finding([_DEFENSE_EVASION])]
    assert assess_chain(findings).to_dict() == assess_chain(findings).to_dict()


def test_assessment_is_frozen():
    a = assess_chain([_Finding([_C2])])
    with pytest.raises((AttributeError, TypeError)):
        a.phases = ()  # type: ignore[misc]
