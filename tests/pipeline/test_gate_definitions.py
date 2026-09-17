"""Tests for nexus_pipeline.gates.definitions (spec section 3).

Confirms the ordered gate sequence and each definition's static shape. The
exact literal commands are re-verified against live CI/repo source in
test_ci_drift_guard.py, not here -- this module tests the committed
contract (ordering, field shape, pass predicate), not repo drift.
"""

import pytest

from nexus_pipeline.gates.definitions import GATE_DEFINITIONS, GateDefinition


def test_gate_definitions_are_ordered_a_b_c_e():
    names_in_order = [definition.name for definition in GATE_DEFINITIONS]

    # Gate A runs two commands (ruff, black); B, C, E run once each. Gate D
    # is a separate pure-function policy and must never appear here.
    assert names_in_order == ["A", "A", "B", "C", "E"]


def test_every_definition_has_a_nonempty_string_argv():
    for definition in GATE_DEFINITIONS:
        assert definition.argv
        assert all(isinstance(token, str) for token in definition.argv)


def test_default_pass_predicate_requires_exit_zero():
    definition = GATE_DEFINITIONS[0]

    assert definition.is_pass(0) is True
    assert definition.is_pass(1) is False


def test_gate_c_sets_pythonpath_env_overlay():
    gate_c = next(d for d in GATE_DEFINITIONS if d.name == "C")

    assert gate_c.env == {"PYTHONPATH": "."}


def test_other_gates_have_no_env_overlay():
    for definition in GATE_DEFINITIONS:
        if definition.name != "C":
            assert definition.env is None


def test_gate_definitions_are_frozen():
    definition = GateDefinition(name="X", argv=("true",), cwd=None)

    with pytest.raises(AttributeError):
        definition.name = "Y"  # type: ignore[misc]


def test_gate_d_evidence_guard_is_not_in_the_sequence():
    names = {definition.name for definition in GATE_DEFINITIONS}

    assert "D" not in names


def test_gate_f_mutation_testing_is_not_in_the_sequence():
    names = {definition.name for definition in GATE_DEFINITIONS}

    assert "F" not in names
