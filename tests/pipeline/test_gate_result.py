"""Tests for nexus_pipeline.gates.result (spec section 3 / 6.7).

GateResult is the record for one executed gate command; GateSuiteResult is
the outcome of a full runner.run() pass over the ordered gate sequence.
"""

import pytest

from nexus_pipeline.gates.result import GateResult, GateSuiteResult


def test_gate_result_holds_name_command_exit_code_and_pass_flag():
    result = GateResult(name="A", command="ruff check .", exit_code=0, passed=True)

    assert result.name == "A"
    assert result.command == "ruff check ."
    assert result.exit_code == 0
    assert result.passed is True


def test_gate_result_detail_defaults_to_none():
    result = GateResult(name="A", command="ruff check .", exit_code=0, passed=True)

    assert result.detail is None


def test_gate_result_accepts_an_explicit_detail():
    result = GateResult(
        name="B", command="pytest -q", exit_code=1, passed=False, detail="last line"
    )

    assert result.detail == "last line"


def test_gate_result_is_frozen():
    result = GateResult(name="A", command="ruff check .", exit_code=0, passed=True)

    with pytest.raises(AttributeError):
        result.passed = False  # type: ignore[misc]


def test_gate_suite_result_holds_ordered_results_and_first_failure():
    passing = GateResult(name="A", command="ruff check .", exit_code=0, passed=True)
    failing = GateResult(name="B", command="pytest -q", exit_code=1, passed=False)

    suite = GateSuiteResult(results=(passing, failing), passed=False, first_failure="B")

    assert suite.results == (passing, failing)
    assert suite.passed is False
    assert suite.first_failure == "B"


def test_gate_suite_result_first_failure_none_when_all_pass():
    passing = GateResult(name="A", command="ruff check .", exit_code=0, passed=True)

    suite = GateSuiteResult(results=(passing,), passed=True, first_failure=None)

    assert suite.first_failure is None


def test_gate_suite_result_is_frozen():
    suite = GateSuiteResult(results=(), passed=True, first_failure=None)

    with pytest.raises(AttributeError):
        suite.passed = False  # type: ignore[misc]
