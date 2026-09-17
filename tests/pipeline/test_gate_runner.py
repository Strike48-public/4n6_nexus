"""Tests for nexus_pipeline.gates.runner (spec section 3; audit contract
from containment.audit, SFE-rbje.4).

Every test here except the one marked `integration` mocks the subprocess
seam: the runner must never actually shell out to the real pytest/scenario
suite (slow, and it would recurse). The `integration` test opts into a real,
fast, end-to-end gate (`ruff check .`) to prove the subprocess wiring
(argv/cwd/env) genuinely works, not just the mock.
"""

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from nexus_pipeline.gates import runner
from nexus_pipeline.gates.definitions import GateDefinition
from nexus_pipeline.gates.result import GateSuiteResult


@pytest.fixture(autouse=True)
def isolated_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _completed(exit_code: int, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess(
        args=["x"], returncode=exit_code, stdout=stdout, stderr=stderr
    )


def _read_audit_records(cwd: Path, issue_id: str) -> list[dict]:
    log_path = cwd / "reports" / "audit" / f"{issue_id}.jsonl"
    if not log_path.exists():
        return []
    return [
        json.loads(line) for line in log_path.read_text().splitlines() if line.strip()
    ]


def test_runs_every_gate_and_reports_passed_when_all_succeed():
    definitions = (
        GateDefinition(name="A", argv=("true",), cwd=None),
        GateDefinition(name="B", argv=("true",), cwd=None),
    )
    with patch.object(runner.subprocess, "run", return_value=_completed(0)) as mock_run:
        result = runner.run("SFE-1", cwd=Path("."), definitions=definitions)

    assert isinstance(result, GateSuiteResult)
    assert result.passed is True
    assert result.first_failure is None
    assert len(result.results) == 2
    assert mock_run.call_count == 2


def test_short_circuits_on_first_failure_and_does_not_run_later_gates():
    definitions = (
        GateDefinition(name="A", argv=("ruff", "check", "."), cwd=None),
        GateDefinition(name="B", argv=("pytest", "-q"), cwd=None),
        GateDefinition(name="C", argv=("python3", "harness.py"), cwd=None),
    )
    with patch.object(
        runner.subprocess, "run", side_effect=[_completed(0), _completed(1)]
    ) as mock_run:
        result = runner.run("SFE-1", cwd=Path("."), definitions=definitions)

    assert result.passed is False
    assert result.first_failure == "B"
    assert len(result.results) == 2
    assert mock_run.call_count == 2


def test_maps_nonzero_exit_code_to_failed_result():
    definitions = (GateDefinition(name="A", argv=("false",), cwd=None),)
    with patch.object(runner.subprocess, "run", return_value=_completed(1)):
        result = runner.run("SFE-1", cwd=Path("."), definitions=definitions)

    assert result.results[0].passed is False
    assert result.results[0].exit_code == 1


def test_subprocess_error_maps_to_failed_result_without_raising():
    definitions = (GateDefinition(name="A", argv=("does-not-exist",), cwd=None),)
    with patch.object(
        runner.subprocess, "run", side_effect=FileNotFoundError("no such file")
    ):
        result = runner.run("SFE-1", cwd=Path("."), definitions=definitions)

    assert result.passed is False
    assert result.results[0].passed is False
    assert result.results[0].exit_code != 0


def test_emits_a_gate_result_audit_entry_per_executed_gate(isolated_cwd):
    definitions = (
        GateDefinition(name="A", argv=("true",), cwd=None),
        GateDefinition(name="B", argv=("true",), cwd=None),
    )
    with patch.object(runner.subprocess, "run", return_value=_completed(0)):
        runner.run("SFE-audit-1", cwd=Path("."), definitions=definitions)

    records = _read_audit_records(isolated_cwd, "SFE-audit-1")
    assert len(records) == 2
    assert all(record["category"] == "gate_result" for record in records)


def test_short_circuit_only_audits_gates_actually_run(isolated_cwd):
    definitions = (
        GateDefinition(name="A", argv=("true",), cwd=None),
        GateDefinition(name="B", argv=("false",), cwd=None),
        GateDefinition(name="C", argv=("true",), cwd=None),
    )
    with patch.object(
        runner.subprocess, "run", side_effect=[_completed(0), _completed(1)]
    ):
        runner.run("SFE-audit-2", cwd=Path("."), definitions=definitions)

    records = _read_audit_records(isolated_cwd, "SFE-audit-2")
    assert len(records) == 2


def test_gate_detail_is_secret_scrubbed():
    definitions = (GateDefinition(name="A", argv=("true",), cwd=None),)
    secret_looking = "Authorization: Bearer abc123.def456-notlivetoken789"
    with patch.object(
        runner.subprocess, "run", return_value=_completed(0, stdout=secret_looking)
    ):
        result = runner.run("SFE-audit-3", cwd=Path("."), definitions=definitions)

    assert secret_looking not in result.results[0].detail
    assert "***REDACTED***" in result.results[0].detail


def test_default_definitions_used_when_none_supplied():
    with patch.object(runner.subprocess, "run", return_value=_completed(0)) as mock_run:
        runner.run("SFE-default", cwd=Path("."))

    # The real GATE_DEFINITIONS sequence has 5 entries (A, A, B, C, E).
    assert mock_run.call_count == 5


@pytest.mark.integration
def test_real_ruff_check_gate_runs_end_to_end(isolated_cwd):
    # A minimal, syntactically valid Python file so `ruff check .` has
    # something to lint and genuinely exits 0 -- proves the subprocess
    # wiring (argv, cwd, env merge) works against a real interpreter, not
    # just the mock every other test in this module uses.
    (isolated_cwd / "clean.py").write_text('"""Trivial clean module."""\n')
    definitions = (GateDefinition(name="A", argv=("ruff", "check", "."), cwd=None),)

    result = runner.run("SFE-real-ruff", cwd=isolated_cwd, definitions=definitions)

    assert result.passed is True
    assert result.results[0].exit_code == 0
