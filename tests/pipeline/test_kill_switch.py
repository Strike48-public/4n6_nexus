"""Tests for nexus_pipeline.containment.kill_switch (spec section 6.4).

Covers both halt sources (repo variable, sentinel label), the "both clear"
pass-through case, fail-closed behavior on gh errors/timeouts, and the rule
that no secret ever reaches a gh subprocess's argv.
"""

import subprocess

import pytest

from nexus_pipeline.containment import kill_switch


def _completed(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["gh"], returncode=returncode, stdout=stdout, stderr=""
    )


def _fake_run_gh(variable_result, label_result):
    """Return a stand-in for kill_switch._run_gh that dispatches on gh subcommand."""

    def _run(args):
        if args[0] == "variable":
            return variable_result
        return label_result

    return _run


def test_halted_when_autonomy_variable_is_off(monkeypatch):
    monkeypatch.setattr(
        kill_switch,
        "_run_gh",
        _fake_run_gh(_completed("off"), _completed("[]")),
    )
    assert kill_switch.is_halted() is True


def test_halted_when_halt_label_present(monkeypatch):
    monkeypatch.setattr(
        kill_switch,
        "_run_gh",
        _fake_run_gh(_completed("on"), _completed('[{"number": 42}]')),
    )
    assert kill_switch.is_halted() is True


def test_not_halted_when_both_clear(monkeypatch):
    monkeypatch.setattr(
        kill_switch,
        "_run_gh",
        _fake_run_gh(_completed("on"), _completed("[]")),
    )
    assert kill_switch.is_halted() is False


def test_gh_error_on_variable_check_fails_closed(monkeypatch):
    monkeypatch.setattr(
        kill_switch,
        "_run_gh",
        _fake_run_gh(_completed("", returncode=1), _completed("[]")),
    )
    assert kill_switch.is_halted() is True


def test_gh_error_on_label_check_fails_closed(monkeypatch):
    monkeypatch.setattr(
        kill_switch,
        "_run_gh",
        _fake_run_gh(_completed("on"), _completed("", returncode=1)),
    )
    assert kill_switch.is_halted() is True


def test_gh_timeout_fails_closed(monkeypatch):
    # kill_switch._run_gh contracts to return None on a timeout; is_halted
    # must treat that the same as any other unreadable-gh-output case.
    monkeypatch.setattr(kill_switch, "_run_gh", lambda args: None)
    assert kill_switch.is_halted() is True


def test_run_gh_returns_none_on_subprocess_timeout(monkeypatch):
    def _fake_subprocess_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="gh", timeout=15)

    monkeypatch.setattr(kill_switch.subprocess, "run", _fake_subprocess_run)
    assert kill_switch._run_gh(["variable", "get", "PIPELINE_AUTONOMY"]) is None


def test_gh_missing_binary_fails_closed(monkeypatch):
    def _fake_subprocess_run(*args, **kwargs):
        raise FileNotFoundError("gh not found")

    monkeypatch.setattr(kill_switch.subprocess, "run", _fake_subprocess_run)
    assert kill_switch.is_halted() is True


def test_assert_not_halted_raises_when_halted(monkeypatch):
    monkeypatch.setattr(
        kill_switch,
        "_run_gh",
        _fake_run_gh(_completed("off"), _completed("[]")),
    )
    with pytest.raises(kill_switch.PipelineHalted):
        kill_switch.assert_not_halted()


def test_assert_not_halted_passes_when_clear(monkeypatch):
    monkeypatch.setattr(
        kill_switch,
        "_run_gh",
        _fake_run_gh(_completed("on"), _completed("[]")),
    )
    kill_switch.assert_not_halted()  # must not raise


def test_no_secret_reaches_gh_subprocess_argv(monkeypatch):
    sentinel_token = "sk-live-secret-should-never-appear-in-argv"
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", sentinel_token)
    captured_argv: list[list[str]] = []

    def _fake_subprocess_run(args, **kwargs):
        captured_argv.append(list(args))
        return _completed("on")

    monkeypatch.setattr(kill_switch.subprocess, "run", _fake_subprocess_run)

    kill_switch.is_halted()

    assert captured_argv, "expected at least one gh invocation"
    for argv in captured_argv:
        for token in argv:
            assert sentinel_token not in token
