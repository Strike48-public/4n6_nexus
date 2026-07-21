"""Adversarial guardrail-bypass regression suite for the MCP tool boundary.

These tests prove that the read-only, deny-by-default guardrails in
``sift_find_evil/mcp/guardrails.py`` actually hold against the bypass vectors an
adversarial agent would try. They exercise the real ``ToolGuard`` boundary check
against the production ``default_policies`` (from ``server.py``) as well as a
minimal synthetic policy, and assert every rejection path plus a pristine
positive control.

Verified empirically against the live API, not by reasoning about the diff.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sift_find_evil.mcp.guardrails import (
    CircuitBreakerOpen,
    GuardrailViolation,
    ToolGuard,
    ToolPolicy,
)
from sift_find_evil.mcp.server import default_policies

# A set of clearly destructive / write / modify verbs an attacker might smuggle
# in. None of these should ever appear in a read-only policy's allowed flags.
DESTRUCTIVE_FLAGS: frozenset[str] = frozenset(
    {
        "-w",
        "--write",
        "-D",
        "--delete",
        "--rm",
        "-rm",
        "--overwrite",
        "--truncate",
        "--move",
        "-mv",
        "--modify",
        "--dump-dir",
        "--wipe",
        "--format",
    }
)


def _make_guard(tmp_path: Path, max_failures: int = 3) -> ToolGuard:
    """Build a guard over a minimal read-only volatility-shaped policy."""
    policies = {
        "volatility": ToolPolicy(
            allowed_flags={"-f", "-r", "windows.pslist"},
            path_flags={"-f"},
            value_flags={"-r"},
        )
    }
    return ToolGuard(
        policies=policies,
        evidence_root=tmp_path,
        max_consecutive_failures=max_failures,
    )


# -- deny-by-default: unknown tools and flags --------------------------------


def test_unknown_tool_is_rejected(tmp_path: Path) -> None:
    # Arrange
    guard = _make_guard(tmp_path)

    # Act / Assert
    with pytest.raises(GuardrailViolation):
        guard.check("rm", ["-rf", "/"])


def test_unknown_flag_is_rejected(tmp_path: Path) -> None:
    # Arrange
    guard = _make_guard(tmp_path)

    # Act / Assert -- a write flag the policy never declared
    with pytest.raises(GuardrailViolation):
        guard.check("volatility", ["--dump", "/tmp/out"])


def test_bare_positional_not_on_allowlist_is_rejected(tmp_path: Path) -> None:
    # Arrange
    guard = _make_guard(tmp_path)

    # Act / Assert -- a plugin name that is not whitelisted
    with pytest.raises(GuardrailViolation):
        guard.check("volatility", ["windows.filescan"])


# -- evidence-path containment ----------------------------------------------


def test_path_traversal_vector_is_rejected(tmp_path: Path) -> None:
    # Arrange
    guard = _make_guard(tmp_path)

    # Act / Assert
    with pytest.raises(GuardrailViolation):
        guard.check("volatility", ["-f", "../../etc/passwd"])


def test_absolute_path_outside_evidence_root_is_rejected(tmp_path: Path) -> None:
    # Arrange
    guard = _make_guard(tmp_path)

    # Act / Assert
    with pytest.raises(GuardrailViolation):
        guard.check("volatility", ["-f", "/etc/passwd"])


def test_nul_byte_in_path_arg_is_rejected(tmp_path: Path) -> None:
    """A NUL byte in a path arg is rejected before any tool runs.

    The current implementation canonicalises via ``Path.resolve()``, which raises
    ``ValueError('embedded null byte')`` for NUL vectors. That is still a hard
    rejection (the call never reaches subprocess execution); we assert the
    rejection rather than the specific exception subclass so the test tracks the
    real behavior. If containment is later hardened to raise ``GuardrailViolation``
    for this vector, that also satisfies the assertion.
    """
    # Arrange
    guard = _make_guard(tmp_path)

    # Act / Assert
    with pytest.raises((GuardrailViolation, ValueError)):
        guard.check("volatility", ["-f", "evidence\x00.raw"])


# -- allowlist / destructive-verb disjointness ------------------------------


def test_default_policy_allowed_flags_exclude_destructive_verbs() -> None:
    """No registered read-only policy declares any destructive/write flag."""
    # Arrange
    policies = default_policies()

    # Act / Assert
    for tool, policy in policies.items():
        intersection = policy.allowed_flags & DESTRUCTIVE_FLAGS
        assert not intersection, (
            f"Policy '{tool}' unexpectedly permits destructive flags: "
            f"{sorted(intersection)}"
        )


def test_tshark_capture_write_flag_is_absent() -> None:
    """The tshark capture-write flag (-w) must not be reachable."""
    # Arrange
    policies = default_policies()

    # Act
    tshark = policies["tshark"]

    # Assert
    assert "-w" not in tshark.allowed_flags


# -- circuit breaker ---------------------------------------------------------


def test_n_consecutive_failures_open_circuit_breaker(tmp_path: Path) -> None:
    # Arrange
    guard = _make_guard(tmp_path, max_failures=3)
    valid_target = str(tmp_path / "mem.raw")

    # Act -- record exactly the threshold number of failures
    for _ in range(3):
        guard.record_failure()

    # Assert -- the breaker is open and even a valid call is refused
    assert guard.circuit_open is True
    with pytest.raises(CircuitBreakerOpen):
        guard.check("volatility", ["-f", valid_target, "-r", "json", "windows.pslist"])


def test_success_resets_failure_count(tmp_path: Path) -> None:
    # Arrange
    guard = _make_guard(tmp_path, max_failures=3)
    guard.record_failure()
    guard.record_failure()

    # Act
    guard.record_success()

    # Assert
    assert guard.failure_count == 0
    assert guard.circuit_open is False


# -- inverse control: a pristine valid call still succeeds -------------------


def test_pristine_valid_call_is_permitted(tmp_path: Path) -> None:
    """Negative control: a well-formed read-only invocation passes cleanly."""
    # Arrange
    guard = _make_guard(tmp_path)
    contained = tmp_path / "case01" / "mem.raw"
    contained.parent.mkdir(parents=True, exist_ok=True)
    contained.write_bytes(b"")

    # Act / Assert -- returns None (no raise)
    assert (
        guard.check(
            "volatility",
            ["-f", str(contained), "-r", "json", "windows.pslist"],
        )
        is None
    )


def test_pristine_valid_call_against_default_policies(tmp_path: Path) -> None:
    """The production default policies admit a legitimate read-only mftecmd call."""
    # Arrange
    guard = ToolGuard(
        policies=default_policies(),
        evidence_root=tmp_path,
        max_consecutive_failures=3,
    )
    mft = tmp_path / "MFT.raw"
    mft.write_bytes(b"")
    out_dir = tmp_path / "out"

    # Act / Assert -- -f is an evidence path, --csv output dir is not containment-checked
    assert guard.check("mftecmd", ["-f", str(mft), "--csv", str(out_dir)]) is None
