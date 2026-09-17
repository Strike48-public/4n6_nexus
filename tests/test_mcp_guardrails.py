"""Tests for MCP-boundary architectural guardrails (Constraint Implementation).

These guardrails are enforced at the single chokepoint every agent tool call
passes through, so an agent cannot bypass them -- they are architectural, not
prompt-based. Covers:
- Per-tool argument allowlist (deny-by-default)
- Evidence-path containment (no reads outside the evidence root, no traversal)
- Circuit breaker (N consecutive failures opens the boundary)

The bypass attempts here ARE the bypass-test evidence for the Accuracy Report.
"""

from __future__ import annotations

import pytest

from sift_find_evil.mcp.guardrails import (
    CircuitBreakerOpen,
    GuardrailViolation,
    ToolGuard,
    ToolPolicy,
    tool_supported_on_platform,
)


@pytest.fixture
def evidence_root(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "$MFT").write_bytes(b"fake mft")
    (root / "memory.raw").write_bytes(b"fake mem")
    return root


@pytest.fixture
def guard(evidence_root):
    # mftecmd: read a file (-f) and write CSV to an OUTPUT dir (--csv) -- the csv
    # target is an output path, not evidence, so it is allowed but path-checked
    # against the output root, not the evidence root.
    policies = {
        "mftecmd": ToolPolicy(
            allowed_flags={"-f", "--csv"},
            path_flags={"-f"},  # -f points at evidence (containment-checked)
            value_flags={"--csv"},  # --csv consumes an output dir (not evidence)
        ),
        "volatility": ToolPolicy(
            allowed_flags={"-f", "-r", "windows.pslist", "windows.malfind"},
            path_flags={"-f"},
            value_flags={"-r"},  # -r consumes a format token (e.g. json)
        ),
        # sleuthkit (SFE-qdlk): fls -r -o <offset> <image>. The image is a
        # POSITIONAL evidence path (fls has no -f flag), so it is contained via
        # positional_path rather than a path_flag.
        "sleuthkit": ToolPolicy(
            allowed_flags={"-r", "-o"},
            value_flags={"-o"},  # -o consumes a numeric offset (not a path)
            positional_path=True,  # a bare non-flag token is an evidence path
        ),
    }
    return ToolGuard(
        policies=policies,
        evidence_root=evidence_root,
        max_consecutive_failures=3,
    )


# --------------------------------------------------------------------------
# Per-tool argument allowlist (deny-by-default)
# --------------------------------------------------------------------------


def test_allows_known_readonly_invocation(guard, evidence_root):
    # Should not raise
    guard.check("mftecmd", ["-f", str(evidence_root / "$MFT"), "--csv", "/tmp/out"])


def test_rejects_unknown_flag_not_on_allowlist(guard, evidence_root):
    with pytest.raises(GuardrailViolation) as exc:
        guard.check("mftecmd", ["-f", str(evidence_root / "$MFT"), "--write"])
    assert "--write" in str(exc.value)


def test_rejects_write_flag_even_with_novel_spelling(guard, evidence_root):
    # The old substring denylist would miss these; deny-by-default catches them.
    for bad in ["--wibble", "-w", "--modify", "--delete", "--output-write"]:
        with pytest.raises(GuardrailViolation):
            guard.check("mftecmd", ["-f", str(evidence_root / "$MFT"), bad])


def test_rejects_unknown_tool_entirely(guard, evidence_root):
    with pytest.raises(GuardrailViolation) as exc:
        guard.check("rm", ["-rf", str(evidence_root)])
    assert "rm" in str(exc.value)


def test_rejects_volatility_plugin_not_on_allowlist(guard, evidence_root):
    # An agent must not invoke an unlisted (potentially write-capable) plugin.
    with pytest.raises(GuardrailViolation):
        guard.check(
            "volatility",
            ["-f", str(evidence_root / "memory.raw"), "windows.memmap.dump"],
        )


# --------------------------------------------------------------------------
# Evidence-path containment
# --------------------------------------------------------------------------


def test_rejects_path_outside_evidence_root(guard):
    with pytest.raises(GuardrailViolation) as exc:
        guard.check("mftecmd", ["-f", "/etc/shadow", "--csv", "/tmp/out"])
    assert "evidence" in str(exc.value).lower() or "shadow" in str(exc.value)


def test_rejects_path_traversal_escape(guard, evidence_root):
    sneaky = str(evidence_root / ".." / ".." / "etc" / "passwd")
    with pytest.raises(GuardrailViolation):
        guard.check("mftecmd", ["-f", sneaky, "--csv", "/tmp/out"])


def test_allows_path_inside_evidence_root(guard, evidence_root):
    guard.check(
        "volatility",
        ["-f", str(evidence_root / "memory.raw"), "-r", "json", "windows.pslist"],
    )


def test_only_path_flags_are_path_checked(guard, evidence_root):
    # "-r json" is a format arg, not a path; must not be rejected as a bad path.
    guard.check(
        "volatility",
        ["-f", str(evidence_root / "memory.raw"), "-r", "json", "windows.malfind"],
    )


# --------------------------------------------------------------------------
# Positional evidence path (SFE-qdlk): tools like `fls` take the image as a
# bare positional token, not behind a -f flag. positional_path=True contains it.
# --------------------------------------------------------------------------


def test_allows_positional_path_inside_evidence_root(guard, evidence_root):
    # fls -r -o 63 <image> with the image inside the root must pass.
    (evidence_root / "disk.E01").write_bytes(b"fake image")
    guard.check("sleuthkit", ["-r", "-o", "63", str(evidence_root / "disk.E01")])


def test_rejects_positional_path_outside_evidence_root(guard):
    # A positional image path outside the root must be contained (rejected).
    with pytest.raises(GuardrailViolation) as exc:
        guard.check("sleuthkit", ["-r", "-o", "63", "/etc/shadow"])
    assert "evidence" in str(exc.value).lower() or "shadow" in str(exc.value)


def test_rejects_positional_path_traversal_escape(guard, evidence_root):
    sneaky = str(evidence_root / ".." / ".." / "etc" / "passwd")
    with pytest.raises(GuardrailViolation):
        guard.check("sleuthkit", ["-r", "-o", "63", sneaky])


def test_offset_value_is_not_path_checked(guard, evidence_root):
    # "-o 63" is a numeric offset, not a path; it must not be containment-checked
    # (a bare "63" is not a filesystem path and must not be rejected as one).
    (evidence_root / "disk.E01").write_bytes(b"fake image")
    guard.check("sleuthkit", ["-o", "63", str(evidence_root / "disk.E01")])


def test_positional_token_still_rejected_when_not_positional_path(guard, evidence_root):
    # Regression guard: a tool WITHOUT positional_path (volatility) must still
    # reject a bare positional that is not on its allowlist -- the new behavior
    # must not leak into tools that never opted in.
    with pytest.raises(GuardrailViolation):
        guard.check(
            "volatility",
            ["-f", str(evidence_root / "memory.raw"), "/etc/shadow"],
        )


# --------------------------------------------------------------------------
# Circuit breaker
# --------------------------------------------------------------------------


def test_circuit_opens_after_consecutive_failures(guard, evidence_root):
    args = ["-f", str(evidence_root / "$MFT"), "--csv", "/tmp/out"]
    guard.check("mftecmd", args)  # passes guardrail
    for _ in range(3):
        guard.record_failure()
    with pytest.raises(CircuitBreakerOpen):
        guard.check("mftecmd", args)


def test_success_resets_failure_count(guard, evidence_root):
    args = ["-f", str(evidence_root / "$MFT"), "--csv", "/tmp/out"]
    guard.record_failure()
    guard.record_failure()
    guard.record_success()  # reset
    guard.record_failure()
    guard.record_failure()
    # only 2 consecutive now -> still closed
    guard.check("mftecmd", args)  # should not raise


def test_manual_reset_closes_circuit(guard, evidence_root):
    args = ["-f", str(evidence_root / "$MFT"), "--csv", "/tmp/out"]
    for _ in range(3):
        guard.record_failure()
    guard.reset_circuit()
    guard.check("mftecmd", args)  # should not raise


# -- platform-gated tools (SFE-ybki) ----------------------------------------
#
# A tool whose binary resolves is not necessarily a tool that can do work.
# PECmd installs fine on Linux (a `dotnet PECmd.dll` wrapper on PATH) but
# refuses to run -- it prints "Non-Windows platforms not supported..." and
# EXITS 0, so the exec boundary scored it `success: True` for a run that
# produced nothing. These tests pin the single-source predicate that both
# doorways (advertise + exec) consult.


def test_pecmd_is_unsupported_on_linux():
    assert tool_supported_on_platform("pecmd", system=lambda: "Linux") is False


def test_pecmd_is_supported_on_windows():
    assert tool_supported_on_platform("pecmd", system=lambda: "Windows") is True


def test_cross_platform_eztools_are_supported_on_linux():
    # Only PECmd is Windows-bound; the other three EZ Tools run fine on Linux
    # and must NOT be caught by the gate (SFE-ybki scope guard).
    for tool in ("mftecmd", "evtxecmd", "recmd"):
        assert tool_supported_on_platform(tool, system=lambda: "Linux") is True


def test_unknown_tool_is_supported_by_default():
    # The gate is an explicit denylist, not an allowlist: a tool with no
    # platform constraint must stay runnable, or adding a tool silently
    # disables it.
    assert tool_supported_on_platform("tshark", system=lambda: "Linux") is True


def test_platform_check_defaults_to_real_platform():
    # The default argument must be the live platform, so a caller that omits
    # `system` is still gated (the exec doorway calls it with no override).
    import platform as _platform

    expected = _platform.system() == "Windows"
    assert tool_supported_on_platform("pecmd") is expected
