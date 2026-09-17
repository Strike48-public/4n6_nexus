"""Tests for role-scoped tool authorization at the MCP boundary (SFE-l7mp).

A least-privilege dimension layered ON TOP of the per-arg allowlist: the arg
allowlist governs *how* a tool may run; the role registry governs *who* may run
it. Each forensic tool is tagged with the analyst roles permitted to call it; a
call whose role is not authorized is refused at the same chokepoint as an arg
violation (and audited identically -- see test_mcp_role_wiring.py).

Enforcement is OPT-IN: when no role is supplied the boundary behaves exactly as
before, so the existing MCP guardrail suite is unaffected.
"""

from __future__ import annotations

import pytest

from sift_find_evil.mcp.guardrails import (
    GuardrailViolation,
    ToolGuard,
    ToolPolicy,
    get_tools_for_role,
    role_can_use,
    ROLE_ACCESS,
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
    """A guard over the full default tool set so role gating is meaningful."""
    from sift_find_evil.mcp.server import default_policies

    return ToolGuard(
        policies=default_policies(),
        evidence_root=evidence_root,
        max_consecutive_failures=3,
    )


# --------------------------------------------------------------------------
# The registry itself is derivable and self-consistent
# --------------------------------------------------------------------------


def test_registry_covers_every_forensic_tool():
    # Every tool that has a default policy must be reachable by at least one
    # role -- otherwise a tool would be exposed at the boundary yet callable by
    # no role, an orphan the role gate would silently deny for every caller.
    from sift_find_evil.mcp.server import default_policies

    reachable = set().union(*ROLE_ACCESS.values())
    for tool in default_policies():
        assert tool in reachable, f"{tool} is reachable by no role in ROLE_ACCESS"


def test_get_tools_for_role_returns_scoped_set():
    disk = get_tools_for_role("disk_analyst")
    assert "mftecmd" in disk
    assert "pecmd" in disk
    assert "evtxecmd" in disk
    assert "recmd" in disk
    assert "sleuthkit" in disk
    # A disk analyst has no business running the network capture tool.
    assert "tshark" not in disk


def test_get_tools_for_role_memory_and_network_are_narrow():
    assert get_tools_for_role("memory_analyst") == {"volatility"}
    assert get_tools_for_role("network_analyst") == {"tshark"}


def test_unknown_role_authorizes_nothing():
    # An unrecognized role is deny-by-default (empty allowed set), NOT allow-all.
    assert get_tools_for_role("intruder") == set()


# --------------------------------------------------------------------------
# role_can_use is the single predicate the boundary consults
# --------------------------------------------------------------------------


def test_role_can_use_matches_registry():
    assert role_can_use("memory_analyst", "volatility") is True
    assert role_can_use("memory_analyst", "tshark") is False
    assert role_can_use("network_analyst", "tshark") is True


# --------------------------------------------------------------------------
# Verifier: READ-ONLY TIEBREAKER set (operator decision 2026-08-12).
# Not the blanket "no forensic tools" the gallery states -- our dfir-verifier
# resolves contradictions via a live psscan / Event-Log tiebreaker call.
# --------------------------------------------------------------------------


def test_verifier_has_readonly_tiebreaker_tools():
    verifier = get_tools_for_role("verifier")
    # The tiebreaker lookups the self-correction loop actually performs.
    assert "volatility" in verifier  # psscan / pslist tiebreaker
    assert "evtxecmd" in verifier  # Event Log 4688 tiebreaker


def test_verifier_cannot_spawn_jobs_or_unrelated_tools():
    verifier = get_tools_for_role("verifier")
    # The verifier re-runs a narrow read-only lookup, never a disk image listing
    # or a detached job.
    assert "sleuthkit" not in verifier
    assert "start_job" not in verifier


# --------------------------------------------------------------------------
# ToolGuard.check enforces the role when one is supplied
# --------------------------------------------------------------------------


def test_check_allows_authorized_role(guard, evidence_root):
    # memory_analyst -> volatility is authorized; should not raise.
    guard.check(
        "volatility",
        ["-f", str(evidence_root / "memory.raw"), "-r", "json", "windows.pslist"],
        role="memory_analyst",
    )


def test_check_blocks_unauthorized_role(guard, evidence_root):
    # network_analyst calling volatility: args are valid, but the ROLE is not.
    with pytest.raises(GuardrailViolation) as exc:
        guard.check(
            "volatility",
            ["-f", str(evidence_root / "memory.raw"), "-r", "json", "windows.pslist"],
            role="network_analyst",
        )
    msg = str(exc.value).lower()
    assert "role" in msg
    assert "network_analyst" in str(exc.value)


def test_check_unknown_role_is_denied_when_role_supplied(guard, evidence_root):
    with pytest.raises(GuardrailViolation):
        guard.check(
            "volatility",
            ["-f", str(evidence_root / "memory.raw"), "-r", "json", "windows.pslist"],
            role="intruder",
        )


def test_check_role_match_is_case_insensitive(guard, evidence_root):
    # A caller whose agent id arrives mis-cased still resolves to the canonical
    # lowercase role rather than being wrongly denied (fail-closed either way).
    guard.check(
        "volatility",
        ["-f", str(evidence_root / "memory.raw"), "-r", "json", "windows.pslist"],
        role="Memory_Analyst",
    )


def test_check_role_match_is_whitespace_insensitive(guard, evidence_root):
    # A space-padded agent id from an upstream caller must not cause a cosmetic
    # false-deny (review finding #4): normalization strips before lookup.
    guard.check(
        "volatility",
        ["-f", str(evidence_root / "memory.raw"), "-r", "json", "windows.pslist"],
        role="  memory_analyst  ",
    )


# --------------------------------------------------------------------------
# Dispatch roles: own no forensic tool, but manage the job queue (finding #1)
# --------------------------------------------------------------------------


def test_dispatch_roles_own_no_forensic_tool():
    # The dispatch roles are exactly the empty-set entries in ROLE_ACCESS.
    for role in ("orchestrator", "lead", "triage"):
        assert get_tools_for_role(role) == set()


def test_is_dispatch_role_identifies_dispatch_roles():
    from sift_find_evil.mcp.guardrails import is_dispatch_role

    assert is_dispatch_role("orchestrator") is True
    assert is_dispatch_role("lead") is True
    assert is_dispatch_role("triage") is True
    # Case/space-insensitive, mirroring check()'s normalization.
    assert is_dispatch_role("  Orchestrator ") is True
    # Analysts and verifier are NOT dispatch roles.
    assert is_dispatch_role("memory_analyst") is False
    assert is_dispatch_role("verifier") is False
    assert is_dispatch_role(None) is False
    assert is_dispatch_role("intruder") is False


# --------------------------------------------------------------------------
# Backward compatibility: role=None preserves legacy behavior exactly
# --------------------------------------------------------------------------


def test_check_without_role_is_legacy_behavior(guard, evidence_root):
    # No role supplied -> only the arg allowlist applies, as before.
    guard.check(
        "tshark",
        ["-r", str(evidence_root / "memory.raw")],
        # role omitted entirely
    )


def test_check_without_role_still_enforces_arg_allowlist(guard, evidence_root):
    # Dropping role enforcement must NOT weaken the arg allowlist.
    with pytest.raises(GuardrailViolation):
        guard.check("mftecmd", ["-f", str(evidence_root / "$MFT"), "--write"])


# --------------------------------------------------------------------------
# A tool no role governs is outside the role dimension (defers to arg allowlist)
# --------------------------------------------------------------------------


def test_ungoverned_tool_defers_to_arg_allowlist(evidence_root):
    # A bespoke tool with its own policy that NO role claims must not be blocked
    # by the role gate just because a role was supplied -- the gate governs only
    # role-owned tools. (This is the injection-defense suite's ``echotool`` case.)
    from sift_find_evil.mcp.guardrails import is_role_governed

    policies = {"echotool": ToolPolicy(allowed_flags={"-m"}, value_flags={"-m"})}
    g = ToolGuard(policies=policies, evidence_root=evidence_root)
    assert is_role_governed("echotool") is False
    # A role is supplied, but echotool is ungoverned -> arg allowlist only.
    g.check("echotool", ["-m", "x"], role="disk_analyst")
    # The arg allowlist is still enforced for the ungoverned tool.
    with pytest.raises(GuardrailViolation):
        g.check("echotool", ["--write"], role="disk_analyst")
