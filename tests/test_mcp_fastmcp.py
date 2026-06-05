"""Tests for the FastMCP registration + stdio launcher.

`build_fastmcp` must register a typed MCP tool for every forensic tool the
agents are told to use (the dfir-* analyst definitions reference mftecmd, pecmd,
evtxecmd, recmd, sleuthkit, volatility). Each registered tool must delegate to
`EvidenceMCPServer.run_tool`, so the architectural guardrails and audit logging
are unavoidable over the live transport. The stdio launcher
(`sift_find_evil.mcp.__main__`) must build a server + FastMCP app without
requiring a live transport to test.
"""

from __future__ import annotations

import asyncio

import pytest

from sift_find_evil.mcp.server import (
    EvidenceMCPServer,
    build_fastmcp,
    default_policies,
)

# Every tool an analyst agent is allowed to drive must be exposed as a typed MCP
# tool. This is the set in default_policies() (the read-only policy allowlist).
EXPECTED_TOOLS = {
    "volatility",
    "mftecmd",
    "pecmd",
    "evtxecmd",
    "recmd",
    "sleuthkit",
    "tshark",
}


@pytest.fixture
def evidence_root(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "mft.raw").write_bytes(b"fake mft")
    return root


@pytest.fixture
def server(tmp_path, evidence_root):
    return EvidenceMCPServer(
        case_id="INC-2026-001",
        evidence_root=evidence_root,
        audit_path=tmp_path / "audit.jsonl",
        examiner="jtomek",
    )


def _registered_tool_names(mcp) -> set[str]:
    return {t.name for t in asyncio.run(mcp.list_tools())}


def test_fastmcp_registers_a_tool_for_every_policy(server):
    """No agent should reference a forensic tool the MCP server doesn't expose."""
    mcp = build_fastmcp(server)
    registered = _registered_tool_names(mcp)
    assert EXPECTED_TOOLS.issubset(
        registered
    ), f"missing MCP tools: {EXPECTED_TOOLS - registered}"


def test_registered_tools_match_default_policies(server):
    """The exposed tool set tracks the read-only policy allowlist exactly."""
    mcp = build_fastmcp(server)
    registered = _registered_tool_names(mcp)
    assert registered == set(
        default_policies()
    ), "every registered MCP tool must have a read-only policy and vice versa"


def test_registered_tool_routes_through_guardrail_and_audit(server, monkeypatch):
    """A registered tool delegates to run_tool, so a denial is still audited."""
    mcp = build_fastmcp(server)
    tools = {t.name: t for t in asyncio.run(mcp.list_tools())}
    assert "mftecmd" in tools

    # Drive the registered mftecmd tool with a path OUTSIDE the evidence root.
    # It must be denied by the guardrail and the denial recorded as tool_blocked,
    # proving the FastMCP layer cannot route around the boundary.
    with pytest.raises(Exception):
        asyncio.run(
            mcp.call_tool(
                "mftecmd",
                {
                    "mft_file": "/etc/shadow",
                    "output_dir": "/tmp/out",
                    "correlation_id": "corr-x",
                },
            )
        )
    blocked = [
        e
        for e in server.audit_logger.get_recent(limit=10)
        if e.action == "tool_blocked"
    ]
    assert blocked, "a denial through the FastMCP layer must be audited as tool_blocked"


def test_stdio_launcher_builds_server_and_app(tmp_path, evidence_root):
    """The __main__ launcher composes a server + FastMCP app without a transport."""
    from sift_find_evil.mcp.__main__ import build_app

    mcp = build_app(
        case_id="INC-2026-001",
        evidence_root=evidence_root,
        audit_path=tmp_path / "audit.jsonl",
        examiner="jtomek",
    )
    registered = _registered_tool_names(mcp)
    assert EXPECTED_TOOLS.issubset(registered)
