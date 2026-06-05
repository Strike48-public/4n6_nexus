"""Live stdio transport round-trip for the Custom MCP server.

Unit tests (test_mcp_fastmcp.py) exercise the dispatch core in-process. This
test closes the last untested seam: it spawns the REAL server over stdio
(`python -m sift_find_evil.mcp`) and drives it with the official MCP client,
proving the transport handshake, tool-schema serialization, and -- most
importantly -- that the architectural guardrail denial survives the wire and is
recorded in the audit log the subprocess writes.

No forensic binaries are needed: the guardrail rejects the out-of-bounds read
BEFORE any tool subprocess would run, so this validates the integrity-critical
"the agent physically cannot" claim over a live transport on any machine.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

# The client-over-stdio stack is part of the official SDK; skip cleanly if a
# slim install lacks it rather than failing the suite.
mcp_client = pytest.importorskip("mcp.client.stdio")
from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

EXPECTED_TOOLS = {"volatility", "mftecmd", "pecmd", "evtxecmd", "recmd", "sleuthkit"}


def _server_params(evidence_root: Path, audit_path: Path) -> StdioServerParameters:
    """Launch params for the real stdio server, with the repo on PYTHONPATH."""
    repo_root = Path(__file__).resolve().parent.parent
    env = {**os.environ, "PYTHONPATH": str(repo_root)}
    return StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "sift_find_evil.mcp",
            "--case-id",
            "INC-2026-001",
            "--evidence-root",
            str(evidence_root),
            "--audit-path",
            str(audit_path),
            "--examiner",
            "roundtrip-test",
        ],
        env=env,
    )


async def _drive(evidence_root: Path, audit_path: Path) -> tuple[set[str], bool]:
    """Connect over stdio: list tools, then attempt an out-of-bounds read.

    Returns (registered tool names, whether the denial was signalled to client).
    """
    async with stdio_client(_server_params(evidence_root, audit_path)) as (
        read,
        write,
    ):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            names = {t.name for t in tools.tools}

            # Drive mftecmd at a path OUTSIDE the evidence root. The guardrail
            # must reject it; over MCP that surfaces as an error result or a
            # raised exception -- either way the client learns it was denied.
            denied = False
            try:
                result = await session.call_tool(
                    "mftecmd",
                    {
                        "mft_file": "/etc/shadow",
                        "output_dir": "/tmp/out",
                        "correlation_id": "corr-roundtrip",
                    },
                )
                denied = bool(getattr(result, "isError", False))
            except Exception:
                denied = True

            return names, denied


def test_stdio_roundtrip_lists_tools_and_enforces_guardrail(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    (evidence_root / "mft.raw").write_bytes(b"fake")
    audit_path = tmp_path / "audit.jsonl"

    names, denied = asyncio.run(_drive(evidence_root, audit_path))

    # 1. The transport handshake + tool listing works over the real wire.
    assert EXPECTED_TOOLS.issubset(
        names
    ), f"missing over stdio: {EXPECTED_TOOLS - names}"

    # 2. The out-of-bounds read was denied to the client.
    assert denied, "guardrail denial must surface to the MCP client"

    # 3. The denial was recorded as tool_blocked in the audit log the SERVER
    #    subprocess wrote -- cross-process proof the boundary fired, not a stub.
    assert audit_path.is_file(), "server must have written the audit log"
    actions = [
        json.loads(line)["action"]
        for line in audit_path.read_text().splitlines()
        if line.strip()
    ]
    assert (
        "tool_blocked" in actions
    ), f"expected a tool_blocked audit entry from the live server; saw {actions}"
