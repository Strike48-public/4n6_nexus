"""Tests for the legacy MCPClient write-flag guard (SFE-0dq).

IMPORTANT: MCPClient is NOT the architectural security boundary. The real
read-only + path-containment enforcement lives in EvidenceMCPServer + ToolGuard
(see test_mcp_server.py / test_mcp_guardrails.py). These tests pin down the
best-effort write-flag rejection on the legacy client path so it cannot be
trivially bypassed by a flag spelling the old substring check missed.
"""

from __future__ import annotations

import pytest

from sift_find_evil.mcp.client import MCPClient


@pytest.fixture
def client():
    return MCPClient()


@pytest.mark.parametrize(
    "command",
    [
        ["tshark", "-w", "/tmp/exfil.pcap"],  # -w as a standalone token
        ["tool", "input.raw", "-w"],  # -w as the FINAL token (old check missed)
        ["vol.py", "--write", "out"],
        ["tool", "--modify", "x"],
        ["tool", "--delete", "x"],
        ["dd", "--write-out=/tmp/x"],  # write flag with attached value
        ["tool", "-W", "x"],  # uppercase variant
    ],
)
def test_write_flags_are_rejected(client, command):
    with pytest.raises(ValueError, match="(?i)write operations not allowed"):
        client.execute_tool(command[0], command)


@pytest.mark.parametrize(
    "command",
    [
        ["vol.py", "-f", "mem.raw", "windows.pslist"],
        ["tshark", "-r", "capture.pcap", "-T", "fields"],
        ["mftecmd", "-f", "$MFT", "--csv", "/out"],  # -d/--csv style dir args, no write
        ["tool", "--password", "secret"],  # contains 'w' but is not a write flag
        ["tool", "--forward", "x"],  # contains 'w' but is not a write flag
    ],
)
def test_legitimate_read_flags_are_allowed_past_the_guard(client, command, monkeypatch):
    """Read-only commands must pass the write-flag guard (then hit subprocess).

    We stub subprocess so the test asserts the guard does not raise; execution
    itself is irrelevant here.
    """

    class _FakeProc:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(
        "sift_find_evil.mcp.client.subprocess.run", lambda *a, **k: _FakeProc()
    )
    result = client.execute_tool(command[0], command)
    assert result.success is True
