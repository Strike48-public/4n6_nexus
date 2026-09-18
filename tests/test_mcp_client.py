"""Tests for the legacy MCPClient exec path, now routed through ToolGuard.

Until SFE-fibx.14 this client enforced only a best-effort write-flag denylist and
ran ``subprocess.run`` directly -- NO path containment. That was a ToolGuard
bypass reachable through exported public API (``EZToolsTool``) and the documented
``cli_mcp`` entrypoint. It now builds the SAME ``ToolGuard`` the shipping
``EvidenceMCPServer`` uses (read-only allowlist + input/output path containment),
so the exported/CLI path can no longer drift into a real hole.

These tests pin that routing: the guard governs every ``execute_tool`` call, and
the write-flag rejection is now subsumed by the deny-by-default allowlist. The
platform gate (SFE-ybki) still runs before spawning.
"""

from __future__ import annotations

import pytest

from sift_find_evil.mcp.client import MCPClient
from sift_find_evil.mcp.guardrails import GuardrailViolation
from sift_find_evil.mcp.tools import EZToolsTool, SleuthKitTool


@pytest.fixture
def evidence_root(tmp_path):
    """A case evidence root (no literal 'evidence' path component, so the
    output-containment check keys only on the configured root here)."""
    root = tmp_path / "ev_root"
    root.mkdir()
    return root


@pytest.fixture
def client(evidence_root):
    return MCPClient(evidence_root=evidence_root)


def _stub_subprocess(monkeypatch, returncode=0, stdout="ok", stderr=""):
    class _FakeProc:
        pass

    proc = _FakeProc()
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    monkeypatch.setattr(
        "sift_find_evil.mcp.client.subprocess.run", lambda *a, **k: proc
    )


# -- the allowlist now governs the legacy path (write flags subsumed) ---------


@pytest.mark.parametrize(
    "command",
    [
        ["tshark", "-r", "cap.pcap", "-w", "out.pcap"],  # -w not on tshark allowlist
        ["vol.py", "--write", "out"],  # unknown flag for volatility
        ["dd", "--write-out=/tmp/x"],  # unknown tool entirely
        ["tool", "--modify", "x"],  # unknown tool
    ],
)
def test_write_capable_or_unknown_invocations_are_denied(client, command):
    """A write flag or unknown tool/flag is refused by the ToolGuard allowlist
    (deny-by-default), replacing the old best-effort write-flag denylist."""
    with pytest.raises(GuardrailViolation):
        client.execute_tool(command[0], command)


# -- the bypass being closed: input/output path containment (SFE-fibx.14) -----


def test_input_path_outside_evidence_is_rejected(client, evidence_root, tmp_path):
    """The core bypass fix: an input path resolving OUTSIDE the evidence root is
    refused. The legacy denylist never checked this."""
    outside = tmp_path / "not_evidence" / "$MFT"
    with pytest.raises(GuardrailViolation, match="(?i)outside the evidence root"):
        client.execute_tool("mftecmd", ["mftecmd", "-f", str(outside)])


def test_output_path_into_evidence_is_rejected(client, evidence_root):
    """An output (--csv) path resolving INSIDE the evidence root is refused, so a
    tool cannot be told to write into read-only evidence."""
    in_mft = evidence_root / "$MFT"
    into_evidence = evidence_root / "out"
    with pytest.raises(GuardrailViolation, match="(?i)evidence"):
        client.execute_tool(
            "mftecmd", ["mftecmd", "-f", str(in_mft), "--csv", str(into_evidence)]
        )


def test_exported_wrapper_path_is_guarded(client, evidence_root):
    """Consumer trace: the EXPORTED EZToolsTool wrapper -- the reachable public
    API named in the issue -- now routes through the guard too. Output into
    evidence via the wrapper is blocked, proving the fix is at the choke point,
    not just the direct call."""
    ez = EZToolsTool(client)
    with pytest.raises(GuardrailViolation):
        ez.mftecmd(evidence_root / "$MFT", evidence_root / "out")


def test_legitimate_read_only_command_passes_the_guard(
    client, evidence_root, tmp_path, monkeypatch
):
    """In-evidence input + out-of-evidence output passes the guard and reaches
    subprocess (stubbed)."""
    _stub_subprocess(monkeypatch)
    in_mft = evidence_root / "$MFT"
    out_dir = tmp_path / "analysis"  # sibling of evidence_root, no 'evidence' part
    result = client.execute_tool(
        "mftecmd", ["mftecmd", "-f", str(in_mft), "--csv", str(out_dir)]
    )
    assert result.success is True


def test_volatility_plugin_positional_passes_the_guard(
    client, evidence_root, monkeypatch
):
    """The Volatility legacy command shape (``-f <mem> -r json windows.pslist``)
    passes: the plugin name is an allowlisted positional, not a path."""
    _stub_subprocess(monkeypatch)
    mem = evidence_root / "mem.raw"
    result = client.execute_tool(
        "volatility", ["vol.py", "-f", str(mem), "-r", "json", "windows.pslist"]
    )
    assert result.success is True


# -- platform gate still runs on the legacy path (SFE-ybki) -------------------


def test_platform_unsupported_tool_is_refused_before_spawning(
    client, evidence_root, monkeypatch
):
    monkeypatch.setattr("sift_find_evil.mcp.client.platform.system", lambda: "Linux")

    def _must_not_spawn(*_a, **_k):  # pragma: no cover - asserts non-invocation
        raise AssertionError("subprocess.run must not be reached for a gated tool")

    monkeypatch.setattr("sift_find_evil.mcp.client.subprocess.run", _must_not_spawn)

    prefetch = evidence_root / "prefetch"
    with pytest.raises(RuntimeError, match="(?i)not supported on this platform"):
        client.execute_tool("pecmd", ["pecmd", "-d", str(prefetch)])

    # An environment condition must not trip the circuit breaker.
    assert client.failure_count == 0


def test_cross_platform_tool_still_runs_on_legacy_client(
    client, evidence_root, monkeypatch
):
    monkeypatch.setattr("sift_find_evil.mcp.client.platform.system", lambda: "Linux")
    spawned = {}

    class _FakeProc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def _fake_run(cmd, **_k):
        spawned["cmd"] = cmd
        return _FakeProc()

    monkeypatch.setattr("sift_find_evil.mcp.client.subprocess.run", _fake_run)

    result = client.execute_tool(
        "mftecmd", ["mftecmd", "-f", str(evidence_root / "$MFT")]
    )

    assert result.success is True
    assert spawned["cmd"][0] == "mftecmd"


def test_spawned_binary_is_derived_from_tool_key_not_command0(
    client, evidence_root, monkeypatch
):
    """The spawned binary is a pure function of the guard-checked ``tool`` key.

    A caller could pair a permissive policy key with a hostile command[0]
    (tool='tshark' allows -r, but command[0]='sh'). The guard vets the args
    against tshark, so without key-derived binary resolution ``sh`` would spawn.
    Assert the injected command[0] is IGNORED and ``tool_binary('tshark')`` runs.
    """
    spawned = {}

    class _FakeProc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def _fake_run(cmd, **_k):
        spawned["cmd"] = cmd
        return _FakeProc()

    monkeypatch.setattr("sift_find_evil.mcp.client.subprocess.run", _fake_run)

    client.execute_tool("tshark", ["sh", "-r", str(evidence_root / "cap.pcap")])

    assert spawned["cmd"][0] == "tshark", "caller's command[0] must not be spawned"
    assert "sh" not in spawned["cmd"][:1]


def test_evidence_root_is_required():
    """Containment is meaningless without a root: there is no ungated fallback."""
    with pytest.raises(TypeError):
        MCPClient()  # type: ignore[call-arg]


# -- SFE-kek8: retired wrappers that did not map to a boundary capability -----


def test_surviving_sleuthkit_fls_routes_through_the_guard(
    client, evidence_root, monkeypatch
):
    """fls is the one exposed sleuthkit capability and still routes correctly:
    an in-evidence image passes and spawns the resolved 'fls' binary."""
    _stub_subprocess(monkeypatch)
    sk = SleuthKitTool(client)
    result = sk.fls(evidence_root / "disk.img")
    assert result.success is True


def test_fls_image_outside_evidence_is_rejected(client, tmp_path):
    """The kept wrapper is genuinely guarded, not merely retained."""
    sk = SleuthKitTool(client)
    with pytest.raises(GuardrailViolation, match="(?i)outside the evidence root"):
        sk.fls(tmp_path / "not_evidence" / "disk.img")


def test_retired_wrappers_are_gone():
    """PlasoTool and the misrouting SleuthKitTool methods were removed (SFE-kek8):
    they did not map to the guarded boundary and had no consumers."""
    import sift_find_evil.mcp as mcp_pkg

    assert not hasattr(mcp_pkg, "PlasoTool")
    assert "PlasoTool" not in mcp_pkg.__all__
    for gone in ("mmls", "icat", "mactime"):
        assert not hasattr(
            SleuthKitTool, gone
        ), f"SleuthKitTool.{gone} should be retired"
