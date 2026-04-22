"""VolatilityRunner — subprocess wrapper around Volatility 3.

Volatility 3 exposes a plugin registry through ``vol``; we invoke it with
``-r json`` and parse the resulting tree-of-dicts into immutable
dataclasses. We deliberately do NOT import Volatility's framework directly
because:

1. Its public API is the CLI — the Python entry points change between
   minor releases and are not version-stable.
2. A crashed plugin should not take the whole analysis process down;
   running out-of-process means a segfault in libyara/pefile dependencies
   cannot brick the engine.
3. We can swap the runner for MemProcFS / a remote Velociraptor endpoint
   later without touching detectors.

Missing install policy
----------------------
``vol`` not being on PATH raises ``MissingVolatilityError`` (a subclass of
RuntimeError) so callers can distinguish it from a generic CommandNotFound
and surface a clean install hint. This mirrors ``MissingYaraError`` in
``yara_scan.scanner``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

# The five Windows plugins SFE-ig6 targets. Keep them as a frozenset so
# detectors can reference them without worrying about mutation, and so
# typos at the call site fail fast instead of silently invoking an
# unknown plugin.
WINDOWS_PLUGINS: frozenset[str] = frozenset(
    {
        "windows.pslist.PsList",
        "windows.psscan.PsScan",
        "windows.netscan.NetScan",
        "windows.malfind.Malfind",
        "windows.cmdline.CmdLine",
    }
)

_DEFAULT_TIMEOUT_SEC = 600  # 10 minutes; large dumps take a while to symbolize


class MissingVolatilityError(RuntimeError):
    """Raised when the ``vol`` executable is not on PATH.

    Distinct from ``FileNotFoundError`` so callers can distinguish a
    missing install from a missing memory image and print an actionable
    ``pip install volatility3`` hint.
    """


class PluginExecutionError(RuntimeError):
    """Raised when a Volatility plugin exits non-zero.

    Wraps the plugin name, exit code, and captured stderr so callers can
    log one line and move on. We do NOT re-raise the underlying
    CalledProcessError because its default string is noisy (full argv)
    and leaks the memory image path into logs.
    """

    def __init__(self, plugin: str, returncode: int, stderr: str):
        super().__init__(
            f"volatility plugin {plugin!r} failed "
            f"(exit {returncode}): {stderr.strip().splitlines()[-1] if stderr else 'no stderr'}"
        )
        self.plugin = plugin
        self.returncode = returncode
        self.stderr = stderr


# -- normalized row dataclasses --------------------------------------------
#
# One dataclass per plugin shape the detectors actually consume. We keep
# these immutable (frozen=True) for the same reason YaraMatch is: they
# cross the detector boundary, and any mutation there is a bug, not a
# feature.
#
# Fields map to Volatility 3 column names verbatim but use snake_case so
# downstream Python code is idiomatic. The raw_row dict is preserved on
# every row so future detectors can pull out Volatility columns we did
# not project into a typed field.


@dataclass(frozen=True)
class ProcessRow:
    """One row from windows.pslist or windows.psscan."""

    pid: int
    ppid: int
    name: str
    create_time: Optional[str]
    exit_time: Optional[str]
    raw_row: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class NetworkRow:
    """One row from windows.netscan."""

    pid: Optional[int]
    owner: Optional[str]
    protocol: Optional[str]
    local_addr: Optional[str]
    local_port: Optional[int]
    foreign_addr: Optional[str]
    foreign_port: Optional[int]
    state: Optional[str]
    raw_row: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class InjectionRow:
    """One row from windows.malfind.

    ``protection`` holds the VAD protection (e.g. ``PAGE_EXECUTE_READWRITE``)
    which is the key signal for unbacked RWX memory. ``tag`` is the VAD
    tag (e.g. ``VadS``). The detector uses both to score suspicion.
    """

    pid: int
    process: str
    start_vpn: Optional[int]
    end_vpn: Optional[int]
    tag: Optional[str]
    protection: Optional[str]
    commit_charge: Optional[int]
    private_memory: Optional[int]
    file_output: Optional[str]
    hexdump: Optional[str]
    raw_row: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CommandLineRow:
    """One row from windows.cmdline."""

    pid: int
    process: str
    args: Optional[str]
    raw_row: dict[str, Any] = field(default_factory=dict)


class VolatilityRunner:
    """Execute Volatility 3 plugins against one memory image.

    Instantiating the runner does not touch the image. Each ``run_*``
    method shells out once; there is no long-lived vol process. That is
    slower than a single-process multi-plugin run but keeps each plugin's
    failure domain isolated, which matters for community-submitted
    plugins that sometimes segfault on mismatched symbols.
    """

    def __init__(
        self,
        image_path: Path,
        *,
        vol_executable: str = "vol",
        timeout_sec: int = _DEFAULT_TIMEOUT_SEC,
        offline: bool = True,
    ):
        """Build a runner bound to one memory image.

        Parameters
        ----------
        image_path:
            Path to the memory dump (raw, lime, crash dump, vmem, etc.).
        vol_executable:
            Name or absolute path of the vol CLI. Override in tests to
            inject a fake binary.
        timeout_sec:
            Per-plugin timeout. Vol3 can legitimately take several
            minutes on multi-GB Windows dumps while it builds symbol
            tables, so we default to 10 minutes.
        offline:
            When True, pass ``--offline`` so Volatility does not attempt
            to download symbol tables mid-run. Set to False only when
            the operator has explicitly confirmed network access and
            needs missing symbols fetched.
        """
        if not image_path.is_file():
            raise FileNotFoundError(f"memory image not found: {image_path}")
        resolved_vol = shutil.which(vol_executable)
        if resolved_vol is None:
            raise MissingVolatilityError(
                f"volatility 3 CLI {vol_executable!r} not found on PATH. "
                "Install with `pip install volatility3`."
            )
        self._image_path = image_path
        self._vol_executable = resolved_vol
        self._timeout_sec = timeout_sec
        self._offline = offline

    @property
    def image_path(self) -> Path:
        return self._image_path

    def run_pslist(self) -> list[ProcessRow]:
        """Run ``windows.pslist.PsList`` and return one ProcessRow per entry."""
        rows = self._run_plugin("windows.pslist.PsList")
        return [_to_process_row(r) for r in rows]

    def run_psscan(self) -> list[ProcessRow]:
        """Run ``windows.psscan.PsScan`` — finds hidden / terminated procs."""
        rows = self._run_plugin("windows.psscan.PsScan")
        return [_to_process_row(r) for r in rows]

    def run_netscan(self) -> list[NetworkRow]:
        """Run ``windows.netscan.NetScan`` for tcp/udp connection entries."""
        rows = self._run_plugin("windows.netscan.NetScan")
        return [_to_network_row(r) for r in rows]

    def run_malfind(self) -> list[InjectionRow]:
        """Run ``windows.malfind.Malfind`` — unbacked RWX memory regions."""
        rows = self._run_plugin("windows.malfind.Malfind")
        return [_to_injection_row(r) for r in rows]

    def run_cmdline(self) -> list[CommandLineRow]:
        """Run ``windows.cmdline.CmdLine`` — per-process command lines."""
        rows = self._run_plugin("windows.cmdline.CmdLine")
        return [_to_cmdline_row(r) for r in rows]

    def _run_plugin(self, plugin: str) -> list[dict[str, Any]]:
        """Invoke one Volatility plugin and return its flattened row list.

        The JSON renderer nests subrows under ``__children``; we flatten
        to a single list because every plugin we ship consumes rows as a
        flat stream. Callers that need the tree shape can pull raw_row
        off each typed dataclass.
        """
        argv = [
            self._vol_executable,
            "-q",  # suppress progress bars
            "-r", "json",
            "-f", str(self._image_path),
        ]
        if self._offline:
            argv.append("--offline")
        argv.append(plugin)
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=self._timeout_sec,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise PluginExecutionError(
                plugin, returncode=-1, stderr=f"timed out after {self._timeout_sec}s"
            ) from exc
        if completed.returncode != 0:
            raise PluginExecutionError(plugin, completed.returncode, completed.stderr)
        return _parse_json_output(completed.stdout)


# -- parsing / coercion ----------------------------------------------------


def _parse_json_output(stdout: str) -> list[dict[str, Any]]:
    """Parse Volatility's ``-r json`` output and flatten nested children.

    The JSON renderer emits a list of top-level rows, each of which may
    carry a ``__children`` list for subrows (malfind does this for the
    per-region hexdump). We flatten the tree into one list and strip
    ``__children`` from every node so downstream code never has to
    distinguish tree shapes.
    """
    stripped = stdout.strip()
    if not stripped:
        return []
    try:
        tree = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise PluginExecutionError(
            plugin="?",
            returncode=0,
            stderr=f"could not parse JSON output: {exc}",
        ) from exc
    if not isinstance(tree, list):
        return []
    flat: list[dict[str, Any]] = []
    _walk(tree, flat)
    return flat


def _walk(nodes: list[Any], flat: list[dict[str, Any]]) -> None:
    # Non-mutating flatten: copy each node without __children rather than
    # pop()ing on the input tree. Pop() would mutate the parsed JSON in
    # place, and the same dicts get copied into raw_row downstream — so
    # the raw_row a detector receives would be missing __children only
    # because _walk already stripped it. Keep _parse_json_output pure.
    for node in nodes:
        if not isinstance(node, dict):
            continue
        children = node.get("__children")
        flat.append({k: v for k, v in node.items() if k != "__children"})
        if isinstance(children, list) and children:
            _walk(children, flat)


def _to_int(value: Any) -> Optional[int]:
    """Coerce Volatility's mixed int/str/None fields to Optional[int]."""
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _to_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    return str(value)


def _to_process_row(row: dict[str, Any]) -> ProcessRow:
    return ProcessRow(
        pid=_to_int(row.get("PID")) or 0,
        ppid=_to_int(row.get("PPID")) or 0,
        name=str(row.get("ImageFileName") or row.get("Name") or ""),
        create_time=_to_str(row.get("CreateTime")),
        exit_time=_to_str(row.get("ExitTime")),
        raw_row=dict(row),
    )


def _to_network_row(row: dict[str, Any]) -> NetworkRow:
    return NetworkRow(
        pid=_to_int(row.get("PID")),
        owner=_to_str(row.get("Owner")),
        protocol=_to_str(row.get("Proto")),
        local_addr=_to_str(row.get("LocalAddr")),
        local_port=_to_int(row.get("LocalPort")),
        foreign_addr=_to_str(row.get("ForeignAddr")),
        foreign_port=_to_int(row.get("ForeignPort")),
        state=_to_str(row.get("State")),
        raw_row=dict(row),
    )


def _to_injection_row(row: dict[str, Any]) -> InjectionRow:
    return InjectionRow(
        pid=_to_int(row.get("PID")) or 0,
        process=str(row.get("Process") or ""),
        start_vpn=_to_int(row.get("Start VPN")),
        end_vpn=_to_int(row.get("End VPN")),
        tag=_to_str(row.get("Tag")),
        protection=_to_str(row.get("Protection")),
        commit_charge=_to_int(row.get("CommitCharge")),
        private_memory=_to_int(row.get("PrivateMemory")),
        file_output=_to_str(row.get("File output")),
        hexdump=_to_str(row.get("Hexdump")),
        raw_row=dict(row),
    )


def _to_cmdline_row(row: dict[str, Any]) -> CommandLineRow:
    return CommandLineRow(
        pid=_to_int(row.get("PID")) or 0,
        process=str(row.get("Process") or ""),
        args=_to_str(row.get("Args")),
        raw_row=dict(row),
    )
