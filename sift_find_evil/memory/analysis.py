"""Connector-safe, high-level memory analysis entry points.

Two shapes feed the correlating :class:`MemoryDetector`:

  * a **directory** of pre-parsed Volatility plugin JSON (``windows_pslist.json``,
    ``windows_malfind.json``, …) — the deterministic shape the scored scenario
    harness consumes and the only one runnable without a multi-GB dump and the
    ``vol`` binary; and
  * a raw memory **dump** (``.raw``/``.lime``/``.vmem``/``.dmp``) — Volatility 3
    runs in-process via :class:`VolatilityRunner`.

Unlike ``sift_find_evil.cli._run_memory_detector`` (which ``sys.exit``s on a
missing install so the *CLI* reports a clean non-zero exit), these functions
RAISE ordinary exceptions. That distinction is load-bearing for the connector:
it guards ``analyze_fn`` with ``except Exception`` (never ``BaseException``), so
a ``SystemExit`` would escape the guard and kill the worker instead of returning
a ``{success: False, error}`` envelope.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sift_find_evil.detectors.memory_detector import MemoryDetector
from sift_find_evil.memory.volatility_runner import (
    PluginExecutionError,
    VolatilityRunner,
    _to_bash_history_row,
    _to_cmdline_row,
    _to_injection_row,
    _to_linux_network_row,
    _to_linux_process_row,
    _to_network_row,
    _to_process_row,
)

# plugin_key -> row coercer. SINGLE SOURCE OF TRUTH for the coercion LOGIC,
# shared by the scenario harness (scored path) and the connector adapter, so a
# Volatility output-shape change is absorbed in exactly one place rather than
# drifting between two copies. Keys are the conventional plugin-JSON basenames
# (``<key>.json``) and the scenario.yaml ``fixtures.memory`` keys. NOTE this
# shares only the coercers: path RESOLUTION still differs by caller — the
# harness honors per-plugin scenario.yaml paths, while ``analyze_memory_dir``
# globs ``<plugin_key>.json`` in a directory.
PLUGIN_COERCERS = {
    "windows_pslist": _to_process_row,
    "windows_psscan": _to_process_row,
    "windows_malfind": _to_injection_row,
    "windows_cmdline": _to_cmdline_row,
    "windows_netscan": _to_network_row,
    "linux_bash": _to_bash_history_row,
    "linux_pslist": _to_linux_process_row,
    "linux_sockstat": _to_linux_network_row,
}

# plugin_key -> the ``MemoryDetector.analyze()`` keyword it feeds.
PLUGIN_TO_KWARG = {
    "windows_pslist": "pslist",
    "windows_psscan": "psscan",
    "windows_malfind": "malfind",
    "windows_cmdline": "cmdline",
    "windows_netscan": "netscan",
    "linux_bash": "linux_bash",
    "linux_pslist": "linux_pslist",
    "linux_sockstat": "linux_sockstat",
}


def coerce_streams(raw_by_plugin: dict[str, list]) -> dict[str, list]:
    """Map ``{plugin_key: raw_row_list}`` -> ``MemoryDetector.analyze`` kwargs.

    Unrecognized plugin keys are skipped. Each recognized key's raw rows are
    coerced into the runner's typed dataclasses via the shared coercers above.
    """
    kwargs: dict[str, list] = {}
    for plugin_key, raw_rows in raw_by_plugin.items():
        coercer = PLUGIN_COERCERS.get(plugin_key)
        analyze_kw = PLUGIN_TO_KWARG.get(plugin_key)
        if coercer is None or analyze_kw is None:
            continue
        kwargs[analyze_kw] = [coercer(row) for row in raw_rows]
    return kwargs


def analyze_memory_dir(directory: Path) -> list[Any]:
    """Run MemoryDetector over a directory of pre-parsed Volatility plugin JSON.

    Reads ``<plugin_key>.json`` for each recognized plugin; a file whose content
    is not a JSON list is ignored. Raises :class:`ValueError` when the directory
    holds no recognized plugin JSON at all — almost certainly the wrong directory
    — so a mis-pointed path never masquerades as "analyzed, found nothing".
    """
    raw_by_plugin: dict[str, list] = {}
    for plugin_key in PLUGIN_COERCERS:
        fixture = directory / f"{plugin_key}.json"
        if not fixture.is_file():
            continue
        try:
            with fixture.open(encoding="utf-8") as handle:
                raw_rows = json.load(handle)
        except json.JSONDecodeError as err:
            # Fail fast on a corrupt fixture (manual edit, truncated download,
            # disk error) rather than silently running on partial data — a
            # forensic no-silent-corruption rule. Re-raise as ValueError with an
            # operator-legible message; the connector's error envelope shows
            # this string, and the chained cause keeps the parser detail in logs.
            raise ValueError(
                f"malformed JSON in {fixture}: {err.msg} "
                f"(line {err.lineno}, column {err.colno})"
            ) from err
        if isinstance(raw_rows, list):
            raw_by_plugin[plugin_key] = raw_rows
    if not raw_by_plugin:
        expected = ", ".join(f"{key}.json" for key in PLUGIN_COERCERS)
        raise ValueError(
            f"no recognized Volatility plugin JSON in {directory} "
            f"(expected one of: {expected})"
        )
    return MemoryDetector().analyze(**coerce_streams(raw_by_plugin))


def analyze_memory_dump(dump_path: Path) -> list[Any]:
    """Run Volatility 3 + MemoryDetector against a raw memory dump.

    Raises :class:`MissingVolatilityError` / :class:`FileNotFoundError` (from
    :class:`VolatilityRunner`) rather than ``sys.exit`` so the connector returns
    a clean error envelope instead of the worker dying on a ``SystemExit``.

    Every plugin is tried on every dump: a Windows dump simply fails the
    ``linux.*`` plugins (and vice versa). A single plugin crash is skipped, not
    fatal — ``MemoryDetector.analyze`` tolerates missing streams — so partial
    success still yields findings. But if EVERY plugin fails, raises
    :class:`ValueError` rather than returning 0 findings (which would be
    indistinguishable from a clean-but-empty dump).
    """
    runner = VolatilityRunner(dump_path)
    streams: dict[str, list] = {}
    for kwarg, run_plugin in (
        ("pslist", runner.run_pslist),
        ("psscan", runner.run_psscan),
        ("malfind", runner.run_malfind),
        ("cmdline", runner.run_cmdline),
        ("netscan", runner.run_netscan),
        ("linux_bash", runner.run_linux_bash),
        ("linux_pslist", runner.run_linux_pslist),
        ("linux_sockstat", runner.run_linux_sockstat),
    ):
        try:
            streams[kwarg] = run_plugin()
        except PluginExecutionError:
            continue
    # No-fabrication parity with analyze_memory_dir: if EVERY plugin failed the
    # dump is malformed or its symbols are unresolved, and 0 findings would be
    # indistinguishable from a clean-but-empty dump. The CLI warns to stderr
    # here; the connector has no operator stderr, so raise and let it surface in
    # the error envelope. A single surviving (even empty) stream is real partial
    # success — a Windows dump legitimately fails every linux.* plugin.
    if not streams:
        raise ValueError(
            "no memory plugins returned data; confirm the dump is a supported "
            "format and that Volatility can resolve symbols for its kernel"
        )
    return MemoryDetector().analyze(**streams)


def run_memory_analysis(memory_path: Path) -> list[Any]:
    """Dispatch on the path shape: directory -> plugin-JSON; file -> raw dump.

    Raises :class:`FileNotFoundError` when the path is neither a directory nor a
    file, matching how the trio/registry/network paths reject a bad path.
    """
    if memory_path.is_dir():
        return analyze_memory_dir(memory_path)
    if memory_path.is_file():
        return analyze_memory_dump(memory_path)
    # Distinguish "exists but wrong kind" (FIFO, socket, device) from "absent":
    # labeling an existing path "not found" reads as a typo and hides the real
    # problem (the operator pointed at the wrong artifact kind).
    if memory_path.exists():
        raise ValueError(
            f"memory path is not a regular file or directory: {memory_path}"
        )
    raise FileNotFoundError(f"memory path not found: {memory_path}")
