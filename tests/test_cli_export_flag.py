"""CLI --export wiring: emit findings as STIX 2.1 / OCSF / Wazuh next to --output.

Mirrors the --harden wiring tests (test_cli_harden.py): a sibling file is written
next to --output, guarded against evidence directories, and is a no-op without
the flag. The pure exporters themselves are unit-tested in test_interop_*.py; this
suite guards only the CLI glue (path derivation, evidence guard, precondition).
"""

from __future__ import annotations

import json
import xml.dom.minidom
from pathlib import Path
from types import SimpleNamespace

import pytest

from sift_find_evil.cli import _export_path, _maybe_write_export
from sift_find_evil.findings import Finding, FindingCategory


def _finding(title: str = "beacon") -> Finding:
    return Finding(
        title=title,
        description="periodic C2",
        finding_type="indicator",
        severity="high",
        category=FindingCategory.COMMAND_AND_CONTROL,
        evidence={"dst_ip": "8.8.8.8", "mitre_attack": ["T1071"]},
        confidence=0.9,
    )


# --- path derivation --------------------------------------------------------


def test_export_path_is_sibling_of_output() -> None:
    assert _export_path(Path("/x/findings.json"), "stix.json") == Path(
        "/x/findings.stix.json"
    )


# --- no-op without flag -----------------------------------------------------


def test_noop_without_export_flag(tmp_path: Path) -> None:
    args = SimpleNamespace(export=None, output=str(tmp_path / "findings.json"))
    _maybe_write_export(args, [_finding()])
    assert list(tmp_path.iterdir()) == []


# --- each format writes the right sibling -----------------------------------


def test_stix_export_writes_bundle(tmp_path: Path) -> None:
    output = tmp_path / "findings.json"
    args = SimpleNamespace(export="stix", output=str(output))
    _maybe_write_export(args, [_finding()])

    stix = tmp_path / "findings.stix.json"
    assert stix.exists()
    bundle = json.loads(stix.read_text(encoding="utf-8"))
    assert bundle["type"] == "bundle"
    assert any(o["type"] == "indicator" for o in bundle["objects"])
    # The findings --output itself is not written by the export helper.
    assert not output.exists()


def test_ocsf_export_writes_detection_findings(tmp_path: Path) -> None:
    output = tmp_path / "findings.json"
    args = SimpleNamespace(export="ocsf", output=str(output))
    _maybe_write_export(args, [_finding()])

    ocsf = tmp_path / "findings.ocsf.json"
    assert ocsf.exists()
    events = json.loads(ocsf.read_text(encoding="utf-8"))
    assert events[0]["class_uid"] == 2004


def test_wazuh_export_writes_ndjson_and_rules_xml(tmp_path: Path) -> None:
    output = tmp_path / "findings.json"
    args = SimpleNamespace(export="wazuh", output=str(output))
    _maybe_write_export(args, [_finding()])

    alerts = tmp_path / "findings.wazuh.json"
    rules = tmp_path / "findings.wazuh-rules.xml"
    assert alerts.exists() and rules.exists()
    # NDJSON: one JSON object per line.
    lines = [ln for ln in alerts.read_text(encoding="utf-8").splitlines() if ln]
    assert json.loads(lines[0])["rule"]["level"] == 12
    # Rules XML parses.
    dom = xml.dom.minidom.parseString(rules.read_text(encoding="utf-8"))
    assert dom.documentElement.tagName == "group"


# --- evidence-dir guard -----------------------------------------------------


def test_export_refuses_evidence_dir(monkeypatch, tmp_path: Path) -> None:
    # An --output resolving into an evidence dir must abort the export write.
    evidence_out = "/cases/case1/findings.json"
    args = SimpleNamespace(export="stix", output=evidence_out)
    with pytest.raises(SystemExit) as exc:
        _maybe_write_export(args, [_finding()])
    assert exc.value.code == 1
    assert not Path("/cases/case1/findings.stix.json").exists()


# --- precondition: --export requires --output -------------------------------


def test_export_without_output_exits() -> None:
    from sift_find_evil.cli import cmd_analyze

    args = SimpleNamespace(
        harden=False,
        export="stix",
        output=None,
        mft="m",
        prefetch="p",
        evtx="e",
    )
    with pytest.raises(SystemExit) as exc:
        cmd_analyze(args)
    assert exc.value.code == 1
