"""Coverage-focused tests for sift_find_evil.orchestration (SFE coverage push).

These exercise the fixture-loading error/guard paths in ``_load_rows``, the
empty-domain early returns in the memory/network analysts, and the ``main()``
CLI entrypoint -- branches the end-to-end happy-path tests in
``test_orchestration.py`` do not reach.
"""

from __future__ import annotations

import json
import sys

import pytest

from sift_find_evil import orchestration
from sift_find_evil.orchestration import (
    InvestigationOrchestrator,
    _load_rows,
    _to_tcp_conversation,
    main,
)


# -- _load_rows guard / error paths -----------------------------------------


def test_load_rows_returns_empty_when_file_absent(tmp_path):
    """Line 57: a genuinely-absent fixture yields [] (the disk-only path)."""
    missing = tmp_path / "nope.json"
    assert _load_rows(missing, _to_tcp_conversation) == []


def test_load_rows_raises_on_malformed_json(tmp_path):
    """Lines 61-62: a present-but-corrupt fixture raises rather than masking a gap."""
    bad = tmp_path / "bad.json"
    bad.write_text("{ this is not valid json", encoding="utf-8")
    with pytest.raises(RuntimeError, match="Failed to read fixture"):
        _load_rows(bad, _to_tcp_conversation)


def test_load_rows_raises_on_unreadable_file(tmp_path, monkeypatch):
    """Lines 61-62: an OSError while reading also surfaces as a RuntimeError."""
    target = tmp_path / "present.json"
    target.write_text("[]", encoding="utf-8")

    def boom(*_args, **_kwargs):
        raise OSError("disk gone")

    # is_file() passes, but opening explodes -> the except clause runs.
    monkeypatch.setattr(orchestration.Path, "open", boom)
    with pytest.raises(RuntimeError, match="Failed to read fixture"):
        _load_rows(target, _to_tcp_conversation)


def test_load_rows_raises_when_not_a_list(tmp_path):
    """Line 64: a JSON object (not array) is a malformed fixture."""
    obj = tmp_path / "obj.json"
    obj.write_text(json.dumps({"endpoint_a_ip": "1.2.3.4"}), encoding="utf-8")
    with pytest.raises(ValueError, match="expected a JSON array, got dict"):
        _load_rows(obj, _to_tcp_conversation)


def test_load_rows_raises_when_coercer_fails(tmp_path):
    """Lines 67-68: a row missing required keys fails coercion -> RuntimeError."""
    arr = tmp_path / "rows.json"
    # _to_tcp_conversation requires endpoint_a_ip etc.; an empty row -> KeyError.
    arr.write_text(json.dumps([{}]), encoding="utf-8")
    with pytest.raises(RuntimeError, match="Failed to coerce a row"):
        _load_rows(arr, _to_tcp_conversation)


# -- analyst empty-domain early returns --------------------------------------


def test_memory_analyst_returns_empty_without_fixtures(tmp_path):
    """Line 366: no memory_fixtures/ -> no findings, no tools (disk-only path)."""
    orch = InvestigationOrchestrator(
        case_id="INC-EMPTY",
        audit_path=tmp_path / "audit.jsonl",
        examiner="jtomek",
        scenario_dir=tmp_path,  # bare dir: no memory_fixtures/
    )
    findings, tool_ids = orch._memory_analyst()
    assert findings == []
    assert tool_ids == []


def test_network_analyst_returns_empty_without_conversations(tmp_path):
    """Line 401: no conversations -> no findings, no tools (disk-only path)."""
    orch = InvestigationOrchestrator(
        case_id="INC-EMPTY",
        audit_path=tmp_path / "audit.jsonl",
        examiner="jtomek",
        scenario_dir=tmp_path,  # bare dir: no network_fixtures/
    )
    findings, tool_ids = orch._network_analyst()
    assert findings == []
    assert tool_ids == []


# -- main() CLI entrypoint ---------------------------------------------------


def test_main_runs_and_writes_artifacts(tmp_path, monkeypatch, capsys):
    """Lines 438-474: the CLI parses args, runs the demo, and writes outputs."""
    out_dir = tmp_path / "demo_run"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "orchestration",
            "--case-id",
            "INC-CLI-001",
            "--output-dir",
            str(out_dir),
            "--examiner",
            "tester",
        ],
    )

    rc = main()

    assert rc == 0
    assert (out_dir / "audit.jsonl").exists()
    report_path = out_dir / "report.json"
    assert report_path.exists()

    report = json.loads(report_path.read_text())
    assert report["case_id"] == "INC-CLI-001"
    assert report["findings"], "the demo run should surface findings"

    captured = capsys.readouterr().out
    assert "Case INC-CLI-001" in captured
    assert "A2A audit log:" in captured
    assert "Report:" in captured
    assert "Trace any finding:" in captured
    # The per-finding print loop (lines 465-470) ran for each finding.
    assert "F-001" in captured


def test_main_with_bypass_demo_flag(tmp_path, monkeypatch):
    """Line 446-450 + bypass path: --bypass-demo records a blocked tool attempt."""
    out_dir = tmp_path / "bypass_run"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "orchestration",
            "--output-dir",
            str(out_dir),
            "--bypass-demo",
        ],
    )

    rc = main()

    assert rc == 0
    # Default case-id is used when not supplied.
    report = json.loads((out_dir / "report.json").read_text())
    assert report["case_id"] == "INC-2026-001"
