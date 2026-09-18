"""Tests for the OpenSearch push driver's PURE helpers (SFE-b0om).

The network call itself is not unit-tested (it is driver glue, coverage-omitted),
but the document loading and _bulk NDJSON construction carry real logic worth
guarding: STIX bundles and OCSF event lists must both load, and the bulk body
must be valid NDJSON with an action line per doc.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sift_find_evil.interop.push_opensearch import _bulk_ndjson, _load_docs


def test_load_docs_from_stix_bundle(tmp_path: Path) -> None:
    bundle = {"type": "bundle", "id": "bundle--x", "objects": [{"type": "indicator"}]}
    path = tmp_path / "b.stix.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    assert _load_docs(path) == [{"type": "indicator"}]


def test_load_docs_from_ocsf_list(tmp_path: Path) -> None:
    events = [{"class_uid": 2004}, {"class_uid": 2004}]
    path = tmp_path / "e.ocsf.json"
    path.write_text(json.dumps(events), encoding="utf-8")
    assert _load_docs(path) == events


def test_load_docs_rejects_unknown_shape(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"not": "a bundle"}), encoding="utf-8")
    with pytest.raises(ValueError):
        _load_docs(path)


def test_bulk_ndjson_has_action_line_per_doc() -> None:
    docs = [{"a": 1}, {"b": 2}]
    body = _bulk_ndjson(docs, "dfir-findings")
    lines = body.strip().split("\n")
    # One action line + one source line per doc.
    assert len(lines) == 4
    assert json.loads(lines[0]) == {"index": {"_index": "dfir-findings"}}
    assert json.loads(lines[1]) == {"a": 1}
    assert body.endswith("\n")


def test_bulk_ndjson_empty_docs() -> None:
    assert _bulk_ndjson([], "idx") == "\n"
