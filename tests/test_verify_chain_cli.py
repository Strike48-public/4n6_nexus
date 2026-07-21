"""Tests for the standalone offline audit-chain verifier (gallery idea #5).

``tools/verify_chain.py`` re-implements canonicalization + hashing from the
stdlib only, importing NOTHING from sift_find_evil, so a third party can prove
integrity without our engine and any writer/reader drift is itself detectable.
Semantic exit codes: 0 ok, 1 chain-invalid, 2 file error.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from sift_find_evil.audit.logger import AuditLogger

TOOL = Path(__file__).resolve().parents[1] / "tools" / "verify_chain.py"


def _run(path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), str(path)],
        capture_output=True,
        text=True,
    )


@pytest.fixture
def chained_log(tmp_path):
    p = tmp_path / "audit.jsonl"
    logger = AuditLogger(p)
    for i in range(8):
        logger.log_action(f"step_{i}", details={"i": i})
    return p


def test_tool_exists():
    assert TOOL.is_file(), "tools/verify_chain.py must exist"


def test_pristine_chain_exit_zero(chained_log):
    res = _run(chained_log)
    assert res.returncode == 0, res.stderr
    assert "OK" in res.stdout.upper()


def test_standalone_imports_nothing_from_product():
    """No import of the product (a doc-comment *reference* to a path is fine)."""
    import ast

    tree = ast.parse(TOOL.read_text())
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported += [n.name for n in node.names]
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")
    assert not any(
        m.startswith("sift_find_evil") for m in imported
    ), f"standalone verifier must not import the product; imports={imported}"


def test_tampered_chain_exit_one(chained_log):
    lines = chained_log.read_text().splitlines()
    rec = json.loads(lines[4])
    rec["details"]["i"] = 4242
    lines[4] = json.dumps(rec)
    chained_log.write_text("\n".join(lines) + "\n")

    res = _run(chained_log)
    assert res.returncode == 1
    assert "4" in res.stdout  # reports the failing entry index


def test_missing_file_exit_two(tmp_path):
    res = _run(tmp_path / "nope.jsonl")
    assert res.returncode == 2


def test_agrees_with_in_product_verifier_on_pristine_and_tampered(chained_log):
    # Pristine: both agree OK.
    assert AuditLogger(chained_log).verify_chain()[0] is True
    assert _run(chained_log).returncode == 0

    # Tamper: both agree BROKEN at the same index.
    lines = chained_log.read_text().splitlines()
    rec = json.loads(lines[3])
    rec["action"] = "forged"
    lines[3] = json.dumps(rec)
    chained_log.write_text("\n".join(lines) + "\n")

    ok, broken_at, _ = AuditLogger(chained_log).verify_chain()
    assert ok is False and broken_at == 3
    res = _run(chained_log)
    assert res.returncode == 1
    assert "3" in res.stdout
