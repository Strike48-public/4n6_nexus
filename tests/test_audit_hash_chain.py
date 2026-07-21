"""Tests for the hash-chained tamper-evident audit log (gallery idea #1).

Upgrades the append-only audit log from independent per-entry SHA-256 output
hashes to a genesis-anchored hash chain: each entry commits to the prior
entry's digest, so deletion, reordering, or in-line edits break the chain and
are localized to an exact sequence number.

RED-first: these behaviors did not exist before this change (entries had an
``output_hash`` over tool output but no ``prev_hash``/``entry_hash`` linking).
"""

import json

import pytest

from sift_find_evil.audit.logger import AuditLogger
from sift_find_evil.audit.models import (
    GENESIS_HASH,
    AuditEntry,
    compute_entry_hash,
)


@pytest.fixture
def audit_path(tmp_path):
    return tmp_path / "audit.jsonl"


def _write_chain(logger: AuditLogger, n: int) -> list[str]:
    ids = []
    for i in range(n):
        ids.append(logger.log_action(f"action_{i}", details={"i": i}))
    return ids


def test_first_entry_links_to_genesis(audit_path):
    logger = AuditLogger(audit_path)
    logger.log_action("first", details={"x": 1})

    entries = logger._read_all()
    assert len(entries) == 1
    assert entries[0].prev_hash == GENESIS_HASH
    assert entries[0].entry_hash is not None
    assert len(entries[0].entry_hash) == 64


def test_each_entry_commits_to_prior(audit_path):
    logger = AuditLogger(audit_path)
    _write_chain(logger, 5)

    entries = logger._read_all()
    for prev, cur in zip(entries, entries[1:]):
        assert cur.prev_hash == prev.entry_hash


def test_pristine_chain_verifies(audit_path):
    logger = AuditLogger(audit_path)
    _write_chain(logger, 10)

    ok, broken_at, reason = logger.verify_chain()
    assert ok is True
    assert broken_at is None
    assert reason is None


def test_inline_edit_of_middle_entry_is_localized(audit_path):
    logger = AuditLogger(audit_path)
    _write_chain(logger, 6)

    # Tamper: flip a byte in the details of the entry at index 3.
    lines = audit_path.read_text().splitlines()
    rec = json.loads(lines[3])
    rec["details"]["i"] = 999  # was 3
    lines[3] = json.dumps(rec)
    audit_path.write_text("\n".join(lines) + "\n")

    ok, broken_at, reason = logger.verify_chain()
    assert ok is False
    # The edited entry's recomputed hash no longer matches its stored hash.
    assert broken_at == 3
    assert "entry_hash" in reason.lower() or "content" in reason.lower()


def test_deletion_breaks_chain(audit_path):
    logger = AuditLogger(audit_path)
    _write_chain(logger, 6)

    lines = audit_path.read_text().splitlines()
    del lines[2]  # remove one entry
    audit_path.write_text("\n".join(lines) + "\n")

    ok, broken_at, reason = logger.verify_chain()
    assert ok is False
    # After deletion, the entry that used to follow #2 now has a prev_hash that
    # points at a digest no longer present -> link break at the new index 2.
    assert broken_at == 2
    assert "prev_hash" in reason.lower() or "link" in reason.lower()


def test_reorder_breaks_chain(audit_path):
    logger = AuditLogger(audit_path)
    _write_chain(logger, 6)

    lines = audit_path.read_text().splitlines()
    lines[2], lines[4] = lines[4], lines[2]  # swap two entries
    audit_path.write_text("\n".join(lines) + "\n")

    ok, broken_at, reason = logger.verify_chain()
    assert ok is False


def test_append_forgery_without_key_still_breaks_link(audit_path):
    logger = AuditLogger(audit_path)
    _write_chain(logger, 4)

    # Attacker appends a fabricated entry that does NOT chain from the tail.
    forged = AuditEntry(action="evil", details={"planted": True})
    forged.entry_id = "evt-000099"
    forged.prev_hash = GENESIS_HASH  # wrong: should be the real tail
    forged.entry_hash = compute_entry_hash(
        {k: v for k, v in forged.to_dict().items() if k != "entry_hash"}
    )
    with open(audit_path, "a") as f:
        f.write(json.dumps(forged.to_dict()) + "\n")

    ok, broken_at, reason = logger.verify_chain()
    assert ok is False
    assert broken_at == 4


def test_chain_resumes_across_logger_instances(audit_path):
    logger1 = AuditLogger(audit_path)
    _write_chain(logger1, 3)

    # A fresh logger over the same file must continue the chain, not restart it.
    logger2 = AuditLogger(audit_path)
    logger2.log_action("continued", details={"x": 2})

    entries = logger2._read_all()
    assert len(entries) == 4
    assert entries[3].prev_hash == entries[2].entry_hash

    ok, broken_at, reason = logger2.verify_chain()
    assert ok is True


def test_verify_empty_log_is_ok(audit_path):
    logger = AuditLogger(audit_path)
    ok, broken_at, reason = logger.verify_chain()
    assert ok is True
    assert broken_at is None


def test_full_output_hash_retained_for_chain_but_display_truncates(audit_path):
    """Tool invocations keep the 16-char display hash; the chain uses full digests."""
    logger = AuditLogger(audit_path)
    logger.log_tool_invocation(
        tool="mftecmd", command="MFTECmd -f $MFT", output="some tool output"
    )
    entries = logger._read_all()
    entry = entries[0]
    # Chain digests are full SHA-256.
    assert len(entry.entry_hash) == 64
    # The tool output display hash stays truncated for UI (unchanged behavior).
    assert len(entry.details["output_hash"]) == 16
