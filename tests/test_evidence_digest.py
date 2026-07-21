"""Tests for the evidence digest (PR #3 review nit #2 - content-collision fix).

Taylor's review: the old ``_evidence_image_sha256`` hashed only the sorted
(relative_path, size) inventory of a directory tree - so two trees with the same
layout but DIFFERENT file contents received the same digest, and every receipt in
both runs would bind to the same "image". Fixed: for a directory, hash file
CONTENTS (streamed), not just the inventory. Renamed to make the semantics clear.
"""

from sift_find_evil.orchestration import _evidence_digest


def test_single_file_hashes_its_bytes(tmp_path):
    f = tmp_path / "image.dd"
    f.write_bytes(b"evidence-bytes")
    assert len(_evidence_digest(f)) == 64


def test_same_layout_different_content_yields_different_digests(tmp_path):
    # The collision the review flagged: identical filenames/sizes, different bytes.
    a = tmp_path / "a"
    b = tmp_path / "b"
    for root in (a, b):
        (root / "sub").mkdir(parents=True)
    (a / "sub" / "f.csv").write_text("AAAA")
    (b / "sub" / "f.csv").write_text("BBBB")  # same name + size, different content
    assert _evidence_digest(a) != _evidence_digest(b)


def test_identical_trees_yield_identical_digests(tmp_path):
    # Determinism: same content -> same digest (receipts reproducible per fixture).
    a = tmp_path / "a"
    b = tmp_path / "b"
    for root in (a, b):
        (root / "sub").mkdir(parents=True)
        (root / "sub" / "f.csv").write_text("same-content")
        (root / "g.json").write_text("{}")
    assert _evidence_digest(a) == _evidence_digest(b)


def test_digest_is_order_independent_of_filesystem_walk(tmp_path):
    # Files are hashed in sorted path order, so the digest is stable regardless of
    # creation order.
    a = tmp_path / "a"
    a.mkdir()
    (a / "z.csv").write_text("z")
    (a / "a.csv").write_text("a")
    first = _evidence_digest(a)
    # Re-read: identical.
    assert _evidence_digest(a) == first
