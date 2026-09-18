"""Tests for cli_mcp's evidence-root derivation (SFE-fibx.14).

cli_mcp derives the ToolGuard evidence_root from the supplied evidence inputs.
The security-relevant property is that a scatter of inputs from different trees
must NOT silently widen the root to the filesystem root, which would make
ToolGuard path-containment a no-op on the documented ``python -m
sift_find_evil.cli_mcp`` entrypoint.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from sift_find_evil.cli_mcp import _derive_evidence_root


def _args(**kw) -> SimpleNamespace:
    base = dict(
        windows_mount=None,
        mft_file=None,
        prefetch_dir=None,
        evtx_file=None,
        memory_file=None,
    )
    base.update(kw)
    return SimpleNamespace(**base)


def test_windows_mount_is_the_root():
    assert _derive_evidence_root(_args(windows_mount="/mnt/c")) == Path("/mnt/c")


def test_single_input_contains_to_itself():
    root = _derive_evidence_root(_args(mft_file="/evidence/case1/$MFT"))
    assert root == Path("/evidence/case1/$MFT")


def test_scattered_inputs_under_one_tree_share_that_ancestor():
    root = _derive_evidence_root(
        _args(
            mft_file="/evidence/case1/$MFT", evtx_file="/evidence/case1/Security.evtx"
        )
    )
    assert root == Path("/evidence/case1")


def test_inputs_from_different_trees_are_rejected_not_widened_to_root():
    """The core fix: inputs sharing only '/' must raise, not silently produce a
    root of '/' that defeats containment."""
    with pytest.raises(ValueError, match="(?i)filesystem root|no common directory"):
        _derive_evidence_root(
            _args(mft_file="/home/user/evidence/mft.csv", evtx_file="/tmp/x/mal.evtx")
        )
