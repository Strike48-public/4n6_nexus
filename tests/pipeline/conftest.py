"""Shared fixtures for tests/pipeline (bd SFE-rbje.1 / SFE-rbje.4)."""

from pathlib import Path

import pytest


@pytest.fixture
def repo_root() -> Path:
    """The 4n6_nexus repository root, resolved from this test file's own
    location so the fixture is correct regardless of the invoking cwd.
    """
    return Path(__file__).resolve().parents[2]
