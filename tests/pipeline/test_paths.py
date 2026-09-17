"""Tests for nexus_pipeline.state.paths.

Covers default resolution, env override, replicated-root refusal (each
guarded root), permission enforcement on the created directory, and refusal
when a symlink indirects into a replicated root.
"""

import os
import stat

import pytest

from nexus_pipeline.state import paths

REPLICATED_ROOT_NAMES = (
    "code",
    "bin",
    "git",
    "tasks",
    "homelab",
    "personal",
    "Documents",
    "sync",
    "claude-config",
)


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Point HOME at a scratch dir so tests never touch the real state dir."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("NEXUS_PIPELINE_STATE_DIR", raising=False)
    monkeypatch.delenv("NEXUS_PIPELINE_WORKTREE_DIR", raising=False)
    return home


def test_state_dir_default_location(isolated_home):
    result = paths.state_dir()
    assert result == isolated_home / ".local" / "state" / "nexus-pipeline"


def test_worktree_dir_default_location(isolated_home):
    result = paths.worktree_dir()
    assert result == isolated_home / ".cache" / "nexus-pipeline" / "worktrees"


def test_state_dir_env_override(isolated_home, monkeypatch, tmp_path):
    override = tmp_path / "elsewhere" / "state"
    monkeypatch.setenv("NEXUS_PIPELINE_STATE_DIR", str(override))
    result = paths.state_dir()
    assert result == override.resolve()


def test_worktree_dir_env_override(isolated_home, monkeypatch, tmp_path):
    override = tmp_path / "elsewhere" / "worktrees"
    monkeypatch.setenv("NEXUS_PIPELINE_WORKTREE_DIR", str(override))
    result = paths.worktree_dir()
    assert result == override.resolve()


def test_capital_code_is_allowed(isolated_home, monkeypatch):
    override = isolated_home / "Code" / "nexus-state"
    monkeypatch.setenv("NEXUS_PIPELINE_STATE_DIR", str(override))
    result = paths.state_dir()
    assert result == override.resolve()


@pytest.mark.parametrize("root_name", REPLICATED_ROOT_NAMES)
def test_replicated_root_refused(isolated_home, monkeypatch, root_name):
    override = isolated_home / root_name / "nexus-state"
    monkeypatch.setenv("NEXUS_PIPELINE_STATE_DIR", str(override))
    with pytest.raises(paths.ReplicatedPathError):
        paths.state_dir()


def test_created_dir_has_mode_0700(isolated_home):
    result = paths.state_dir()
    mode = stat.S_IMODE(os.stat(result).st_mode)
    assert mode == 0o700


def test_existing_dir_with_looser_perms_raises(isolated_home, monkeypatch, tmp_path):
    override = tmp_path / "loose"
    override.mkdir(mode=0o755)
    monkeypatch.setenv("NEXUS_PIPELINE_STATE_DIR", str(override))
    with pytest.raises(paths.StateDirPermissionError):
        paths.state_dir()


def test_existing_dir_with_correct_perms_is_reused(
    isolated_home, monkeypatch, tmp_path
):
    override = tmp_path / "already-secure"
    override.mkdir(mode=0o700)
    monkeypatch.setenv("NEXUS_PIPELINE_STATE_DIR", str(override))
    result = paths.state_dir()
    assert result == override.resolve()


def test_symlink_into_replicated_root_refused(isolated_home, monkeypatch):
    real_target = isolated_home / "tasks" / "real-state-dir"
    real_target.mkdir(parents=True)
    symlink_path = isolated_home / "innocuous-looking-state"
    symlink_path.symlink_to(real_target, target_is_directory=True)
    monkeypatch.setenv("NEXUS_PIPELINE_STATE_DIR", str(symlink_path))
    with pytest.raises(paths.ReplicatedPathError):
        paths.state_dir()


# --- safe_component: shared path-component validator (secreview CRITICAL-1) ---


@pytest.mark.parametrize(
    "unsafe",
    [
        "../../tmp/x",
        "../etc/passwd",
        "/etc/passwd",
        "/tmp/pwned",
        "",
        ".",
        "..",
        ".hidden",
        "a/b",
        "a\\b",
        # post-PR review (MEDIUM): re.match + "$" let a trailing "\n" slip past
        # validation (e.g. unstripped gh output); fullmatch rejects it.
        "SFE-1\n",
        "SFE-1\n\n",
        "a\nb",
    ],
)
def test_safe_component_rejects_unsafe_values(unsafe):
    with pytest.raises(paths.UnsafePathComponentError):
        paths.safe_component(unsafe)


def test_safe_component_accepts_a_normal_issue_id():
    assert paths.safe_component("SFE-rbje.4") == "SFE-rbje.4"


def test_assert_within_accepts_a_direct_child(tmp_path):
    parent = tmp_path / "parent"
    parent.mkdir()
    child = parent / "child.json"

    assert paths.assert_within(child, parent) == child.resolve()


def test_assert_within_rejects_a_path_outside_parent(tmp_path):
    parent = tmp_path / "parent"
    parent.mkdir()
    outside = tmp_path / "outside.json"

    with pytest.raises(paths.UnsafePathComponentError):
        paths.assert_within(outside, parent)


def test_assert_within_rejects_a_symlink_escaping_the_parent(tmp_path):
    parent = tmp_path / "parent"
    parent.mkdir()
    outside_target = tmp_path / "outside-real.json"
    outside_target.write_text("{}")
    escaping_symlink = parent / "looks-safe.json"
    escaping_symlink.symlink_to(outside_target)

    with pytest.raises(paths.UnsafePathComponentError):
        paths.assert_within(escaping_symlink, parent)
