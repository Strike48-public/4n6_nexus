"""Tests for nexus_pipeline.gates.evidence_guard (Gate D, spec section 3
lines 122-123 and 157-178; digest section A).

Gate D is a CLOSED allow-list (secreview finding #1): a path is allowed only
if it resolves inside worktree_root AND its top-level segment relative to
worktree_root is in ALLOW_TOP_LEVEL. Everything else -- repo-governance
files, dotfiles, and this harness's own package -- is denied by omission.
Within an allowed top-level, DENY still wins on any relative segment.
"""

import os

import pytest

from nexus_pipeline.gates.evidence_guard import is_write_allowed


def test_allows_write_under_worktree_analysis_dir(tmp_path):
    worktree = tmp_path / "worktree"
    (worktree / "analysis").mkdir(parents=True)

    assert is_write_allowed(
        worktree / "analysis" / "report.json", worktree_root=worktree
    )


def test_allows_write_under_worktree_exports_and_reports_dirs(tmp_path):
    worktree = tmp_path / "worktree"
    (worktree / "exports").mkdir(parents=True)
    (worktree / "reports").mkdir(parents=True)

    assert is_write_allowed(worktree / "exports" / "out.csv", worktree_root=worktree)
    assert is_write_allowed(worktree / "reports" / "out.json", worktree_root=worktree)


def test_allows_write_under_worktree_source_tree(tmp_path):
    worktree = tmp_path / "worktree"
    (worktree / "sift_find_evil" / "detectors").mkdir(parents=True)

    assert is_write_allowed(
        worktree / "sift_find_evil" / "detectors" / "new_detector.py",
        worktree_root=worktree,
    )


def test_allows_write_under_worktree_test_tree(tmp_path):
    # Deliberately NOT under tests/pipeline/ (see the harness-self-protection
    # tests below): a detector test lives directly under tests/ or in a
    # sibling subdir, not inside the harness's own guard-test package.
    worktree = tmp_path / "worktree"
    (worktree / "tests" / "detectors").mkdir(parents=True)

    assert is_write_allowed(
        worktree / "tests" / "detectors" / "test_new_thing.py",
        worktree_root=worktree,
    )


def test_denies_absolute_cases_directory(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()

    assert not is_write_allowed("/cases/evidence.img", worktree_root=worktree)


def test_denies_absolute_mnt_and_media(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()

    assert not is_write_allowed("/mnt/usb/out.txt", worktree_root=worktree)
    assert not is_write_allowed("/media/case1/out.txt", worktree_root=worktree)


def test_denies_any_evidence_segment_inside_worktree(tmp_path):
    worktree = tmp_path / "worktree"
    (worktree / "evidence").mkdir(parents=True)

    assert not is_write_allowed(
        worktree / "evidence" / "note.txt", worktree_root=worktree
    )


def test_denies_dotdot_traversal_outside_worktree(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()

    assert not is_write_allowed("../../etc/passwd", worktree_root=worktree)


def test_denies_allow_dir_symlink_pointing_into_deny_dir(tmp_path):
    worktree = tmp_path / "worktree"
    (worktree / "analysis").mkdir(parents=True)
    deny_target = tmp_path / "mnt" / "real_evidence"
    deny_target.mkdir(parents=True)
    trap = worktree / "analysis" / "linked"
    os.symlink(deny_target, trap)

    assert not is_write_allowed(trap / "out.txt", worktree_root=worktree)


def test_denies_symlink_whose_target_is_a_deny_path(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    real_evidence_dir = tmp_path / "evidence"
    real_evidence_dir.mkdir()
    link = worktree / "looks_safe"
    os.symlink(real_evidence_dir, link)

    assert not is_write_allowed(link / "out.txt", worktree_root=worktree)


def test_denies_absolute_case_variant_of_deny_segment(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()

    assert not is_write_allowed("/CASES/evidence.img", worktree_root=worktree)
    assert not is_write_allowed("/Mnt/usb.img", worktree_root=worktree)


def test_denies_case_variant_of_evidence_segment_inside_worktree(tmp_path):
    worktree = tmp_path / "worktree"
    (worktree / "Evidence").mkdir(parents=True)

    assert not is_write_allowed(
        worktree / "Evidence" / "note.txt", worktree_root=worktree
    )


def test_denies_trailing_slash_string_form_of_deny_dir(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()

    assert not is_write_allowed("/cases/", worktree_root=worktree)


def test_denies_dot_segment_form_resolving_into_evidence_dir(tmp_path):
    worktree = tmp_path / "worktree"
    (worktree / "evidence").mkdir(parents=True)
    path = worktree / "analysis" / ".." / "." / "evidence" / "file.txt"

    assert not is_write_allowed(path, worktree_root=worktree)


def test_denies_absolute_path_outside_worktree_even_when_allow_named(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    outside_exports = tmp_path / "exports" / "report.json"
    outside_exports.parent.mkdir(parents=True)

    assert not is_write_allowed(outside_exports, worktree_root=worktree)


def test_resolves_relative_path_against_worktree_root_not_cwd(tmp_path, monkeypatch):
    worktree = tmp_path / "worktree"
    (worktree / "analysis").mkdir(parents=True)
    other_cwd = tmp_path / "elsewhere"
    other_cwd.mkdir()
    monkeypatch.chdir(other_cwd)

    assert is_write_allowed("analysis/report.json", worktree_root=worktree)


def test_denies_relative_traversal_resolved_against_worktree_root(
    tmp_path, monkeypatch
):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    other_cwd = tmp_path / "elsewhere"
    other_cwd.mkdir()
    monkeypatch.chdir(other_cwd)

    assert not is_write_allowed("../cases/x", worktree_root=worktree)


def test_worktree_root_itself_may_be_given_as_a_relative_path(tmp_path, monkeypatch):
    # NOTE: `path` is relative to worktree_root, not cwd -- it must NOT
    # repeat the "worktree" segment (an earlier version of this test did,
    # and only passed by coincidence under the old open-deny-list, which
    # allowed any non-deny path regardless of whether it pointed at a real
    # location; the closed allow-list correctly rejects the double-joined
    # "worktree/worktree/analysis/..." path that mistake produced).
    (tmp_path / "worktree" / "analysis").mkdir(parents=True)
    monkeypatch.chdir(tmp_path)

    assert is_write_allowed("analysis/report.json", worktree_root="worktree")


# --- Closed allow-list (secreview CRITICAL #1): repo-governance / dotfile /
# self-protection paths must be denied even though they carry no DENY
# segment and sit squarely inside the worktree. ---------------------------


def test_denies_repo_root_pyproject_toml(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()

    assert not is_write_allowed(worktree / "pyproject.toml", worktree_root=worktree)


def test_denies_ci_workflow_file(tmp_path):
    worktree = tmp_path / "worktree"
    (worktree / ".github" / "workflows").mkdir(parents=True)

    assert not is_write_allowed(
        worktree / ".github" / "workflows" / "ci.yml", worktree_root=worktree
    )


def test_denies_dot_git_hooks_file(tmp_path):
    worktree = tmp_path / "worktree"
    (worktree / ".git" / "hooks").mkdir(parents=True)

    assert not is_write_allowed(
        worktree / ".git" / "hooks" / "x", worktree_root=worktree
    )


def test_denies_pre_commit_config(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()

    assert not is_write_allowed(
        worktree / ".pre-commit-config.yaml", worktree_root=worktree
    )


def test_denies_dot_env_file(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()

    assert not is_write_allowed(worktree / ".env", worktree_root=worktree)


def test_denies_own_gate_harness_source_self_protection(tmp_path):
    worktree = tmp_path / "worktree"
    (worktree / "nexus_pipeline" / "gates").mkdir(parents=True)

    assert not is_write_allowed(
        worktree / "nexus_pipeline" / "gates" / "runner.py", worktree_root=worktree
    )


def test_denies_write_under_tests_pipeline_subtree(tmp_path):
    # Post-PR review finding: `tests` is a blanket top-level ALLOW so an
    # agent could otherwise rewrite the very tests
    # (evidence_guard/sources/runner) that prove this harness behaves --
    # the same self-certification risk as the pyproject.toml hole, applied
    # to the guard tests themselves.
    worktree = tmp_path / "worktree"
    (worktree / "tests" / "pipeline").mkdir(parents=True)

    assert not is_write_allowed(
        worktree / "tests" / "pipeline" / "test_evidence_guard.py",
        worktree_root=worktree,
    )


def test_denies_the_tests_pipeline_directory_itself(tmp_path):
    worktree = tmp_path / "worktree"
    (worktree / "tests" / "pipeline").mkdir(parents=True)

    assert not is_write_allowed(worktree / "tests" / "pipeline", worktree_root=worktree)


def test_allows_write_under_tests_outside_the_pipeline_subtree(tmp_path):
    worktree = tmp_path / "worktree"
    (worktree / "tests").mkdir(parents=True)

    assert is_write_allowed(
        worktree / "tests" / "test_detector.py", worktree_root=worktree
    )


def test_denies_docs_scripts_rules_and_connector_dirs(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()

    for name in (
        "docs",
        "scripts",
        "rules",
        "strike48_connector",
        "strike48_connector_4n6",
        "ui",
        ".claudeignore",
    ):
        assert not is_write_allowed(worktree / name / "x", worktree_root=worktree)


def test_allows_scenario_synthetic_scenario_yaml(tmp_path):
    worktree = tmp_path / "worktree"
    (worktree / "scenarios" / "synthetic" / "foo").mkdir(parents=True)

    assert is_write_allowed(
        worktree / "scenarios" / "synthetic" / "foo" / "scenario.yaml",
        worktree_root=worktree,
    )


def test_worktree_under_a_parent_dir_named_mnt_still_allows_legit_source_write(
    tmp_path,
):
    # secreview MEDIUM #2: a plausible deployment topology (worktrees
    # provisioned under ~/.../mnt/...) must not deny 100% of legitimate
    # writes just because worktree_root's own ancestry contains a DENY
    # word -- only a segment the caller chose INSIDE the worktree counts.
    worktree = tmp_path / "mnt" / "actual_worktree"
    (worktree / "sift_find_evil" / "detectors").mkdir(parents=True)

    assert is_write_allowed(
        worktree / "sift_find_evil" / "detectors" / "new_detector.py",
        worktree_root=worktree,
    )


def test_worktree_under_a_parent_dir_named_cases_still_allows_legit_output_write(
    tmp_path,
):
    worktree = tmp_path / "cases" / "actual_worktree"
    (worktree / "analysis").mkdir(parents=True)

    assert is_write_allowed(
        worktree / "analysis" / "report.json", worktree_root=worktree
    )


def test_denies_nested_case_variant_of_deny_segment(tmp_path):
    worktree = tmp_path / "worktree"
    (worktree / "analysis" / "CASES").mkdir(parents=True)

    assert not is_write_allowed(
        worktree / "analysis" / "CASES" / "x.img", worktree_root=worktree
    )


def test_denies_nested_deny_segment_with_trailing_whitespace(tmp_path):
    # secreview LOW #6: a directory literally named "cases " (trailing
    # space) must not bypass the deny check via exact-string mismatch.
    worktree = tmp_path / "worktree"
    (worktree / "analysis" / "cases ").mkdir(parents=True)

    assert not is_write_allowed(
        worktree / "analysis" / "cases " / "x.img", worktree_root=worktree
    )


def test_evidence_report_directory_name_is_not_treated_as_evidence(tmp_path):
    worktree = tmp_path / "worktree"
    (worktree / "analysis" / "evidence_report").mkdir(parents=True)

    assert is_write_allowed(
        worktree / "analysis" / "evidence_report" / "summary.json",
        worktree_root=worktree,
    )


def test_my_evidence_directory_name_is_not_treated_as_evidence(tmp_path):
    worktree = tmp_path / "worktree"
    (worktree / "analysis" / "my_evidence").mkdir(parents=True)

    assert is_write_allowed(
        worktree / "analysis" / "my_evidence" / "summary.json",
        worktree_root=worktree,
    )


def test_malformed_null_byte_path_raises_rather_than_silently_allowing(tmp_path):
    # secreview MEDIUM #4/#5 exception contract: this function must never
    # silently return True on a malformed path -- it must raise, and the
    # module docstring documents that any exception is DENY-by-contract for
    # the caller.
    worktree = tmp_path / "worktree"
    worktree.mkdir()

    with pytest.raises(ValueError):
        is_write_allowed("bad\x00path", worktree_root=worktree)
