"""Tests for nexus_pipeline.gates.sources (spec section 3, "derive from live
executable source, never CLAUDE.md prose"; digest section A).

Unit tests construct minimal synthetic CI/config files under tmp_path to
exercise parsing and error handling in isolation. The `live_*` tests read
the actual repo files via the `repo_root` fixture -- that IS the point of
this module, so those tests are intentionally not mocked.
"""

import glob

import pytest

from nexus_pipeline.gates import sources


def _write(path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_core_ci_commands_parses_ruff_black_and_pytest_steps(tmp_path):
    _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - name: ruff check\n"
        "        run: ruff check .\n"
        "      - name: black check\n"
        "        run: black --check .\n"
        "      - name: pytest core\n"
        "        if: matrix.tier == 'core'\n"
        "        run: |\n"
        "          pytest -q \\\n"
        "            --cov=sift_find_evil \\\n"
        "            --cov-report=term-missing\n",
    )

    commands = sources.core_ci_commands(tmp_path)

    assert commands.lint_command == "ruff check ."
    assert commands.format_command == "black --check ."
    assert "--cov=sift_find_evil" in commands.coverage_command
    assert "--cov-fail-under" not in commands.coverage_command


def test_core_ci_commands_parses_a_bare_cov_coverage_step(tmp_path):
    """The spelling the real ci.yml uses since #237.

    A bare --cov inherits [tool.coverage.run] source; the parser must find the
    step by its --cov TOKEN, not by a package name baked into the pattern.
    Keying on the literal "--cov=sift_find_evil" is what took main red when
    #237 switched CI to this spelling.
    """
    _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - name: ruff check\n"
        "        run: ruff check .\n"
        "      - name: black check\n"
        "        run: black --check .\n"
        "      - name: pytest core\n"
        "        run: |\n"
        "          pytest -q \\\n"
        "            --cov \\\n"
        "            --cov-report=term-missing\n",
    )

    commands = sources.core_ci_commands(tmp_path)

    assert commands.coverage_command == "pytest -q --cov --cov-report=term-missing"


def test_core_ci_commands_rejects_a_cov_report_only_step_as_the_coverage_gate(
    tmp_path,
):
    """``--cov-report`` shares the ``--cov`` prefix but enables no coverage.

    A substring test would accept this step as the coverage gate and report a
    non-enforcing command as CI's floor. Token-exact matching finds no real
    --cov here, so parsing must fail loudly instead.
    """
    _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - name: ruff check\n"
        "        run: ruff check .\n"
        "      - name: black check\n"
        "        run: black --check .\n"
        "      - name: pytest without coverage\n"
        "        run: pytest -q --cov-report=term-missing\n",
    )

    with pytest.raises(sources.LiveSourceError):
        sources.core_ci_commands(tmp_path)


def test_core_ci_commands_ignores_a_cov_mention_inside_a_shell_comment(tmp_path):
    """Comment text must never decide which step is the coverage gate.

    ``run: |`` blocks are flattened to one line, so before comments were
    stripped a comment saying a step runs WITHOUT coverage was enough to make
    that step match as the coverage gate. ci.yml uses such comments heavily.
    """
    _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - name: ruff check\n"
        "        run: ruff check .\n"
        "      - name: black check\n"
        "        run: black --check .\n"
        "      - name: pytest core\n"
        "        run: pytest -q --cov\n"
        "      - name: benchmark gate\n"
        "        run: |\n"
        "          # note this gate deliberately runs without --cov\n"
        "          pytest -q tests/test_benchmark_heldout.py\n",
    )

    commands = sources.core_ci_commands(tmp_path)

    assert commands.coverage_command == "pytest -q --cov"


def test_core_ci_commands_raises_when_two_steps_enable_coverage(tmp_path):
    """Ambiguity must fail loudly rather than resolve by position.

    The scan previously kept the LAST match, so a second --cov step silently
    displaced the real gate and the drift guard compared the wrong command.
    """
    _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - name: ruff check\n"
        "        run: ruff check .\n"
        "      - name: black check\n"
        "        run: black --check .\n"
        "      - name: pytest core\n"
        "        run: pytest -q --cov\n"
        "      - name: partial rerun\n"
        "        run: pytest -q tests/test_benchmark_heldout.py --cov --cov-append\n",
    )

    with pytest.raises(sources.LiveSourceError, match="2 coverage steps"):
        sources.core_ci_commands(tmp_path)


def test_core_ci_commands_ignores_a_cov_token_in_a_non_pytest_step(tmp_path):
    """A --cov token outside a pytest invocation is not the coverage gate.

    Pins the ``pytest``-token requirement, which previously changed no test
    outcome and so guarded nothing.
    """
    _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - name: ruff check\n"
        "        run: ruff check .\n"
        "      - name: black check\n"
        "        run: black --check .\n"
        "      - name: usage banner\n"
        "        run: echo 'run it with --cov to measure coverage'\n",
    )

    with pytest.raises(sources.LiveSourceError):
        sources.core_ci_commands(tmp_path)


def test_core_ci_commands_raises_on_missing_pytest_step(tmp_path):
    _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - name: ruff check\n"
        "        run: ruff check .\n"
        "      - name: black check\n"
        "        run: black --check .\n",
    )

    with pytest.raises(sources.LiveSourceError):
        sources.core_ci_commands(tmp_path)


def test_core_ci_commands_raises_when_workflow_file_is_missing(tmp_path):
    with pytest.raises(sources.LiveSourceError):
        sources.core_ci_commands(tmp_path)


def test_sanitize_ci_command_parses_the_sync_script_step(tmp_path):
    _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "jobs:\n"
        "  test:\n"
        "    steps: []\n"
        "  sanitize:\n"
        "    steps:\n"
        "      - name: sync allowlist sanitizer\n"
        "        run: bash scripts/sync-to-public.sh --check-only\n",
    )

    assert (
        sources.sanitize_ci_command(tmp_path)
        == "bash scripts/sync-to-public.sh --check-only"
    )


def test_sanitize_ci_command_raises_when_step_missing(tmp_path):
    _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "jobs:\n"
        "  test:\n"
        "    steps: []\n"
        "  sanitize:\n"
        "    steps:\n"
        "      - name: unrelated\n"
        "        run: echo hello\n",
    )

    with pytest.raises(sources.LiveSourceError):
        sources.sanitize_ci_command(tmp_path)


def test_coverage_fail_under_reads_pyproject(tmp_path):
    _write(
        tmp_path / "pyproject.toml",
        "[tool.coverage.report]\nfail_under = 97.5\nprecision = 2\n",
    )

    assert sources.coverage_fail_under(tmp_path) == 97.5


def test_coverage_fail_under_raises_when_key_missing(tmp_path):
    _write(tmp_path / "pyproject.toml", "[tool.black]\nline-length = 88\n")

    with pytest.raises(sources.LiveSourceError):
        sources.coverage_fail_under(tmp_path)


def test_coverage_fail_under_raises_when_file_missing(tmp_path):
    with pytest.raises(sources.LiveSourceError):
        sources.coverage_fail_under(tmp_path)


def test_pinned_linter_versions_reads_precommit_config(tmp_path):
    _write(
        tmp_path / ".pre-commit-config.yaml",
        "repos:\n"
        "  - repo: https://github.com/psf/black\n"
        "    rev: 25.9.0\n"
        "    hooks:\n"
        "      - id: black\n"
        "  - repo: https://github.com/astral-sh/ruff-pre-commit\n"
        "    rev: v0.15.11\n"
        "    hooks:\n"
        "      - id: ruff\n",
    )

    versions = sources.pinned_linter_versions(tmp_path)

    assert versions.black == "25.9.0"
    assert versions.ruff == "v0.15.11"


def test_pinned_linter_versions_raises_when_a_pin_is_missing(tmp_path):
    _write(
        tmp_path / ".pre-commit-config.yaml",
        "repos:\n"
        "  - repo: https://github.com/psf/black\n"
        "    rev: 25.9.0\n"
        "    hooks:\n"
        "      - id: black\n",
    )

    with pytest.raises(sources.LiveSourceError):
        sources.pinned_linter_versions(tmp_path)


def test_pinned_linter_versions_skips_a_non_mapping_repo_entry_and_still_parses(
    tmp_path,
):
    # secreview MEDIUM #3: a bare-string repos entry alongside two valid
    # ones used to crash with AttributeError ('str' object has no
    # attribute 'get') instead of being skipped.
    _write(
        tmp_path / ".pre-commit-config.yaml",
        "repos:\n"
        "  - repo: https://github.com/psf/black\n"
        "    rev: 25.9.0\n"
        "  - just-a-bare-string-not-a-mapping\n"
        "  - repo: https://github.com/astral-sh/ruff-pre-commit\n"
        "    rev: v0.15.11\n",
    )

    versions = sources.pinned_linter_versions(tmp_path)

    assert versions.black == "25.9.0"
    assert versions.ruff == "v0.15.11"


def test_pinned_linter_versions_raises_cleanly_when_all_entries_are_malformed(
    tmp_path,
):
    _write(tmp_path / ".pre-commit-config.yaml", "repos:\n  - not-a-mapping\n  - 42\n")

    with pytest.raises(sources.LiveSourceError):
        sources.pinned_linter_versions(tmp_path)


def test_pinned_linter_versions_raises_cleanly_when_repo_field_is_not_a_string(
    tmp_path,
):
    # secreview MEDIUM #3: a non-string `repo:` value used to crash with
    # TypeError ("argument of type 'int' is not iterable") on the `in`
    # membership test instead of being skipped.
    _write(
        tmp_path / ".pre-commit-config.yaml", "repos:\n  - repo: 12345\n    rev: 1.0\n"
    )

    with pytest.raises(sources.LiveSourceError):
        sources.pinned_linter_versions(tmp_path)


def test_core_ci_commands_raises_cleanly_when_jobs_is_not_a_mapping(tmp_path):
    # secreview MEDIUM #3: `jobs` as a list used to crash with TypeError
    # ("list indices must be integers or slices, not str") instead of
    # raising LiveSourceError.
    _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "jobs:\n  - not-a-mapping\n",
    )

    with pytest.raises(sources.LiveSourceError):
        sources.core_ci_commands(tmp_path)


def test_core_ci_commands_skips_a_blank_step_entry_and_still_parses(tmp_path):
    # secreview MEDIUM #3: a blank list item (`- ` with no content, valid
    # YAML for a null step) used to crash with AttributeError ('NoneType'
    # object has no attribute 'get') instead of being skipped.
    _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - \n"
        "      - name: ruff check\n"
        "        run: ruff check .\n"
        "      - name: black check\n"
        "        run: black --check .\n"
        "      - name: pytest core\n"
        "        run: pytest -q --cov=sift_find_evil\n",
    )

    commands = sources.core_ci_commands(tmp_path)

    assert commands.lint_command == "ruff check ."
    assert commands.format_command == "black --check ."


def test_sanitize_ci_command_skips_a_blank_step_entry_and_still_parses(tmp_path):
    _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "jobs:\n"
        "  test:\n"
        "    steps: []\n"
        "  sanitize:\n"
        "    steps:\n"
        "      - \n"
        "      - name: sync allowlist sanitizer\n"
        "        run: bash scripts/sync-to-public.sh --check-only\n",
    )

    assert (
        sources.sanitize_ci_command(tmp_path)
        == "bash scripts/sync-to-public.sh --check-only"
    )


def test_coverage_fail_under_raises_cleanly_when_coverage_is_not_a_table(tmp_path):
    # secreview MEDIUM #3: [tool.coverage] as a non-table value used to
    # crash with TypeError ("string indices must be integers") instead of
    # raising LiveSourceError.
    _write(tmp_path / "pyproject.toml", '[tool]\ncoverage = "oops-not-a-table"\n')

    with pytest.raises(sources.LiveSourceError):
        sources.coverage_fail_under(tmp_path)


def test_coverage_fail_under_raises_cleanly_when_value_is_not_a_number(tmp_path):
    _write(tmp_path / "pyproject.toml", '[tool.coverage.report]\nfail_under = "high"\n')

    with pytest.raises(sources.LiveSourceError):
        sources.coverage_fail_under(tmp_path)


def test_scenario_count_reflects_a_live_glob_not_a_literal(tmp_path):
    scenario_dir = tmp_path / "scenarios" / "synthetic"
    _write(scenario_dir / "01_clean_baseline" / "scenario.yaml", "expected: []\n")

    assert sources.scenario_count(tmp_path) == 1

    _write(scenario_dir / "02_new_scenario" / "scenario.yaml", "expected: []\n")

    assert sources.scenario_count(tmp_path) == 2


def test_live_core_ci_commands_match_real_repo(repo_root):
    commands = sources.core_ci_commands(repo_root)

    assert commands.lint_command == "ruff check ."
    assert commands.format_command == "black --check ."
    assert "--cov-fail-under" not in commands.coverage_command


def test_live_pinned_linter_versions_are_nonempty(repo_root):
    versions = sources.pinned_linter_versions(repo_root)

    assert versions.black
    assert versions.ruff


def test_live_coverage_fail_under_is_a_float(repo_root):
    assert isinstance(sources.coverage_fail_under(repo_root), float)


def test_live_scenario_count_matches_an_independent_glob(repo_root):
    expected = len(
        glob.glob(
            str(repo_root / "scenarios" / "synthetic" / "**" / "scenario.yaml"),
            recursive=True,
        )
    )

    assert sources.scenario_count(repo_root) == expected
    assert sources.scenario_count(repo_root) > 0


# ---------------------------------------------------------------------------
# Command position. Text that merely CONTAINS a pytest token must never be
# selected as the coverage gate -- the same "prose decides step selection"
# class as the shell-comment vector, reached through heredoc bodies and
# quoted arguments instead of through comments.
# ---------------------------------------------------------------------------


_LINT_AND_FORMAT = (
    "      - name: ruff check\n"
    "        run: ruff check .\n"
    "      - name: black check\n"
    "        run: black --check .\n"
)


def _ci_with(extra_steps: str) -> str:
    return "jobs:\n  test:\n    steps:\n" + _LINT_AND_FORMAT + extra_steps


def test_heredoc_body_is_not_mistaken_for_the_coverage_gate(tmp_path):
    """A coverage command quoted inside a heredoc body is data, not a command.

    The step below runs `cat`; it never invokes pytest. Selecting it would let
    file CONTENT decide which step is the gate.
    """
    _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        _ci_with(
            "      - name: write a note\n"
            "        run: |\n"
            "          cat <<'EOF' > note.txt\n"
            "          pytest tests/ --cov=sift_find_evil\n"
            "          EOF\n"
        ),
    )

    with pytest.raises(sources.LiveSourceError, match="has no coverage step"):
        sources.core_ci_commands(tmp_path)


def test_echo_of_usage_text_is_not_mistaken_for_the_coverage_gate(tmp_path):
    """The case _enables_coverage's docstring explicitly promises."""
    _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        _ci_with(
            "      - name: print usage\n"
            "        run: |\n"
            "          echo 'usage: pytest --cov'\n"
        ),
    )

    with pytest.raises(sources.LiveSourceError, match="has no coverage step"):
        sources.core_ci_commands(tmp_path)


def test_coverage_run_is_not_mistaken_for_the_coverage_gate(tmp_path):
    """The other case the docstring promises: `coverage run`, not pytest."""
    _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        _ci_with(
            "      - name: coverage run\n"
            "        run: coverage run --cov -m unittest discover\n"
        ),
    )

    with pytest.raises(sources.LiveSourceError, match="has no coverage step"):
        sources.core_ci_commands(tmp_path)


def test_heredoc_noise_does_not_hide_the_real_coverage_gate(tmp_path):
    """Noise must be ignored, not merely raise ambiguity alongside the real gate."""
    _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        _ci_with(
            "      - name: write a note\n"
            "        run: |\n"
            "          cat <<'EOF' > note.txt\n"
            "          pytest tests/ --cov=sift_find_evil\n"
            "          EOF\n"
            "      - name: coverage\n"
            "        run: pytest -q --cov --cov-report=xml\n"
        ),
    )

    commands = sources.core_ci_commands(tmp_path)

    assert commands.coverage_command == "pytest -q --cov --cov-report=xml"


def test_python_dash_m_pytest_is_detected_as_the_coverage_gate(tmp_path):
    """`python -m pytest` is a normal CI spelling; failing to match it would
    raise LiveSourceError and turn main red, the failure this parser exists
    to prevent."""
    _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        _ci_with(
            "      - name: coverage\n"
            "        run: python -m pytest -q --cov --cov-report=xml\n"
        ),
    )

    commands = sources.core_ci_commands(tmp_path)

    assert commands.coverage_command == "python -m pytest -q --cov --cov-report=xml"


def test_env_prefixed_pytest_is_detected_as_the_coverage_gate(tmp_path):
    """A `VAR=value` prefix is not the command word."""
    _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        _ci_with(
            "      - name: coverage\n" "        run: PYTHONPATH=. pytest -q --cov\n"
        ),
    )

    commands = sources.core_ci_commands(tmp_path)

    assert commands.coverage_command == "PYTHONPATH=. pytest -q --cov"


def test_chained_commands_in_one_step_find_the_pytest_member(tmp_path):
    """Selection looks at each command in a multi-command step, not the
    flattened blob, but the REPORTED command stays the whole step."""
    _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        _ci_with(
            "      - name: coverage\n"
            "        run: |\n"
            "          echo starting\n"
            "          pytest -q --cov\n"
        ),
    )

    commands = sources.core_ci_commands(tmp_path)

    assert commands.coverage_command == "echo starting pytest -q --cov"


def test_quoted_cov_flag_is_detected_as_the_coverage_gate(tmp_path):
    """Quoting a flag is legal shell, so the gate must still be recognized.

    This is what pins POSIX-mode lexing specifically. Grouping alone (which
    non-POSIX shlex also does) is enough to stop a quoted `pytest` mention
    being read as a command; stripping the quotes is what keeps a quoted
    `'--cov'` comparing equal to the bare flag.
    """
    _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        _ci_with("      - name: coverage\n" "        run: pytest -q '--cov'\n"),
    )

    commands = sources.core_ci_commands(tmp_path)

    assert commands.coverage_command == "pytest -q '--cov'"


def test_unquoted_pytest_mention_is_not_the_coverage_gate(tmp_path):
    """An unquoted pytest token in a non-pytest command must not select the gate.

    This is the shape that isolates the command-word check. Nothing is quoted,
    so shlex grouping cannot exclude it, and there is no heredoc to strip, so
    only :func:`_invokes_pytest` deciding on the command WORD rejects it.
    Without this test the mechanism is unguarded: reverting that function to
    plain token membership leaves every other test in this module green.
    """
    _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        _ci_with("      - name: banner\n        run: echo pytest --cov\n"),
    )

    with pytest.raises(sources.LiveSourceError, match="has no coverage step"):
        sources.core_ci_commands(tmp_path)


def test_a_surviving_hash_does_not_discard_the_real_coverage_step(tmp_path):
    """A `#` that opens no shell comment must not hide a later command.

    _strip_shell_comments deliberately preserves a `#` that does not start a
    word, such as a URL fragment. The block is then flattened to one line
    before lexing, so leaving shlex's own `commenters` enabled treats that `#`
    as a comment and discards every command after it -- the real coverage step
    included -- failing the gate closed and turning main red. That is the exact
    failure this parser exists to prevent, reached through a different door.
    """
    _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        _ci_with(
            "      - name: coverage\n"
            "        run: |\n"
            "          curl -sSL https://example.com/docs#install -o d.html\n"
            "          pytest -q --cov\n"
        ),
    )

    commands = sources.core_ci_commands(tmp_path)

    assert commands.coverage_command.endswith("pytest -q --cov")
