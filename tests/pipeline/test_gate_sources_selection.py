"""Step-selection tests for nexus_pipeline.gates.sources (bd SFE-e7hx).

These pin the four gaps left after PR #239, all of the same class: text that
is not a command (a comment, a quoted string, a mention) deciding which CI
step a matcher selects, or a matcher resolving ambiguity by position instead
of raising. The coverage path already resolved them; these tests make the
lint, format and sanitize paths resolve the same way, and close the two
parser gaps (per-line quote state, unrecognized pytest spellings) that still
lost a real coverage command.

Companion to test_gate_sources.py, split out so that module stays under the
file-size review gate; the seam is "which step gets selected", not "what a
selected step parses to".
"""

import pytest

from nexus_pipeline.gates import sources


def _write(path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _step(run: str) -> str:
    indented = "\n".join(f"          {line}" for line in run.splitlines())
    return f"      - run: |\n{indented}\n"


def _ci(tmp_path, test_steps: str, sanitize_steps: str = "") -> None:
    text = "jobs:\n  test:\n    steps:\n" + test_steps
    if sanitize_steps:
        text += "  sanitize:\n    steps:\n" + sanitize_steps
    _write(tmp_path / ".github" / "workflows" / "ci.yml", text)


_LINT_AND_FORMAT = _step("ruff check .") + _step("black --check .")


# -- A. quote state must span the whole block ---------------------------------


def test_a_quote_spanning_lines_does_not_hide_the_coverage_gate(tmp_path):
    """A ``#`` inside a multi-line quoted string is data, not a comment.

    Per-line comment stripping deleted the closing quote, shlex then failed,
    the fallback examined only the block's first word, and the real
    ``pytest --cov`` two lines down was lost (SFE-e7hx vector A).
    """
    _ci(tmp_path, _LINT_AND_FORMAT + _step('echo "a\nb # c"\npytest -q --cov'))

    commands = sources.core_ci_commands(tmp_path)

    assert commands.coverage_command.endswith("pytest -q --cov")


# -- B. ordinary pytest spellings must be recognized --------------------------


@pytest.mark.parametrize(
    "command",
    [
        "python -u -m pytest --cov",
        "python -X dev -m pytest --cov",
        "python -W error -m pytest --cov",
        "python3 -W error::DeprecationWarning -u -m pytest --cov",
        "env FOO=1 pytest --cov",
        "env -i PATH=/usr/bin pytest --cov",
        "timeout 600 pytest --cov",
        "timeout -k 10 600 pytest --cov",
        "nice pytest --cov",
        "nice -n 10 pytest --cov",
        "xvfb-run pytest --cov",
        "xvfb-run -a -s '-screen 0 1024x768x24' pytest --cov",
        "uv run --frozen pytest --cov",
        "uv run --frozen --no-sync pytest --cov",
        "poetry run pytest --cov",
        "timeout 600 uv run --frozen python -u -m pytest --cov",
    ],
)
def test_b_ordinary_pytest_spellings_are_the_coverage_gate(tmp_path, command):
    _ci(tmp_path, _LINT_AND_FORMAT + _step(command))

    commands = sources.core_ci_commands(tmp_path)

    assert commands.coverage_command == command


@pytest.mark.parametrize(
    "command",
    [
        "python -c 'import pytest' -m pytest --cov",
        "uv run --with pytest-cov --cov",
        "timeout 600 --cov",
        "echo timeout 600 pytest --cov",
        "xargs pytest --cov",
        "pytest -q -- --cov",
        "python -c -x -m pytest --cov",
    ],
)
def test_b_a_wrapper_that_does_not_reach_pytest_is_not_the_gate(tmp_path, command):
    _ci(tmp_path, _LINT_AND_FORMAT + _step(command))

    with pytest.raises(sources.LiveSourceError):
        sources.core_ci_commands(tmp_path)


# -- C. sanitize selection resolves by command, not by raw text --------------


def test_c_sanitize_ignores_a_comment_that_names_the_sync_script(tmp_path):
    """The raw-substring match selected a step for its COMMENT and then
    reported the de-commented command, so selection and report disagreed
    (SFE-e7hx vector C: it returned ``echo hi``).
    """
    _ci(
        tmp_path,
        _LINT_AND_FORMAT + _step("pytest -q --cov"),
        _step("echo hi # sync-to-public.sh")
        + _step("bash scripts/sync-to-public.sh --check-only"),
    )

    assert sources.sanitize_ci_command(tmp_path) == (
        "bash scripts/sync-to-public.sh --check-only"
    )


def test_c_sanitize_ignores_a_quoted_mention_of_the_sync_script(tmp_path):
    _ci(
        tmp_path,
        _LINT_AND_FORMAT + _step("pytest -q --cov"),
        _step("echo 'run sync-to-public.sh yourself'")
        + _step("scripts/sync-to-public.sh --check-only"),
    )

    assert (
        sources.sanitize_ci_command(tmp_path)
        == "scripts/sync-to-public.sh --check-only"
    )


def test_c_sanitize_ignores_a_step_that_only_handles_the_script_as_a_file(tmp_path):
    """``cp scripts/sync-to-public.sh /tmp/x`` names the script as an ARGUMENT to
    a command that is neither the script nor a shell; only the command word,
    or a shell interpreter's script operand, may select the step.
    """
    _ci(
        tmp_path,
        _LINT_AND_FORMAT + _step("pytest -q --cov"),
        _step("cp scripts/sync-to-public.sh /tmp/x")
        + _step("ls -l scripts/sync-to-public.sh")
        + _step("bash scripts/sync-to-public.sh --check-only"),
    )

    assert (
        sources.sanitize_ci_command(tmp_path)
        == "bash scripts/sync-to-public.sh --check-only"
    )


def test_c_sanitize_raises_when_two_steps_run_the_sync_script(tmp_path):
    _ci(
        tmp_path,
        _LINT_AND_FORMAT + _step("pytest -q --cov"),
        _step("bash scripts/sync-to-public.sh --check-only")
        + _step("bash scripts/sync-to-public.sh --public-dir /tmp/pub"),
    )

    with pytest.raises(sources.LiveSourceError, match="2 sync-to-public.sh steps"):
        sources.sanitize_ci_command(tmp_path)


# -- D. lint and format selection raise on ambiguity, like coverage ----------


def test_d_two_ruff_check_steps_raise_instead_of_last_match_winning(tmp_path):
    _ci(
        tmp_path,
        _step("ruff check .")
        + _step("ruff check --select E9 .")
        + _step("black --check .")
        + _step("pytest -q --cov"),
    )

    with pytest.raises(sources.LiveSourceError, match="2 ruff check steps"):
        sources.core_ci_commands(tmp_path)


def test_d_two_black_check_steps_raise_instead_of_last_match_winning(tmp_path):
    _ci(
        tmp_path,
        _step("ruff check .")
        + _step("black --check .")
        + _step("black --check --diff .")
        + _step("pytest -q --cov"),
    )

    with pytest.raises(sources.LiveSourceError, match="2 black --check steps"):
        sources.core_ci_commands(tmp_path)


def test_d_a_lint_step_is_selected_by_its_command_not_its_first_characters(tmp_path):
    """``normalized.startswith("ruff check")`` selected by TEXT position: a
    step whose command was preceded by an environment assignment or a
    comment line was not found, and a step that merely echoed the words was.
    """
    _ci(
        tmp_path,
        _step("echo 'ruff check would go here'")
        + _step("# lint\nRUFF_CACHE_DIR=/tmp/ruff ruff check .")
        + _step("black --check .")
        + _step("pytest -q --cov"),
    )

    commands = sources.core_ci_commands(tmp_path)

    assert commands.lint_command == "RUFF_CACHE_DIR=/tmp/ruff ruff check ."


def test_d_ruff_format_is_not_mistaken_for_ruff_check(tmp_path):
    _ci(
        tmp_path,
        _step("ruff format --check .")
        + _step("ruff check .")
        + _step("black --check .")
        + _step("pytest -q --cov"),
    )

    commands = sources.core_ci_commands(tmp_path)

    assert commands.lint_command == "ruff check ."
