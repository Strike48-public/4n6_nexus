"""Guards against the harness's committed Gate A/B/C/E commands silently
drifting from what .github/workflows/ci.yml (and pyproject.toml) actually
say (spec section 3, "derive from live source"; digest section A). If CI's
real command changes without this harness being updated to match, these
tests fail -- that failure IS the guard.
"""

import glob

from nexus_pipeline.gates import definitions, sources


def _argv_as_command(argv: tuple[str, ...]) -> str:
    return " ".join(argv)


def test_gate_a_ruff_matches_live_ci_lint_command(repo_root):
    live = sources.core_ci_commands(repo_root)
    gate_a_ruff = next(
        d for d in definitions.GATE_DEFINITIONS if d.name == "A" and d.argv[0] == "ruff"
    )

    assert _argv_as_command(gate_a_ruff.argv) == live.lint_command


def test_gate_a_black_matches_live_ci_format_command(repo_root):
    live = sources.core_ci_commands(repo_root)
    gate_a_black = next(
        d
        for d in definitions.GATE_DEFINITIONS
        if d.name == "A" and d.argv[0] == "black"
    )

    assert _argv_as_command(gate_a_black.argv) == live.format_command


def test_gate_b_and_live_ci_both_enable_coverage_with_a_bare_cov(repo_root):
    """Both must pass a BARE ``--cov``, never ``--cov=<pkg>``.

    A package-qualified --cov REPLACES the ``[tool.coverage.run] source`` list
    instead of inheriting it, which silently drops nexus_pipeline from what is
    measured -- the coverage-inclusion gap SFE-rbje closed. Asserting the
    spelling (rather than which package is named, as this test did before
    #237) is what keeps both sides inheriting that one source list.

    Scope, stated honestly: this checks the --cov SPELLING on each side, not
    that the two commands measure the same set. Gate A gets a real equality
    assertion against the live command; Gate B has never had one, so a live
    ci.yml of ``pytest -q tests/unit --cov --cov-branch`` would still pass here
    despite measuring something quite different. Tightening Gate B to an
    equality-style assertion is worth doing; it is not what this test does.
    """
    live = sources.core_ci_commands(repo_root)
    gate_b = next(d for d in definitions.GATE_DEFINITIONS if d.name == "B")

    for label, command in (
        ("Gate B", _argv_as_command(gate_b.argv)),
        ("live ci.yml", live.coverage_command),
    ):
        tokens = command.split()
        assert "--cov" in tokens, f"{label} enables no coverage: {command!r}"
        qualified = [t for t in tokens if t.startswith("--cov=")]
        assert not qualified, (
            f"{label} passes {qualified}; a package-qualified --cov discards "
            f"[tool.coverage.run] source and drops nexus_pipeline from the "
            f"floor: {command!r}"
        )


def test_gate_b_never_passes_cov_fail_under(repo_root):
    live = sources.core_ci_commands(repo_root)
    gate_b = next(d for d in definitions.GATE_DEFINITIONS if d.name == "B")

    assert "--cov-fail-under" not in _argv_as_command(gate_b.argv)
    assert "--cov-fail-under" not in live.coverage_command


def test_reported_coverage_floor_matches_live_pyproject(repo_root):
    assert definitions.reported_coverage_floor(
        repo_root
    ) == sources.coverage_fail_under(repo_root)


def test_gate_e_matches_live_ci_sanitize_command(repo_root):
    live_sanitize = sources.sanitize_ci_command(repo_root)
    gate_e = next(d for d in definitions.GATE_DEFINITIONS if d.name == "E")

    assert _argv_as_command(gate_e.argv) == live_sanitize


def test_gate_c_script_path_exists_in_the_live_repo(repo_root):
    gate_c = next(d for d in definitions.GATE_DEFINITIONS if d.name == "C")
    script_path = next(token for token in gate_c.argv if token.endswith(".py"))

    assert (repo_root / script_path).is_file()


def test_scenario_count_used_for_reporting_is_a_live_glob(repo_root):
    # A hardcoded literal would not change if the corpus grows; confirm the
    # count matches an independent glob call taken at test time.
    expected = len(
        glob.glob(
            str(repo_root / "scenarios" / "synthetic" / "**" / "scenario.yaml"),
            recursive=True,
        )
    )

    assert sources.scenario_count(repo_root) == expected
