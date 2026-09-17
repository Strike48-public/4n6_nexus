"""Coverage-inclusion invariant guard (bd SFE-rbje; covgap flap postmortem).

The autonomous-pipeline code lives in a SECOND top-level package,
``nexus_pipeline`` (containment/, gates/, state/), alongside ``sift_find_evil``.
pytest-cov measures a package only when it is BOTH:

    1. listed in ``[tool.coverage.run] source`` in pyproject.toml, AND
    2. NOT shadowed by a CLI ``--cov=<pkg>`` override.

Point 2 is the non-obvious pytest-cov mechanic that caused the gap: a CLI
``--cov=X`` REPLACES the config ``source`` list wholesale; only a bare ``--cov``
inherits it. So the two settings are COUPLED -- you must add the package to
``source`` AND switch every enforcing invocation to bare ``--cov``. Doing one
without the other silently measures nothing new.

The original defect: ``nexus_pipeline`` was exercised by 130 tests in
tests/pipeline/ but measured by neither, because ``source`` listed only
``sift_find_evil`` while every CI invocation passed ``--cov=sift_find_evil``
(which nullifies ``source``). 100% of its lines could rot untested while the
97.5 floor stayed green -- the exact "green but untested" failure mode.

This test encodes the coupling as a machine-checkable invariant so it cannot
silently regress again. It is deliberately dependency-free (tomllib + file
reads) so it runs in the enforcing CI ``core`` tier, not only the forensic tier.
"""

import shlex
import subprocess
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# Every package whose lines the coverage floor must actually account for. Add a
# new top-level pipeline package here the moment it ships code under test.
REQUIRED_COVERAGE_SOURCES = {"sift_find_evil", "nexus_pipeline"}

# The invocations that ENFORCE the floor. A ``--cov=<pkg>`` override in any of
# these silently drops whatever is not named on the CLI, defeating point 2 above.
ENFORCING_INVOCATION_FILES = [
    REPO_ROOT / ".github" / "workflows" / "ci.yml",
    REPO_ROOT / "scripts" / "ci-local.sh",
    # Every file below hands a reader a coverage command to RUN, so each is a
    # door back into the SFE-rbje gap: follow a qualified --cov and you measure
    # only sift_find_evil, silently dropping nexus_pipeline from the floor.
    # They all drifted that way after #237 switched CI to a bare --cov.
    #
    # CLAUDE.md's Quality Gates block states it "mirrors the authoritative core
    # tier" and is what an agent actually runs. The design spec's Gate B row is
    # the authority definitions.py cites, so a stale row there means anyone
    # re-deriving Gate B reintroduces the bug. The rest are contributor-facing
    # "run this" recipes.
    REPO_ROOT / "CLAUDE.md",
    REPO_ROOT
    / "docs"
    / "superpowers"
    / "specs"
    / "2026-08-24-nexus-pipeline-design.md",
    REPO_ROOT / "docs" / "CONTRIBUTING.md",
    # The Definition of Done hands the reader the local quality-gate command, so
    # it is the same class of door as CLAUDE.md's Quality Gates block.
    REPO_ROOT / "docs" / "WORKING_AGREEMENT.md",
    REPO_ROOT / "docs" / "USER_GUIDE.md",
    REPO_ROOT / "README.md",
    # Hands the reader a pyproject ``addopts`` line, not a pytest command. That
    # is the worst shape to teach wrongly, because addopts applies to EVERY
    # pytest run in the repo that copies it, not to one documented invocation.
    # PR #239 fixed a qualified --cov here but could not list the file, because
    # _coverage_invocations then matched only the pytest-token shape (SFE-t9k7).
    REPO_ROOT / "docs" / "REPOSITORY_MANAGEMENT.md",
]

# The tree-wide sweep below reads every tracked file with one of these
# suffixes. These are the file types that hand a human or agent a command or a
# config line to copy. Source-code test fixtures (.py) deliberately contain the
# qualified spelling as negative cases, so they are not swept.
SWEPT_SUFFIXES = {".md", ".sh", ".yml", ".yaml", ".toml", ".cfg", ".ini", ".txt"}

# Subtrees whose files are not this engine's coverage recipes: the Rust GUI
# connector and the vendored signature rules.
SWEEP_EXCLUDED_PREFIXES = ("ui/", "rules/")


def _coverage_invocations(path: Path) -> list[str]:
    """Every line of ``path`` that invokes pytest WITH coverage.

    Backslash continuations are joined first, so a multi-line ci.yml or shell
    invocation reads as a single line. Matching is then by command SHAPE, never
    by file structure. Two shapes count:

    1. a ``pytest`` token and a ``--cov`` token on the same line (a command);
    2. an ``addopts`` token and a ``--cov`` token on the same line (a pytest
       config line, which pytest prepends to EVERY run that reads it);
    3. a ``PYTEST_ADDOPTS`` assignment carrying a ``--cov`` token (the
       environment-variable form of shape 2: ``export PYTEST_ADDOPTS=...`` in
       a shell script, or ``PYTEST_ADDOPTS: ...`` under ``env:`` in a
       workflow), which pytest also prepends to every run that sees it.

    Shape 2 exists because an ``addopts = "--cov=pkg"`` line names no pytest
    command at all, so shape 1 alone left the guard blind to the one form that
    reaches every invocation rather than one documented command (SFE-t9k7).

    Shape matching is what makes this robust across the file types in
    ENFORCING_INVOCATION_FILES. An earlier revision scanned markdown fenced
    code blocks and was fail-open in every direction: a 4-space indented
    block, a ``~~~`` fence, an inline code span, and even a stray ``` in prose
    (which desynchronizes fence pairing and skips the real block) all hid the
    command from the guard. Prose that merely *explains* the rule is still
    tolerated, because an explanation names no pytest command and no addopts.

    An ``addopts`` value split over several lines (a TOML array, or the
    indented continuation style of pytest.ini / setup.cfg / tox.ini) is folded
    back onto its key line first, because the ``--cov=`` token then sits on a
    line that carries neither ``addopts`` nor ``pytest`` and shape 2 alone
    would miss it.
    """
    text = path.read_text(encoding="utf-8", errors="replace").replace("\\\n", " ")
    invocations = []
    for line in _fold_addopts_continuations(text.splitlines()):
        # Backticks are markdown emphasis and quotes are TOML/shell delimiters,
        # not part of the flag; drop them so an inline `pytest --cov=x` span or
        # an addopts = "--cov" value tokenizes like the flag it carries.
        tokens = line.replace("`", " ").replace('"', " ").replace("'", " ")
        # Detach the assignment operator so the value tokenizes on its own:
        # PYTEST_ADDOPTS=--cov=pkg is one shell word but two facts.
        tokens = tokens.replace("PYTEST_ADDOPTS=", "PYTEST_ADDOPTS ")
        tokens = tokens.replace("PYTEST_ADDOPTS:", "PYTEST_ADDOPTS ").split()
        if not {"pytest", "addopts", "PYTEST_ADDOPTS"} & set(tokens):
            continue
        if any(token == "--cov" or token.startswith("--cov=") for token in tokens):
            invocations.append(line.strip())
    return invocations


def _fold_addopts_continuations(lines: list[str]) -> list[str]:
    """Join the continuation lines of a multi-line ``addopts`` value onto its key line.

    Two continuation styles exist. TOML: the value opens a ``[`` array and runs
    until the matching ``]``. INI (pytest.ini, setup.cfg, tox.ini): every
    following line that starts with whitespace belongs to the key. A blank line
    or a comment line ends either style, so the fold never reaches into prose
    that happens to follow a config snippet. Lines outside an ``addopts`` value
    are returned unchanged, so the pytest-command shape is not affected.
    """
    folded: list[str] = []
    depth = 0
    in_addopts = False
    for line in lines:
        stripped = line.strip()
        is_comment = stripped.startswith(("#", ";"))
        is_continuation = in_addopts and stripped and not is_comment
        is_continuation = is_continuation and (depth > 0 or line[:1].isspace())
        if is_continuation:
            folded[-1] = f"{folded[-1]} {stripped}"
        else:
            folded.append(line)
            in_addopts = "addopts" in line.replace("=", " ").split()
            depth = 0
        depth = max(depth + line.count("[") - line.count("]"), 0) if in_addopts else 0
    return folded


def _tracked_text_files() -> list[Path]:
    """Every git-tracked file the tree-wide sweep reads.

    Uses the git index rather than a filesystem walk so untracked local
    clutter (virtualenvs, scratch notes, editor backups) never fails the
    guard, and so a file deleted from the index stops being swept the moment
    it is deleted.
    """
    listing = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    # A failed listing must read as a guard failure, not an opaque
    # CalledProcessError: outside a git checkout (an sdist, a git-archive
    # export) the sweep has no file set and cannot vouch for anything.
    assert listing.returncode == 0, (
        f"git ls-files failed ({listing.stderr.strip()}); the tree-wide sweep "
        f"needs a git checkout to know which files to read."
    )
    return [
        REPO_ROOT / name
        for name in listing.stdout.split("\0")
        if name
        and Path(name).suffix in SWEPT_SUFFIXES
        and not name.startswith(SWEEP_EXCLUDED_PREFIXES)
    ]


@pytest.mark.parametrize(
    ("content", "expect_qualified"),
    [
        pytest.param('addopts = "--cov=pkg -q"\n', True, id="toml-one-line"),
        pytest.param(
            'addopts = [\n  "--cov=pkg",\n  "-q",\n]\n', True, id="toml-array"
        ),
        pytest.param(
            "[pytest]\naddopts =\n    --cov=pkg\n    --cov-report=term\n",
            True,
            id="ini-continuation",
        ),
        pytest.param("pytest tests/ \\\n  --cov=pkg\n", True, id="shell-backslash"),
        pytest.param("run: pytest -q `--cov=pkg`\n", True, id="markdown-inline-span"),
        pytest.param('export PYTEST_ADDOPTS="--cov=pkg -q"\n', True, id="env-export"),
        pytest.param(
            "env:\n  PYTEST_ADDOPTS: --cov=pkg\n", True, id="env-yaml-mapping"
        ),
        pytest.param('PYTEST_ADDOPTS="--cov -q" pytest\n', False, id="env-bare-cov"),
        pytest.param('addopts = "--cov -q"\n', False, id="toml-bare-cov"),
        pytest.param(
            "[pytest]\naddopts =\n    --cov\n\n    --cov=pkg\n", False, id="blank-ends"
        ),
        pytest.param(
            'addopts = [\n  "--cov",\n]\n# never write --cov=pkg here\n',
            False,
            id="comment-not-folded",
        ),
        pytest.param(
            "Never pass `--cov=pkg`; it discards source.\n", False, id="prose"
        ),
    ],
)
def test_coverage_invocations_sees_every_config_shape(
    tmp_path, content, expect_qualified
):
    """The scanner must flag ``--cov=`` in every shape a config or doc can carry it.

    The multi-line shapes are the ones the SFE-t9k7 review found fail-open:
    a TOML array or an INI continuation puts the ``--cov=`` token on a line
    with no ``addopts`` or ``pytest`` token, so a per-line scan never saw it.
    The negative cases pin the fold's boundaries so it cannot creep into prose.
    """
    # Arrange
    path = tmp_path / "snippet.toml"
    path.write_text(content)

    # Act
    qualified = [line for line in _coverage_invocations(path) if "--cov=" in line]

    # Assert
    assert bool(qualified) is expect_qualified, qualified


def test_coverage_source_lists_every_measured_package():
    """[tool.coverage.run] source must include every pipeline package.

    A package absent from ``source`` is invisible to a bare ``--cov`` run, so
    the floor never accounts for it (bd SFE-rbje coverage-inclusion gap).
    """
    # Arrange
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())

    # Act
    source = set(pyproject["tool"]["coverage"]["run"]["source"])

    # Assert
    missing = REQUIRED_COVERAGE_SOURCES - source
    assert not missing, (
        f"[tool.coverage.run] source is missing {sorted(missing)}; these "
        f"packages are exercised by tests but their lines are not measured by "
        f"the coverage floor. Add them to source in pyproject.toml."
    )


def test_enforcing_invocations_use_bare_cov():
    """Every file that hands out a coverage command must use a bare ``--cov``.

    ``--cov=X`` REPLACES the config ``source`` list, so it would measure only
    ``X`` no matter what ``source`` says -- re-opening the SFE-rbje gap through
    a different door even after ``source`` is fixed. Bare ``--cov`` inherits
    ``source`` and keeps the package list in ONE place.

    The set is not just CI: it is every file in ENFORCING_INVOCATION_FILES,
    which includes the docs an agent or contributor actually copies from. A
    correct ci.yml does not help if the instructions beside it say otherwise.
    """
    for path in ENFORCING_INVOCATION_FILES:
        # Arrange
        invocations = _coverage_invocations(path)

        # Assert POSITIVELY first. Checking only for the absence of a bad
        # string let this pass vacuously: deleting the command, or moving it
        # out of where the scan looked, both read as success while the file an
        # agent follows was no longer guarded at all.
        assert invocations, (
            f"{path.relative_to(REPO_ROOT)} contains no 'pytest ... --cov' "
            f"invocation for this guard to check. Either the command moved and "
            f"the scan no longer sees it, or this file no longer reproduces the "
            f"enforcing invocation and should leave ENFORCING_INVOCATION_FILES."
        )

        # "--cov=" is the override form; "--cov-report=" and "--cov-fail-under"
        # are "--cov-", not "--cov=", so they never match.
        qualified = [line for line in invocations if "--cov=" in line]
        assert not qualified, (
            f"{path.relative_to(REPO_ROOT)} passes a '--cov=<pkg>' override in "
            f"{qualified}, which discards the [tool.coverage.run] source list "
            f"and measures only the named package. Use a bare '--cov' so "
            f"coverage inherits source (the single source of truth)."
        )


def test_pyproject_addopts_never_qualifies_cov():
    """The live ``[tool.pytest.ini_options] addopts`` must never carry ``--cov=``.

    pytest prepends ``addopts`` to every invocation that reads pyproject.toml,
    so a ``--cov=<pkg>`` there would override the ``source`` list on EVERY run,
    including CI's bare ``--cov``, with no command line anywhere to show it.
    This is checked structurally (tomllib, the same parse pytest performs)
    rather than by line scan, so it cannot be fooled by formatting.

    An absent ``addopts`` is a genuine clean result, not a scan miss: pytest
    reads exactly this key, so if it is not there, no override exists. That is
    why this test, unlike the invocation-file test above, has no positive
    "must exist" arm.
    """
    # Arrange
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    addopts = (
        pyproject["tool"].get("pytest", {}).get("ini_options", {}).get("addopts", "")
    )
    if isinstance(addopts, list):
        addopts = " ".join(addopts)

    # Act
    qualified = [token for token in shlex.split(addopts) if token.startswith("--cov=")]

    # Assert
    assert not qualified, (
        f"pyproject.toml [tool.pytest.ini_options] addopts carries {qualified}, "
        f"which overrides [tool.coverage.run] source on every pytest run. Use a "
        f"bare '--cov' (or none; CI passes it explicitly)."
    )


def test_no_tracked_text_file_teaches_a_qualified_cov():
    """No tracked doc, script, or config anywhere may show a ``--cov=<pkg>`` form.

    ENFORCING_INVOCATION_FILES is hand-maintained, so on its own it is
    fail-open for the file nobody thought to list: a new doc that pastes a
    qualified coverage command is a fresh door back into the SFE-rbje gap and
    passes the guard above by omission (SFE-t9k7, SFE-ah8p). This sweep closes
    the class by reading every tracked file of a copyable type and applying the
    same shape rule, so the list only has to name the files that must ALSO keep
    teaching the command (the positive arm above); it no longer has to be
    complete to be safe.

    Files under the excluded prefixes and non-swept suffixes are not this
    engine's coverage recipes; .py test fixtures in particular hold the
    qualified spelling on purpose as negative cases.
    """
    # Arrange
    files = _tracked_text_files()
    assert files, "git ls-files returned no swept files; the sweep is not running"

    # Act
    offenders = {
        str(path.relative_to(REPO_ROOT)): [
            line for line in _coverage_invocations(path) if "--cov=" in line
        ]
        for path in files
    }
    offenders = {name: lines for name, lines in offenders.items() if lines}

    # Assert
    assert not offenders, (
        f"These tracked files hand out a '--cov=<pkg>' coverage form, which "
        f"discards the [tool.coverage.run] source list: {offenders}. Change each "
        f"to a bare '--cov'."
    )
