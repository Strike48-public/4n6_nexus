"""Tests for nexus_pipeline.tier.classifier (spec section 4).

The classifier is itself safety-critical: it is the sole authority that
turns a raw diff into a merge-risk tier. Every rule is fail-toward-T2 and
first-match-wins over the whole diff, so a single T2 path poisons the whole
PR. The adversarial shapes below (detector+engine, rename, comment-only CI
change, empty diff, additive pair, modified scenario, lone detector) are the
core deliverable, not incidental coverage.

Mutation-proofing (security/code-review HIGH fix). An isolated diff whose
only entry is a T2-pattern path is mutation-BLIND: deleting the predicate
that matches it still leaves the diff falling through to rule 4's
unmapped-default T2, so the test cannot distinguish "the rule matched"
from "the rule is gone and the default saved us." Every T2-rule test below
that is meant to GUARD a specific predicate therefore pairs the dangerous
path with an unrelated `tests/test_x.py` entry, which by itself would
classify T1 (rule 2) -- so deleting the T2 predicate flips that test's
result from T2 to T1, and it goes red. Each such test also asserts the
poisoning path appears in TierResult.reason, as a second, cheaper signal
that the specific rule (not the default) produced the T2. See
tasks/scratch/nexus-pipeline-shadow-tier-impl.md's "Fix pass" section for
the self-mutation confirmation run against these guards.
"""

import pytest

from nexus_pipeline.tier.classifier import DiffEntry, Tier, TierResult, classify

_BENIGN_TEST_FILE = DiffEntry(path="tests/test_x.py", status="A")


def test_diff_entry_is_frozen():
    entry = DiffEntry(path="README.md", status="M")

    with pytest.raises(AttributeError):
        entry.path = "other.md"


def test_tier_result_is_frozen():
    result = TierResult(tier=Tier.T0, reason="docs only")

    with pytest.raises(AttributeError):
        result.tier = Tier.T2


# --- Adversarial shapes required by the design (locked in, do not weaken) --


def test_detector_plus_engine_diff_is_t2():
    """A single T2 path poisons the whole PR, even alongside an additive
    detector that would otherwise be T1 on its own. The benign test file
    makes this a genuine mutation guard: without it, an added detector
    alone already falls to T2 via the unmapped default (see
    test_lone_new_detector_without_scenario_is_t2), so deleting the engine
    predicate would not have been caught.
    """
    entries = [
        DiffEntry(path="sift_find_evil/detectors/new_thing.py", status="A"),
        DiffEntry(path="sift_find_evil/engine/core.py", status="M"),
        _BENIGN_TEST_FILE,
    ]

    result = classify(entries)

    assert result.tier is Tier.T2
    assert "sift_find_evil/engine/core.py" in result.reason


def test_renamed_engine_file_mixed_with_test_file_is_t2():
    """A rename (status R) is never the additive-detector exemption, which
    requires status A specifically. Mixed with a benign test file so
    deleting the engine predicate is observable (flips to T1).
    """
    entries = [
        DiffEntry(path="sift_find_evil/engine/core_renamed.py", status="R"),
        _BENIGN_TEST_FILE,
    ]

    result = classify(entries)

    assert result.tier is Tier.T2
    assert "sift_find_evil/engine/core_renamed.py" in result.reason


def test_comment_only_github_workflow_change_is_t2():
    """The classifier only sees path+status, never diff content, so a
    'comment-only' claim about a .github/** file cannot lower its tier --
    any .github/** path is T2 unconditionally.
    """
    entries = [DiffEntry(path=".github/workflows/ci.yml", status="M")]

    result = classify(entries)

    assert result.tier is Tier.T2


def test_github_workflow_change_mixed_with_test_file_is_t2():
    entries = [
        DiffEntry(path=".github/workflows/ci.yml", status="M"),
        _BENIGN_TEST_FILE,
    ]

    result = classify(entries)

    assert result.tier is Tier.T2
    assert ".github/workflows/ci.yml" in result.reason


def test_empty_diff_is_t2():
    """Zero information is not evidence of safety: ambiguity never resolves
    downward, so an empty diff falls through every rule to unmapped -> T2.
    """
    result = classify([])

    assert result.tier is Tier.T2


def test_added_detector_and_added_scenario_pair_is_t1():
    entries = [
        DiffEntry(path="sift_find_evil/detectors/new_thing.py", status="A"),
        DiffEntry(path="scenarios/synthetic/new_thing/scenario.yaml", status="A"),
    ]

    result = classify(entries)

    assert result.tier is Tier.T1


def test_modified_existing_scenario_yaml_is_t2():
    """An existing scored scenario.yaml is the ground truth Gate C grades
    against; touching it (not adding a fresh one) is never additive.
    """
    entries = [
        DiffEntry(path="scenarios/synthetic/02_ransomware/scenario.yaml", status="M")
    ]

    result = classify(entries)

    assert result.tier is Tier.T2


def test_modified_existing_scenario_yaml_mixed_with_test_file_is_t2():
    entries = [
        DiffEntry(path="scenarios/synthetic/02_ransomware/scenario.yaml", status="M"),
        _BENIGN_TEST_FILE,
    ]

    result = classify(entries)

    assert result.tier is Tier.T2
    assert "scenarios/synthetic/02_ransomware/scenario.yaml" in result.reason


def test_lone_new_detector_without_scenario_is_t2():
    """Locked reading of the flagged edge case (design doc line 58-61): a
    status-A file under sift_find_evil/detectors/ is exempt from rule 1's
    T2 (so it does not poison itself), but rule 2's pair requires BOTH an
    added detector AND an added scenario.yaml in the same diff. A lone
    detector satisfies neither rule 1 (T2) nor rule 2 (T1) nor rule 3
    (docs-only), so it falls through to rule 4's unmapped default, which
    fails toward the safest tier: T2. This is deliberate, not an oversight
    -- a detector that ships without its own scenario.yaml has no F1
    evidence backing it, so it cannot be additive-safe.
    """
    entries = [DiffEntry(path="sift_find_evil/detectors/new_thing.py", status="A")]

    result = classify(entries)

    assert result.tier is Tier.T2


def test_added_scenario_without_matching_detector_is_t2():
    """Symmetric to the lone-detector edge: an added scenario.yaml alone,
    with no added detector in the same diff, also falls to unmapped -> T2.
    """
    entries = [
        DiffEntry(path="scenarios/synthetic/new_thing/scenario.yaml", status="A")
    ]

    result = classify(entries)

    assert result.tier is Tier.T2


# --- Additional rule coverage ------------------------------------------------


def test_markdown_only_diff_is_t0():
    entries = [DiffEntry(path="README.md", status="M")]

    result = classify(entries)

    assert result.tier is Tier.T0


def test_docs_dir_diff_is_t0():
    entries = [DiffEntry(path="docs/reference-standards.md", status="A")]

    result = classify(entries)

    assert result.tier is Tier.T0


def test_mixed_docs_and_readme_diff_is_t0():
    entries = [
        DiffEntry(path="README.md", status="M"),
        DiffEntry(path="docs/ACCURACY_REPORT.md", status="M"),
    ]

    result = classify(entries)

    assert result.tier is Tier.T0


def test_mixed_docs_and_ordinary_code_diff_is_not_t0():
    """Guards T0's all()-not-any() semantics: mutating all() to any() would
    make this T0 (since README.md IS docs), letting an arbitrary code
    change ride an unrelated README edit to unattended auto-merge
    eligibility. app/main.py matches no T1 or T2 rule, so the correct
    result is T2 via the unmapped default, not T0.
    """
    entries = [
        DiffEntry(path="README.md", status="M"),
        DiffEntry(path="app/main.py", status="M"),
    ]

    result = classify(entries)

    assert result.tier is Tier.T2


def test_test_file_under_tests_dir_is_t1():
    entries = [DiffEntry(path="tests/pipeline/test_new_thing.py", status="A")]

    result = classify(entries)

    assert result.tier is Tier.T1


def test_test_suffixed_file_outside_tests_dir_is_t1():
    entries = [DiffEntry(path="sift_find_evil/foo_test.py", status="M")]

    # A non-additive sift_find_evil path would normally be T2 (rule 1), but
    # this asserts rule ordering: rule 1 is checked FIRST, so a test file
    # under sift_find_evil/ still poisons to T2, not T1. This is the correct
    # first-match-wins behavior, not a bug in the test-file rule.
    result = classify(entries)

    assert result.tier is Tier.T2


def test_pyproject_toml_change_is_t1():
    entries = [DiffEntry(path="pyproject.toml", status="M")]

    result = classify(entries)

    assert result.tier is Tier.T1


def test_requirements_file_change_is_t1():
    entries = [DiffEntry(path="requirements-dev.txt", status="M")]

    result = classify(entries)

    assert result.tier is Tier.T1


def test_lockfile_change_is_t1():
    entries = [DiffEntry(path="poetry.lock", status="M")]

    result = classify(entries)

    assert result.tier is Tier.T1


def test_strike48_connector_change_is_t2():
    entries = [DiffEntry(path="strike48_connector/sdk/client.py", status="M")]

    result = classify(entries)

    assert result.tier is Tier.T2


def test_strike48_connector_change_mixed_with_test_file_is_t2():
    entries = [
        DiffEntry(path="strike48_connector/sdk/client.py", status="M"),
        _BENIGN_TEST_FILE,
    ]

    result = classify(entries)

    assert result.tier is Tier.T2
    assert "strike48_connector/sdk/client.py" in result.reason


def test_strike48_connector_4n6_change_is_t2():
    entries = [DiffEntry(path="strike48_connector_4n6/app.py", status="A")]

    result = classify(entries)

    assert result.tier is Tier.T2


def test_scenarios_schema_yaml_change_is_t2():
    entries = [DiffEntry(path="scenarios/_schemas/scenario.yaml", status="M")]

    result = classify(entries)

    assert result.tier is Tier.T2


def test_scenarios_schema_yaml_change_mixed_with_test_file_is_t2():
    """Uses status A (not M) so this does not also independently trip the
    modified-scored-scenario rule -- that overlap would mask the schema
    predicate specifically being deleted. See the module docstring's
    mutation-proofing note.
    """
    entries = [
        DiffEntry(path="scenarios/_schemas/scenario.yaml", status="A"),
        _BENIGN_TEST_FILE,
    ]

    result = classify(entries)

    assert result.tier is Tier.T2
    assert "scenarios/_schemas/scenario.yaml" in result.reason


def test_migration_path_is_t2():
    entries = [
        DiffEntry(path="sift_find_evil/state/migrations/0001_init.sql", status="A")
    ]

    result = classify(entries)

    assert result.tier is Tier.T2


def test_top_level_migrations_dir_is_t2():
    entries = [DiffEntry(path="migrations/0002_add_column.py", status="A")]

    result = classify(entries)

    assert result.tier is Tier.T2


def test_migration_path_mixed_with_test_file_is_t2():
    """A top-level migrations/ path (not under sift_find_evil/, so the
    engine rule cannot also independently poison it) mixed with a benign
    test file: deleting the migration predicate flips this to T1.
    """
    entries = [
        DiffEntry(path="migrations/0002_add_column.py", status="A"),
        _BENIGN_TEST_FILE,
    ]

    result = classify(entries)

    assert result.tier is Tier.T2
    assert "migrations/0002_add_column.py" in result.reason


def test_auth_dir_path_is_t2():
    entries = [DiffEntry(path="strike48_connector_4n6/auth/handler.py", status="A")]

    result = classify(entries)

    assert result.tier is Tier.T2


def test_credentials_file_is_t2():
    entries = [DiffEntry(path="scripts/credentials.py", status="A")]

    result = classify(entries)

    assert result.tier is Tier.T2


def test_credentials_file_mixed_with_test_file_is_t2():
    """scripts/credentials.py sits outside every other T2-prefixed root
    (sift_find_evil/, strike48_connector*, scenarios/, .github/,
    migrations/), so this isolates the auth/credential predicate
    specifically: deleting it flips this to T1.
    """
    entries = [DiffEntry(path="scripts/credentials.py", status="A"), _BENIGN_TEST_FILE]

    result = classify(entries)

    assert result.tier is Tier.T2
    assert "scripts/credentials.py" in result.reason


def test_similar_but_unrelated_filename_is_not_treated_as_auth():
    """Guards against a naive substring match: 'author.py' contains 'auth'
    as a substring but is not an auth/credential path. Locks the tokenized
    equality reading (token "author" != token "auth"), not substring
    matching.
    """
    entries = [DiffEntry(path="docs/author.py", status="A")]

    result = classify(entries)

    assert result.tier is not Tier.T2


def test_authors_py_is_not_treated_as_auth_path():
    entries = [DiffEntry(path="docs/authors.py", status="A")]

    result = classify(entries)

    assert result.tier is not Tier.T2


def test_one_t2_path_poisons_an_otherwise_docs_only_diff():
    entries = [
        DiffEntry(path="README.md", status="M"),
        DiffEntry(path=".github/workflows/ci.yml", status="M"),
    ]

    result = classify(entries)

    assert result.tier is Tier.T2


def test_reason_is_a_non_empty_string_for_every_tier():
    for entries in (
        [DiffEntry(path="README.md", status="M")],
        [DiffEntry(path="tests/test_x.py", status="A")],
        [DiffEntry(path=".github/workflows/ci.yml", status="M")],
    ):
        result = classify(entries)
        assert isinstance(result.reason, str)
        assert result.reason


# --- Tokenized auth/credential/migration matching (security review CRITICAL) -


@pytest.mark.parametrize(
    "dangerous_path",
    [
        "scripts/db_credentials.py",
        "config/aws_credentials.json",
        "config/credentials.prod.yaml",
        "scripts/secret_key.py",
    ],
)
def test_compound_credential_filename_mixed_with_test_file_is_t2(dangerous_path):
    """Whole-segment/whole-stem equality previously let these compound,
    realistic naming styles ride an unrelated test-file edit to T1 (secreview
    finding #1). Tokenizing each segment on non-alphanumeric boundaries
    catches all of them while keeping author.py/authors.py safe.
    """
    entries = [DiffEntry(path=dangerous_path, status="A"), _BENIGN_TEST_FILE]

    result = classify(entries)

    assert result.tier is Tier.T2
    assert dangerous_path in result.reason


def test_compound_migration_dirname_mixed_with_test_file_is_t2():
    entries = [
        DiffEntry(path="db_migrations/0001.sql", status="A"),
        _BENIGN_TEST_FILE,
    ]

    result = classify(entries)

    assert result.tier is Tier.T2
    assert "db_migrations/0001.sql" in result.reason


# --- Status-suffix normalization (security review HIGH fix) -----------------


def test_unstripped_rename_suffix_on_scenario_yaml_mixed_with_test_file_is_t2():
    """An unstripped git similarity-score suffix ("R100") must not defeat
    the modified-scenario rule: the classifier normalizes to the leading
    letter itself rather than trusting a caller to have stripped it.
    """
    entries = [
        DiffEntry(
            path="scenarios/synthetic/02_ransomware/scenario.yaml", status="R100"
        ),
        _BENIGN_TEST_FILE,
    ]

    result = classify(entries)

    assert result.tier is Tier.T2


def test_unstripped_copy_suffix_on_scenario_yaml_mixed_with_test_file_is_t2():
    entries = [
        DiffEntry(
            path="scenarios/synthetic/02_ransomware/scenario.yaml", status="C100"
        ),
        _BENIGN_TEST_FILE,
    ]

    result = classify(entries)

    assert result.tier is Tier.T2


# --- Path normalization before prefix matching (security review HIGH fix) ---


def test_dot_slash_prefixed_engine_path_mixed_with_test_file_is_t2():
    entries = [
        DiffEntry(path="./sift_find_evil/engine/x.py", status="M"),
        _BENIGN_TEST_FILE,
    ]

    result = classify(entries)

    assert result.tier is Tier.T2


def test_double_slash_engine_path_mixed_with_test_file_is_t2():
    entries = [
        DiffEntry(path="sift_find_evil//engine/x.py", status="M"),
        _BENIGN_TEST_FILE,
    ]

    result = classify(entries)

    assert result.tier is Tier.T2
