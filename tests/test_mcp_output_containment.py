"""ToolGuard rejects output paths that would write INTO the evidence root (SFE-fibx.2).

Read-only was enforced (allowlist + input-path containment) but a genuine OUTPUT
flag -- EZTools ``--csv <dir>`` -- was consumed as an unchecked value: a caller
could tell mftecmd to write its CSV output into the read-only evidence tree, and
ToolGuard let it. The CLI had an inverse guard; the MCP boundary did not. These
tests attack that boundary and pin the registry-level read-only proof.
"""

import pytest

from sift_find_evil.mcp.guardrails import GuardrailViolation, ToolGuard, ToolPolicy
from sift_find_evil.mcp.server import default_policies

# A CORE vocabulary of clearly write/modify-shaped flags. This list is NOT
# exhaustive and does not need to be: the read-only proof is STRUCTURAL (the
# per-tool allowlist is deny-by-default, so any flag not explicitly declared --
# including an exotic ``--export``/``--save`` -- is already rejected, and any
# declared write-target flag must be a containment-guarded ``output_flag``). This
# set is a fast tripwire for the OBVIOUS write verbs slipping onto an allowlist.
# Deliberately EXCLUDED because they have legitimate non-write uses here: ``-o``
# (sleuthkit numeric offset), ``-d`` (pecmd INPUT dir), ``-r`` (input read /
# format). ``--csv`` is a genuine output-dir flag, permitted ONLY when declared
# as a guarded output flag.
_WRITE_FLAGS = frozenset(
    {"-w", "--write", "--output", "--out", "--delete", "--modify", "--dump"}
)


def _guard(tmp_path):
    return ToolGuard(policies=default_policies(), evidence_root=tmp_path)


def test_csv_output_into_evidence_is_rejected(tmp_path):
    """--csv pointed inside the evidence root must be refused at the boundary."""
    guard = _guard(tmp_path)
    inside = str(tmp_path / "exfil")  # resolves inside evidence_root
    with pytest.raises(GuardrailViolation):
        guard.check("mftecmd", ["-f", str(tmp_path / "MFT"), "--csv", inside])


def test_csv_output_outside_evidence_is_allowed(tmp_path):
    """A legitimate --csv to a non-evidence dir still passes (no false positive)."""
    guard = _guard(tmp_path)
    outside = str(tmp_path.parent / "analysis_out")
    # Input -f must be inside evidence; output --csv must be outside it.
    guard.check("mftecmd", ["-f", str(tmp_path / "MFT"), "--csv", outside])


def test_every_output_flag_in_the_registry_is_containment_guarded(tmp_path):
    """Registry proof: for every policy that declares output_flags, an output value
    resolving into evidence is rejected -- so no tool can be told to write into it."""
    guard = _guard(tmp_path)
    for tool, policy in default_policies().items():
        for oflag in getattr(policy, "output_flags", frozenset()):
            with pytest.raises(GuardrailViolation):
                guard.check(tool, [oflag, str(tmp_path / "into_evidence")])


def test_no_policy_permits_a_write_capable_flag():
    """Registry proof (stronger than a denylist intersection): enumerate every
    exposed tool's allowed_flags and assert none is a known write/destructive flag,
    EXCEPT --csv which is permitted ONLY when declared as a containment-guarded
    output flag (never as a raw write)."""
    for tool, policy in default_policies().items():
        for flag in policy.allowed_flags:
            if flag == "--csv":
                # --csv is allowed only if it is a guarded output flag.
                assert "--csv" in getattr(
                    policy, "output_flags", frozenset()
                ), f"{tool}: --csv permitted but not declared a guarded output flag"
                continue
            assert (
                flag not in _WRITE_FLAGS
            ), f"{tool}: permits write-capable flag {flag!r}"


# -- SFE-fibx.15: reject any 'evidence'-component output path (multi-case) ----


def test_csv_output_into_another_cases_evidence_is_rejected(tmp_path):
    """An output path in a DIFFERENT case's evidence subtree is refused even though
    it is outside the configured evidence_root -- it still has an 'evidence' path
    component (the dev/multi-case risk SFE-fibx.15 closes)."""
    guard = _guard(tmp_path)  # evidence_root = tmp_path
    other_case = tmp_path.parent / "caseB" / "evidence" / "out"
    with pytest.raises(GuardrailViolation):
        guard.check("mftecmd", ["-f", str(tmp_path / "MFT"), "--csv", str(other_case)])


def test_csv_output_to_a_sibling_analysis_dir_is_allowed(tmp_path):
    """A non-'evidence' output dir outside the root still passes: the new clause
    keys on an 'evidence' path component, so /cases/.../analysis is NOT a false
    positive (mirrors the CLI guard's deliberate scope)."""
    guard = _guard(tmp_path)
    analysis_out = tmp_path.parent / "caseB" / "analysis"
    guard.check("mftecmd", ["-f", str(tmp_path / "MFT"), "--csv", str(analysis_out)])


# -- SFE-fibx.15: path_flags/output_flags must be disjoint at construction ----


def test_toolpolicy_rejects_a_flag_listed_as_both_input_and_output():
    """A flag declared as BOTH a path_flag and an output_flag must fail loudly at
    construction, not silently resolve as an input path (a latent footgun)."""
    with pytest.raises(ValueError, match="disjoint"):
        ToolPolicy(
            allowed_flags={"--csv"},
            path_flags={"--csv"},
            output_flags={"--csv"},
        )


def test_toolpolicy_with_disjoint_flags_constructs(tmp_path):
    """The normal, disjoint case still constructs (no false positive on the guard)."""
    ToolPolicy(
        allowed_flags={"-f", "--csv"},
        path_flags={"-f"},
        output_flags={"--csv"},
    )
