"""Tests for the provenance gate (gallery idea #3).

Every finding citation must resolve to a real logged tool call. A citation
that fails the strict id regex (path traversal, homoglyph, injection) is
unresolved and must never be looked up. Grades: FULL / PARTIAL / NONE.

Each behavior has an inverse/negative control.
"""

from __future__ import annotations

from sift_find_evil.findings.provenance import (
    ProvenanceResult,
    gate_finding,
    resolve_provenance,
)


def _audit_index() -> dict:
    """A minimal synthetic audit index mapping tool_call_id -> metadata."""
    return {
        "evt-000001": {
            "input_sha256": "a" * 64,
            "input_files": ["/evidence/mem.raw"],
            "produced_ids": ["evt-000001"],
        },
        "evt-000002": {
            "input_sha256": "",
            "input_files": [],
            "produced_ids": ["evt-000002"],
        },
    }


def test_fully_cited_finding_grades_full_and_gate_passes() -> None:
    # Arrange
    citations = ["evt-000001"]
    index = _audit_index()

    # Act
    result = resolve_provenance(citations, index)

    # Assert
    assert isinstance(result, ProvenanceResult)
    assert result.grade == "FULL"
    assert result.resolved == ["evt-000001"]
    assert result.unresolved == []
    assert gate_finding(citations, index) is True


def test_unknown_citation_not_in_index_is_unresolved() -> None:
    # Arrange: valid id shape but absent from the index.
    citations = ["evt-009999"]
    index = _audit_index()

    # Act
    result = resolve_provenance(citations, index)

    # Assert
    assert result.grade == "NONE"
    assert result.unresolved == ["evt-009999"]
    assert result.resolved == []


def test_traversal_id_rejected_by_regex_and_never_looked_up() -> None:
    # Arrange: an injection/traversal citation must fail the regex first.
    citations = ["../etc"]
    # An index whose key coincides with a raw traversal would be a trap; ensure
    # the regex gate rejects before any lookup can ever succeed.
    index = {"../etc": {"input_sha256": "b" * 64, "input_files": ["x"]}}

    # Act
    result = resolve_provenance(citations, index)

    # Assert
    assert result.grade == "NONE"
    assert result.unresolved == ["../etc"]
    assert result.resolved == []
    assert gate_finding(citations, index) is False


def test_partial_when_some_resolve_and_some_do_not() -> None:
    # Arrange: one real, one absent.
    citations = ["evt-000001", "evt-009999"]
    index = _audit_index()

    # Act
    result = resolve_provenance(citations, index)

    # Assert
    assert result.grade == "PARTIAL"
    assert result.resolved == ["evt-000001"]
    assert result.unresolved == ["evt-009999"]
    assert gate_finding(citations, index) is True


def test_empty_citations_grade_none_and_gate_rejects() -> None:
    # Arrange (inverse control: zero citations must never pass).
    citations: list[str] = []
    index = _audit_index()

    # Act
    result = resolve_provenance(citations, index)

    # Assert
    assert result.grade == "NONE"
    assert result.resolved == []
    assert result.unresolved == []
    assert gate_finding(citations, index) is False


def test_citation_present_but_registers_no_sha_or_file_is_unresolved() -> None:
    # Arrange: in-index but neither a registered sha nor input file.
    citations = ["evt-000002"]
    index = _audit_index()

    # Act
    result = resolve_provenance(citations, index)

    # Assert: does not walk to a registered sha/file -> unresolved -> NONE.
    assert result.grade == "NONE"
    assert result.unresolved == ["evt-000002"]


def test_full_requires_at_least_one_sha_resolution() -> None:
    # Arrange: one file-only resolution and one sha resolution -> FULL.
    citations = ["evt-000001", "evt-000003"]
    index = _audit_index()
    index["evt-000003"] = {
        "input_sha256": "",
        "input_files": ["/evidence/disk.e01"],
        "produced_ids": ["evt-000003"],
    }

    # Act
    result = resolve_provenance(citations, index)

    # Assert: all cited resolve and >=1 resolves to a registered sha -> FULL.
    assert set(result.resolved) == {"evt-000001", "evt-000003"}
    assert result.unresolved == []
    assert result.grade == "FULL"


def test_all_resolve_by_file_only_grades_partial_not_full() -> None:
    # Inverse control for the FULL sha requirement: file-only resolutions all
    # succeed but none registers a sha, so grade must be PARTIAL, not FULL.
    citations = ["evt-000010"]
    index = {
        "evt-000010": {
            "input_sha256": "",
            "input_files": ["/evidence/only.raw"],
            "produced_ids": ["evt-000010"],
        }
    }

    # Act
    result = resolve_provenance(citations, index)

    # Assert
    assert result.resolved == ["evt-000010"]
    assert result.unresolved == []
    assert result.grade == "PARTIAL"
    assert gate_finding(citations, index) is True


def test_input_files_not_a_list_does_not_walk_to_file() -> None:
    # Covers the _walks_to_file guard where input_files is not a list. With no
    # sha and a non-list files field the citation cannot resolve -> NONE.
    citations = ["evt-000005"]
    index = {
        "evt-000005": {
            "input_sha256": "",
            "input_files": "/evidence/not-a-list.raw",
            "produced_ids": ["evt-000005"],
        }
    }

    result = resolve_provenance(citations, index)

    assert result.resolved == []
    assert result.unresolved == ["evt-000005"]
    assert result.grade == "NONE"


def test_homoglyph_and_injection_shapes_are_regex_rejected() -> None:
    # Arrange: cyrillic homoglyph, wrong length, SQL-ish injection, whitespace.
    citations = [
        "evt-00000",  # too short
        "evt-0000001",  # too long
        "evt-00A001",  # non-digit
        "evt-000001; DROP",  # injection tail
        " evt-000001",  # leading space
        "еvt-000001",  # cyrillic e homoglyph
    ]
    index = _audit_index()

    # Act
    result = resolve_provenance(citations, index)

    # Assert: every malformed citation is unresolved, none resolved.
    assert result.resolved == []
    assert set(result.unresolved) == set(citations)
    assert result.grade == "NONE"
