"""Provenance gate - every finding citation must resolve to a logged tool call.

A generated finding may cite event ids as evidence. This module verifies that
each citation (a) is a well-formed event id and (b) walks back to a real,
logged tool call that registered either an input SHA-256 or an input file. A
citation that cannot be traced is treated as fabricated provenance and drags
the finding's grade down; a finding whose provenance grades to NONE is rejected
by the gate.

Two-step verification:

STEP 1 (regex first): every citation is validated against a strict compiled
regex ``^evt-[0-9]{6}$``. A citation that fails - path traversal ``../``,
homoglyph, injection tail, wrong length - is unresolved and is NEVER used as a
lookup key. This ordering is deliberate: it denies an attacker who plants a
raw traversal string as an audit-index key any chance of resolution.

STEP 2 (walk): a syntactically valid citation resolves only if it is present in
``audit_index`` AND that entry walks to a registered ``input_sha256`` or a
non-empty ``input_files`` entry.

Grading:
* FULL    - all citations resolve and at least one resolves to a registered sha.
* PARTIAL - at least one citation resolves (but not enough for FULL).
* NONE    - no citation resolves, or there are zero citations.

The model narrates; deterministic code decides. No LLM is involved, so the gate
is fully CI-testable against synthetic audit indexes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Strict citation id shape: literal ``evt-`` followed by exactly six digits.
# Anchored at both ends so no prefix/suffix (injection tail, leading space,
# traversal) can smuggle past. Compiled once at import.
_CITATION_RE = re.compile(r"^evt-[0-9]{6}$")

# A SHA-256 hex digest is 64 lowercase/uppercase hex chars. We treat any
# non-empty string as "registered"; callers own the format upstream. Kept as a
# named guard for readability.
_MIN_SHA_LEN = 1


@dataclass(frozen=True)
class ProvenanceResult:
    """Outcome of resolving a finding's citations against the audit index.

    Attributes:
        grade: ``"FULL"``, ``"PARTIAL"`` or ``"NONE"``.
        resolved: Citations that resolved to a real logged tool call, in the
            order they were cited.
        unresolved: Citations that failed the regex or did not walk to a
            registered sha/file, in the order they were cited.
    """

    grade: str
    resolved: list[str]
    unresolved: list[str]


def _is_well_formed(citation: str) -> bool:
    """Return True only for a citation matching the strict id regex."""
    return bool(_CITATION_RE.match(citation))


def _walks_to_sha(entry: dict) -> bool:
    """Return True if the audit entry registers a non-empty input sha."""
    sha = entry.get("input_sha256", "")
    return isinstance(sha, str) and len(sha) >= _MIN_SHA_LEN


def _walks_to_file(entry: dict) -> bool:
    """Return True if the audit entry registers at least one input file."""
    files = entry.get("input_files", [])
    if not isinstance(files, list):
        return False
    return any(isinstance(f, str) and f for f in files)


def resolve_provenance(
    finding_citations: list[str], audit_index: dict
) -> ProvenanceResult:
    """Resolve a finding's citations against a logged-tool-call audit index.

    Args:
        finding_citations: Event ids the finding cites as evidence.
        audit_index: Maps ``tool_call_id`` -> ``{"input_sha256": str,
            "input_files": list[str], "produced_ids": list[str]}``.

    Returns:
        A :class:`ProvenanceResult` with the grade and the resolved/unresolved
        partition. Order of the input citations is preserved in both lists.
    """
    resolved: list[str] = []
    unresolved: list[str] = []
    resolved_via_sha = False

    for citation in finding_citations:
        # STEP 1: strict regex FIRST. A malformed citation is never looked up.
        if not _is_well_formed(citation):
            unresolved.append(citation)
            continue

        # STEP 2: must be in the index AND walk to a registered sha or file.
        entry = audit_index.get(citation)
        if not isinstance(entry, dict):
            unresolved.append(citation)
            continue

        has_sha = _walks_to_sha(entry)
        has_file = _walks_to_file(entry)
        if has_sha or has_file:
            resolved.append(citation)
            resolved_via_sha = resolved_via_sha or has_sha
        else:
            unresolved.append(citation)

    grade = _grade(finding_citations, resolved, unresolved, resolved_via_sha)
    return ProvenanceResult(grade=grade, resolved=resolved, unresolved=unresolved)


def _grade(
    citations: list[str],
    resolved: list[str],
    unresolved: list[str],
    resolved_via_sha: bool,
) -> str:
    """Derive the provenance grade from the resolution partition."""
    if not citations:
        return "NONE"
    if not resolved:
        return "NONE"
    if not unresolved and resolved_via_sha:
        return "FULL"
    return "PARTIAL"


def gate_finding(finding_citations: list[str], audit_index: dict) -> bool:
    """Return False (reject) for a finding whose provenance grades to NONE.

    Args:
        finding_citations: Event ids the finding cites as evidence.
        audit_index: The logged-tool-call audit index (see
            :func:`resolve_provenance`).

    Returns:
        ``True`` if the finding has at least PARTIAL provenance, ``False`` if it
        grades to NONE (zero citations or nothing resolves).
    """
    return resolve_provenance(finding_citations, audit_index).grade != "NONE"
