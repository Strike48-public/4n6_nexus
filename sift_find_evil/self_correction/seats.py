"""Deterministic refutation seats (tool-semantics gate).

A pure-code verification floor that bounces over-read findings keyed to the
forensic tool that produced them. Each seat encodes what a tool CANNOT
establish on its own (its semantic ceiling). For example, a shimcache entry
proves that a binary was *present* on disk and known to the system, but it
does NOT prove the binary ever *executed*. An interpretation that leaps to
"the program executed" is a tool misread and gets bounced here.

The gate judges each clause of an interpretation locally: a bad-vocabulary
match only counts as a violation when the same clause carries no negation
(for example "does not prove execution"). This keeps correctly-scoped and
explicitly-hedged language from being flagged.

This module depends only on the Python standard library.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Clause boundaries: sentence terminators and semicolons.
_CLAUSE_SPLIT_RE = re.compile(r"[.;!?\n]+")

# Local negation cues that neutralize a bad-vocab match within the same clause.
_NEGATION_RE = re.compile(
    r"\b(?:"
    r"does not (?:indicate|prove|show|establish|mean)"
    r"|do not (?:indicate|prove|show|establish|mean)"
    r"|cannot (?:establish|prove|confirm|show|indicate)"
    r"|can not (?:establish|prove|confirm|show|indicate)"
    r"|no evidence of"
    r"|not (?:proof|evidence) of"
    r"|does not"
    r"|is not"
    r"|without"
    r")\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SeatViolation:
    """A single tool-semantics violation found in one clause.

    Attributes:
        rule_why: Human-readable explanation of the semantic ceiling breached.
        matched_phrase: The exact bad-vocabulary phrase that triggered the seat.
    """

    rule_why: str
    matched_phrase: str


@dataclass(frozen=True)
class SemanticRule:
    """One tool-semantics seat.

    Attributes:
        tool_regex: Pattern matched (case-insensitive) against the tool name.
        bad_vocab_regex: Pattern of vocabulary the tool cannot support.
        why: Explanation of what the tool cannot establish.
    """

    tool_regex: str
    bad_vocab_regex: str
    why: str


# The verification floor: what each tool CANNOT establish on its own.
TOOL_SEMANTIC_RULES: list[SemanticRule] = [
    SemanticRule(
        tool_regex=r"shim\s*cache|appcompatcache|amcache",
        bad_vocab_regex=r"execut(?:ed|ion|es|ing)|\bran\b|launch(?:ed|es|ing)?|was run",
        why=(
            "shimcache/amcache records program presence and metadata, not "
            "execution - it cannot establish that a binary executed, ran, or "
            "was launched"
        ),
    ),
    SemanticRule(
        tool_regex=r"pslist|psscan|pstree",
        bad_vocab_regex=r"c2|command[\s-]and[\s-]control|beacon(?:ing|ed|s)?|exfiltrat(?:e|ed|ion|ing)",
        why=(
            "pslist/psscan enumerate processes at a point in time - alone they "
            "cannot establish C2, beaconing, or exfiltration"
        ),
    ),
    SemanticRule(
        tool_regex=r"netscan|netstat",
        bad_vocab_regex=r"exfiltrat(?:e|ed|ion|ing)|beacon(?:ing|ed|s)?|c2|command[\s-]and[\s-]control",
        why=(
            "netscan lists sockets/connections present at capture time - it "
            "cannot establish exfiltration or beaconing"
        ),
    ),
    SemanticRule(
        tool_regex=r"\bfls\b|\bmft\b|mftecmd|\$mft",
        bad_vocab_regex=r"execut(?:ed|ion|es|ing)|\bran\b|launch(?:ed|es|ing)?|was run",
        why=(
            "fls/MFT parse filesystem metadata, not execution - they cannot "
            "establish that a file executed, ran, or was launched"
        ),
    ),
]


def _split_clauses(interpretation: str) -> list[str]:
    """Split an interpretation into clauses on sentence/semicolon boundaries.

    Args:
        interpretation: The free-text interpretation to split.

    Returns:
        A list of non-empty, stripped clause strings.
    """
    return [
        clause.strip()
        for clause in _CLAUSE_SPLIT_RE.split(interpretation)
        if clause.strip()
    ]


def _clause_has_negation(clause: str) -> bool:
    """Return True if the clause contains a local negation cue.

    Args:
        clause: A single clause of an interpretation.

    Returns:
        True when negation language neutralizes a bad-vocab match.
    """
    return _NEGATION_RE.search(clause) is not None


def check_seats(tool: str, interpretation: str) -> list[SeatViolation]:
    """Check an interpretation against the tool-semantics seats.

    Each clause is judged locally: a bad-vocabulary match is only recorded as
    a violation when the clause carries no local negation.

    Args:
        tool: Name of the forensic tool that produced the finding.
        interpretation: The free-text interpretation of the finding.

    Returns:
        A list of SeatViolation objects, one per offending clause/rule.
    """
    violations: list[SeatViolation] = []
    clauses = _split_clauses(interpretation)

    for rule in TOOL_SEMANTIC_RULES:
        if not re.search(rule.tool_regex, tool, re.IGNORECASE):
            continue
        bad_vocab = re.compile(rule.bad_vocab_regex, re.IGNORECASE)
        for clause in clauses:
            match = bad_vocab.search(clause)
            if match is None:
                continue
            if _clause_has_negation(clause):
                continue
            violations.append(
                SeatViolation(rule_why=rule.why, matched_phrase=match.group(0))
            )

    return violations


def adjudicate(tool: str, interpretation: str) -> str:
    """Adjudicate whether an interpretation is supported by its tool.

    Args:
        tool: Name of the forensic tool that produced the finding.
        interpretation: The free-text interpretation of the finding.

    Returns:
        "MISREAD_TOOL" if any seat is violated, otherwise "SUPPORTED".
    """
    return "MISREAD_TOOL" if check_seats(tool, interpretation) else "SUPPORTED"
