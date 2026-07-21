"""Tests for deterministic refutation seats (tool-semantics gate).

Validates that over-read findings are bounced when the interpretation claims
something the producing forensic tool cannot establish, while correctly-scoped
or locally-negated claims are supported.
"""

from sift_find_evil.self_correction.seats import (
    SeatViolation,
    adjudicate,
    check_seats,
)


def test_shimcache_claiming_execution_is_misread() -> None:
    # Arrange
    tool = "shimcache"
    interpretation = "The program executed on the host."

    # Act
    violations = check_seats(tool, interpretation)
    verdict = adjudicate(tool, interpretation)

    # Assert
    assert verdict == "MISREAD_TOOL"
    assert len(violations) == 1
    assert isinstance(violations[0], SeatViolation)
    assert "executed" in violations[0].matched_phrase


def test_shimcache_with_local_negation_is_supported() -> None:
    # Arrange
    tool = "shimcache"
    interpretation = "Shimcache presence does not prove execution."

    # Act
    violations = check_seats(tool, interpretation)
    verdict = adjudicate(tool, interpretation)

    # Assert (inverse/negative control: negated clause must NOT be flagged)
    assert verdict == "SUPPORTED"
    assert violations == []


def test_netscan_claiming_beaconing_is_misread() -> None:
    # Arrange
    tool = "netscan"
    interpretation = "This shows beaconing to C2."

    # Act
    verdict = adjudicate(tool, interpretation)

    # Assert
    assert verdict == "MISREAD_TOOL"


def test_netscan_scoped_socket_claim_is_supported() -> None:
    # Arrange (inverse control: correctly-scoped netscan finding)
    tool = "netscan"
    interpretation = "An open socket to 10.0.0.5 was present at capture time."

    # Act
    violations = check_seats(tool, interpretation)
    verdict = adjudicate(tool, interpretation)

    # Assert
    assert verdict == "SUPPORTED"
    assert violations == []


def test_amcache_claiming_ran_is_misread() -> None:
    # Arrange
    tool = "amcache"
    interpretation = "The binary ran multiple times."

    # Act
    verdict = adjudicate(tool, interpretation)

    # Assert
    assert verdict == "MISREAD_TOOL"


def test_pslist_claiming_exfiltration_is_misread() -> None:
    # Arrange
    tool = "pslist"
    interpretation = "The process performed exfiltration of data."

    # Act
    verdict = adjudicate(tool, interpretation)

    # Assert
    assert verdict == "MISREAD_TOOL"


def test_fls_claiming_execution_is_misread() -> None:
    # Arrange
    tool = "fls"
    interpretation = "The file was launched by the user."

    # Act
    verdict = adjudicate(tool, interpretation)

    # Assert
    assert verdict == "MISREAD_TOOL"


def test_clause_locality_only_flags_offending_clause() -> None:
    # Arrange: two clauses, only the second over-reads for shimcache
    tool = "shimcache"
    interpretation = "Shimcache does not prove execution; the program executed anyway."

    # Act
    violations = check_seats(tool, interpretation)

    # Assert: exactly one violation from the non-negated clause
    assert len(violations) == 1
    assert "executed" in violations[0].matched_phrase


def test_unknown_tool_is_supported() -> None:
    # Arrange (inverse control: no rule matches the tool)
    tool = "custom_parser"
    interpretation = "The program executed and performed exfiltration."

    # Act
    verdict = adjudicate(tool, interpretation)

    # Assert
    assert verdict == "SUPPORTED"


def test_netscan_scoped_claim_not_flagged_by_pslist_rule() -> None:
    # Arrange: benign netscan clause with no bad vocab
    tool = "netscan"
    interpretation = "A listening port was observed."

    # Act
    violations = check_seats(tool, interpretation)

    # Assert
    assert violations == []
