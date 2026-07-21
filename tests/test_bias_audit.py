"""Tests for the cognitive-bias / process-integrity meta-verifier.

Validates the Heuer ACH-inspired methodology auditor in
sift_find_evil.self_correction.bias_audit.
"""

from sift_find_evil.self_correction.bias_audit import (
    MIN_DISCONFIRMATION,
    MIN_DIVERSITY,
    MIN_ACTIONS,
    MethodologyReport,
    audit_process,
)


def test_fewer_than_min_actions_returns_insufficient() -> None:
    # Arrange
    tool_calls = [
        {"tool": "grep", "hypothesis_id": "H1", "disconfirming": False}
        for _ in range(MIN_ACTIONS - 1)
    ]

    # Act
    report = audit_process(tool_calls)

    # Assert
    assert isinstance(report, MethodologyReport)
    assert report.status == "insufficient_actions"
    assert report.correctives == []


def test_empty_input_returns_insufficient() -> None:
    # Arrange / Act
    report = audit_process([])

    # Assert
    assert report.status == "insufficient_actions"


def test_tunnel_vision_run_emits_correctives() -> None:
    # Arrange: 6 actions, all confirming a single hypothesis, none disconfirming.
    tool_calls = [
        {"tool": f"tool_{i}", "hypothesis_id": "H1", "disconfirming": False}
        for i in range(6)
    ]

    # Act
    report = audit_process(tool_calls)

    # Assert
    assert report.status == "biased"
    assert report.confirmation_ratio == 1.0
    assert report.disconfirmation_ratio == 0.0
    assert report.diversity == 1
    assert report.correctives  # non-empty
    joined = " ".join(report.correctives).lower()
    assert "disprove" in joined
    assert any("hypothes" in c.lower() for c in report.correctives)


def test_balanced_run_is_healthy() -> None:
    # Arrange: diverse hypotheses with several disconfirming checks.
    tool_calls = [
        {"tool": "grep", "hypothesis_id": "H1", "disconfirming": False},
        {"tool": "yara", "hypothesis_id": "H2", "disconfirming": True},
        {"tool": "vol", "hypothesis_id": "H3", "disconfirming": True},
        {"tool": "mft", "hypothesis_id": "H1", "disconfirming": True},
        {"tool": "reg", "hypothesis_id": "H2", "disconfirming": False},
        {"tool": "net", "hypothesis_id": "H3", "disconfirming": True},
    ]

    # Act
    report = audit_process(tool_calls)

    # Assert
    assert report.status == "healthy"
    assert report.diversity >= MIN_DIVERSITY
    assert report.disconfirmation_ratio >= MIN_DISCONFIRMATION
    assert report.correctives == []


def test_low_diversity_emits_diversity_corrective() -> None:
    # Arrange: enough disconfirming checks but only one hypothesis explored.
    tool_calls = [
        {"tool": f"tool_{i}", "hypothesis_id": "H1", "disconfirming": i % 2 == 0}
        for i in range(6)
    ]

    # Act
    report = audit_process(tool_calls)

    # Assert
    assert report.diversity < MIN_DIVERSITY
    assert any("hypothes" in c.lower() for c in report.correctives)


def test_ratios_are_computed_correctly() -> None:
    # Arrange: 4 confirming + 1 disconfirming across 2 hypotheses.
    tool_calls = [
        {"tool": "a", "hypothesis_id": "H1", "disconfirming": False},
        {"tool": "b", "hypothesis_id": "H1", "disconfirming": False},
        {"tool": "c", "hypothesis_id": "H2", "disconfirming": False},
        {"tool": "d", "hypothesis_id": "H2", "disconfirming": False},
        {"tool": "e", "hypothesis_id": "H2", "disconfirming": True},
    ]

    # Act
    report = audit_process(tool_calls)

    # Assert
    assert report.disconfirmation_ratio == 0.2
    assert report.confirmation_ratio == 0.8
    assert report.diversity == 2


def test_does_not_mutate_input() -> None:
    # Arrange
    tool_calls = [
        {"tool": "grep", "hypothesis_id": "H1", "disconfirming": False}
        for _ in range(6)
    ]
    snapshot = [dict(c) for c in tool_calls]

    # Act
    audit_process(tool_calls)

    # Assert
    assert tool_calls == snapshot
