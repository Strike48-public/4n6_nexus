"""Tests for the regression testing framework."""

from datetime import datetime
from pathlib import Path


from sift_find_evil.findings import FindingCategory
from sift_find_evil.self_correction.engine import Finding
from sift_find_evil.testing.compare_runs import (
    TestRun,
    compare_runs,
)


def test_test_run_severity_counts():
    """Test TestRun severity counting properties."""
    findings = [
        Finding(
            title="Critical Finding",
            description="Test",
            finding_type="indicator",
            severity="CRITICAL",
            category=FindingCategory.TIMELINE_TAMPERING,
        ),
        Finding(
            title="High Finding",
            description="Test",
            finding_type="indicator",
            severity="HIGH",
            category=FindingCategory.ANTI_FORENSICS,
        ),
        Finding(
            title="Medium Finding",
            description="Test",
            finding_type="indicator",
            severity="MEDIUM",
            category=FindingCategory.UNKNOWN,
        ),
    ]

    run = TestRun(
        timestamp=datetime.now(),
        scenario_name="test",
        directory=Path("/tmp"),
        findings=findings,
    )

    assert run.critical_count == 1
    assert run.high_count == 1
    assert run.medium_count == 1
    assert run.low_count == 0
    assert run.info_count == 0


def test_test_run_average_confidence():
    """Test TestRun average confidence calculation."""
    findings = [
        Finding(
            title="Finding 1",
            description="Test",
            finding_type="indicator",
            severity="CRITICAL",
            category=FindingCategory.TIMELINE_TAMPERING,
            confidence=0.9,
        ),
        Finding(
            title="Finding 2",
            description="Test",
            finding_type="indicator",
            severity="HIGH",
            category=FindingCategory.ANTI_FORENSICS,
            confidence=0.8,
        ),
        Finding(
            title="Finding 3",
            description="Test",
            finding_type="indicator",
            severity="MEDIUM",
            category=FindingCategory.UNKNOWN,
            confidence=0.7,
        ),
    ]

    run = TestRun(
        timestamp=datetime.now(),
        scenario_name="test",
        directory=Path("/tmp"),
        findings=findings,
    )

    expected_avg = (0.9 + 0.8 + 0.7) / 3
    assert abs(run.average_confidence - expected_avg) < 0.001


def test_test_run_attack_techniques():
    """Test TestRun extraction of ATT&CK techniques."""
    findings = [
        Finding(
            title="NTDS.dit Extraction",
            description="Detected T1003.003 OS Credential Dumping: NTDS",
            finding_type="indicator",
            severity="CRITICAL",
            category=FindingCategory.TIMELINE_TAMPERING,
            evidence={"technique": "T1003.003"},
        ),
        Finding(
            title="PsExec",
            description="Detected T1021.002 lateral movement",
            finding_type="indicator",
            severity="HIGH",
            category=FindingCategory.ANTI_FORENSICS,
        ),
    ]

    run = TestRun(
        timestamp=datetime.now(),
        scenario_name="test",
        directory=Path("/tmp"),
        findings=findings,
    )

    techniques = run.attack_techniques
    assert "T1003.003" in techniques
    assert "T1021.002" in techniques


def test_compare_runs_new_detections():
    """Test compare_runs identifies new detections."""
    baseline_findings = [
        Finding(
            title="Finding 1",
            description="Test",
            finding_type="indicator",
            severity="CRITICAL",
            category=FindingCategory.TIMELINE_TAMPERING,
            evidence={"technique": "T1003", "executable": "ntdsutil.exe"},
        ),
    ]

    current_findings = [
        Finding(
            title="Finding 1",
            description="Test",
            finding_type="indicator",
            severity="CRITICAL",
            category=FindingCategory.TIMELINE_TAMPERING,
            evidence={"technique": "T1003", "executable": "ntdsutil.exe"},
        ),
        Finding(
            title="Finding 2",
            description="New detection",
            finding_type="indicator",
            severity="HIGH",
            category=FindingCategory.ANTI_FORENSICS,
            evidence={"technique": "T1021", "executable": "psexec.exe"},
        ),
    ]

    baseline = TestRun(
        timestamp=datetime.now(),
        scenario_name="test",
        directory=Path("/tmp"),
        findings=baseline_findings,
    )

    current = TestRun(
        timestamp=datetime.now(),
        scenario_name="test",
        directory=Path("/tmp"),
        findings=current_findings,
    )

    comparison = compare_runs(baseline, current)

    assert len(comparison.new_detections) == 1
    assert comparison.new_detections[0].title == "Finding 2"
    assert len(comparison.missed_detections) == 0
    assert not comparison.has_regressions


def test_compare_runs_missed_detections():
    """Test compare_runs identifies missed detections (regressions)."""
    baseline_findings = [
        Finding(
            title="Finding 1",
            description="Test",
            finding_type="indicator",
            severity="CRITICAL",
            category=FindingCategory.TIMELINE_TAMPERING,
            evidence={"technique": "T1003", "executable": "ntdsutil.exe"},
        ),
        Finding(
            title="Finding 2",
            description="Test",
            finding_type="indicator",
            severity="HIGH",
            category=FindingCategory.ANTI_FORENSICS,
            evidence={"technique": "T1021", "executable": "psexec.exe"},
        ),
    ]

    current_findings = [
        Finding(
            title="Finding 1",
            description="Test",
            finding_type="indicator",
            severity="CRITICAL",
            category=FindingCategory.TIMELINE_TAMPERING,
            evidence={"technique": "T1003", "executable": "ntdsutil.exe"},
        ),
    ]

    baseline = TestRun(
        timestamp=datetime.now(),
        scenario_name="test",
        directory=Path("/tmp"),
        findings=baseline_findings,
    )

    current = TestRun(
        timestamp=datetime.now(),
        scenario_name="test",
        directory=Path("/tmp"),
        findings=current_findings,
    )

    comparison = compare_runs(baseline, current)

    assert len(comparison.missed_detections) == 1
    assert comparison.missed_detections[0].title == "Finding 2"
    assert len(comparison.new_detections) == 0
    assert comparison.has_regressions


def test_compare_runs_confidence_changes():
    """Test compare_runs identifies significant confidence changes."""
    baseline_findings = [
        Finding(
            title="Finding 1",
            description="Test",
            finding_type="indicator",
            severity="CRITICAL",
            category=FindingCategory.TIMELINE_TAMPERING,
            evidence={"technique": "T1003", "executable": "ntdsutil.exe"},
            confidence=0.9,
        ),
    ]

    current_findings = [
        Finding(
            title="Finding 1",
            description="Test",
            finding_type="indicator",
            severity="CRITICAL",
            category=FindingCategory.TIMELINE_TAMPERING,
            evidence={"technique": "T1003", "executable": "ntdsutil.exe"},
            confidence=0.75,  # Dropped by 0.15 (15%)
        ),
    ]

    baseline = TestRun(
        timestamp=datetime.now(),
        scenario_name="test",
        directory=Path("/tmp"),
        findings=baseline_findings,
    )

    current = TestRun(
        timestamp=datetime.now(),
        scenario_name="test",
        directory=Path("/tmp"),
        findings=current_findings,
    )

    comparison = compare_runs(baseline, current)

    assert len(comparison.confidence_changes) == 1
    baseline_f, current_f, delta = comparison.confidence_changes[0]
    assert abs(delta - (-0.15)) < 0.01
    assert comparison.has_regressions  # >10% drop is a regression


def test_compare_runs_severity_changes():
    """Test compare_runs identifies severity changes."""
    baseline_findings = [
        Finding(
            title="Finding 1",
            description="Test",
            finding_type="indicator",
            severity="CRITICAL",
            category=FindingCategory.TIMELINE_TAMPERING,
            evidence={"technique": "T1003", "executable": "ntdsutil.exe"},
        ),
    ]

    current_findings = [
        Finding(
            title="Finding 1",
            description="Test",
            finding_type="indicator",
            severity="HIGH",  # Downgraded
            category=FindingCategory.TIMELINE_TAMPERING,
            evidence={"technique": "T1003", "executable": "ntdsutil.exe"},
        ),
    ]

    baseline = TestRun(
        timestamp=datetime.now(),
        scenario_name="test",
        directory=Path("/tmp"),
        findings=baseline_findings,
    )

    current = TestRun(
        timestamp=datetime.now(),
        scenario_name="test",
        directory=Path("/tmp"),
        findings=current_findings,
    )

    comparison = compare_runs(baseline, current)

    assert len(comparison.severity_changes) == 1
    baseline_f, current_f = comparison.severity_changes[0]
    assert baseline_f.severity == "CRITICAL"
    assert current_f.severity == "HIGH"


def test_finding_serialization_roundtrip():
    """Test Finding to_dict/from_dict roundtrip."""
    original = Finding(
        title="Test Finding",
        description="Test description",
        finding_type="indicator",
        severity="CRITICAL",
        category=FindingCategory.TIMELINE_TAMPERING,
        evidence={"technique": "T1003", "executable": "test.exe"},
        confidence=0.95,
        confidence_label="Very High",
        reasoning_chain=["Step 1", "Step 2"],
    )

    # Serialize and deserialize
    data = original.to_dict()
    restored = Finding.from_dict(data)

    # Verify key fields match
    assert restored.title == original.title
    assert restored.description == original.description
    assert restored.finding_type == original.finding_type
    assert restored.severity == original.severity
    assert restored.category == original.category
    assert restored.evidence == original.evidence
    assert abs(restored.confidence - original.confidence) < 0.01
    assert restored.confidence_label == original.confidence_label
    assert restored.reasoning_chain == original.reasoning_chain


def test_test_run_empty_findings():
    """Test TestRun handles empty findings list gracefully."""
    run = TestRun(
        timestamp=datetime.now(),
        scenario_name="test",
        directory=Path("/tmp"),
        findings=[],
    )

    # Should not raise division by zero
    assert run.average_confidence == 0.0
    assert run.critical_count == 0
    assert run.high_count == 0
    assert len(run.attack_techniques) == 0


def test_attack_techniques_extraction_with_subtechniques():
    """Test extraction of ATT&CK techniques with various sub-technique formats."""
    findings = [
        Finding(
            title="NTDS.dit",
            description="Detected T1003.003 OS Credential Dumping",
            finding_type="indicator",
            severity="CRITICAL",
            category=FindingCategory.TIMELINE_TAMPERING,
        ),
        Finding(
            title="PsExec",
            description="Detected T1021.002 (Remote Services: SMB/Windows Admin Shares)",
            finding_type="indicator",
            severity="HIGH",
            category=FindingCategory.ANTI_FORENSICS,
        ),
        Finding(
            title="Scheduled Task",
            description="T1053.005 scheduled task persistence",
            finding_type="indicator",
            severity="MEDIUM",
            category=FindingCategory.UNKNOWN,
        ),
    ]

    run = TestRun(
        timestamp=datetime.now(),
        scenario_name="test",
        directory=Path("/tmp"),
        findings=findings,
    )

    techniques = run.attack_techniques
    assert "T1003.003" in techniques
    assert "T1021.002" in techniques
    assert "T1053.005" in techniques
