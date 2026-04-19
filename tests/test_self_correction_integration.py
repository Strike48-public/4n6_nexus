"""
Integration test for self-correction engine using synthetic data.

This test validates the full workflow:
1. Load synthetic CSV files (MFT, Prefetch, Event Logs)
2. Detect contradictions (causality violation in malware.exe)
3. Resolve via Event Log tiebreaker
4. Calculate confidence adjustments
5. Generate findings with reasoning chain
"""

import pytest
from pathlib import Path

from sift_find_evil.parsers.mft_parser import MFTParser
from sift_find_evil.parsers.prefetch_parser import PrefetchParser
from sift_find_evil.parsers.evtx_parser import EventLogParser
from sift_find_evil.self_correction.engine import SelfCorrectionEngine
from sift_find_evil.self_correction.contradiction_detector import ContradictionType


# Test data directory
TEST_DATA_DIR = Path(__file__).parent / 'fixtures'


@pytest.fixture
def synthetic_data():
    """Load all synthetic test data."""
    mft_parser = MFTParser()
    prefetch_parser = PrefetchParser()
    evtx_parser = EventLogParser()

    mft_entries = mft_parser.parse_csv(TEST_DATA_DIR / 'synthetic_mft.csv')
    prefetch_entries = prefetch_parser.parse_csv(TEST_DATA_DIR / 'synthetic_prefetch.csv')
    evtx_entries = evtx_parser.parse_csv(
        TEST_DATA_DIR / 'synthetic_evtx.csv',
        filter_event_ids=[4688]
    )

    return {
        'mft': mft_entries,
        'prefetch': prefetch_entries,
        'evtx': evtx_entries
    }


def test_malware_causality_violation_detection(synthetic_data):
    """
    Test that we detect the causality violation in malware.exe.

    Expected:
    - MFT shows modification at 14:30
    - Prefetch shows execution at 14:25
    - This violates causality (file modified AFTER execution)
    """
    engine = SelfCorrectionEngine()

    findings = engine.analyze(
        synthetic_data['mft'],
        synthetic_data['prefetch'],
        synthetic_data['evtx']
    )

    # Should find malware.exe with contradictions
    malware_findings = [f for f in findings if 'malware.exe' in f.title.lower()]
    assert len(malware_findings) >= 1, "Should detect malware.exe contradiction"

    malware_finding = malware_findings[0]

    # Should have detected causality violation
    causality_contradictions = [
        c for c in malware_finding.contradictions
        if c.type == ContradictionType.CAUSALITY_VIOLATION
    ]
    assert len(causality_contradictions) >= 1, "Should detect causality violation"

    causality = causality_contradictions[0]

    # Verify details
    assert 'malware.exe' in causality.description
    assert causality.confidence_impact < 0, "Should reduce confidence"
    assert causality.severity.value in ['medium', 'high', 'critical'], "Should be serious severity"


def test_event_log_resolution(synthetic_data):
    """
    Test that Event Log resolves the contradiction.

    Expected:
    - Event ID 4688 confirms execution at 14:25:03
    - Matches Prefetch LastRunTime (14:25:00) within tolerance
    - Should apply resolution with confidence recovery
    """
    engine = SelfCorrectionEngine()

    findings = engine.analyze(
        synthetic_data['mft'],
        synthetic_data['prefetch'],
        synthetic_data['evtx']
    )

    malware_findings = [f for f in findings if 'malware.exe' in f.title.lower()]
    assert len(malware_findings) >= 1

    malware_finding = malware_findings[0]

    # Should have applied resolution
    assert len(malware_finding.resolutions) >= 1, "Should have at least one resolution"

    resolution = malware_finding.resolutions[0]

    # Verify resolution details
    assert resolution.contradiction_type == 'causality_violation'
    assert resolution.resolution_method == 'event_log_confirms_prefetch'
    assert resolution.confidence_recovery > 0, "Should recover confidence"
    assert resolution.confidence_recovery == pytest.approx(0.30, abs=0.01), "Should recover +0.30"

    # Verify evidence
    assert 'prefetch_time' in resolution.evidence
    assert 'event_log_time' in resolution.evidence
    assert 'event_id' in resolution.evidence
    assert resolution.evidence['event_id'] == 4688


def test_confidence_calculation(synthetic_data):
    """
    Test that confidence is calculated correctly.

    Expected workflow:
    1. Start with base confidence (0.85)
    2. Reduce for causality violation (-0.45 to -0.60 depending on delta)
    3. Recover via Event Log resolution (+0.30)
    4. Final confidence should be reasonable (0.50-0.75 range)
    """
    engine = SelfCorrectionEngine(base_confidence=0.85)

    findings = engine.analyze(
        synthetic_data['mft'],
        synthetic_data['prefetch'],
        synthetic_data['evtx']
    )

    malware_findings = [f for f in findings if 'malware.exe' in f.title.lower()]
    assert len(malware_findings) >= 1

    malware_finding = malware_findings[0]

    # Verify confidence calculation
    assert 0.0 <= malware_finding.confidence <= 1.0, "Confidence must be in valid range"

    # With contradiction and resolution, should be moderate confidence
    # (not too high, not too low)
    assert 0.40 <= malware_finding.confidence <= 0.80, \
        f"Expected moderate confidence after correction, got {malware_finding.confidence}"

    # Verify calculation details exist
    assert 'initial_confidence' in malware_finding.confidence_calculation
    assert 'final_confidence' in malware_finding.confidence_calculation
    assert 'calculation_steps' in malware_finding.confidence_calculation

    # Initial should be higher than final (contradiction reduces confidence)
    initial = malware_finding.confidence_calculation['initial_confidence']
    final = malware_finding.confidence_calculation['final_confidence']

    # After contradiction + resolution, final should be lower than initial but not critically low
    assert final < initial, "Contradiction should reduce confidence even after resolution"
    assert final >= 0.40, "After resolution, should maintain reasonable confidence"


def test_reasoning_chain(synthetic_data):
    """
    Test that reasoning chain is comprehensive and clear.

    Expected:
    - Document initial confidence
    - Document each contradiction detected
    - Document each resolution applied
    - Document final confidence
    """
    engine = SelfCorrectionEngine()

    findings = engine.analyze(
        synthetic_data['mft'],
        synthetic_data['prefetch'],
        synthetic_data['evtx']
    )

    malware_findings = [f for f in findings if 'malware.exe' in f.title.lower()]
    assert len(malware_findings) >= 1

    malware_finding = malware_findings[0]

    # Verify reasoning chain exists and is comprehensive
    assert len(malware_finding.reasoning_chain) >= 4, \
        "Should have at least 4 reasoning steps (initial, contradiction, resolution, final)"

    reasoning = ' '.join(malware_finding.reasoning_chain).lower()

    # Check for key elements
    assert 'initial confidence' in reasoning, "Should document initial confidence"
    assert 'causality_violation' in reasoning or 'causality violation' in reasoning, \
        "Should document causality violation"
    assert 'event log' in reasoning, "Should document Event Log resolution"
    assert 'final confidence' in reasoning, "Should document final confidence"


def test_legitimate_files_no_contradictions(synthetic_data):
    """
    Test that legitimate files (legitapp.exe, notepad.exe) have no contradictions.

    Expected:
    - These files have aligned timestamps
    - Should have high confidence
    - No contradictions detected
    """
    engine = SelfCorrectionEngine()

    findings = engine.analyze(
        synthetic_data['mft'],
        synthetic_data['prefetch'],
        synthetic_data['evtx']
    )

    # Filter for legitimate files
    legit_findings = [
        f for f in findings
        if 'legitapp.exe' in f.title.lower() or 'notepad.exe' in f.title.lower()
    ]

    # Legitimate files should not be flagged
    # (if they are in findings, they should have no contradictions)
    for finding in legit_findings:
        assert len(finding.contradictions) == 0, \
            f"{finding.title} should have no contradictions"
        assert finding.confidence >= 0.80, \
            f"{finding.title} should have high confidence"


def test_artifact_count_affects_confidence(synthetic_data):
    """
    Test that having more artifact types increases confidence.

    Expected:
    - Files with 3 artifact types (MFT + Prefetch + EventLog) should have
      higher initial confidence than files with fewer types
    """
    engine = SelfCorrectionEngine()

    findings = engine.analyze(
        synthetic_data['mft'],
        synthetic_data['prefetch'],
        synthetic_data['evtx']
    )

    # All test files should have at least 2 artifact types
    for finding in findings:
        assert len(finding.artifact_sources) >= 2, \
            f"{finding.title} should have at least 2 artifact sources"

        # Initial confidence should reflect artifact count
        calc = finding.confidence_calculation
        initial = calc['initial_confidence']

        if len(finding.artifact_sources) >= 3:
            # With 3+ types, initial confidence should be boosted
            assert initial >= 0.90, \
                f"With {len(finding.artifact_sources)} types, initial confidence should be high"


def test_finding_json_serialization(synthetic_data):
    """
    Test that findings can be serialized to JSON (for output).

    Expected:
    - to_dict() should return valid dictionary
    - All required fields present
    - No datetime objects (should be ISO strings)
    """
    engine = SelfCorrectionEngine()

    findings = engine.analyze(
        synthetic_data['mft'],
        synthetic_data['prefetch'],
        synthetic_data['evtx']
    )

    assert len(findings) >= 1, "Should have at least one finding"

    for finding in findings:
        finding_dict = finding.to_dict()

        # Verify required fields
        assert 'title' in finding_dict
        assert 'description' in finding_dict
        assert 'confidence' in finding_dict
        assert 'reasoning_chain' in finding_dict
        assert 'contradictions' in finding_dict
        assert 'resolutions' in finding_dict
        assert 'detected_at' in finding_dict

        # Verify types (JSON serializable)
        assert isinstance(finding_dict['confidence'], (int, float))
        assert isinstance(finding_dict['reasoning_chain'], list)
        assert isinstance(finding_dict['detected_at'], str)

        # Verify contradictions are serialized
        for contradiction in finding_dict['contradictions']:
            assert isinstance(contradiction, dict)
            assert 'type' in contradiction
            assert 'severity' in contradiction
