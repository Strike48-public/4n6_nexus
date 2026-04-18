"""Tests for graduated confidence scoring in exfiltration detector."""

import pytest
from datetime import datetime, timezone
from sift_find_evil.disk.exfil_detector import _calculate_confidence


def test_confidence_immediate_exfiltration():
    """Time delta 0-60s = 0.95 (Very High)."""
    confidence, label = _calculate_confidence(10.0)
    assert confidence == 0.95
    assert label == "Very High"

    confidence, label = _calculate_confidence(60.0)
    assert confidence == 0.95
    assert label == "Very High"


def test_confidence_deliberate_exfiltration():
    """Time delta 60-180s = 0.90 (High)."""
    confidence, label = _calculate_confidence(61.0)
    assert confidence == 0.90
    assert label == "High"

    confidence, label = _calculate_confidence(120.0)
    assert confidence == 0.90
    assert label == "High"

    confidence, label = _calculate_confidence(180.0)
    assert confidence == 0.90
    assert label == "High"


def test_confidence_slower_exfiltration():
    """Time delta 180-300s = 0.85 (Medium-High)."""
    confidence, label = _calculate_confidence(181.0)
    assert confidence == 0.85
    assert label == "Medium-High"

    confidence, label = _calculate_confidence(250.0)
    assert confidence == 0.85
    assert label == "Medium-High"

    confidence, label = _calculate_confidence(300.0)
    assert confidence == 0.85
    assert label == "Medium-High"


def test_confidence_jean_case_44s():
    """Jean case (44s delta) should get 0.95 confidence."""
    confidence, label = _calculate_confidence(43.9)
    assert confidence == 0.95
    assert label == "Very High"
