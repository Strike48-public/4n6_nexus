"""Tests for nexus_pipeline.containment.parking (spec section 6.3/6.6, primitive only).

Only the ParkReason enum and the park() primitive are built here. The
GitHub label mirror, Hermes re-ping cadence, and weekly drift job are
runtime/Hermes concerns deferred to .3/.5 (documented, not built here).
"""

import json

import pytest

from nexus_pipeline.containment import parking
from nexus_pipeline.state import paths


@pytest.fixture(autouse=True)
def isolated_state_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_PIPELINE_STATE_DIR", str(tmp_path / "state"))


def test_park_reason_values_match_label_convention():
    assert parking.ParkReason.NEEDS_INFO.value == "needs-info"
    assert parking.ParkReason.BUDGET_EXCEEDED.value == "budget-exceeded"
    assert parking.ParkReason.GATE_FAILED.value == "gate-failed"


def test_park_returns_a_parked_record():
    record = parking.park(
        "SFE-1", parking.ParkReason.BUDGET_EXCEEDED, "per-issue ceiling hit"
    )

    assert record.issue_id == "SFE-1"
    assert record.reason is parking.ParkReason.BUDGET_EXCEEDED
    assert record.detail == "per-issue ceiling hit"
    assert record.ts


def test_park_persists_to_state_dir():
    parking.park("SFE-1", parking.ParkReason.NEEDS_INFO, "missing acceptance criteria")

    record_path = paths.state_dir() / "parked" / "SFE-1.json"
    assert record_path.exists()
    data = json.loads(record_path.read_text())
    assert data["issue_id"] == "SFE-1"
    assert data["reason"] == "needs-info"
    assert data["detail"] == "missing acceptance criteria"


def test_re_parking_overwrites_the_prior_record():
    parking.park("SFE-1", parking.ParkReason.GATE_FAILED, "gate B failed")
    updated = parking.park(
        "SFE-1", parking.ParkReason.BUDGET_EXCEEDED, "then budget tripped"
    )

    record_path = paths.state_dir() / "parked" / "SFE-1.json"
    data = json.loads(record_path.read_text())
    assert data["reason"] == "budget-exceeded"
    assert updated.detail == "then budget tripped"


def test_park_rejects_path_traversal_issue_id():
    with pytest.raises(paths.UnsafePathComponentError):
        parking.park(
            "../../../../../../tmp/pwned-park",
            parking.ParkReason.NEEDS_INFO,
            "x",
        )


def test_park_rejects_absolute_path_issue_id():
    with pytest.raises(paths.UnsafePathComponentError):
        parking.park("/tmp/pwned-park-abs", parking.ParkReason.NEEDS_INFO, "x")
