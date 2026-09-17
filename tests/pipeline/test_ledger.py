"""Tests for nexus_pipeline.containment.ledger (spec section 6.1).

Covers totals math, per-issue and per-day cap trips, panel spend sharing the
same ledger as generation spend, fail-closed behavior on an unreadable
ledger, and append-only (never-truncating) writes.
"""

import pytest

from nexus_pipeline.containment import caps, ledger
from nexus_pipeline.state import paths


@pytest.fixture(autouse=True)
def isolated_state_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_PIPELINE_STATE_DIR", str(tmp_path / "state"))


def _entry(issue_id="SFE-1", day="2026-08-24", kind="spawn", cost_usd=1.0, turns=1):
    return ledger.LedgerEntry(
        ts="2026-08-24T00:00:00+00:00",
        issue_id=issue_id,
        day=day,
        kind=kind,
        cost_usd=cost_usd,
        turns=turns,
        source="sdk-session",
    )


def test_read_totals_sums_cost_for_issue_and_day():
    ledger.record(_entry(cost_usd=1.5, kind="spawn"))
    ledger.record(_entry(cost_usd=2.5, kind="turn"))

    totals = ledger.read_totals("SFE-1", "2026-08-24")

    assert totals.issue_usd == pytest.approx(4.0)
    assert totals.day_usd == pytest.approx(4.0)


def test_per_issue_ceiling_trip(monkeypatch):
    monkeypatch.setattr(caps, "PER_ISSUE_USD_CEILING", 3.0)
    monkeypatch.setattr(caps, "PER_DAY_FLEET_USD_CEILING", 1000.0)
    # Spend accrues across two different days for the same issue.
    ledger.record(_entry(day="2026-08-23", cost_usd=2.0))
    ledger.record(_entry(day="2026-08-24", cost_usd=2.0))

    decision = ledger.check_before_spawn("SFE-1", now_day="2026-08-24")

    assert isinstance(decision, ledger.Trip)
    assert "per-issue" in decision.reason


def test_per_day_fleet_ceiling_trip(monkeypatch):
    monkeypatch.setattr(caps, "PER_ISSUE_USD_CEILING", 1000.0)
    monkeypatch.setattr(caps, "PER_DAY_FLEET_USD_CEILING", 3.0)
    ledger.record(_entry(issue_id="SFE-1", day="2026-08-24", cost_usd=2.0))
    ledger.record(_entry(issue_id="SFE-2", day="2026-08-24", cost_usd=2.0))

    decision = ledger.check_before_spawn("SFE-1", now_day="2026-08-24")

    assert isinstance(decision, ledger.Trip)
    assert "per-day" in decision.reason


def test_decision_is_allow_when_under_both_caps(monkeypatch):
    monkeypatch.setattr(caps, "PER_ISSUE_USD_CEILING", 1000.0)
    monkeypatch.setattr(caps, "PER_DAY_FLEET_USD_CEILING", 1000.0)
    ledger.record(_entry(cost_usd=1.0))

    decision = ledger.check_before_spawn("SFE-1", now_day="2026-08-24")

    assert isinstance(decision, ledger.Allow)


def test_panel_cost_charged_to_same_ledger_as_generation(monkeypatch):
    monkeypatch.setattr(caps, "PER_ISSUE_USD_CEILING", 5.0)
    monkeypatch.setattr(caps, "PER_DAY_FLEET_USD_CEILING", 1000.0)
    ledger.record(_entry(kind="spawn", cost_usd=3.0))
    ledger.record(_entry(kind="panel", cost_usd=3.0))

    decision = ledger.check_before_spawn("SFE-1", now_day="2026-08-24")

    assert isinstance(decision, ledger.Trip)
    totals = ledger.read_totals("SFE-1", "2026-08-24")
    assert totals.issue_usd == pytest.approx(6.0)


def test_unreadable_ledger_fails_closed_to_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_PIPELINE_STATE_DIR", str(tmp_path / "state"))
    ledger.record(_entry(day="2026-08-24"))
    day_file = tmp_path / "state" / "ledger" / "2026-08-24.jsonl"
    day_file.write_text("{not valid json\n")

    decision = ledger.check_before_spawn("SFE-1", now_day="2026-08-24")

    assert isinstance(decision, ledger.Trip)
    assert decision.reason == "ledger-unreadable"


def test_record_never_truncates_existing_entries():
    ledger.record(_entry(cost_usd=1.0))
    ledger.record(_entry(cost_usd=1.0))
    ledger.record(_entry(cost_usd=1.0))

    day_file_lines = ledger.read_totals("SFE-1", "2026-08-24")
    assert day_file_lines.issue_usd == pytest.approx(3.0)


def test_record_rejects_unknown_kind():
    with pytest.raises(ValueError):
        ledger.record(_entry(kind="not-a-real-kind"))


def test_allow_when_no_ledger_entries_exist_yet():
    # A brand-new issue on a brand-new day: no ledger dir/file has been
    # created at all yet. read_totals must not raise, and the decision must
    # be Allow, not a false Trip.
    decision = ledger.check_before_spawn("SFE-never-seen", now_day="2026-08-24")

    assert isinstance(decision, ledger.Allow)


@pytest.mark.parametrize(
    "malformed_line",
    [
        '{"ts": "x", "issue_id": "SFE-1", "day": "2026-08-24", "kind": "spawn", "cost_usd": "not-a-number", "turns": 1, "source": "s"}',
        '{"ts": "x", "issue_id": "SFE-1", "day": "2026-08-24", "kind": "spawn", "cost_usd": null, "turns": 1, "source": "s"}',
        '["not", "an", "object"]',
    ],
    ids=["cost_usd-is-string", "cost_usd-is-null", "line-is-a-json-array"],
)
def test_check_before_spawn_fails_closed_on_malformed_entry(
    tmp_path, monkeypatch, malformed_line
):
    monkeypatch.setenv("NEXUS_PIPELINE_STATE_DIR", str(tmp_path / "state"))
    ledger.record(_entry(day="2026-08-24"))  # creates the properly-permissioned tree
    day_file = tmp_path / "state" / "ledger" / "2026-08-24.jsonl"
    day_file.write_text(malformed_line + "\n")

    decision = ledger.check_before_spawn("SFE-1", now_day="2026-08-24")

    assert isinstance(decision, ledger.Trip)
    assert decision.reason == "ledger-unreadable"


def test_record_rejects_path_traversal_day():
    with pytest.raises(paths.UnsafePathComponentError):
        ledger.record(_entry(day="../../../../../../tmp/pwned-ledger"))


def test_record_rejects_absolute_path_day():
    with pytest.raises(paths.UnsafePathComponentError):
        ledger.record(_entry(day="/tmp/pwned-ledger-abs"))
