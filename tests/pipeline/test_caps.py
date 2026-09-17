"""Tests for nexus_pipeline.containment.caps.

Verifies each budget/turn/wall-clock cap has the documented Phase-1 default
and is overridable via its matching environment variable. Constants are
computed at import time, so overrides are exercised via importlib.reload.
"""

import importlib

from nexus_pipeline.containment import caps


def test_defaults_match_phase1_design():
    importlib.reload(caps)
    assert caps.MAX_TURNS_PER_SESSION == 40
    assert caps.MAX_BUDGET_USD_PER_SESSION == 8.0
    assert caps.PER_ISSUE_USD_CEILING == 8.0
    assert caps.PER_DAY_FLEET_USD_CEILING == 50.0
    assert caps.WALL_CLOCK_SECONDS_PER_ISSUE == 1800


def test_max_turns_overridable_by_env(monkeypatch):
    monkeypatch.setenv("MAX_TURNS_PER_SESSION", "7")
    importlib.reload(caps)
    try:
        assert caps.MAX_TURNS_PER_SESSION == 7
    finally:
        monkeypatch.delenv("MAX_TURNS_PER_SESSION", raising=False)
        importlib.reload(caps)


def test_max_budget_usd_overridable_by_env(monkeypatch):
    monkeypatch.setenv("MAX_BUDGET_USD_PER_SESSION", "3.5")
    importlib.reload(caps)
    try:
        assert caps.MAX_BUDGET_USD_PER_SESSION == 3.5
    finally:
        monkeypatch.delenv("MAX_BUDGET_USD_PER_SESSION", raising=False)
        importlib.reload(caps)


def test_per_issue_ceiling_overridable_by_env(monkeypatch):
    monkeypatch.setenv("PER_ISSUE_USD_CEILING", "1.25")
    importlib.reload(caps)
    try:
        assert caps.PER_ISSUE_USD_CEILING == 1.25
    finally:
        monkeypatch.delenv("PER_ISSUE_USD_CEILING", raising=False)
        importlib.reload(caps)


def test_per_day_fleet_ceiling_overridable_by_env(monkeypatch):
    monkeypatch.setenv("PER_DAY_FLEET_USD_CEILING", "12.0")
    importlib.reload(caps)
    try:
        assert caps.PER_DAY_FLEET_USD_CEILING == 12.0
    finally:
        monkeypatch.delenv("PER_DAY_FLEET_USD_CEILING", raising=False)
        importlib.reload(caps)


def test_wall_clock_seconds_overridable_by_env(monkeypatch):
    monkeypatch.setenv("WALL_CLOCK_SECONDS_PER_ISSUE", "60")
    importlib.reload(caps)
    try:
        assert caps.WALL_CLOCK_SECONDS_PER_ISSUE == 60
    finally:
        monkeypatch.delenv("WALL_CLOCK_SECONDS_PER_ISSUE", raising=False)
        importlib.reload(caps)
