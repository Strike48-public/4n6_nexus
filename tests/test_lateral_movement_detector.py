"""Tests for LateralMovementDetector (cross-host authentication heuristics).

Promotes the SFE-e3g logon-graph signals into unit-tested detector behaviour:
failed-logon spikes (4625), service-account RDP (4624 type 10), cross-host
account spread (4624/4648), and explicit-credential bursts (4648). Noise filters
for machine accounts and local session principals are exercised explicitly.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sift_find_evil.detectors.lateral_movement_detector import (
    DEFAULT_CROSS_HOST_THRESHOLD,
    DEFAULT_EXPLICIT_CRED_THRESHOLD,
    DEFAULT_FAILED_LOGON_THRESHOLD,
    DEFAULT_SERVICE_ACCOUNT_MARKERS,
    DEFAULT_SPRAY_DENSITY_THRESHOLD,
    DEFAULT_SPRAY_MIN_ACCOUNTS,
    DEFAULT_SPRAY_WINDOW_SECONDS,
    LateralMovementDetector,
)
from sift_find_evil.findings import FindingCategory
from sift_find_evil.parsers.evtx_parser import EventLogEntry

_TS = datetime(2025, 4, 15, 14, 30, 0, tzinfo=timezone.utc)


def _logon(
    *,
    event_id: int,
    account: str | None = None,
    computer: str = "TARGET-01",
    logon_type: str | None = None,
    remote_host: str | None = None,
    record_id: int = 1,
    when: datetime | None = None,
) -> EventLogEntry:
    """Build a Security logon EventLogEntry shaped like EvtxECmd output."""
    payload1 = f"Target: {account}" if account is not None else None
    payload2 = f"LogonType {logon_type}" if logon_type is not None else None
    return EventLogEntry(
        time_created=when or _TS,
        event_id=event_id,
        record_id=record_id,
        computer=computer,
        channel="Security",
        level="Information",
        payload_data1=payload1,
        payload_data2=payload2,
        remote_host=remote_host,
    )


def _many(entry_factory, count: int):
    """Produce `count` entries with distinct record ids/timestamps."""
    return [
        entry_factory(record_id=i, when=_TS + timedelta(seconds=i))
        for i in range(count)
    ]


# --- constructor validation -----------------------------------------------
@pytest.mark.parametrize(
    "kwargs",
    [
        {"failed_logon_threshold": 0},
        {"cross_host_threshold": 0},
        {"explicit_cred_threshold": -1},
    ],
)
def test_subone_threshold_rejected(kwargs):
    with pytest.raises(ValueError, match="must be >= 1"):
        LateralMovementDetector(**kwargs)


# --- empty / no-op paths --------------------------------------------------
def test_no_events_returns_empty():
    assert LateralMovementDetector().analyze() == []
    assert LateralMovementDetector().analyze([]) == []


def test_only_process_creation_events_is_silent():
    """Existing scenarios carry only 4688; the detector must ignore them."""
    events = [_logon(event_id=4688, account="CORP\\jsmith")]
    assert LateralMovementDetector().analyze(events) == []


# --- Signal 1: failed-logon spike (4625) ----------------------------------
def test_failed_logon_spike_by_account_fires():
    events = _many(
        lambda record_id, when: _logon(
            event_id=4625, account="CORP\\admin", record_id=record_id, when=when
        ),
        DEFAULT_FAILED_LOGON_THRESHOLD,
    )

    findings = LateralMovementDetector().analyze(events)

    spikes = [f for f in findings if f.evidence["signal"] == "failed_logon_spike"]
    by_account = [f for f in spikes if f.evidence.get("pivot") == "account"]
    assert len(by_account) == 1
    f = by_account[0]
    assert f.category == FindingCategory.LATERAL_MOVEMENT
    assert f.evidence["account"] == "CORP\\admin"
    assert f.evidence["failed_count"] == DEFAULT_FAILED_LOGON_THRESHOLD
    assert f.evidence["mitre"] == "T1110"
    assert f.severity == "high"


def test_failed_logon_below_threshold_is_silent():
    events = _many(
        lambda record_id, when: _logon(
            event_id=4625, account="CORP\\admin", record_id=record_id, when=when
        ),
        DEFAULT_FAILED_LOGON_THRESHOLD - 1,
    )
    assert LateralMovementDetector().analyze(events) == []


def test_failed_logon_spike_by_source_fires():
    events = _many(
        lambda record_id, when: _logon(
            event_id=4625,
            account="CORP\\bob",
            remote_host="ATTACKER (10.0.0.9)",
            record_id=record_id,
            when=when,
        ),
        DEFAULT_FAILED_LOGON_THRESHOLD,
    )

    findings = LateralMovementDetector().analyze(events)

    by_source = [
        f
        for f in findings
        if f.evidence["signal"] == "failed_logon_spike"
        and f.evidence.get("pivot") == "source"
    ]
    assert len(by_source) == 1
    assert by_source[0].evidence["source"] == "ATTACKER (10.0.0.9)"


def test_custom_threshold_lowers_the_bar():
    events = _many(
        lambda record_id, when: _logon(
            event_id=4625, account="CORP\\svc", record_id=record_id, when=when
        ),
        3,
    )
    findings = LateralMovementDetector(failed_logon_threshold=3).analyze(events)
    assert any(f.evidence["signal"] == "failed_logon_spike" for f in findings)


# --- Signal 2: service-account RDP (4624 type 10) -------------------------
def test_service_account_rdp_fires():
    events = [
        _logon(
            event_id=4624,
            account="CORP\\svc_sql",
            logon_type="10",
            computer="DBHOST",
            remote_host="JUMP (10.0.0.5)",
        )
    ]

    findings = LateralMovementDetector().analyze(events)

    svc = [f for f in findings if f.evidence["signal"] == "service_account_rdp"]
    assert len(svc) == 1
    assert svc[0].evidence["account"] == "CORP\\svc_sql"
    assert svc[0].evidence["host"] == "DBHOST"
    assert svc[0].evidence["mitre"] == "T1078"
    assert svc[0].category == FindingCategory.LATERAL_MOVEMENT


def test_service_account_rdp_deduplicates_account_host_pair():
    events = [
        _logon(
            event_id=4624,
            account="CORP\\svc_sql",
            logon_type="10",
            computer="DBHOST",
            record_id=1,
        ),
        _logon(
            event_id=4624,
            account="CORP\\svc_sql",
            logon_type="10",
            computer="DBHOST",
            record_id=2,
        ),
    ]
    findings = LateralMovementDetector().analyze(events)
    svc = [f for f in findings if f.evidence["signal"] == "service_account_rdp"]
    assert len(svc) == 1


def test_normal_user_rdp_does_not_fire_service_signal():
    events = [
        _logon(event_id=4624, account="CORP\\jsmith", logon_type="10", computer="WKSTN")
    ]
    findings = LateralMovementDetector().analyze(events)
    assert not [f for f in findings if f.evidence["signal"] == "service_account_rdp"]


def test_service_account_network_logon_does_not_fire():
    """Type 3 (network) by a service account is normal; only RDP (10) is abuse."""
    events = [
        _logon(
            event_id=4624, account="CORP\\svc_backup", logon_type="3", computer="FILE01"
        )
    ]
    findings = LateralMovementDetector().analyze(events)
    assert not [f for f in findings if f.evidence["signal"] == "service_account_rdp"]


def test_service_account_rdp_uses_fallbacks_when_host_and_source_missing():
    events = [_logon(event_id=4624, account="svc_iis", logon_type="10", computer="")]
    findings = LateralMovementDetector().analyze(events)
    svc = [f for f in findings if f.evidence["signal"] == "service_account_rdp"]
    assert len(svc) == 1
    assert svc[0].evidence["host"] == "unknown host"
    assert svc[0].evidence["source"] == "an unknown source"


# --- Signal 3: cross-host account spread ----------------------------------
def test_cross_host_spread_fires_at_threshold():
    events = [
        _logon(
            event_id=4624, account="CORP\\cbarton-a", computer=f"HOST{i}", record_id=i
        )
        for i in range(DEFAULT_CROSS_HOST_THRESHOLD)
    ]

    findings = LateralMovementDetector().analyze(events)

    spread = [f for f in findings if f.evidence["signal"] == "cross_host_spread"]
    assert len(spread) == 1
    assert spread[0].evidence["host_count"] == DEFAULT_CROSS_HOST_THRESHOLD
    assert spread[0].evidence["account"] == "CORP\\cbarton-a"
    assert spread[0].evidence["mitre"] == "T1021"
    # Host list is sorted and complete.
    assert spread[0].evidence["hosts"] == sorted(
        f"HOST{i}" for i in range(DEFAULT_CROSS_HOST_THRESHOLD)
    )


def test_cross_host_spread_counts_explicit_cred_hosts_too():
    events = [
        _logon(event_id=4624, account="CORP\\admin", computer="A", record_id=1),
        _logon(event_id=4648, account="CORP\\admin", computer="B", record_id=2),
        _logon(event_id=4624, account="CORP\\admin", computer="C", record_id=3),
    ]
    findings = LateralMovementDetector(cross_host_threshold=3).analyze(events)
    spread = [f for f in findings if f.evidence["signal"] == "cross_host_spread"]
    assert len(spread) == 1
    assert spread[0].evidence["hosts"] == ["A", "B", "C"]


def test_single_host_repeat_does_not_spread():
    events = [
        _logon(event_id=4624, account="CORP\\admin", computer="A", record_id=i)
        for i in range(5)
    ]
    findings = LateralMovementDetector().analyze(events)
    assert not [f for f in findings if f.evidence["signal"] == "cross_host_spread"]


# --- Signal 4: explicit-credential burst (4648) ---------------------------
def test_explicit_cred_burst_fires():
    events = _many(
        lambda record_id, when: _logon(
            event_id=4648,
            account="STARK\\tdungan",
            computer="RD-01",
            record_id=record_id,
            when=when,
        ),
        DEFAULT_EXPLICIT_CRED_THRESHOLD,
    )

    findings = LateralMovementDetector().analyze(events)

    burst = [f for f in findings if f.evidence["signal"] == "explicit_cred_burst"]
    assert len(burst) == 1
    assert burst[0].evidence["account"] == "STARK\\tdungan"
    assert burst[0].evidence["host"] == "RD-01"
    assert burst[0].evidence["explicit_cred_count"] == DEFAULT_EXPLICIT_CRED_THRESHOLD
    assert burst[0].evidence["mitre"] == "T1078"


def test_explicit_cred_below_threshold_is_silent():
    events = _many(
        lambda record_id, when: _logon(
            event_id=4648,
            account="STARK\\tdungan",
            computer="RD-01",
            record_id=record_id,
            when=when,
        ),
        DEFAULT_EXPLICIT_CRED_THRESHOLD - 1,
    )
    burst = [
        f
        for f in LateralMovementDetector().analyze(events)
        if f.evidence["signal"] == "explicit_cred_burst"
    ]
    assert burst == []


# --- Noise filters --------------------------------------------------------
def test_machine_accounts_are_filtered_everywhere():
    events = (
        _many(
            lambda record_id, when: _logon(
                event_id=4625,
                account="CORP\\WKSTN-01$",
                record_id=record_id,
                when=when,
            ),
            DEFAULT_FAILED_LOGON_THRESHOLD,
        )
        + [
            _logon(
                event_id=4624,
                account="CORP\\WKSTN-01$",
                computer=f"H{i}",
                record_id=100 + i,
            )
            for i in range(DEFAULT_CROSS_HOST_THRESHOLD)
        ]
        + _many(
            lambda record_id, when: _logon(
                event_id=4648,
                account="CORP\\WKSTN-01$",
                computer="RD-01",
                record_id=200 + record_id,
                when=when,
            ),
            DEFAULT_EXPLICIT_CRED_THRESHOLD,
        )
    )
    assert LateralMovementDetector().analyze(events) == []


def test_local_session_principals_are_filtered():
    events = [
        _logon(
            event_id=4624,
            account="Window Manager\\DWM-1",
            computer=f"H{i}",
            record_id=i,
        )
        for i in range(DEFAULT_CROSS_HOST_THRESHOLD)
    ] + [
        _logon(
            event_id=4624,
            account="NT AUTHORITY\\SYSTEM",
            computer=f"S{i}",
            record_id=50 + i,
        )
        for i in range(DEFAULT_CROSS_HOST_THRESHOLD)
    ]
    assert LateralMovementDetector().analyze(events) == []


def test_empty_target_account_is_ignored():
    events = _many(
        lambda record_id, when: _logon(
            event_id=4625, account="", record_id=record_id, when=when
        ),
        DEFAULT_FAILED_LOGON_THRESHOLD,
    )
    # No account and no remote host -> nothing to attribute the spike to.
    assert LateralMovementDetector().analyze(events) == []


def test_missing_target_payload_is_ignored():
    """A 4625 row with no PayloadData1 at all must not crash or fire."""
    events = _many(
        lambda record_id, when: _logon(
            event_id=4625, account=None, record_id=record_id, when=when
        ),
        DEFAULT_FAILED_LOGON_THRESHOLD,
    )
    assert LateralMovementDetector().analyze(events) == []


# --- edge cases for parsing/labelling helpers -----------------------------
def test_backslash_only_target_is_noise():
    """A bare '\\' target (no account name) must be treated as noise."""
    events = _many(
        lambda record_id, when: _logon(
            event_id=4625, account="\\", record_id=record_id, when=when
        ),
        DEFAULT_FAILED_LOGON_THRESHOLD,
    )
    assert LateralMovementDetector().analyze(events) == []


def test_failed_source_label_host_only_when_no_ip():
    """RemoteHost with a name but no parenthesised IP labels by host alone."""
    events = _many(
        lambda record_id, when: _logon(
            event_id=4625,
            account="CORP\\bob",
            remote_host="JUMPBOX",
            record_id=record_id,
            when=when,
        ),
        DEFAULT_FAILED_LOGON_THRESHOLD,
    )
    by_source = [
        f
        for f in LateralMovementDetector().analyze(events)
        if f.evidence["signal"] == "failed_logon_spike"
        and f.evidence.get("pivot") == "source"
    ]
    assert len(by_source) == 1
    assert by_source[0].evidence["source"] == "JUMPBOX"


def test_machine_account_rdp_is_filtered_before_service_check():
    """A machine account doing RDP is filtered as noise, never a service hit."""
    events = [
        _logon(
            event_id=4624, account="CORP\\DBHOST$", logon_type="10", computer="DBHOST"
        )
    ]
    findings = LateralMovementDetector().analyze(events)
    assert not [f for f in findings if f.evidence["signal"] == "service_account_rdp"]


# --- Combined / realistic ------------------------------------------------
def test_full_campaign_emits_all_four_signals():
    events: list[EventLogEntry] = []
    # 1) spray against one account from one source
    events += _many(
        lambda record_id, when: _logon(
            event_id=4625,
            account="CORP\\admin",
            remote_host="ATTACKER (10.0.0.9)",
            record_id=record_id,
            when=when,
        ),
        DEFAULT_FAILED_LOGON_THRESHOLD,
    )
    # 2) service-account RDP
    events.append(
        _logon(
            event_id=4624,
            account="CORP\\svc_sql",
            logon_type="10",
            computer="DBHOST",
            record_id=900,
        )
    )
    # 3) cross-host spread for a pivot account
    events += [
        _logon(
            event_id=4624,
            account="CORP\\cbarton-a",
            computer=f"HOST{i}",
            record_id=1000 + i,
        )
        for i in range(DEFAULT_CROSS_HOST_THRESHOLD)
    ]
    # 4) explicit-cred burst
    events += _many(
        lambda record_id, when: _logon(
            event_id=4648,
            account="STARK\\tdungan",
            computer="RD-01",
            record_id=2000 + record_id,
            when=when,
        ),
        DEFAULT_EXPLICIT_CRED_THRESHOLD,
    )

    findings = LateralMovementDetector().analyze(events)
    signals = {f.evidence["signal"] for f in findings}
    assert signals == {
        "failed_logon_spike",
        "service_account_rdp",
        "cross_host_spread",
        "explicit_cred_burst",
    }
    assert all(f.category == FindingCategory.LATERAL_MOVEMENT for f in findings)


# ===========================================================================
# SFE-e76: hardened service-account heuristic (word-boundary + configurable)
# ===========================================================================
def _svc_rdp(account: str, detector: LateralMovementDetector | None = None):
    """Run a single service-account RDP event and return matching findings."""
    events = [
        _logon(event_id=4624, account=account, logon_type="10", computer="DBHOST")
    ]
    det = detector or LateralMovementDetector()
    return [
        f for f in det.analyze(events) if f.evidence["signal"] == "service_account_rdp"
    ]


@pytest.mark.parametrize(
    "account",
    [
        "CORP\\svc_sql",  # svc_ prefix
        "CORP\\svc-web",  # svc- prefix (hyphen separator)
        "CORP\\svc",  # bare marker as whole name
        "CORP\\sqladmin",  # sql prefix (was a documented FN)
        "CORP\\backup_admin",  # backup prefix (was a documented FN)
        "CORP\\iis_apppool",  # iis prefix
    ],
)
def test_service_account_true_positives_still_fire(account):
    """Real service accounts (leading role token) must still match."""
    assert len(_svc_rdp(account)) == 1


@pytest.mark.parametrize(
    "account",
    [
        "CORP\\Bob.Service",  # 'service' is a trailing name word, not a role
        "CORP\\Priscilla",  # human name; 'sql' only as an interior substring
        "CORP\\Joschka",  # human name; guards against 'sched' substring
        "CORP\\Marissa",  # human name; guards against interior matches
    ],
)
def test_human_accounts_do_not_false_positive(account):
    """Human names whose leading token is not a role marker must not match."""
    assert _svc_rdp(account) == []


def test_service_markers_are_configurable():
    """A custom marker list overrides the defaults."""
    det = LateralMovementDetector(service_account_markers=("robot",))
    assert len(_svc_rdp("CORP\\robot_agent", det)) == 1
    # A default marker is no longer active under the override.
    assert _svc_rdp("CORP\\svc_sql", det) == []


def test_service_markers_default_constant_matches_scenario_account():
    """The default marker set keeps the scenario-22 svc_sql detection."""
    assert "svc" in DEFAULT_SERVICE_ACCOUNT_MARKERS


def test_empty_service_markers_rejected():
    with pytest.raises(ValueError, match="service_account_markers"):
        LateralMovementDetector(service_account_markers=())


def test_tokenless_account_never_matches_service():
    """A name that splits to zero tokens (all separators) is not a service."""
    from sift_find_evil.detectors.lateral_movement_detector import (
        _looks_like_service_account,
    )

    assert _looks_like_service_account("CORP\\___") is False
    assert _looks_like_service_account("") is False


def test_min_span_seconds_raises_when_fewer_than_k():
    """Fewer than k timestamps is a precondition violation, not a silent 0.0.

    A silent zero would propagate to hosts_per_hour=inf downstream, masking the
    error. The cross-host caller guards this via the host-count check, so this
    only fires on direct misuse.
    """
    from sift_find_evil.detectors.lateral_movement_detector import (
        LateralMovementDetector as _D,
    )

    with pytest.raises(ValueError, match="timestamps to span"):
        _D._min_span_seconds([_TS], 3)
    with pytest.raises(ValueError, match="timestamps to span"):
        _D._min_span_seconds([], 3)


def test_distributed_spray_exact_window_boundary_inclusive():
    """Events spanning exactly `window` seconds co-inhabit one window.

    Pins the closed-interval [anchor-window, anchor] convention the reviewer
    flagged as untested: 31 failures at 0s,10s,...,300s across 6 accounts span
    exactly 300s and must still trip the density signal.
    """
    events = [
        _logon(
            event_id=4625,
            account=f"CORP\\user{i % 6}",
            remote_host=f"SRC{i % 6} (10.0.0.{i % 6})",
            record_id=i,
            when=_TS + timedelta(seconds=i * 10),  # 0s .. 300s == exactly window
        )
        for i in range(31)
    ]
    findings = LateralMovementDetector(
        spray_density_threshold=30, spray_window_seconds=300
    ).analyze(events)
    spray = [f for f in findings if f.evidence["signal"] == "distributed_spray"]
    assert len(spray) == 1
    assert spray[0].evidence["span_seconds"] == pytest.approx(300.0)


# ===========================================================================
# SFE-axz: temporal clustering — cross-host window + distributed spray
# ===========================================================================
# --- cross-host time window (opt-in; default off) -------------------------
def test_cross_host_window_defaults_off_flags_slow_spread():
    """With no window set, a 30-day-apart 3-host spread still fires (legacy)."""
    events = [
        _logon(
            event_id=4624,
            account="CORP\\svc_monitor",
            computer=f"HOST{i}",
            record_id=i,
            when=_TS + timedelta(days=15 * i),
        )
        for i in range(DEFAULT_CROSS_HOST_THRESHOLD)
    ]
    spread = [
        f
        for f in LateralMovementDetector().analyze(events)
        if f.evidence["signal"] == "cross_host_spread"
    ]
    assert len(spread) == 1


def test_cross_host_window_suppresses_slow_admin_spread():
    """An opt-in window drops '3 hosts over 30 days' (routine admin)."""
    events = [
        _logon(
            event_id=4624,
            account="CORP\\monitor",
            computer=f"HOST{i}",
            record_id=i,
            when=_TS + timedelta(days=15 * i),
        )
        for i in range(DEFAULT_CROSS_HOST_THRESHOLD)
    ]
    det = LateralMovementDetector(cross_host_window_seconds=300)
    spread = [
        f for f in det.analyze(events) if f.evidence["signal"] == "cross_host_spread"
    ]
    assert spread == []


def test_cross_host_window_keeps_fast_spread():
    """A burst spread inside the window still fires under the gate."""
    events = [
        _logon(
            event_id=4624,
            account="CORP\\cbarton-a",
            computer=f"HOST{i}",
            record_id=i,
            when=_TS + timedelta(seconds=30 * i),
        )
        for i in range(DEFAULT_CROSS_HOST_THRESHOLD)
    ]
    det = LateralMovementDetector(cross_host_window_seconds=300)
    spread = [
        f for f in det.analyze(events) if f.evidence["signal"] == "cross_host_spread"
    ]
    assert len(spread) == 1
    # Temporal evidence is attached regardless of the gate.
    assert spread[0].evidence["span_seconds"] == pytest.approx(
        30 * (DEFAULT_CROSS_HOST_THRESHOLD - 1)
    )
    assert "hosts_per_hour" in spread[0].evidence


def test_cross_host_evidence_carries_span_even_without_window():
    """Temporal fields are always present so operators can triage rate."""
    events = [
        _logon(
            event_id=4624,
            account="CORP\\cbarton-a",
            computer=f"HOST{i}",
            record_id=i,
            when=_TS + timedelta(seconds=60 * i),
        )
        for i in range(DEFAULT_CROSS_HOST_THRESHOLD)
    ]
    spread = [
        f
        for f in LateralMovementDetector().analyze(events)
        if f.evidence["signal"] == "cross_host_spread"
    ]
    assert len(spread) == 1
    assert spread[0].evidence["span_seconds"] == pytest.approx(
        60 * (DEFAULT_CROSS_HOST_THRESHOLD - 1)
    )


def test_cross_host_window_rejects_subone():
    with pytest.raises(ValueError, match="cross_host_window_seconds"):
        LateralMovementDetector(cross_host_window_seconds=0)


# --- distributed low-and-slow spray --------------------------------------
def test_distributed_spray_fires_on_many_accounts_many_sources():
    """Many accounts x many sources, each below the per-target threshold,
    still trips an aggregate time-boxed density signal."""
    events: list[EventLogEntry] = []
    rid = 0
    # 6 accounts x 6 sources, 1 failure each = 36 failures, none per-target
    # anywhere near DEFAULT_FAILED_LOGON_THRESHOLD (20).
    for a in range(6):
        for s in range(6):
            events.append(
                _logon(
                    event_id=4625,
                    account=f"CORP\\user{a}",
                    remote_host=f"SRC{s} (10.0.0.{s})",
                    record_id=rid,
                    when=_TS + timedelta(seconds=rid),
                )
            )
            rid += 1

    findings = LateralMovementDetector(
        spray_density_threshold=30, spray_window_seconds=300
    ).analyze(events)
    spray = [f for f in findings if f.evidence["signal"] == "distributed_spray"]
    assert len(spray) == 1
    assert spray[0].severity == "high"
    assert spray[0].evidence["failed_count"] >= 30
    assert spray[0].evidence["distinct_accounts"] == 6
    assert spray[0].evidence["mitre"] == "T1110"
    # No per-target spike should have fired (each target has only 6 or fewer).
    assert not [f for f in findings if f.evidence["signal"] == "failed_logon_spike"]


def test_distributed_spray_needs_breadth_not_single_account():
    """A single-account concentrated spray must NOT trip the density signal —
    this is what protects the scenario-22 ground truth from a 6th finding."""
    events = _many(
        lambda record_id, when: _logon(
            event_id=4625,
            account="CORP\\admin",
            remote_host="ATTACKER (10.0.0.9)",
            record_id=record_id,
            when=when,
        ),
        40,  # well over any density threshold, but ONE account + ONE source
    )
    findings = LateralMovementDetector(
        spray_density_threshold=30, spray_window_seconds=300
    ).analyze(events)
    assert not [f for f in findings if f.evidence["signal"] == "distributed_spray"]


def test_distributed_spray_respects_time_window():
    """Failures spread beyond the window do not aggregate into a burst."""
    events: list[EventLogEntry] = []
    rid = 0
    for a in range(6):
        for s in range(6):
            events.append(
                _logon(
                    event_id=4625,
                    account=f"CORP\\user{a}",
                    remote_host=f"SRC{s} (10.0.0.{s})",
                    record_id=rid,
                    # 1 hour apart -> never 30 within any 300s window.
                    when=_TS + timedelta(hours=rid),
                )
            )
            rid += 1
    findings = LateralMovementDetector(
        spray_density_threshold=30, spray_window_seconds=300
    ).analyze(events)
    assert not [f for f in findings if f.evidence["signal"] == "distributed_spray"]


def test_distributed_spray_defaults_are_conservative():
    """Exported defaults exist and stay above scenario-noise levels."""
    assert DEFAULT_SPRAY_DENSITY_THRESHOLD >= 30
    assert DEFAULT_SPRAY_MIN_ACCOUNTS >= 2
    assert DEFAULT_SPRAY_WINDOW_SECONDS >= 60


def test_distributed_spray_min_accounts_configurable():
    with pytest.raises(ValueError, match="spray_min_accounts"):
        LateralMovementDetector(spray_min_accounts=0)


def test_distributed_spray_rejects_subone_window_and_threshold():
    with pytest.raises(ValueError, match="spray_window_seconds"):
        LateralMovementDetector(spray_window_seconds=0)
    with pytest.raises(ValueError, match="spray_density_threshold"):
        LateralMovementDetector(spray_density_threshold=0)
