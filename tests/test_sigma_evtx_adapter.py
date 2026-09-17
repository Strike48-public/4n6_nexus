"""SFE-katy PR2: EVTX -> flat Sigma-event adapter.

The mini-Sigma matcher (detectors/sigma_scan/matcher.py) evaluates rules over
FLAT ``{field: value}`` dicts keyed by Sigma logical field names (Image,
CommandLine, ParentImage, ...). The EVTX parser emits ``EventLogEntry`` objects
whose Sigma-relevant fields live either in positional ``payload_dataN`` columns
or inside ``payload_json["EventData"]["Data"]`` - reachable only via accessor
methods. This adapter bridges the two: one ``EventLogEntry`` -> one flat Sigma
event dict, per-EventID field mapping. Without it the matcher cannot see EVTX.
"""

from __future__ import annotations

from datetime import datetime

from sift_find_evil.detectors.sigma_scan.evtx_adapter import event_to_sigma
from sift_find_evil.parsers.evtx_parser import EventLogEntry


def _entry(**kw) -> EventLogEntry:
    base = dict(
        time_created=datetime(2025, 3, 15, 10, 30, 0),
        event_id=4688,
        record_id=1,
        computer="VICTIM-PC",
        channel="Security",
        level="Information",
    )
    base.update(kw)
    return EventLogEntry(**base)


# --- 4688 Process Create: the primary Sigma target -------------------------


def test_4688_maps_image_commandline_parentimage() -> None:
    entry = _entry(
        event_id=4688,
        payload_data1=r"C:\Users\v\AppData\Roaming\crypt_engine.exe",
        payload_data4=r"C:\Users\v\Downloads\ransom_note.exe",
        payload_data6="crypt_engine.exe --encrypt C:\\Users",
    )

    sigma = event_to_sigma(entry)

    assert sigma["EventID"] == 4688
    assert sigma["Channel"] == "Security"
    assert sigma["Image"] == r"C:\Users\v\AppData\Roaming\crypt_engine.exe"
    assert sigma["ParentImage"] == r"C:\Users\v\Downloads\ransom_note.exe"
    assert sigma["CommandLine"] == "crypt_engine.exe --encrypt C:\\Users"


def test_4688_prefers_json_payload_over_positional() -> None:
    # When the richer payload_json is present, the parser accessors use it; the
    # adapter must reflect that (real EvtxECmd output carries NewProcessName).
    entry = _entry(
        event_id=4688,
        payload_data1="ignored-if-json-present",
        payload_json={
            "EventData": {
                "Data": [
                    {
                        "@Name": "NewProcessName",
                        "#text": r"C:\Windows\System32\cmd.exe",
                    },
                    {"@Name": "CommandLine", "#text": "cmd.exe /c whoami"},
                ]
            }
        },
    )

    sigma = event_to_sigma(entry)

    assert sigma["Image"] == r"C:\Windows\System32\cmd.exe"
    assert sigma["CommandLine"] == "cmd.exe /c whoami"


# --- 4624/4625 Logon: the lateral-movement / spray Sigma target ------------


def test_4625_maps_logon_fields() -> None:
    entry = _entry(
        event_id=4625,
        channel="Security",
        payload_data1="Target: CORP\\admin",
        payload_data2="LogonType 3",
        remote_host="ATTACKER (10.0.0.9)",
        map_description="Failed logon",
    )

    sigma = event_to_sigma(entry)

    assert sigma["EventID"] == 4625
    # The target account and logon type must be extracted from the positional
    # payload so a Sigma rule can match "LogonType 3 failed logons".
    assert "admin" in sigma["TargetUserName"]
    assert sigma["LogonType"] == "3"


# --- shared / invariant behavior -------------------------------------------


def test_common_fields_always_present() -> None:
    entry = _entry(event_id=4648)
    sigma = event_to_sigma(entry)
    # Every Sigma event carries the routing fields a logsource/rule needs.
    for key in ("EventID", "Channel", "Computer"):
        assert key in sigma


def test_absent_fields_are_omitted_not_none() -> None:
    # A missing field must be ABSENT from the dict, not present-as-None: the
    # matcher does `field_name in event`, so a None would falsely register the
    # field as present and a `not`-condition could misfire.
    entry = _entry(event_id=4688, payload_data1=None, payload_data6=None)
    sigma = event_to_sigma(entry)
    assert "Image" not in sigma or sigma["Image"]
    assert None not in sigma.values()


def test_adapter_does_not_mutate_the_entry() -> None:
    entry = _entry(event_id=4688, payload_data1="a.exe")
    before = entry.payload_data1
    event_to_sigma(entry)
    assert entry.payload_data1 == before
