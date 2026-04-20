"""Tests for LnkJumpListDetector."""

from __future__ import annotations

from datetime import datetime, timezone

from sift_find_evil.detectors.lnk_jumplist_detector import LnkJumpListDetector
from sift_find_evil.findings import FindingCategory
from sift_find_evil.parsers.lnk_jumplist_parser import JumpListEntry, LnkEntry


_TS = datetime(2025, 3, 15, 10, 30, 0, tzinfo=timezone.utc)


def _lnk(
    *,
    lnk_path: str = "C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\q3.lnk",
    target_path: str = "E:\\quarterly\\q3_financials.xlsx",
    target_size: int = 81920,
    working_directory: str = "",
    arguments: str = "",
    drive_type: str = "removable",
    volume_serial: str = "ABCD-1234",
    volume_label: str = "EXFIL_USB",
    machine_id: str = "WIN-CORPDC",
    mac_address: str = "aa:bb:cc:dd:ee:ff",
) -> LnkEntry:
    return LnkEntry(
        lnk_path=lnk_path,
        target_path=target_path,
        target_size=target_size,
        target_created=_TS,
        target_modified=_TS,
        target_accessed=_TS,
        working_directory=working_directory,
        arguments=arguments,
        drive_type=drive_type,
        volume_serial=volume_serial,
        volume_label=volume_label,
        machine_id=machine_id,
        mac_address=mac_address,
        created=_TS,
    )


def _jl(
    *,
    app_id: str = "9d1f905ce5044aee",
    app_name: str = "Microsoft Excel",
    entry_type: str = "automatic",
    target_path: str = "\\\\fileserver\\share\\budget.xlsx",
    drive_type: str = "network",
    jumplist_path: str = "/ev/excel.automaticDestinations-ms",
) -> JumpListEntry:
    return JumpListEntry(
        app_id=app_id,
        app_name=app_name,
        entry_type=entry_type,
        target_path=target_path,
        drive_type=drive_type,
        opened_time=_TS,
        jumplist_path=jumplist_path,
    )


# --- Removable / network media access ---------------------------------------


def test_lnk_on_removable_media_with_sensitive_ext_flagged():
    findings = LnkJumpListDetector().analyze(lnk_entries=[_lnk()])
    assert len(findings) == 1
    f = findings[0]
    assert f.category == FindingCategory.DATA_EXFILTRATION
    assert f.severity == "high"
    assert "q3_financials.xlsx" in f.title
    assert f.evidence["drive_types"] == ["removable"]
    assert f.evidence["sources"] == ["lnk"]
    # Single-source, single-volume hit: conservative base confidence.
    assert f.confidence == 0.60
    assert f.evidence["volume_serials"] == ["ABCD-1234"]


def test_multi_volume_removable_hits_bump_confidence():
    # Same file seen across two distinct USB serials is a repeat-staging signal.
    findings = LnkJumpListDetector().analyze(
        lnk_entries=[
            _lnk(volume_serial="ABCD-1234", volume_label="USB_A"),
            _lnk(
                lnk_path="C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\q3_alt.lnk",
                volume_serial="EFGH-5678",
                volume_label="USB_B",
            ),
        ]
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.confidence >= 0.70
    assert sorted(f.evidence["volume_serials"]) == ["ABCD-1234", "EFGH-5678"]


def test_lnk_on_fixed_drive_ignored_even_with_sensitive_ext():
    findings = LnkJumpListDetector().analyze(
        lnk_entries=[_lnk(drive_type="fixed", target_path="C:\\users\\bob\\budget.xlsx")]
    )
    assert findings == []


def test_lnk_on_removable_media_with_nonsensitive_ext_ignored():
    findings = LnkJumpListDetector().analyze(
        lnk_entries=[_lnk(target_path="E:\\tools\\installer.exe")]
    )
    assert findings == []


def test_jumplist_on_network_drive_with_sensitive_ext_flagged():
    findings = LnkJumpListDetector().analyze(jumplist_entries=[_jl()])
    assert len(findings) == 1
    f = findings[0]
    assert f.category == FindingCategory.DATA_EXFILTRATION
    assert f.severity == "medium"
    assert f.evidence["drive_types"] == ["network"]


def test_lnk_and_jumplist_corroborate_same_target():
    lnk = _lnk(target_path="\\\\fileserver\\share\\budget.xlsx", drive_type="network")
    jl = _jl(target_path="\\\\fileserver\\share\\BUDGET.XLSX", drive_type="network")
    findings = LnkJumpListDetector().analyze(lnk_entries=[lnk], jumplist_entries=[jl])
    assert len(findings) == 1
    f = findings[0]
    assert sorted(f.evidence["sources"]) == ["jumplist", "lnk"]
    # Cross-source corroboration bumps confidence.
    assert f.confidence >= 0.70


# --- Startup persistence ----------------------------------------------------


_STARTUP_LNK = (
    "C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\"
    "Start Menu\\Programs\\Startup\\sync.lnk"
)


def test_startup_lnk_launching_powershell_flagged_persistence():
    entry = _lnk(
        lnk_path=_STARTUP_LNK,
        target_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        arguments="-nop -w hidden -enc AAAA",
        drive_type="fixed",
    )
    findings = LnkJumpListDetector().analyze(lnk_entries=[entry])
    persistence = [f for f in findings if f.category == FindingCategory.PERSISTENCE]
    assert len(persistence) == 1
    f = persistence[0]
    assert f.severity == "high"
    reasons = f.evidence["reasons"]
    assert any("LOLBAS" in r for r in reasons)
    assert any("hidden/encoded/bypass" in r for r in reasons)


def test_startup_lnk_to_user_writable_path_flagged():
    entry = _lnk(
        lnk_path=_STARTUP_LNK,
        target_path="C:\\Users\\Public\\update.exe",
        arguments="",
        drive_type="fixed",
    )
    findings = LnkJumpListDetector().analyze(lnk_entries=[entry])
    persistence = [f for f in findings if f.category == FindingCategory.PERSISTENCE]
    assert len(persistence) == 1
    assert persistence[0].confidence == 0.65
    assert persistence[0].severity == "medium"


def test_non_startup_lnk_not_flagged_as_persistence():
    entry = _lnk(
        lnk_path="C:\\Users\\bob\\Desktop\\shortcut.lnk",
        target_path="C:\\Users\\Public\\update.exe",
        drive_type="fixed",
    )
    findings = LnkJumpListDetector().analyze(lnk_entries=[entry])
    persistence = [f for f in findings if f.category == FindingCategory.PERSISTENCE]
    assert persistence == []


def test_startup_lnk_to_signed_path_not_flagged():
    entry = _lnk(
        lnk_path=_STARTUP_LNK,
        target_path="C:\\Program Files\\Microsoft\\OneDrive\\OneDrive.exe",
        arguments="/background",
        drive_type="fixed",
    )
    findings = LnkJumpListDetector().analyze(lnk_entries=[entry])
    assert findings == []


def test_startup_lnk_to_onedrive_in_programdata_not_flagged():
    # Regression: legitimate OneDrive auto-start lives under ProgramData on
    # every corporate workstation. Without the signed-autostart allowlist, the
    # generic "programdata is user-writable" signal fires on a benign app.
    entry = _lnk(
        lnk_path=_STARTUP_LNK,
        target_path="C:\\ProgramData\\Microsoft\\OneDrive\\OneDrive.exe",
        arguments="/background",
        drive_type="fixed",
    )
    findings = LnkJumpListDetector().analyze(lnk_entries=[entry])
    assert findings == []


def test_startup_lnk_to_teams_in_appdata_not_flagged():
    # Similar regression for Microsoft Teams.
    entry = _lnk(
        lnk_path=_STARTUP_LNK,
        target_path="C:\\Users\\alice\\AppData\\Local\\Microsoft\\Teams\\Update.exe",
        arguments="--processStart Teams.exe",
        drive_type="fixed",
    )
    findings = LnkJumpListDetector().analyze(lnk_entries=[entry])
    assert findings == []


def test_startup_lnk_to_chrome_in_appdata_not_flagged():
    entry = _lnk(
        lnk_path=_STARTUP_LNK,
        target_path="C:\\Users\\alice\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
        arguments="",
        drive_type="fixed",
    )
    findings = LnkJumpListDetector().analyze(lnk_entries=[entry])
    assert findings == []


def test_startup_lnk_to_unsigned_appdata_path_still_flagged():
    # Guard the allowlist isn't over-broad: a random unknown binary in
    # AppData\Roaming must still trip the signal.
    entry = _lnk(
        lnk_path=_STARTUP_LNK,
        target_path="C:\\Users\\alice\\AppData\\Roaming\\Suspicious\\payload.exe",
        arguments="",
        drive_type="fixed",
    )
    findings = LnkJumpListDetector().analyze(lnk_entries=[entry])
    persistence = [f for f in findings if f.category == FindingCategory.PERSISTENCE]
    assert len(persistence) == 1


def test_startup_lnk_survives_pathological_arguments():
    # Regression: catastrophic-backtracking DoS if an adversary plants a giant
    # -e-prefixed blob in Arguments.
    entry = _lnk(
        lnk_path=_STARTUP_LNK,
        target_path="C:\\Users\\Public\\foo.exe",
        arguments="-e" * 50_000,
        drive_type="fixed",
    )
    findings = LnkJumpListDetector().analyze(lnk_entries=[entry])
    # Path signal should still fire; hidden-flag signal should NOT fire on
    # oversize input.
    persistence = [f for f in findings if f.category == FindingCategory.PERSISTENCE]
    assert len(persistence) == 1
    assert all("hidden/encoded/bypass" not in r for r in persistence[0].evidence["reasons"])


# --- Jump List UNC indicator ------------------------------------------------


def test_jumplist_unc_target_without_network_drive_type_flagged():
    entry = _jl(
        target_path="\\\\server\\share\\proposal.pdf",
        drive_type="unknown",
    )
    findings = LnkJumpListDetector().analyze(jumplist_entries=[entry])
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].confidence == 0.55


def test_jumplist_non_unc_target_not_flagged_as_unc_indicator():
    entry = _jl(
        target_path="C:\\Users\\bob\\local.pdf",
        drive_type="fixed",
    )
    findings = LnkJumpListDetector().analyze(jumplist_entries=[entry])
    assert findings == []


def test_jumplist_network_drive_only_reports_under_media_branch():
    # Regression: when drive_type == "network", the UNC branch must not also
    # report (avoid double-counting).
    entry = _jl(target_path="\\\\server\\share\\a.docx", drive_type="network")
    findings = LnkJumpListDetector().analyze(jumplist_entries=[entry])
    assert len(findings) == 1
    # Should be the media-access finding, not the UNC indicator.
    assert findings[0].evidence["sources"] == ["jumplist"]


# --- End-to-end -------------------------------------------------------------


def test_empty_inputs_produce_no_findings():
    d = LnkJumpListDetector()
    assert d.analyze() == []
    assert d.analyze(lnk_entries=[], jumplist_entries=[]) == []


def test_grouping_by_target_case_insensitive():
    findings = LnkJumpListDetector().analyze(
        lnk_entries=[
            _lnk(target_path="E:\\exfil\\A.DOCX"),
            _lnk(
                lnk_path="C:\\other.lnk",
                target_path="e:\\EXFIL\\a.docx",
            ),
        ]
    )
    assert len(findings) == 1
    assert len(findings[0].evidence["details"]) == 2
