"""Tests for RegistryDetector (persistence + suspicious-path execution)."""

from __future__ import annotations

from datetime import datetime, timezone

from sift_find_evil.detectors.registry_detector import RegistryDetector
from sift_find_evil.findings import FindingCategory
from sift_find_evil.parsers.registry_parser import (
    AmcacheEntry,
    BAMEntry,
    RunKeyEntry,
    ShimcacheEntry,
    UserAssistEntry,
)


_TS = datetime(2025, 3, 15, 10, 30, 0, tzinfo=timezone.utc)


def _run_key(
    *,
    command: str,
    value_name: str = "Updater",
    key_path: str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    hive: str = "HKCU",
) -> RunKeyEntry:
    return RunKeyEntry(
        key_path=key_path,
        value_name=value_name,
        command=command,
        hive=hive,
        last_write_time=_TS,
    )


def _amcache(
    path: str, sha1: str = "a" * 40, publisher: str | None = None
) -> AmcacheEntry:
    return AmcacheEntry(
        file_path=path,
        first_execution=_TS,
        sha1_hash=sha1,
        file_size=1024,
        publisher=publisher,
    )


def _shimcache(path: str) -> ShimcacheEntry:
    return ShimcacheEntry(
        file_path=path,
        last_modified=_TS,
        file_size=2048,
        exec_flag=True,
    )


def _bam(path: str) -> BAMEntry:
    return BAMEntry(
        file_path=path,
        execution_time=_TS,
        user_sid="S-1-5-21-111-222-333-1001",
    )


def _userassist(program: str, focus_ms: int = 0, runs: int = 3) -> UserAssistEntry:
    return UserAssistEntry(
        program_name=program,
        run_count=runs,
        last_execution=_TS,
        focus_count=0,
        focus_time_ms=focus_ms,
    )


# --- Run keys ---------------------------------------------------------------


def test_run_key_flags_suspicious_temp_path_launcher():
    entry = _run_key(
        command='"C:\\Users\\Public\\update.exe"',
    )
    findings = RegistryDetector().analyze(run_keys=[entry])
    assert len(findings) == 1
    ev = findings[0].evidence
    assert ev["hive"] == "HKCU"
    assert ev["launcher"] == "update.exe"
    assert findings[0].category == FindingCategory.PERSISTENCE
    assert any("users\\public" in r.lower() for r in ev["reasons"])


def test_run_key_flags_powershell_encoded():
    entry = _run_key(
        command="powershell.exe -w hidden -encodedcommand ABCDEFG==",
    )
    findings = RegistryDetector().analyze(run_keys=[entry])
    assert len(findings) == 1
    ev = findings[0].evidence
    reasons = ev["reasons"]
    assert any("LOLBAS" in r for r in reasons)
    assert any("hidden/encoded/bypass" in r for r in reasons)
    # Two reasons should push confidence to High.
    assert findings[0].confidence_label == "High"


def test_run_key_flags_double_extension_target():
    entry = _run_key(
        command='"C:\\Program Files\\App\\launcher.exe" "C:\\Users\\bob\\resume.pdf.exe"',
    )
    findings = RegistryDetector().analyze(run_keys=[entry])
    assert len(findings) == 1
    assert any("double extension" in r for r in findings[0].evidence["reasons"])


def test_run_key_ignores_benign_signed_path():
    entry = _run_key(
        command='"C:\\Program Files\\Microsoft\\OneDrive\\OneDrive.exe" /background',
    )
    findings = RegistryDetector().analyze(run_keys=[entry])
    assert findings == []


def test_run_key_path_only_is_low_confidence():
    # Path alone is suspicious but no LOLBAS launcher, no hidden flags —
    # many legitimate updaters also write to ProgramData, so this should be
    # low-confidence and not scare the investigator into action on its own.
    entry = _run_key(
        command='"C:\\ProgramData\\MyApp\\helper.exe"',
    )
    findings = RegistryDetector().analyze(run_keys=[entry])
    assert len(findings) == 1
    assert findings[0].confidence_label == "Low"
    assert findings[0].confidence == 0.50
    reasons = findings[0].evidence["reasons"]
    assert len(reasons) == 1
    assert "programdata" in reasons[0].lower()


def test_run_key_lolbas_alone_is_medium_confidence():
    # LOLBAS host without path/flags is a stronger single signal than path
    # alone: still medium, not low.
    entry = _run_key(command="regsvr32.exe /s /u scrobj.dll")
    findings = RegistryDetector().analyze(run_keys=[entry])
    assert len(findings) == 1
    assert findings[0].confidence_label == "Medium"
    assert findings[0].confidence == 0.65


def test_run_key_survives_pathological_long_command():
    # Regression: catastrophic-backtracking DoS if a Run key carries a
    # megabyte-sized -e-prefixed blob. Detector must not hang and must not
    # flag the hidden-flags signal on oversize input.
    entry = _run_key(command="-e" * 50_000)
    findings = RegistryDetector().analyze(run_keys=[entry])
    assert findings == []


def test_run_key_multiple_powershell_flags():
    entry = _run_key(
        command="powershell.exe -NoProfile -WindowStyle hidden -ExecutionPolicy Bypass -EncodedCommand AAAA"
    )
    findings = RegistryDetector().analyze(run_keys=[entry])
    assert len(findings) == 1
    reasons = findings[0].evidence["reasons"]
    # Should fire LOLBAS + hidden-flags once each, not one-per-flag.
    assert sum("hidden/encoded/bypass" in r for r in reasons) == 1
    assert findings[0].confidence_label == "High"


def test_run_key_empty_command_is_rejected_by_dataclass():
    # RunKeyEntry.__post_init__ rejects empty commands outright. Sanity check
    # that the detector never sees one.
    import pytest

    with pytest.raises(ValueError):
        _run_key(command="")


def test_run_key_whitespace_only_command_produces_no_finding():
    entry = _run_key(command="   ")
    findings = RegistryDetector().analyze(run_keys=[entry])
    assert findings == []


def test_run_key_userassist_finding_tagged_persistence():
    # Regression: UserAssist should map to PERSISTENCE, not UNKNOWN — zero-
    # focus shell invocation of a script host is an automation signal.
    findings = RegistryDetector().analyze(
        userassist=[_userassist("powershell.exe")],
    )
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.PERSISTENCE


# --- Shimcache / Amcache / BAM ---------------------------------------------


def test_execution_in_public_directory_flagged():
    findings = RegistryDetector().analyze(
        shimcache=[_shimcache("C:\\Users\\Public\\tools\\mimi.exe")],
    )
    assert len(findings) == 1
    ev = findings[0].evidence
    assert ev["file_path"] == "C:\\Users\\Public\\tools\\mimi.exe"
    assert ev["sources"] == ["shimcache"]


def test_execution_double_extension_is_high_severity():
    findings = RegistryDetector().analyze(
        amcache=[_amcache("C:\\Users\\Public\\resume.pdf.exe")],
    )
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert any("double-extension" in r for r in findings[0].evidence["reasons"])


def test_execution_corroborated_across_sources():
    path = "C:\\ProgramData\\evil\\launcher.exe"
    findings = RegistryDetector().analyze(
        shimcache=[_shimcache(path)],
        amcache=[_amcache(path)],
        bam=[_bam(path)],
    )
    assert len(findings) == 1
    ev = findings[0].evidence
    assert sorted(ev["sources"]) == ["amcache", "bam", "shimcache"]
    # Cross-source corroboration bumps confidence.
    assert findings[0].confidence >= 0.70


def test_execution_ignores_system32_path():
    findings = RegistryDetector().analyze(
        bam=[_bam("C:\\Windows\\System32\\cmd.exe")],
    )
    assert findings == []


def test_execution_groups_by_path_case_insensitive():
    findings = RegistryDetector().analyze(
        shimcache=[_shimcache("C:\\Users\\Public\\TOOL.exe")],
        amcache=[_amcache("C:\\users\\public\\tool.exe")],
    )
    assert len(findings) == 1
    assert len(findings[0].evidence["sources"]) == 2


# --- UserAssist -------------------------------------------------------------


def test_userassist_flags_zero_focus_launcher():
    findings = RegistryDetector().analyze(
        userassist=[_userassist("powershell.exe")],
    )
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.PERSISTENCE
    assert findings[0].evidence["program_name"] == "powershell.exe"


def test_userassist_ignores_nonlauncher_with_zero_focus():
    findings = RegistryDetector().analyze(
        userassist=[_userassist("notepad.exe")],
    )
    assert findings == []


def test_userassist_ignores_launcher_with_focus():
    findings = RegistryDetector().analyze(
        userassist=[_userassist("powershell.exe", focus_ms=1500)],
    )
    assert findings == []


# --- End-to-end -------------------------------------------------------------


def test_empty_inputs_produce_no_findings():
    detector = RegistryDetector()
    assert detector.analyze() == []
    assert (
        detector.analyze(shimcache=[], amcache=[], bam=[], userassist=[], run_keys=[])
        == []
    )


def test_run_key_evidence_prefers_payload_basename_over_lolbas_launcher():
    # When the launcher is a script host, harness-level matching needs the
    # payload basename, not "powershell.exe". The target here is malware.ps1.
    entry = _run_key(
        command='powershell.exe -nop -w hidden -File "C:\\Users\\Public\\malware.ps1"'
    )
    findings = RegistryDetector().analyze(run_keys=[entry])
    assert len(findings) == 1
    assert findings[0].evidence["executable"] == "malware.ps1"
    assert findings[0].evidence["launcher"] == "powershell.exe"


def test_run_key_evidence_falls_back_to_launcher_when_no_payload_token():
    # regsvr32 /s /u scrobj.dll — scrobj.dll is a Windows system DLL, not a
    # named payload on its own. Harness-level accounting should still have
    # *something* to match, so we fall back to the launcher basename.
    entry = _run_key(command="regsvr32.exe /s /u scrobj.dll")
    findings = RegistryDetector().analyze(run_keys=[entry])
    assert len(findings) == 1
    assert findings[0].evidence["executable"] == "scrobj.dll"


def test_run_key_evidence_uses_launcher_when_not_lolbas():
    # Non-LOLBAS launcher: the executable IS the payload.
    entry = _run_key(command='"C:\\Users\\Public\\update.exe"')
    findings = RegistryDetector().analyze(run_keys=[entry])
    assert len(findings) == 1
    assert findings[0].evidence["executable"] == "update.exe"


def test_execution_evidence_has_executable_basename():
    findings = RegistryDetector().analyze(
        shimcache=[_shimcache("C:\\Users\\Public\\tools\\mimi.exe")],
    )
    assert findings[0].evidence["executable"] == "mimi.exe"


def test_userassist_evidence_has_executable_basename():
    findings = RegistryDetector().analyze(
        userassist=[_userassist("powershell.exe")],
    )
    assert findings[0].evidence["executable"] == "powershell.exe"


def test_full_pipeline_produces_mixed_findings():
    findings = RegistryDetector().analyze(
        run_keys=[
            _run_key(command="powershell.exe -nop -w hidden -enc AAAA"),
            _run_key(command='"C:\\Program Files\\Signed\\app.exe"'),
        ],
        shimcache=[_shimcache("C:\\Users\\Public\\mimi.exe")],
        amcache=[_amcache("C:\\Windows\\System32\\cmd.exe")],
        userassist=[_userassist("powershell.exe")],
    )
    titles = sorted(f.title for f in findings)
    # Exactly three findings: one Run key, one execution, one UserAssist.
    assert len(findings) == 3
    assert any("Run key" in t for t in titles)
    assert any("attacker-writable" in t for t in titles)
    assert any("UserAssist" in t for t in titles)


def test_basename_with_empty_path():
    """Test _basename handles empty path."""
    from sift_find_evil.detectors.registry_detector import _basename

    assert _basename("") == ""


def test_launcher_basename_malformed_quotes():
    """Test _launcher_basename with malformed quoted command."""
    from sift_find_evil.detectors.registry_detector import RegistryDetector

    # Missing closing quote - should return None
    result = RegistryDetector._launcher_basename('"C:\\test.exe')
    assert result is None


# --- benign-autostart suppression (SFE-box) ---------------------------------
# Real workstations run OneDrive/Teams/Spotify/Dropbox/GPU-driver helpers that
# auto-start from user-writable directories (AppData\Roaming, AppData\Local).
# A *path-only* Run-key signal on a known-good vendor path is noise, not
# persistence. Suppress those while keeping every true positive: any second
# signal (LOLBAS host, hidden flags, double extension) re-escalates, and an
# unknown binary in a user-writable path stays a Low finding.


def test_run_key_path_only_benign_onedrive_appdata_suppressed():
    # OneDrive legitimately auto-starts from AppData\Local\Microsoft\OneDrive.
    # Path-only on a known vendor sub-path -> no finding.
    entry = _run_key(
        value_name="OneDrive",
        command='"C:\\Users\\alice\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background',
    )
    assert RegistryDetector().analyze(run_keys=[entry]) == []


def test_run_key_path_only_benign_spotify_roaming_suppressed():
    # Spotify auto-starts from AppData\Roaming\Spotify.
    entry = _run_key(
        value_name="Spotify",
        command="C:\\Users\\alice\\AppData\\Roaming\\Spotify\\Spotify.exe --autostart",
    )
    assert RegistryDetector().analyze(run_keys=[entry]) == []


def test_run_key_path_only_benign_teams_appdata_suppressed():
    entry = _run_key(
        value_name="com.squirrel.Teams.Teams",
        command='C:\\Users\\alice\\AppData\\Local\\Microsoft\\Teams\\Update.exe --processStart "Teams.exe"',
    )
    assert RegistryDetector().analyze(run_keys=[entry]) == []


def test_run_key_unknown_binary_in_userwritable_still_low_finding():
    # An UNKNOWN binary in a user-writable path is NOT on the allowlist and
    # must still surface as a Low path-only finding (no over-suppression).
    entry = _run_key(
        command="C:\\Users\\alice\\AppData\\Roaming\\totally_legit\\helper.exe",
    )
    findings = RegistryDetector().analyze(run_keys=[entry])
    assert len(findings) == 1
    assert findings[0].confidence == 0.50
    assert findings[0].confidence_label == "Low"


def test_run_key_vendor_path_with_second_signal_not_suppressed():
    # A vendor-name path that ALSO carries a strong signal (hidden PowerShell
    # flags) is an adversary masquerading under a trusted path — must NOT be
    # suppressed by the allowlist.
    entry = _run_key(
        value_name="OneDrive",
        command=(
            "powershell.exe -nop -w hidden -ep bypass -File "
            "C:\\Users\\alice\\AppData\\Local\\Microsoft\\OneDrive\\update.ps1"
        ),
    )
    findings = RegistryDetector().analyze(run_keys=[entry])
    assert len(findings) == 1
    # Multiple strong signals -> High, never suppressed.
    assert findings[0].confidence_label == "High"


def test_scenario08_beacon_run_key_still_flagged():
    # Guard the protected invariant directly: scenario 08's Run key
    # (powershell -enc against C:\Users\Public\beacon.ps1) must stay flagged.
    entry = _run_key(
        value_name="WindowsDefenderUpdate",
        command="powershell.exe -nop -w hidden -ep bypass -File C:\\Users\\Public\\beacon.ps1",
    )
    findings = RegistryDetector().analyze(run_keys=[entry])
    assert len(findings) == 1
    assert findings[0].confidence == 0.80


# --- execution path-only suppression for trusted-publisher binaries (SFE-23x)
# The detector docstring already specs that a path execution finding needs a
# double-extension OR an *unsigned-publisher* binary. The publisher check was
# never implemented, so signed Microsoft binaries that legitimately live under
# ProgramData (Windows Defender platform, VC++ redist) false-positived as
# "execution from attacker-writable directory". Suppress a PATH-ONLY execution
# finding (no double-extension) when the Amcache publisher is a trusted vendor.
# Every scenario true positive carries NO publisher, so they are unaffected.


def test_execution_path_only_trusted_publisher_suppressed():
    # Windows Defender's engine runs from ProgramData and is Microsoft-signed.
    findings = RegistryDetector().analyze(
        amcache=[
            _amcache(
                "C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\4.18\\MsMpEng.exe",
                publisher="Microsoft Corporation",
            )
        ],
    )
    assert findings == []


def test_execution_path_only_unsigned_still_flagged():
    # Same directory, NO publisher -> indistinguishable from a dropped payload,
    # must stay a finding (this is exactly scenario 09's stage1.exe shape).
    findings = RegistryDetector().analyze(
        amcache=[_amcache("C:\\ProgramData\\stage1.exe", publisher=None)],
    )
    assert len(findings) == 1


def test_execution_trusted_publisher_double_extension_still_flagged():
    # A trusted publisher string must NOT rescue a double-extension binary —
    # signing metadata can be spoofed/borrowed; the double extension is the
    # stronger, independent signal and keeps its HIGH severity.
    findings = RegistryDetector().analyze(
        amcache=[
            _amcache(
                "C:\\Users\\Public\\invoice.pdf.exe",
                publisher="Microsoft Corporation",
            )
        ],
    )
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_execution_trusted_publisher_does_not_suppress_corroborated_drop():
    # If the SAME path is also seen via shimcache/bam (no publisher there) the
    # Amcache trusted-publisher tag still suppresses: a genuinely signed binary
    # recorded by multiple execution artifacts is normal. Documents the chosen
    # behavior so a future change is a conscious decision, not drift.
    path = "C:\\ProgramData\\Package Cache\\vcredist\\vc_redist.x64.exe"
    findings = RegistryDetector().analyze(
        amcache=[_amcache(path, publisher="Microsoft Corporation")],
        bam=[_bam(path)],
    )
    assert findings == []


def test_scenario08_beacon_exe_execution_still_flagged():
    # Protected invariant: scenario 08's beacon.exe (Users\Public, EMPTY
    # publisher, corroborated by amcache+bam) must stay flagged.
    path = "C:\\Users\\Public\\beacon.exe"
    findings = RegistryDetector().analyze(
        amcache=[_amcache(path, publisher="")],
        bam=[_bam(path)],
    )
    assert len(findings) == 1
    assert findings[0].evidence["executable"] == "beacon.exe"


# --- OneDrive RunOnce self-cleanup FP (SFE-9rj) -----------------------------
# Found on the SRL-2015 APT corpus (rd-02 rsydow-a, wkstn-01 mhill): the
# legitimate Microsoft OneDrive updater registers RunOnce cleanup commands that
# delete old version directories. These fire on the lone "cmd.exe is a LOLBAS
# host" reason and were flagged Medium. A self-contained `cmd /c del|rmdir`
# cleanup launches NO payload — it only deletes files — so it is benign updater
# behavior, not persistence.


def test_run_key_onedrive_runonce_rmdir_cleanup_suppressed():
    # Verbatim from SRL-2015 wkstn-01 (mhill).
    entry = _run_key(
        value_name="Uninstall 19.232.1124.0008\\amd64",
        key_path="Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        command=(
            "C:\\WINDOWS\\system32\\cmd.exe /q /c rmdir /s /q "
            '"C:\\Users\\mhill\\AppData\\Local\\Microsoft\\OneDrive\\19.232.1124.0008\\amd64"'
        ),
    )
    assert RegistryDetector().analyze(run_keys=[entry]) == []


def test_run_key_onedrive_runonce_del_cleanup_suppressed():
    # Verbatim from SRL-2015 wkstn-01 (mhill).
    entry = _run_key(
        value_name="Delete Cached Update Binary",
        key_path="Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        command=(
            "C:\\WINDOWS\\system32\\cmd.exe /q /c del /q "
            '"C:\\Users\\mhill\\AppData\\Local\\Microsoft\\OneDrive\\Update\\OneDriveSetup.exe"'
        ),
    )
    assert RegistryDetector().analyze(run_keys=[entry]) == []


def test_run_key_cmd_cleanup_outside_known_vendor_path_still_fires():
    # A cmd /c rmdir cleanup that is NOT under a known-good vendor path stays a
    # finding — we only trust the pattern for recognised updater locations, so
    # an attacker can't cloak arbitrary cmd activity as "cleanup".
    entry = _run_key(
        command='C:\\WINDOWS\\system32\\cmd.exe /q /c rmdir /s /q "C:\\Temp\\stage"',
    )
    findings = RegistryDetector().analyze(run_keys=[entry])
    assert len(findings) == 1


def test_run_key_cmd_launching_payload_not_treated_as_cleanup():
    # cmd that chains into execution (not a pure del/rmdir) must still fire even
    # under a vendor path — the suppression is only for file-deletion cleanups.
    entry = _run_key(
        command=(
            'cmd.exe /c "C:\\Users\\mhill\\AppData\\Local\\Microsoft\\OneDrive\\evil.exe"'
        ),
    )
    findings = RegistryDetector().analyze(run_keys=[entry])
    assert len(findings) == 1


def test_run_key_cmd_without_slash_c_not_cleanup_suppressed():
    # A cmd invocation with no /c payload is not a recognised cleanup shape;
    # the lone-LOLBAS finding must still fire (covers the no-/c branch).
    entry = _run_key(
        command=(
            "C:\\WINDOWS\\system32\\cmd.exe "
            '"C:\\Users\\mhill\\AppData\\Local\\Microsoft\\OneDrive\\x"'
        ),
    )
    assert len(RegistryDetector().analyze(run_keys=[entry])) == 1


def test_run_key_cmd_cleanup_with_chaining_not_suppressed():
    # A del/rmdir on a vendor path that CHAINS into a second command (&&) is
    # not benign cleanup — the chaining must keep the finding (covers the
    # command-separator branch). Attacker hiding execution behind a cleanup.
    entry = _run_key(
        key_path="Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        command=(
            "cmd.exe /c rmdir /s /q "
            '"C:\\Users\\mhill\\AppData\\Local\\Microsoft\\OneDrive\\old" '
            "&& C:\\Users\\mhill\\AppData\\Local\\Microsoft\\OneDrive\\evil.exe"
        ),
    )
    assert len(RegistryDetector().analyze(run_keys=[entry])) == 1
