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


def _amcache(path: str, sha1: str = "a" * 40) -> AmcacheEntry:
    return AmcacheEntry(
        file_path=path,
        first_execution=_TS,
        sha1_hash=sha1,
        file_size=1024,
        publisher=None,
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
        command='powershell.exe -w hidden -encodedcommand ABCDEFG==',
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
        command='powershell.exe -NoProfile -WindowStyle hidden -ExecutionPolicy Bypass -EncodedCommand AAAA'
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
    assert detector.analyze(shimcache=[], amcache=[], bam=[], userassist=[], run_keys=[]) == []


def test_full_pipeline_produces_mixed_findings():
    findings = RegistryDetector().analyze(
        run_keys=[
            _run_key(command='powershell.exe -nop -w hidden -enc AAAA'),
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
