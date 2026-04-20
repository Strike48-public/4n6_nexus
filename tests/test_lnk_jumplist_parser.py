"""Tests for LnkParser and JumpListParser."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from sift_find_evil.parsers.lnk_jumplist_parser import (
    JumpListEntry,
    JumpListParser,
    LnkEntry,
    LnkParser,
)


# --- LnkEntry / JumpListEntry dataclass validation --------------------------


def test_lnk_entry_rejects_empty_lnk_path():
    with pytest.raises(ValueError):
        LnkEntry(
            lnk_path="",
            target_path="C:\\file.txt",
            target_size=None,
            target_created=None,
            target_modified=None,
            target_accessed=None,
            working_directory="",
            arguments="",
            drive_type="fixed",
            volume_serial=None,
            volume_label=None,
            machine_id=None,
            mac_address=None,
            created=None,
        )


def test_jumplist_entry_rejects_bad_entry_type():
    with pytest.raises(ValueError):
        JumpListEntry(
            app_id="abc",
            app_name="",
            entry_type="banana",
            target_path="C:\\a.docx",
            drive_type="fixed",
            opened_time=None,
            jumplist_path="/path",
        )


def test_jumplist_entry_rejects_empty_app_id():
    with pytest.raises(ValueError):
        JumpListEntry(
            app_id="",
            app_name="",
            entry_type="automatic",
            target_path="C:\\a.docx",
            drive_type="fixed",
            opened_time=None,
            jumplist_path="/path",
        )


# --- LnkParser --------------------------------------------------------------


def test_lnk_parser_roundtrips_lecmd_style_columns(tmp_path: Path):
    csv_path = tmp_path / "lnk.csv"
    csv_path.write_text(
        "SourceFile,LocalPath,FileSize,TargetCreated,TargetModified,TargetAccessed,"
        "WorkingDirectory,Arguments,DriveType,VolumeSerialNumber,VolumeLabel,"
        "MachineID,MACAddress,SourceCreated\n"
        "C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\q3.lnk,"
        "E:\\quarterly\\q3_financials.xlsx,"
        "81920,"
        "2025-03-01T09:00:00Z,2025-03-02T11:00:00Z,2025-03-03T12:00:00Z,"
        "E:\\quarterly,,"
        "Drive_Removable,"
        "ABCD-1234,EXFIL_USB,"
        "WIN-CORPDC,aa:bb:cc:dd:ee:ff,"
        "2025-03-03T12:00:05Z\n"
    )
    entries = LnkParser().parse_csv(csv_path)
    assert len(entries) == 1
    e = entries[0]
    assert e.target_path == "E:\\quarterly\\q3_financials.xlsx"
    assert e.target_size == 81920
    assert e.drive_type == "removable"
    assert e.volume_serial == "ABCD-1234"
    assert e.volume_label == "EXFIL_USB"
    assert e.machine_id == "WIN-CORPDC"
    assert e.mac_address == "aa:bb:cc:dd:ee:ff"
    assert e.target_accessed == datetime(2025, 3, 3, 12, 0, 0, tzinfo=timezone.utc)
    assert e.created == datetime(2025, 3, 3, 12, 0, 5, tzinfo=timezone.utc)


def test_lnk_parser_skips_rows_with_no_source(tmp_path: Path):
    csv_path = tmp_path / "lnk.csv"
    csv_path.write_text(
        "SourceFile,LocalPath,DriveType\n"
        ",C:\\a.txt,Fixed\n"
        "C:\\shortcut.lnk,C:\\b.txt,Fixed\n"
    )
    entries = LnkParser().parse_csv(csv_path)
    assert len(entries) == 1
    assert entries[0].lnk_path == "C:\\shortcut.lnk"


def test_lnk_parser_missing_file_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        LnkParser().parse_csv(tmp_path / "does_not_exist.csv")


def test_lnk_parser_handles_missing_optional_columns(tmp_path: Path):
    csv_path = tmp_path / "lnk.csv"
    csv_path.write_text(
        "SourceFile,LocalPath,DriveType\n"
        "C:\\shortcut.lnk,C:\\users\\alice\\docs\\plan.docx,Drive_Fixed\n"
    )
    entries = LnkParser().parse_csv(csv_path)
    assert len(entries) == 1
    e = entries[0]
    assert e.drive_type == "fixed"
    assert e.target_size is None
    assert e.volume_serial is None
    assert e.machine_id is None


def test_lnk_parser_normalizes_various_drive_type_spellings(tmp_path: Path):
    csv_path = tmp_path / "lnk.csv"
    csv_path.write_text(
        "SourceFile,LocalPath,DriveType\n"
        "C:\\a.lnk,C:\\x,Removable\n"
        "C:\\b.lnk,C:\\x,DriveRemovable\n"
        "C:\\c.lnk,C:\\x,drive-removable\n"
        "C:\\d.lnk,C:\\x,Drive_Remote\n"
        "C:\\e.lnk,C:\\x,\n"
        "C:\\f.lnk,C:\\x,wut\n"
    )
    entries = LnkParser().parse_csv(csv_path)
    types = [e.drive_type for e in entries]
    assert types == ["removable", "removable", "removable", "network", "unknown", "unknown"]


def test_lnk_parser_tolerates_bad_timestamps(tmp_path: Path):
    csv_path = tmp_path / "lnk.csv"
    csv_path.write_text(
        "SourceFile,LocalPath,TargetAccessed\n"
        "C:\\a.lnk,C:\\x,not-a-date\n"
    )
    entries = LnkParser().parse_csv(csv_path)
    assert len(entries) == 1
    assert entries[0].target_accessed is None


def test_lnk_parser_accepts_lowercase_alias_columns(tmp_path: Path):
    csv_path = tmp_path / "lnk.csv"
    csv_path.write_text(
        "lnk_path,target_path,drive_type,target_size\n"
        "/ev/recent/a.lnk,/mnt/usb/file.xlsx,removable,4096\n"
    )
    entries = LnkParser().parse_csv(csv_path)
    assert len(entries) == 1
    assert entries[0].target_size == 4096


# --- JumpListParser ---------------------------------------------------------


def test_jumplist_parser_parses_automatic_destinations(tmp_path: Path):
    csv_path = tmp_path / "jl.csv"
    csv_path.write_text(
        "SourceFile,AppId,AppIdDescription,EntryType,LocalPath,DriveType,LastModified\n"
        "/ev/automaticdest/excel.automaticDestinations-ms,"
        "9d1f905ce5044aee,Microsoft Excel,Automatic,"
        "\\\\fileserver\\share\\budget.xlsx,Network,"
        "2025-03-10T10:00:00Z\n"
    )
    entries = JumpListParser().parse_csv(csv_path)
    assert len(entries) == 1
    e = entries[0]
    assert e.entry_type == "automatic"
    assert e.drive_type == "network"
    assert e.target_path == "\\\\fileserver\\share\\budget.xlsx"
    assert e.opened_time == datetime(2025, 3, 10, 10, 0, 0, tzinfo=timezone.utc)


def test_jumplist_parser_handles_custom_entry_type(tmp_path: Path):
    csv_path = tmp_path / "jl.csv"
    csv_path.write_text(
        "SourceFile,AppId,EntryType,LocalPath\n"
        "/ev/customdest/task.customDestinations-ms,abc123,Custom,C:\\file.docx\n"
    )
    entries = JumpListParser().parse_csv(csv_path)
    assert entries[0].entry_type == "custom"


def test_jumplist_parser_defaults_missing_entry_type_to_automatic(tmp_path: Path):
    csv_path = tmp_path / "jl.csv"
    csv_path.write_text(
        "SourceFile,AppId,LocalPath\n"
        "/ev/foo.automaticDestinations-ms,abc123,C:\\file.docx\n"
    )
    entries = JumpListParser().parse_csv(csv_path)
    assert entries[0].entry_type == "automatic"


def test_jumplist_parser_synthesizes_placeholder_app_id(tmp_path: Path):
    csv_path = tmp_path / "jl.csv"
    csv_path.write_text(
        "SourceFile,AppId,LocalPath\n"
        "/ev/foo.automaticDestinations-ms,,C:\\orphan.docx\n"
    )
    entries = JumpListParser().parse_csv(csv_path)
    assert len(entries) == 1
    assert entries[0].app_id == "(unknown)"
    assert entries[0].target_path == "C:\\orphan.docx"


def test_jumplist_parser_skips_rows_with_nothing_useful(tmp_path: Path):
    csv_path = tmp_path / "jl.csv"
    csv_path.write_text(
        "SourceFile,AppId,LocalPath\n"
        "/ev/foo.automaticDestinations-ms,,\n"
        "/ev/bar.automaticDestinations-ms,real_app,C:\\a.docx\n"
    )
    entries = JumpListParser().parse_csv(csv_path)
    assert len(entries) == 1
    assert entries[0].app_id == "real_app"


def test_jumplist_parser_missing_file_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        JumpListParser().parse_csv(tmp_path / "missing.csv")


# --- Adversarial input hardening -------------------------------------------


def test_lnk_parser_strips_null_bytes_from_target_path(tmp_path: Path):
    # Regression: an adversarial CSV can embed a NUL to confuse downstream
    # path-fragment checks (Windows APIs treat NUL as string terminator).
    csv_path = tmp_path / "lnk.csv"
    csv_path.write_text(
        "SourceFile,LocalPath,DriveType\n"
        "C:\\a.lnk,C:\\evil.exe\x00C:\\legit.txt,Fixed\n"
    )
    entries = LnkParser().parse_csv(csv_path)
    assert len(entries) == 1
    assert "\x00" not in entries[0].target_path
    assert entries[0].target_path == "C:\\evil.exeC:\\legit.txt"


def test_lnk_parser_truncates_oversize_arguments(tmp_path: Path):
    # Regression: a megabyte-scale Arguments blob must be capped at parse
    # time so downstream regexes never see pathological input.
    csv_path = tmp_path / "lnk.csv"
    giant = "-e" * 50_000
    csv_path.write_text(
        "SourceFile,LocalPath,Arguments,DriveType\n"
        f"C:\\a.lnk,C:\\x.exe,{giant},Fixed\n"
    )
    entries = LnkParser().parse_csv(csv_path)
    assert len(entries) == 1
    assert len(entries[0].arguments) <= 4096
