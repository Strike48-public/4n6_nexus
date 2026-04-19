"""Phase 5: turn extracted artifacts into CSVs consumable by the engine.

Runs three parsers:

1. MFTECmd (EZ Tools, .NET 9 via DOTNET_ROLL_FORWARD=LatestMajor).
2. pyscca (libscca Python bindings) for Prefetch - PECmd refuses on Linux
   because it requires Windows-only decompression libs.
3. `sift_find_evil.parsers.evt_parser.EvtParser` for legacy XP `.Evt`
   files, which EvtxECmd does not understand.

The three CSVs land under `analysis/m57-jean/csv/` and
use column names compatible with EvtxECmd / MFTECmd / PECmd so the engine
does not need special-casing.
"""

from __future__ import annotations

import csv
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from sift_find_evil.parsers.evt_parser import EvtParser

CASE_ROOT = Path("analysis/m57-jean")
EXTRACT = CASE_ROOT / "extracted"
CSV_OUT = CASE_ROOT / "csv"
LOGS = CASE_ROOT / "logs"

MFTECMD_DLL = Path.home() / "tools/ezt/MFTECmd/MFTECmd.dll"


def run_mftecmd() -> None:
    """Run MFTECmd to parse the $MFT and generate MFT.csv."""
    if not MFTECMD_DLL.exists():
        raise FileNotFoundError(f"MFTECmd.dll not found at {MFTECMD_DLL}")
    LOGS.mkdir(parents=True, exist_ok=True)
    CSV_OUT.mkdir(parents=True, exist_ok=True)

    mft_in = EXTRACT / "ntfs/$MFT"
    if not mft_in.exists():
        raise FileNotFoundError(f"$MFT missing at {mft_in}")

    env = {**os.environ, "DOTNET_ROLL_FORWARD": "LatestMajor"}
    cmd = [
        "dotnet",
        str(MFTECMD_DLL),
        "-f",
        str(mft_in),
        "--csv",
        str(CSV_OUT),
        "--csvf",
        "MFT.csv",
    ]
    with (LOGS / "mftecmd.log").open("w") as log:
        subprocess.run(cmd, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    print(f"MFTECmd: wrote {CSV_OUT / 'MFT.csv'}")


def run_pyscca() -> None:
    """Run pyscca to parse Prefetch files and generate Prefetch.csv."""
    import pyscca  # local import: libscca-python is optional

    pf_dir = EXTRACT / "prefetch"
    if not pf_dir.exists():
        raise FileNotFoundError(f"Prefetch dir missing at {pf_dir}")

    CSV_OUT.mkdir(parents=True, exist_ok=True)
    out = CSV_OUT / "Prefetch.csv"

    cols = [
        "ExecutableName",
        "Hash",
        "RunCount",
        "LastRun",
        "LastRun-1",
        "LastRun-2",
        "LastRun-3",
        "LastRun-4",
        "LastRun-5",
        "LastRun-6",
        "LastRun-7",
        "SourceFilename",
        "SourceCreated",
        "SourceModified",
        "FileSize",
        "VolumeCount",
        "FileMetricCount",
    ]
    rows: list[list[object]] = []
    for pf in sorted(pf_dir.glob("*.pf")):
        try:
            s = pyscca.file()
            s.open(str(pf))
        except Exception as exc:
            print(f"  skip {pf.name}: {exc}")
            continue

        runs: list[str] = []
        for i in range(8):
            try:
                t = s.get_last_run_time(i)
                runs.append(t.replace(tzinfo=timezone.utc).isoformat() if t else "")
            except Exception:
                runs.append("")

        stat = pf.stat()
        rows.append(
            [
                s.executable_filename or "",
                f"{s.prefetch_hash:08X}" if s.prefetch_hash else "",
                s.run_count,
                *runs,
                pf.name,
                datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
                datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                stat.st_size,
                s.number_of_volumes,
                s.number_of_file_metrics_entries,
            ]
        )
        s.close()

    with out.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        w.writerows(rows)
    print(f"pyscca:  wrote {out} ({len(rows)} rows)")


def run_evt() -> None:
    """Run EvtParser to parse legacy .Evt files and generate EventLog.csv."""
    evt_dir = EXTRACT / "evtlog"
    if not evt_dir.exists():
        raise FileNotFoundError(f"evtlog dir missing at {evt_dir}")

    CSV_OUT.mkdir(parents=True, exist_ok=True)
    out = CSV_OUT / "EventLog.csv"

    parser = EvtParser()
    all_entries = []
    for name in ("SecEvent.Evt", "AppEvent.Evt", "SysEvent.Evt"):
        path = evt_dir / name
        entries = parser.parse_file(path)
        all_entries.extend(entries)
        print(f"  {name}: {len(entries)} entries")

    all_entries.sort(key=lambda e: e.time_created)

    cols = [
        "TimeCreated",
        "EventId",
        "RecordId",
        "Computer",
        "Channel",
        "Level",
        "UserId",
        "PayloadData1",
        "PayloadData2",
        "PayloadData3",
        "PayloadData4",
        "PayloadData5",
        "PayloadData6",
        "MapDescription",
    ]
    with out.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for e in all_entries:
            w.writerow(
                [
                    e.time_created.isoformat(),
                    e.event_id,
                    e.record_id,
                    e.computer,
                    e.channel,
                    e.level,
                    e.user_id or "",
                    e.payload_data1 or "",
                    e.payload_data2 or "",
                    e.payload_data3 or "",
                    e.payload_data4 or "",
                    e.payload_data5 or "",
                    e.payload_data6 or "",
                    e.map_description or "",
                ]
            )
    print(f"EvtParser: wrote {out} ({len(all_entries)} rows)")


def main() -> int:
    """Run all parsers to generate CSVs from extracted artifacts.

    Returns:
        Exit code (0 = success).
    """
    run_mftecmd()
    run_pyscca()
    run_evt()
    return 0


if __name__ == "__main__":
    sys.exit(main())
