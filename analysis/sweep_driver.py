#!/usr/bin/env python3
"""Real-evidence FP-sweep driver (SFE-07g).

Given a forensic disk image (.E01), this:
  1. Opens it in-process with pyewf + pytsk3 — NO mount, NO sudo, CI-friendly.
  2. Auto-detects the Windows NTFS partition (largest data partition).
  3. Extracts $MFT (and optionally registry hives / event logs) to a scratch dir.
  4. Runs mftecmd to produce the CSV the detectors consume.
  5. Runs the behavioral detectors and reports findings for FP audit.

This generalizes scripts/extract_jean_artifacts.py (which hardcoded the NTFS
offset) so it works across the untriaged corpus on TESLADRIVE.

Output goes under analysis/sweep/<image_stem>/ per the project output-routing
rule. Evidence images are opened read-only and never modified.

Usage:
    PYTHONPATH=. python3 analysis/sweep_driver.py <image.E01> [--out DIR]
        [--mftecmd PATH] [--max-mb N]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pyewf
import pytsk3

_SECTOR = 512
# Skip partitions smaller than this many sectors when hunting the OS volume —
# the GPT/EFI/MSR partitions are tiny next to the multi-GB Windows volume.
_MIN_PARTITION_SECTORS = 100_000


class _EwfImg(pytsk3.Img_Info):
    """Adapter wrapping a pyewf handle so pytsk3 can read the E01 directly."""

    def __init__(self, ewf_handle) -> None:
        self._ewf = ewf_handle
        self._size = ewf_handle.get_media_size()
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def read(self, offset: int, size: int) -> bytes:
        self._ewf.seek(offset)
        return self._ewf.read(size)

    def get_size(self) -> int:
        return self._size

    def close(self) -> None:  # pragma: no cover - pytsk3 compatibility stub
        pass


@dataclass(frozen=True)
class WindowsVolume:
    """The detected Windows NTFS volume within a disk image."""

    start_sector: int
    length_sectors: int
    description: str


def open_image(image_path: Path) -> _EwfImg:
    """Open an E01 (or split E01 set) as a pytsk3 image, in-process."""
    segments = pyewf.glob(str(image_path))
    handle = pyewf.handle()
    handle.open(segments)
    return _EwfImg(handle)


def detect_windows_volume(img: _EwfImg) -> WindowsVolume | None:
    """Return the largest data partition, or None if the image has no volume
    table (a single-partition / bare-filesystem acquisition — the NTFS volume
    then starts at offset 0)."""
    try:
        volume = pytsk3.Volume_Info(img)
    except OSError:
        # No partition table: the image is the filesystem itself.
        return None
    candidates = [
        WindowsVolume(p.start, p.len, p.desc.decode(errors="replace"))
        for p in volume
        if p.len >= _MIN_PARTITION_SECTORS
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda v: v.length_sectors)


def open_ntfs(img: _EwfImg, volume: WindowsVolume | None) -> pytsk3.FS_Info:
    offset = 0 if volume is None else volume.start_sector * _SECTOR
    return pytsk3.FS_Info(img, offset=offset)


def extract_file(fs: pytsk3.FS_Info, src: str, dst: Path, *, max_mb: int) -> bool:
    """Stream one file out of the NTFS volume to dst. Returns True on success."""
    try:
        entry = fs.open(src)
    except Exception as exc:  # noqa: BLE001 - report and continue the sweep
        print(f"    [skip] {src}: {exc}")
        return False
    if entry.info.meta is None:
        print(f"    [skip] {src}: no metadata")
        return False
    size = entry.info.meta.size
    if size > max_mb * 1024 * 1024:
        print(f"    [skip] {src}: {size / 1024**2:.0f} MB exceeds --max-mb {max_mb}")
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    offset = 0
    chunk = 1024 * 1024
    with dst.open("wb") as out:
        while offset < size:
            available = min(chunk, size - offset)
            data = entry.read_random(offset, available)
            if not data:
                break
            out.write(data)
            offset += len(data)
    print(f"    [ok]   {src} -> {dst.name} ({size / 1024**2:.1f} MB)")
    return True


def run_mftecmd(mft_path: Path, out_dir: Path, mftecmd: str) -> Path | None:
    """Run mftecmd on an extracted $MFT, returning the CSV path on success."""
    csv_dir = out_dir / "csv"
    csv_dir.mkdir(parents=True, exist_ok=True)
    cmd = [mftecmd, "-f", str(mft_path), "--csv", str(csv_dir), "--csvf", "mft.csv"]
    print(f"  running mftecmd: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    if result.returncode != 0:
        print(f"  mftecmd failed (exit {result.returncode}): {result.stderr[-300:]}")
        return None
    csv_path = csv_dir / "mft.csv"
    return csv_path if csv_path.is_file() else None


def run_detectors(mft_csv: Path) -> list:
    """Run MFT-driven detection and return findings.

    The $SI/$FN timestomping check lives in SelfCorrectionEngine.detect_all,
    which tolerates empty prefetch/event-log streams — so an MFT-only sweep
    still surfaces timeline-tampering findings (the FP-relevant signal for a
    disk-only image).
    """
    from sift_find_evil.parsers.mft_parser import MFTParser
    from sift_find_evil.self_correction.engine import SelfCorrectionEngine

    entries = MFTParser().parse_csv(mft_csv)
    print(f"  parsed {len(entries)} MFT entries")
    return SelfCorrectionEngine().analyze(entries, [], [])


# -- registry Run-key extraction (HKLM SOFTWARE + per-user NTUSER) ----------
#
# Run/RunOnce keys are the canonical autostart-persistence surface and the
# most FP-prone in an enterprise image (legitimate updaters, AV, vendor
# agents all live here). We pull them straight from the hives with
# python-registry — no RECmd, no mount — into the RunKeyEntry CSV the
# RegistryDetector consumes.

_RUN_KEY_PATHS_HKLM = (
    "Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
)
_RUN_KEY_PATHS_HKCU = (
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
)


def _iter_run_values(hive, subpaths):
    """Yield (key_path, value_name, command, last_write) for each Run value."""
    from Registry.Registry import RegistryKeyNotFoundException

    for subpath in subpaths:
        try:
            key = hive.open(subpath)
        except RegistryKeyNotFoundException:
            continue
        for value in key.values():
            command = value.value()
            if not isinstance(command, str) or not command.strip():
                continue
            yield subpath, value.name(), command, key.timestamp()


def extract_run_keys(fs: pytsk3.FS_Info, out_dir: Path, *, max_mb: int) -> Path | None:
    """Extract Run-key hives and write the RegistryDetector CSV. Returns path."""
    from Registry.Registry import Registry

    hive_dir = out_dir / "extracted" / "hives"
    rows: list[tuple[str, str, str, str, str]] = []

    # HKLM SOFTWARE
    software_dst = hive_dir / "SOFTWARE"
    if extract_file(
        fs, "/Windows/System32/config/SOFTWARE", software_dst, max_mb=max_mb
    ):
        try:
            reg = Registry(str(software_dst))
            for kp, name, cmd, ts in _iter_run_values(reg, _RUN_KEY_PATHS_HKLM):
                rows.append((kp, name, cmd, "HKLM", ts.isoformat()))
        except Exception as exc:  # noqa: BLE001
            print(f"    [warn] SOFTWARE hive parse failed: {exc}")

    # Per-user NTUSER.DAT (HKCU) — walk /Users/<name>/NTUSER.DAT
    for users_root in ("/Users", "/Documents and Settings"):
        try:
            root = fs.open_dir(users_root)
        except Exception:  # noqa: BLE001
            continue
        for entry in root:
            name = entry.info.name.name.decode(errors="replace")
            if name in (".", "..") or entry.info.meta is None:
                continue
            src = f"{users_root}/{name}/NTUSER.DAT"
            user_dst = hive_dir / f"NTUSER_{name}.DAT"
            if not extract_file(fs, src, user_dst, max_mb=max_mb):
                continue
            try:
                reg = Registry(str(user_dst))
                for kp, vname, cmd, ts in _iter_run_values(reg, _RUN_KEY_PATHS_HKCU):
                    # hive must be exactly HKCU (RunKeyEntry validates it);
                    # fold the owning user into key_path for attribution.
                    rows.append(
                        (f"{name}\\{kp}", vname, cmd, "HKCU", ts.isoformat())
                    )
            except Exception as exc:  # noqa: BLE001
                print(f"    [warn] NTUSER ({name}) parse failed: {exc}")

    csv_dir = out_dir / "csv"
    csv_dir.mkdir(parents=True, exist_ok=True)
    csv_path = csv_dir / "run_keys.csv"
    import csv as _csv

    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = _csv.writer(fh)
        writer.writerow(
            ["key_path", "value_name", "command", "hive", "last_write_time"]
        )
        writer.writerows(rows)
    print(f"  extracted {len(rows)} Run-key value(s) -> {csv_path.name}")
    return csv_path if rows else None


def run_registry_detector(run_keys_csv: Path) -> list:
    """Parse the Run-key CSV and run the RegistryDetector."""
    from sift_find_evil.parsers.registry_parser import RegistryParser
    from sift_find_evil.detectors.registry_detector import RegistryDetector

    entries = RegistryParser().parse_run_keys_csv(run_keys_csv)
    return RegistryDetector().analyze(run_keys=entries)


def main() -> int:
    parser = argparse.ArgumentParser(description="Real-evidence FP-sweep driver")
    parser.add_argument("image", type=Path, help="Path to .E01 disk image")
    parser.add_argument("--out", type=Path, default=None, help="Output directory")
    parser.add_argument("--mftecmd", default="mftecmd", help="mftecmd executable")
    parser.add_argument("--max-mb", type=int, default=512, help="Per-file size cap")
    parser.add_argument(
        "--no-registry", action="store_true", help="Skip Run-key extraction"
    )
    args = parser.parse_args()

    if not args.image.is_file():
        print(f"error: image not found: {args.image}", file=sys.stderr)
        return 1

    out_dir = args.out or (Path("analysis/sweep") / args.image.stem)
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"== sweep: {args.image.name} -> {out_dir} ==")

    img = open_image(args.image)
    print(f"  media size: {img.get_size() / 1024**3:.2f} GB")
    volume = detect_windows_volume(img)
    if volume is None:
        print("  no volume table; treating image as a bare NTFS filesystem (offset 0)")
    else:
        print(
            f"  windows volume: sector {volume.start_sector} "
            f"({volume.length_sectors * _SECTOR / 1024**3:.1f} GB, {volume.description})"
        )
    fs = open_ntfs(img, volume)

    mft_dst = out_dir / "extracted" / "$MFT"
    if not extract_file(fs, "/$MFT", mft_dst, max_mb=args.max_mb):
        print("  could not extract $MFT; aborting", file=sys.stderr)
        return 2

    mft_csv = run_mftecmd(mft_dst, out_dir, args.mftecmd)
    if mft_csv is None:
        print("  mftecmd produced no CSV; aborting", file=sys.stderr)
        return 3

    timestomp_findings = run_detectors(mft_csv)

    registry_findings: list = []
    if not args.no_registry:
        run_keys_csv = extract_run_keys(fs, out_dir, max_mb=args.max_mb)
        if run_keys_csv is not None:
            registry_findings = run_registry_detector(run_keys_csv)

    print(
        f"\n== {args.image.stem}: {len(timestomp_findings)} timestomping + "
        f"{len(registry_findings)} run-key finding(s) =="
    )
    for f in (*timestomp_findings, *registry_findings):
        print(f"  [{f.severity}/{f.confidence_label}] {f.title}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
