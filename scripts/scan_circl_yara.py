#!/usr/bin/env python3
"""YARA triage pass over the CIRCL carved executables.

Runs sift_find_evil's YaraDetector (seed rules) against every file under
analysis/circl-2023-wiped/carved_executables/, captures per-file matches,
total runtime, and a family / severity breakdown, and writes a JSON
report to analysis/circl-2023-wiped/yara_scan_report.json.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path

from sift_find_evil.detectors.yara_detector import YaraDetector
from sift_find_evil.yara_scan.scanner import YaraScanner


REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules" / "yara" / "seed"
SCAN_DIR = REPO_ROOT / "analysis" / "circl-2023-wiped" / "carved_executables"
REPORT_PATH = REPO_ROOT / "analysis" / "circl-2023-wiped" / "yara_scan_report.json"


def main() -> None:
    if not SCAN_DIR.is_dir():
        raise SystemExit(f"scan directory not found: {SCAN_DIR}")
    if not RULES_DIR.is_dir():
        raise SystemExit(f"rules directory not found: {RULES_DIR}")

    files = sorted(p for p in SCAN_DIR.iterdir() if p.is_file())
    if not files:
        raise SystemExit(f"no files under {SCAN_DIR}")

    compile_start = time.perf_counter()
    scanner = YaraScanner.compile_from_directory(RULES_DIR)
    compile_elapsed = time.perf_counter() - compile_start

    detector = YaraDetector(scanner=scanner)

    per_file: list[dict] = []
    family_counter: Counter[str] = Counter()
    severity_counter: Counter[str] = Counter()
    rule_counter: Counter[str] = Counter()
    total_bytes = 0

    scan_start = time.perf_counter()
    for path in files:
        size = path.stat().st_size
        total_bytes += size
        file_start = time.perf_counter()
        findings = detector.analyze_file(path)
        file_elapsed = time.perf_counter() - file_start

        matches = []
        for finding in findings:
            evidence = finding.evidence
            rule = evidence.get("rule", "")
            family = evidence.get("family") or "unknown"
            severity = evidence.get("rule_meta", {}).get("severity", "unspecified")
            rule_counter[rule] += 1
            family_counter[family] += 1
            severity_counter[severity] += 1
            matches.append(
                {
                    "rule": rule,
                    "namespace": evidence.get("namespace"),
                    "severity": severity,
                    "family": family,
                    "confidence": finding.confidence,
                    "match_count": evidence.get("match_count", 0),
                    "mitre_attack": evidence.get("mitre_attack", []),
                }
            )

        per_file.append(
            {
                "filename": path.name,
                "size_bytes": size,
                "elapsed_ms": round(file_elapsed * 1000, 2),
                "match_count": len(findings),
                "matches": matches,
            }
        )
    scan_elapsed = time.perf_counter() - scan_start

    report = {
        "rules_dir": str(RULES_DIR.relative_to(REPO_ROOT)),
        "scan_dir": str(SCAN_DIR.relative_to(REPO_ROOT)),
        "rule_count_compiled": scanner.rule_count,
        "rule_compile_errors": len(scanner.compile_errors),
        "compile_elapsed_sec": round(compile_elapsed, 3),
        "scan_elapsed_sec": round(scan_elapsed, 3),
        "files_scanned": len(files),
        "total_bytes_scanned": total_bytes,
        "throughput_mb_per_sec": (
            round((total_bytes / (1024 * 1024)) / scan_elapsed, 2)
            if scan_elapsed > 0
            else None
        ),
        "total_matches": sum(f["match_count"] for f in per_file),
        "files_with_matches": sum(1 for f in per_file if f["match_count"]),
        "rule_breakdown": dict(rule_counter.most_common()),
        "family_breakdown": dict(family_counter.most_common()),
        "severity_breakdown": dict(severity_counter.most_common()),
        "per_file": per_file,
    }

    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"Compiled {scanner.rule_count} rule(s) in {compile_elapsed * 1000:.1f} ms")
    print(
        f"Scanned {len(files)} file(s) ({total_bytes / (1024 * 1024):.1f} MiB) "
        f"in {scan_elapsed:.2f} s → "
        f"{report['throughput_mb_per_sec']} MiB/s"
    )
    print(
        f"{report['files_with_matches']}/{len(files)} file(s) matched "
        f"({report['total_matches']} total matches)"
    )
    if rule_counter:
        print("Top rules:")
        for rule, count in rule_counter.most_common(5):
            print(f"  {rule}: {count}")
    print(f"\nReport → {REPORT_PATH}")


if __name__ == "__main__":
    main()
