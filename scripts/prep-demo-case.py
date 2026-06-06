#!/usr/bin/env python3
"""Stage a multi-finding demo case so the report shows BOTH Mermaid diagrams.

The CIRCL case has a single finding, so its report only carries the A2A sequence
diagram. This script runs the reproducible multi-agent orchestration (6 findings:
5 self-corrected, 1 held) and writes a proper case so `cli report` produces the
full visual report — the A2A sequence AND the colour-coded finding-flow.

Run on the SIFT VM (or anywhere the orchestration runs). The case must exist
first (created via `cli case init`); this script fills it with the multi-agent
findings + audit log, then you generate the report:

    python -m sift_find_evil.cli case init --case-id DEMO-MULTI \
        --name "Multi-Agent Investigation" --examiner "Jonathan Tomek" \
        --case-root ~/demo_cases
    PYTHONPATH=. python3 scripts/prep-demo-case.py --case-id DEMO-MULTI \
        --case-root ~/demo_cases
    python -m sift_find_evil.cli report --case-id DEMO-MULTI \
        --output ~/demo_cases/DEMO-MULTI/report.md --format markdown \
        --all-findings --case-root ~/demo_cases

Idempotent: re-running overwrites the case's findings + audit log. Using the real
`cli case init` (rather than hand-writing CASE.yaml) keeps the case metadata in
exactly the format CaseManager expects.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sift_find_evil.orchestration import InvestigationOrchestrator


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-id", default="DEMO-MULTI")
    parser.add_argument("--case-root", default="./demo_cases")
    parser.add_argument("--examiner", default="Jonathan Tomek")
    args = parser.parse_args()

    case_root = Path(args.case_root).expanduser()
    case_dir = case_root / args.case_id
    if not (case_dir / "CASE.yaml").is_file():
        print(
            f"ERROR: case '{args.case_id}' not found at {case_dir}. "
            f"Run `cli case init --case-id {args.case_id} --case-root {case_root}` "
            "first."
        )
        return 1
    audit_path = case_dir / "audit.jsonl"

    # Run the reproducible investigation; its audit log lands in the case dir so
    # the report's A2A sequence diagram is reconstructed from this exact run.
    orch = InvestigationOrchestrator(
        case_id=args.case_id, audit_path=audit_path, examiner=args.examiner
    )
    report = orch.run_demo_investigation(include_bypass_attempt=False)

    # Write the rich, case-shaped findings (FindingWithApproval) the report reads.
    findings_path = case_dir / "findings.json"
    findings_path.write_text(
        json.dumps({"findings": report["case_findings"]}, indent=2)
    )

    print(f"Staged demo case '{args.case_id}' at {case_dir}")
    print(f"  findings: {len(report['case_findings'])}  (A2A audit: {audit_path})")
    print("Generate the report with:")
    print(
        f"  python -m sift_find_evil.cli report --case-id {args.case_id} "
        f"--output {case_dir / 'report.md'} --format markdown --all-findings "
        f"--case-root {case_root}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
