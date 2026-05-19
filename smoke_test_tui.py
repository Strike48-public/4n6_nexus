#!/usr/bin/env python3
"""
Smoke test for TUI - verifies panels populate with live data.

Run on a synthetic scenario to check:
- Detector panel shows phase status
- Findings panel populates
- Self-correction panel tracks contradictions
- Progress panel updates
"""

import asyncio
from pathlib import Path

from sift_find_evil.progress_tracker import ProgressTracker, FindingSeverity, PhaseStatus
from sift_find_evil.analysis_runner import AnalysisRunner


async def smoke_test():
    """Run minimal analysis and verify tracker state."""
    print("=" * 60)
    print("TUI SMOKE TEST - Synthetic Scenario 02 (Ransomware)")
    print("=" * 60)

    # Setup
    tracker = ProgressTracker()
    runner = AnalysisRunner(tracker)

    # Configure for synthetic ransomware scenario
    scenario_path = Path("scenarios/synthetic/02_ransomware")
    if not scenario_path.exists():
        print(f"❌ Scenario not found: {scenario_path}")
        return False

    runner.configure(scenario_path, mode="quick")

    # Run analysis
    try:
        print(f"\n📂 Evidence path: {scenario_path}")
        print("🔄 Starting quick triage analysis...\n")

        await runner.run_analysis()

        # Verify tracker state
        print("\n" + "=" * 60)
        print("RESULTS:")
        print("=" * 60)

        # Check phases
        print(f"\n✓ Phases registered: {len(tracker.phases)}")
        for phase in tracker.phases:
            status_icon = {
                PhaseStatus.COMPLETE: "✓",
                PhaseStatus.ACTIVE: "●",
                PhaseStatus.PENDING: "○",
                PhaseStatus.ERROR: "✗",
            }[phase.status]
            print(f"  {status_icon} {phase.display_name}: {phase.status.value}")

        # Check findings
        print(f"\n✓ Findings detected: {len(tracker.findings)}")
        findings_by_severity = {}
        for finding in tracker.findings:
            sev = finding.severity.value
            findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1

        for severity, count in sorted(findings_by_severity.items()):
            print(f"  - {severity}: {count}")

        # Check contradictions
        print(f"\n✓ Contradictions resolved: {len(tracker.contradictions)}")
        for i, contradiction in enumerate(tracker.contradictions[:3], 1):
            print(f"  {i}. {contradiction.description}")

        # Check activities
        print(f"\n✓ Activities logged: {len(tracker.activities)}")
        for activity in tracker.activities[:5]:
            print(f"  - {activity.message}")

        # Success criteria
        success = True
        if len(tracker.phases) < 2:
            print("\n❌ Too few phases registered")
            success = False

        if len(tracker.findings) == 0:
            print("\n❌ No findings detected")
            success = False

        completed_phases = sum(1 for p in tracker.phases if p.status == PhaseStatus.COMPLETE)
        if completed_phases < 2:
            print(f"\n❌ Only {completed_phases} phases completed")
            success = False

        if success:
            print("\n" + "=" * 60)
            print("✅ SMOKE TEST PASSED - TUI ready for demo")
            print("=" * 60)
        else:
            print("\n" + "=" * 60)
            print("❌ SMOKE TEST FAILED - Check detector integration")
            print("=" * 60)

        return success

    except Exception as e:
        print(f"\n❌ Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    result = asyncio.run(smoke_test())
    exit(0 if result else 1)
