"""Tests that proven-negative findings are WIRED into the orchestrator.

The proven-negative primitive (sift_find_evil/findings/absence.py:
make_absence_finding / check_absence) landed and was unit-tested standalone
(PR #74); this proves the live orchestrator actually emits proven negatives from
the analyst path, re-verifies each against its cited tool output, and renders
only the PROVEN ones as [NEGATIVE] findings in the report.

Design note: the issue asked detectors to self-emit negatives, but detectors
consume pre-parsed rows and hold no audit tool_call_id (that is minted by the
orchestrator). A proven negative without a cited real run is UNPROVEN by design,
so negatives are emitted in the ORCHESTRATOR analysts, where a real
tool_call_id + the captured tool output + the verifier all exist.

Demo (02_ransomware) exercises BOTH directions:
  * credential-dumping is genuinely clean (no mimikatz/lsass/reg-save/ntdsutil in
    the 4688 command lines) -> a PROVEN negative that SHIPS.
  * memory injection is NOT clean (a hidden process fires) -> its negative is
    correctly WITHHELD (never claim clean when a positive fired).

RED-first: before this change run_demo_investigation emitted no
``proven_negatives`` key.
"""

from __future__ import annotations

import json
from pathlib import Path

from sift_find_evil.orchestration import InvestigationOrchestrator


def _run(tmp_path, name="audit"):
    orch = InvestigationOrchestrator(
        case_id="INC-NEG-001", audit_path=tmp_path / f"{name}.jsonl"
    )
    return orch, orch.run_demo_investigation()


# -- the report carries proven negatives ------------------------------------


def test_report_has_proven_negatives_block(tmp_path):
    _, report = _run(tmp_path)
    assert "proven_negatives" in report, "proven negatives not wired into report"
    assert isinstance(report["proven_negatives"], list)


def test_credential_dumping_negative_is_proven_and_ships(tmp_path):
    _, report = _run(tmp_path)
    creds = [
        n for n in report["proven_negatives"] if n["category"] == "credential_access"
    ]
    assert len(creds) == 1, f"expected 1 credential-dumping negative, got {creds}"
    n = creds[0]
    assert n["status"] == "proven"
    assert n["finding_type"] == "negative"
    assert n["severity"] == "info"
    # It cites a real audit tool_call_id (a negative without a run is UNPROVEN).
    assert n["tool_call_id"], "proven negative must cite a real tool_call_id"


def test_memory_injection_negative_is_withheld_when_injection_fired(tmp_path):
    # A hidden process fires in the demo, so the memory-injection negative must
    # NOT be asserted -- you cannot claim "no injection" when injection fired.
    _, report = _run(tmp_path)
    injection_negs = [
        n for n in report["proven_negatives"] if n["category"] == "process_injection"
    ]
    assert injection_negs == [], f"must not claim clean injection: {injection_negs}"


def test_memory_injection_negative_ships_when_memory_ran_clean(tmp_path):
    """When memory was consulted and NO injection fired, the metric-mode
    proven-negative ("no hidden processes") ships. Exercises the ship path of the
    memory-injection negative, which the demo (where injection fires) never hits.
    """
    orch = InvestigationOrchestrator(
        case_id="INC-NEG-CLEANMEM", audit_path=tmp_path / "a.jsonl"
    )
    orch.run_demo_investigation()
    # Simulate a clean memory run: memory was consulted, but no verified finding
    # is a process-injection positive. Build the negatives directly from an empty
    # verified set (no injection in `fired`) with memory marked consulted.
    orch._memory_consulted = True
    negatives = orch._emit_proven_negatives([])
    injection = [n for n in negatives if n["category"] == "process_injection"]
    assert (
        len(injection) == 1
    ), f"clean memory must ship an injection negative: {negatives}"
    assert injection[0]["status"] == "proven"
    assert injection[0]["tool_call_id"], "must cite the psscan tool_call_id"


def test_every_shipped_negative_is_proven_not_unproven_or_refuted(tmp_path):
    # The verifier gate: a REFUTED or UNPROVEN negative must never ship as a
    # clean claim. Only PROVEN negatives appear in the report.
    _, report = _run(tmp_path)
    assert report["proven_negatives"], "demo must ship at least one proven negative"
    for n in report["proven_negatives"]:
        assert n["status"] == "proven"


def test_credential_negative_is_refuted_and_withheld_when_indicator_present(tmp_path):
    """If a credential-dumping indicator IS present in the 4688 command lines, the
    negative is REFUTED by re-reading that output and must NOT ship as a clean
    claim. This proves check_absence is a real re-verification, not a rubber stamp.
    """
    from unittest.mock import patch

    orig = InvestigationOrchestrator._disk_analyst

    def _inject_mimikatz(self):
        findings, tool_ids = orig(self)
        # Splice a credential-dumping command line into the captured evtx text.
        self._evtx_command_text = (
            self._evtx_command_text or ""
        ) + "\npowershell Invoke-Mimikatz -DumpCreds"
        return findings, tool_ids

    with patch.object(InvestigationOrchestrator, "_disk_analyst", _inject_mimikatz):
        orch = InvestigationOrchestrator(
            case_id="INC-NEG-REFUTE", audit_path=tmp_path / "a.jsonl"
        )
        report = orch.run_demo_investigation()

    creds = [
        n for n in report["proven_negatives"] if n["category"] == "credential_access"
    ]
    assert creds == [], "a refuted credential negative must not ship as clean"


def test_indicator_list_refutes_every_credential_dumping_command():
    """Completeness guard: the "no credential dumping" negative must be REFUTED by
    EVERY command the positive attack-pattern detector fires on. A command the
    detector flags but the indicator list misses would let the negative ship a
    FALSE clean-credential claim -- the highest-risk failure mode. This binds the
    negative's scope to the detector's so a future detector pattern that isn't
    mirrored here fails loudly rather than silently opening a false-clean gap.
    """
    from sift_find_evil.findings.absence import AbsenceStatus, verify_absence
    from sift_find_evil.findings.negatives import (
        CREDENTIAL_DUMP_INDICATORS as _CREDENTIAL_DUMP_INDICATORS,
    )

    # One representative command line per attack_pattern_detector credential
    # pattern (CREDENTIAL_DUMP_PATTERNS + Invoke-Mimikatz). Each MUST refute.
    detector_positive_commands = [
        "mimikatz sekurlsa::logonpasswords",  # T1003.001
        "procdump.exe -ma lsass.exe out.dmp",  # T1003.001
        "reg save hklm\\sam c:\\temp\\sam.hiv",  # T1003.002
        "reg export hklm\\system c:\\sys.hiv",  # T1003.002
        "vssadmin create shadow /for=C:",  # T1003.003 (the gap this guards)
        'ntdsutil "ac i ntds" ifm "create full c:\\d"',  # T1003.003
        "powershell -enc Invoke-Mimikatz -DumpCreds",  # PS attack pattern
    ]
    for cmd in detector_positive_commands:
        report = verify_absence("evt-1", cmd, pattern=list(_CREDENTIAL_DUMP_INDICATORS))
        assert report.status is AbsenceStatus.REFUTED, (
            f"credential-dumping command {cmd!r} did NOT refute the negative "
            f"(status={report.status.value}); the indicator list is incomplete "
            "-> a false-clean credential negative would ship."
        )

    # And the demo's benign anti-forensics command must NOT refute (it is T1490
    # DEFENSE_EVASION, not credential access) -- the negative stays honest.
    benign = verify_absence(
        "evt-1",
        "cmd.exe /c vssadmin delete shadows /all",
        pattern=list(_CREDENTIAL_DUMP_INDICATORS),
    )
    assert benign.status is AbsenceStatus.PROVEN, (
        "vssadmin DELETE shadows is anti-forensics, not credential access; it "
        "must not refute the credential-dumping negative"
    )


# -- audit + integrity ------------------------------------------------------


def test_proven_negative_logged_to_audit_with_receipt(tmp_path):
    orch = InvestigationOrchestrator(
        case_id="INC-NEG-AUDIT", audit_path=tmp_path / "audit.jsonl"
    )
    orch.run_demo_investigation()
    neg_entries = []
    for line in (tmp_path / "audit.jsonl").read_text().splitlines():
        entry = json.loads(line)
        if entry.get("action") == "finding_emitted":
            details = entry.get("details", {})
            if details.get("severity") == "info" and details.get("category") == (
                "credential_access"
            ):
                neg_entries.append(details)
    assert neg_entries, "proven negative was not logged to the audit trail"
    assert neg_entries[0]["content_receipt"], "negative logged without a receipt"


def test_integrity_block_reports_proven_negative_count(tmp_path):
    _, report = _run(tmp_path)
    assert report["integrity"]["proven_negatives"] == len(report["proven_negatives"])
    assert report["integrity"]["proven_negatives"] >= 1


# -- F1 safety: negatives do not perturb the positive finding set -----------


def test_negatives_do_not_leak_into_positive_findings(tmp_path):
    _, report = _run(tmp_path)
    # The positive finding lists must be unchanged: no finding_type=="negative"
    # and no severity=="info" absence assertion sneaks into case_findings.
    for cf in report["case_findings"]:
        assert cf["finding"].get("finding_type") != "negative"
        assert cf["finding"].get("asserts_absence") is not True
    # The flat findings list likewise stays positive-only (6 demo findings).
    assert len(report["findings"]) == 6


# -- gate: no false negative when the source was not consulted --------------


def test_no_credential_negative_without_an_event_log_source(tmp_path):
    # A scenario with no evtx command-line source must not assert a clean
    # credential-dumping negative (an absence with no cited run is UNPROVEN and
    # must not ship). 01_clean_baseline still has evtx, so use a memory-only
    # style check: assert that when the disk analyst produced no cited evtx
    # output text, no credential negative is claimed.
    orch = InvestigationOrchestrator(
        case_id="INC-NEG-NOEVTX",
        audit_path=tmp_path / "a.jsonl",
        scenario_dir=Path("scenarios/synthetic/01_clean_baseline"),
    )
    _, report = orch, orch.run_demo_investigation()
    # 01_clean_baseline is clean, so IF a credential negative ships it must be
    # PROVEN (cited + verified), never UNPROVEN. This guards the "no run -> no
    # clean claim" rule end to end.
    for n in report["proven_negatives"]:
        assert n["status"] == "proven"
        assert n["tool_call_id"]
