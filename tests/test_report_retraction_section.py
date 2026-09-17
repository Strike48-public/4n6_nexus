"""Retraction trail in the PRIMARY human report (SFE-fibx.13).

The candidate-elimination trail is produced by ``analyze --harden`` and persisted
JSON-only as ``findings.hardened.json``; the markdown report an investigator reads
(``cmd_report`` -> ``ReportGenerator._generate_markdown``) never surfaced it. These
tests pin the DATA half: the generator loads the case's hardened sibling and threads
its ``hypothesis_ledger`` into the report, rendering the already-merged
``render_retraction_section`` (SFE-fibx.1) in the human report.

Honesty invariant (the reason we load rather than recompute): the ledger is derived
from each finding's exonerating ``resolutions``, which ``Finding.from_dict`` discards
on the case round-trip -- a recompute from ``findings.json`` is ALWAYS empty. So the
section is rendered ONLY when a real ledger was loaded; a case with no hardened
sibling omits the section entirely rather than overclaiming "nothing was retracted".
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from sift_find_evil.case import CaseManager
from sift_find_evil.reporting.generator import ReportGenerator
from sift_find_evil.reporting.models import ReportFormat

_RETRACTION_HEADING = "Candidate Elimination"


def _write_findings(case_dir: Path) -> None:
    """Write a minimal approval-shaped findings.json into the case dir."""
    finding = {
        "finding_id": "F-001",
        "finding": {
            "title": "crypt_engine.exe hardcoded-IP C2",
            "description": "TCP conversation to an external IP with no DNS lookup.",
            "severity": "high",
            "confidence": 0.82,
            "category": "c2",
            "evidence": {"dst_ip": "8.8.8.8"},
        },
        "approval": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    payload = {"findings": [finding], "summary": {"total": 1}}
    (case_dir / "findings.json").write_text(json.dumps(payload), encoding="utf-8")


def _hardened_payload(correction_trail, retracted=(), self_correction_count=0) -> dict:
    """A hardened-report dict carrying just the hypothesis_ledger the report reads."""
    return {
        "finding_count": 1,
        "hypothesis_ledger": {
            "self_correction_count": self_correction_count,
            "retracted": list(retracted),
            "confirmed": [],
            "open": [],
            "correction_trail": list(correction_trail),
        },
    }


def _make_case(case_root: Path, hardened: dict | None):
    """Scaffold a case dir (CASE.yaml, findings.json) + optional hardened sibling."""
    manager = CaseManager(case_root)
    manager.create_case(
        case_id="INC-2026-013",
        name="Retraction trail report test",
        examiner="tester",
    )
    case_dir = case_root / "INC-2026-013"
    _write_findings(case_dir)
    if hardened is not None:
        (case_dir / "findings.hardened.json").write_text(
            json.dumps(hardened), encoding="utf-8"
        )
    return manager, case_dir


def _generate(tmp_path: Path, hardened: dict | None) -> str:
    manager, _ = _make_case(tmp_path / "cases", hardened)
    out = tmp_path / "report.md"
    ReportGenerator(manager).generate(
        case_id="INC-2026-013",
        output_path=out,
        format=ReportFormat.MARKDOWN,
        approved_only=False,
    )
    return out.read_text(encoding="utf-8")


def test_report_renders_retraction_trail_from_hardened_sibling(tmp_path: Path):
    """A hardened sibling with a real correction reaches the primary report."""
    corr = {
        "sequence": 1,
        "finding_id": "F-001",
        "from_verdict": "supports",
        "to_verdict": "refutes",
        "reason": "known_benign_direct_ip_infrastructure: 8.8.8.8 is a public DNS resolver",
        "trigger_exec_id": "crypt_engine.exe hardcoded-IP C2",
    }
    md = _generate(
        tmp_path,
        _hardened_payload(
            [corr],
            retracted=[{"id": "H-1", "statement": "8.8.8.8 is attacker-controlled"}],
            self_correction_count=1,
        ),
    )
    assert _RETRACTION_HEADING in md
    assert "known_benign_direct_ip_infrastructure" in md
    assert "8.8.8.8 is attacker-controlled" in md
    # Placement: the retraction section follows the findings, not before them.
    assert md.index("## Findings") < md.index(_RETRACTION_HEADING)


def test_report_renders_honest_empty_note_when_sibling_all_confirmed(tmp_path: Path):
    """Hardened sibling present but nothing retracted -> the honest empty-state note,
    which is a REPORTED result (the verifier challenged and nothing fell)."""
    md = _generate(tmp_path, _hardened_payload([], self_correction_count=0))
    assert _RETRACTION_HEADING in md
    assert "no candidate" in md.lower()


def test_report_omits_section_when_no_hardened_sibling(tmp_path: Path):
    """No hardened sibling -> NO section. An absent ledger is not the same as an
    empty trail; rendering the 'nothing retracted' note here would overclaim that
    a self-correction pass ran when it never did (claim-audit honesty)."""
    md = _generate(tmp_path, hardened=None)
    assert _RETRACTION_HEADING not in md


def test_report_omits_section_when_sibling_has_no_ledger(tmp_path: Path):
    """A hardened sibling without a hypothesis_ledger key (older report) -> no
    section, same honesty rule as a missing sibling."""
    md = _generate(tmp_path, hardened={"finding_count": 1})
    assert _RETRACTION_HEADING not in md
