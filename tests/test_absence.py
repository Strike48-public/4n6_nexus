"""Tests for mechanically-verified proven negatives (SFE-rylr).

A proven negative is a first-class finding asserting "tool X ran and found zero Y"
that is INDEPENDENTLY re-verified by re-reading the tool's captured output:

  * pattern-mode -- none of the indicator tokens physically appear (trailing
    word-boundary match, so ".crypt14" does not refute a ".crypt" negative), or
  * metric-mode -- a parsed count is exactly 0.

Empty output proves nothing, and a negative cannot be proven without a real cited
tool run. The verifier is pure and deterministic. RED-first: the module did not
exist before.
"""

import pytest

from sift_find_evil.findings.absence import (
    AbsenceReport,
    AbsenceStatus,
    check_absence,
    make_absence_finding,
    verify_absence,
)
from sift_find_evil.findings.categories import FindingCategory
from sift_find_evil.findings.finding import Finding

# A realistic captured malfind run over a clean image: header + zero result rows.
_CLEAN_MALFIND = (
    "Volatility 3 Framework\nPID\tProcess\tStart VPN\tProtection\n" "\n(no results)\n"
)
# A captured run where a ransomware extension is genuinely present on disk.
_DIRTY_LISTING = "C:/Users/victim/report.docx.crypt\nC:/Users/victim/photo.jpg.crypt\n"


# -- pattern-mode ----------------------------------------------------------


def test_indicator_present_refutes_absence():
    report = verify_absence(
        tool_call_id="evt-001",
        observed_text=_DIRTY_LISTING,
        pattern=[".crypt"],
    )
    assert report.status is AbsenceStatus.REFUTED
    assert ".crypt" in report.refuting_tokens


def test_genuinely_absent_indicator_is_proven():
    report = verify_absence(
        tool_call_id="evt-001",
        observed_text=_CLEAN_MALFIND,
        pattern=[".crypt", ".locked", "mimikatz"],
    )
    assert report.status is AbsenceStatus.PROVEN
    assert report.refuting_tokens == ()


def test_trailing_boundary_does_not_refute_on_longer_token():
    # The classic false-refute: ".crypt14" (a benign WhatsApp DB extension) must
    # NOT refute a ".crypt" ransomware negative -- trailing word-boundary match.
    observed = "C:/Users/v/msgstore.db.crypt14\nC:/Users/v/backup.db.crypt15\n"
    report = verify_absence(
        tool_call_id="evt-002", observed_text=observed, pattern=[".crypt"]
    )
    assert report.status is AbsenceStatus.PROVEN


def test_bare_token_at_boundary_refutes():
    # ".crypt" followed by a non-continuation char (slash / EOL) is the real thing.
    observed = "found C:/Users/v/report.docx.crypt right there\n"
    report = verify_absence(
        tool_call_id="evt-003", observed_text=observed, pattern=[".crypt"]
    )
    assert report.status is AbsenceStatus.REFUTED


def test_indicator_match_is_case_insensitive():
    # A tool that prints "Mimikatz" must still refute a "mimikatz" negative -- the
    # safe direction is to refute (withhold the clean claim), never to miss it.
    report = verify_absence(
        tool_call_id="evt-004",
        observed_text="Detected Mimikatz.exe in memory\n",
        pattern=["mimikatz"],
    )
    assert report.status is AbsenceStatus.REFUTED


def test_multiple_indicators_report_every_offender():
    observed = "mimikatz.exe and also procdump.exe were seen\n"
    report = verify_absence(
        tool_call_id="evt-005",
        observed_text=observed,
        pattern=["mimikatz", "procdump", "lsass.dmp"],
    )
    assert report.status is AbsenceStatus.REFUTED
    assert set(report.refuting_tokens) == {"mimikatz", "procdump"}


# -- metric-mode -----------------------------------------------------------


def test_empty_indicator_token_never_refutes():
    # A degenerate empty pattern token must not spuriously "match" everywhere and
    # refute an otherwise-clean negative.
    report = verify_absence(
        tool_call_id="evt-005b",
        observed_text=_CLEAN_MALFIND,
        pattern=["", ".crypt"],
    )
    assert report.status is AbsenceStatus.PROVEN


def test_metric_zero_is_proven():
    report = verify_absence(
        tool_call_id="evt-006", observed_text=_CLEAN_MALFIND, metric=0
    )
    assert report.status is AbsenceStatus.PROVEN


def test_metric_nonzero_is_refuted():
    report = verify_absence(
        tool_call_id="evt-007", observed_text="4 injected regions\n", metric=4
    )
    assert report.status is AbsenceStatus.REFUTED
    assert "4" in report.reason


# -- combined assertions (AND) ---------------------------------------------


def test_both_modes_must_hold_to_prove():
    report = verify_absence(
        tool_call_id="evt-008",
        observed_text=_CLEAN_MALFIND,
        pattern=[".crypt"],
        metric=0,
    )
    assert report.status is AbsenceStatus.PROVEN


def test_metric_bad_refutes_even_if_pattern_clean():
    report = verify_absence(
        tool_call_id="evt-009",
        observed_text=_CLEAN_MALFIND,  # no pattern token present
        pattern=[".crypt"],
        metric=2,  # but the count is not zero
    )
    assert report.status is AbsenceStatus.REFUTED


# -- unproven conditions (the heart of "empty output proves nothing") ------


def test_empty_output_is_unproven():
    report = verify_absence(
        tool_call_id="evt-010", observed_text="", pattern=[".crypt"]
    )
    assert report.status is AbsenceStatus.UNPROVEN
    assert "empty" in report.reason.lower()


def test_whitespace_only_output_is_unproven():
    report = verify_absence(
        tool_call_id="evt-011", observed_text="   \n\t\n", pattern=[".crypt"]
    )
    assert report.status is AbsenceStatus.UNPROVEN


def test_missing_tool_call_id_is_unproven():
    # A negative cannot be proven without a cited run -- silence is not evidence.
    report = verify_absence(
        tool_call_id="", observed_text=_CLEAN_MALFIND, pattern=[".crypt"]
    )
    assert report.status is AbsenceStatus.UNPROVEN
    assert "tool" in report.reason.lower()


def test_no_assertion_to_check_is_unproven():
    # No pattern and no metric: there is nothing to mechanically verify.
    report = verify_absence(tool_call_id="evt-012", observed_text=_CLEAN_MALFIND)
    assert report.status is AbsenceStatus.UNPROVEN


# -- check_absence over a Finding ------------------------------------------


def test_check_absence_reads_from_finding():
    finding = make_absence_finding(
        title="No ransomware extensions on disk",
        description="mftecmd listed all filenames; none carried a ransomware suffix.",
        category=FindingCategory.ANTI_FORENSICS,
        tool_call_id="evt-020",
        pattern=[".crypt", ".locked"],
        artifact_sources=["mft"],
    )
    report = check_absence(finding, _CLEAN_MALFIND)
    assert report.status is AbsenceStatus.PROVEN


def test_check_absence_on_non_absence_finding_is_unproven():
    finding = Finding(
        title="ordinary positive",
        description="malware.exe executed",
        finding_type="indicator",
        severity="high",
        category=FindingCategory.EXECUTION,
    )
    report = check_absence(finding, _CLEAN_MALFIND)
    assert report.status is AbsenceStatus.UNPROVEN
    assert "not an absence" in report.reason.lower()


# -- make_absence_finding shape --------------------------------------------


def test_make_absence_finding_sets_negative_fields():
    finding = make_absence_finding(
        title="No credential-dumping tooling",
        description="malfind + cmdline ran clean.",
        category=FindingCategory.CREDENTIAL_ACCESS,
        tool_call_id="evt-021",
        metric=0,
    )
    assert finding.asserts_absence is True
    assert finding.absence_metric == 0
    assert finding.finding_type == "negative"
    assert finding.evidence["tool_call_id"] == "evt-021"


def test_absence_finding_round_trips_through_dict():
    finding = make_absence_finding(
        title="No injected regions",
        description="malfind found zero suspicious regions.",
        category=FindingCategory.PROCESS_INJECTION,
        tool_call_id="evt-022",
        pattern=["MZ", "PAGE_EXECUTE_READWRITE"],
        metric=0,
        artifact_sources=["memory"],
    )
    restored = Finding.from_dict(finding.to_dict())
    assert restored.asserts_absence is True
    assert restored.absence_pattern == ["MZ", "PAGE_EXECUTE_READWRITE"]
    assert restored.absence_metric == 0


def test_plain_finding_defaults_are_not_absence():
    finding = Finding(
        title="t",
        description="d",
        finding_type="indicator",
        severity="high",
        category=FindingCategory.EXECUTION,
    )
    assert finding.asserts_absence is False
    assert finding.absence_pattern == []
    assert finding.absence_metric is None
    # to_dict stays backward-compatible: absence flag present and false.
    assert finding.to_dict()["asserts_absence"] is False


# -- report immutability ---------------------------------------------------


def test_absence_report_is_frozen():
    report = AbsenceReport(status=AbsenceStatus.PROVEN, reason="ok")
    with pytest.raises(Exception):
        report.status = AbsenceStatus.REFUTED  # frozen
