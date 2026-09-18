"""Reusable proven-negative emitters for the shipping paths (SFE-fibx.5 PR-C).

A proven negative (findings/absence.py) is a first-class "[NEGATIVE] tool X ran
and found zero Y" finding, mechanically re-verified by re-reading the tool's
captured output so it is grounded, not a bare claim. Until now this only existed
in the demo orchestrator (orchestration._emit_proven_negatives); this module
lifts the domain-specific builders into a reusable, testable unit both the demo
path and the shipping ``analyze`` CLI call.

Scope today: the credential-dumping negative over Event Log 4688 command lines --
the one domain the CLI reliably has re-readable output + a citation for. Memory
(psscan/pslist metric) and other domains stay demo-only until the CLI surfaces
their captured output with a cited run.

Each builder returns a Finding ONLY when the negative genuinely re-verifies
PROVEN, and None otherwise (indicator present, positive already fired, no cited
run, empty output). Pure and deterministic; never mutates its inputs.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from .absence import AbsenceStatus, check_absence, make_absence_finding
from .categories import FindingCategory
from .finding import Finding

# Credential-dumping indicator tokens whose ABSENCE the negative asserts. The
# single source of truth for this vocabulary: the demo orchestrator imports it
# from here rather than keeping a private copy, so the two cannot drift.
#
# The set MUST cover every credential-access pattern the attack-pattern detector
# fires on (attack_pattern_detector.CREDENTIAL_DUMP_PATTERNS + the Invoke-Mimikatz
# PowerShell pattern): mimikatz/sekurlsa, LSASS procdump/comsvcs MiniDump,
# SAM|SYSTEM|SECURITY hive export (reg save/export), NTDS.dit ifm (ntdsutil), and
# the volume-shadow-copy path (vssadmin create shadow). If the detector would fire
# on a command but no token here matches it, the negative would FALSELY ship a
# clean claim -- so test_indicator_list_refutes_every_credential_dumping_command
# binds this set to the detector's scope and fails loudly on any gap.
#
# "vssadmin create shadow" is the full phrase, not bare "vssadmin": the detector's
# pattern is specifically ``vssadmin.*create\s+shadow`` (T1003.003), so a benign
# ``vssadmin delete shadows /all`` (T1490 anti-forensics, NOT credential access)
# must NOT refute the negative. Trailing word-boundary matching (see
# findings/absence.py) means each token only refutes as a whole token; the
# broad-safe direction (refute-if-present) never wrongly ships a clean claim.
CREDENTIAL_DUMP_INDICATORS: tuple[str, ...] = (
    "mimikatz",
    "sekurlsa",
    "lsass",
    "procdump",
    "ntdsutil",
    "ntds.dit",
    "reg save",
    "reg export",
    "comsvcs.dll",
    "vssadmin create shadow",
)


def credential_dump_negative(
    evtx_command_text: Optional[str],
    fired_categories: Iterable[Any],
    tool_call_id: str,
) -> Optional[Finding]:
    """Build a PROVEN "no credential-dumping indicators" negative, or None.

    Re-reads the concatenated Event Log 4688 command-line text and asserts that
    none of :data:`CREDENTIAL_DUMP_INDICATORS` physically appear. The negative is
    emitted ONLY when three conditions hold (else None):

      1. the credential-access positive did NOT fire this run (you cannot claim
         "no credential dumping" when a credential finding was raised);
      2. there is cited, non-empty captured output to re-read (an empty result,
         or no cited run, proves nothing); and
      3. re-verification returns PROVEN (an indicator physically present REFUTES
         the clean claim, so it is withheld).

    Args:
        evtx_command_text: The concatenated 4688 command lines the run captured,
            or None when no Event Log text is available.
        fired_categories: The finding categories already raised this run (any
            iterable; not mutated).
        tool_call_id: The cited Event Log tool invocation backing the claim.

    Returns:
        A PROVEN negative Finding, or None when the clean claim cannot be made.
    """
    if FindingCategory.CREDENTIAL_ACCESS in set(fired_categories):
        return None
    # Short-circuit on no captured text: nothing to re-read. This is also caught
    # by the PROVEN gate below (check_absence treats None/empty output as
    # UNPROVEN), but returning here avoids building a throwaway finding and makes
    # the "no evtx supplied" contract explicit.
    if evtx_command_text is None:
        return None

    finding = make_absence_finding(
        title="No credential-dumping indicators in process-creation logs",
        description=(
            "Re-read the Event ID 4688 command lines: none of the "
            "credential-dumping indicators (mimikatz / LSASS dump / "
            "SAM|SYSTEM hive export / NTDS.dit ifm) are present."
        ),
        category=FindingCategory.CREDENTIAL_ACCESS,
        tool_call_id=tool_call_id,
        pattern=list(CREDENTIAL_DUMP_INDICATORS),
        artifact_sources=["disk"],
    )
    # Only ship a negative that INDEPENDENTLY re-verifies against the same text.
    if check_absence(finding, evtx_command_text).status is not AbsenceStatus.PROVEN:
        return None
    return finding
