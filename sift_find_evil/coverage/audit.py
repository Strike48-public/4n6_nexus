"""Coverage/completeness audit: 'found nothing' versus 'could not look'.

The audit classifies every expected forensic artifact class into one of
three buckets:

* ``covered``: the evidence was present AND a tool capable of parsing it
  was run. Only these classes can honestly be described as 'evaluated'.
* ``not_evaluated``: the evidence was present but no capable tool ran, so
  the analysis 'could not look'. The absence of findings here says
  nothing about whether the system is clean.
* ``absent``: the evidence class was not present at all.

The central invariant this module exists to protect: silence about an
artifact class must never be read as a clean bill of health unless that
class was actually evaluated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Importance levels considered "gaps" when left unevaluated.
GAP_IMPORTANCE: frozenset[str] = frozenset({"critical", "high"})

# Catalog of expected input classes mapped to their forensic capability,
# importance to an investigation, and the tool that evaluates them.
ARTIFACT_CATALOG: dict[str, dict[str, str]] = {
    "mft": {
        "capability": "File creation, deletion, and timestamp analysis",
        "importance": "critical",
        "detecting_tool": "MFTECmd",
    },
    "usn": {
        "capability": "File-system change journal reconstruction",
        "importance": "high",
        "detecting_tool": "MFTECmd",
    },
    "amcache": {
        "capability": "Program execution and installation evidence",
        "importance": "high",
        "detecting_tool": "AmcacheParser",
    },
    "registry_hives": {
        "capability": "System, user, and persistence configuration state",
        "importance": "critical",
        "detecting_tool": "RECmd",
    },
    "prefetch": {
        "capability": "Application execution history and run counts",
        "importance": "high",
        "detecting_tool": "PECmd",
    },
    "lnk": {
        "capability": "Recently accessed files and removable media",
        "importance": "medium",
        "detecting_tool": "LECmd",
    },
    "browser_history": {
        "capability": "Web navigation, downloads, and search terms",
        "importance": "high",
        "detecting_tool": "BrowsingHistoryView",
    },
    "pcap": {
        "capability": "Network flows, C2 beacons, and exfiltration",
        "importance": "high",
        "detecting_tool": "tshark",
    },
    "memory": {
        "capability": "Process injection, rootkits, and volatile artifacts",
        "importance": "critical",
        "detecting_tool": "Volatility",
    },
    "security": {
        "capability": "Logon events, privilege use, and account changes",
        "importance": "critical",
        "detecting_tool": "EvtxECmd",
    },
    "system": {
        "capability": "Service installs, driver loads, and system events",
        "importance": "high",
        "detecting_tool": "EvtxECmd",
    },
    "powershell_operational": {
        "capability": "Script block logging and encoded command execution",
        "importance": "high",
        "detecting_tool": "EvtxECmd",
    },
    "dns_client": {
        "capability": "DNS query history for C2 and exfiltration domains",
        "importance": "medium",
        "detecting_tool": "EvtxECmd",
    },
    "sysmon": {
        "capability": "Process, network, and file telemetry",
        "importance": "high",
        "detecting_tool": "EvtxECmd",
    },
    "task_scheduler": {
        "capability": "Scheduled task creation and persistence",
        "importance": "high",
        "detecting_tool": "EvtxECmd",
    },
}


@dataclass(frozen=True)
class CoverageReport:
    """Result of a coverage assessment across all artifact classes.

    Attributes:
        covered: Classes present and evaluated by a tool.
        not_evaluated: Classes present but never evaluated ('could not
            look') - their silence is not evidence of a clean system.
        absent: Classes not present in the evidence at all.
        evaluated: Per-class True/False evaluation flag for every class
            in the catalog.
        iocs_flagged: Indicators of compromise flagged during the run.
        findings_confirmed: Count of confirmed findings.
        verifications: Count of independent verifications performed.
    """

    covered: list[str]
    not_evaluated: list[str]
    absent: list[str]
    evaluated: dict[str, bool]
    iocs_flagged: list[str] = field(default_factory=list)
    findings_confirmed: int = 0
    verifications: int = 0

    @property
    def covered_count(self) -> int:
        """Number of covered (present and evaluated) classes."""
        return len(self.covered)

    @property
    def not_evaluated_count(self) -> int:
        """Number of present-but-unevaluated classes."""
        return len(self.not_evaluated)

    @property
    def absent_count(self) -> int:
        """Number of classes not present in the evidence."""
        return len(self.absent)

    @property
    def gaps(self) -> list[str]:
        """High/critical classes that were present but not evaluated.

        These are the blind spots that matter: important evidence that
        the analysis could not look at, so no clean conclusion is
        warranted for them.
        """
        return [
            name
            for name in self.not_evaluated
            if ARTIFACT_CATALOG[name]["importance"] in GAP_IMPORTANCE
        ]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the report."""
        return {
            "covered": list(self.covered),
            "not_evaluated": list(self.not_evaluated),
            "absent": list(self.absent),
            "evaluated": dict(self.evaluated),
            "gaps": self.gaps,
            "covered_count": self.covered_count,
            "not_evaluated_count": self.not_evaluated_count,
            "absent_count": self.absent_count,
            "iocs_flagged": list(self.iocs_flagged),
            "findings_confirmed": self.findings_confirmed,
            "verifications": self.verifications,
        }


def assess_coverage(
    evidence_present: set[str],
    tools_run: set[str],
    iocs_flagged: list[str] | None = None,
    findings_confirmed: int = 0,
    verifications: int = 0,
) -> CoverageReport:
    """Assess coverage of expected artifact classes for an analysis run.

    Args:
        evidence_present: Artifact class names that are present in the
            evidence set.
        tools_run: Names of tools that were actually executed.
        iocs_flagged: Optional indicators of compromise flagged.
        findings_confirmed: Count of confirmed findings.
        verifications: Count of independent verifications performed.

    Returns:
        A CoverageReport classifying every catalog class as covered,
        not_evaluated, or absent, without mutating any input.
    """
    covered: list[str] = []
    not_evaluated: list[str] = []
    absent: list[str] = []
    evaluated: dict[str, bool] = {}

    for name, entry in ARTIFACT_CATALOG.items():
        is_present = name in evidence_present
        tool_ran = entry["detecting_tool"] in tools_run

        if not is_present:
            absent.append(name)
            evaluated[name] = False
        elif tool_ran:
            covered.append(name)
            evaluated[name] = True
        else:
            not_evaluated.append(name)
            evaluated[name] = False

    return CoverageReport(
        covered=covered,
        not_evaluated=not_evaluated,
        absent=absent,
        evaluated=evaluated,
        iocs_flagged=list(iocs_flagged) if iocs_flagged else [],
        findings_confirmed=findings_confirmed,
        verifications=verifications,
    )
