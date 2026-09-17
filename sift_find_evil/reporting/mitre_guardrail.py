"""Deterministic MITRE ATT&CK synthesis guardrail.

Builds the CONFIRMED MITRE matrix ONLY from fired-detector technique tags and
quarantines LLM free-form techniques separately. A technique is confirmed only
when a real detector finding cites it via ``evidence["mitre_attack"]``; anything
the LLM proposes that is not already grounded by a finding is placed in the
``unconfirmed`` bucket. Invented or malformed technique ids are dropped outright.

This prevents an LLM narrative layer from silently promoting hallucinated
techniques into the authoritative attack matrix.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Strict MITRE technique id form: T#### with optional .### sub-technique.
_TECHNIQUE_RE = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")

# Small catalog mapping known ids to human-readable metadata. Unknown-but-valid
# ids are still confirmed, but fall back to "unknown" name/tactic.
CATALOG: dict[str, dict[str, str]] = {
    "T1070.006": {"name": "Indicator Removal: Timestomp", "tactic": "Defense Evasion"},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
    },
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    # SFE-katy: techniques emitted by the linux/usn/lateral detectors that now
    # reach the matrix via legacy-key normalization. Names/tactics verified
    # against attack.mitre.org; for multi-tactic techniques the tactic matching
    # the emitting detector's context is chosen (TA0005 = Defense Evasion).
    "T1543.002": {
        "name": "Create or Modify System Process: Systemd Service",
        "tactic": "Persistence",
    },
    "T1053.003": {"name": "Scheduled Task/Job: Cron", "tactic": "Persistence"},
    "T1574.006": {
        "name": "Hijack Execution Flow: Dynamic Linker Hijacking",
        "tactic": "Persistence",
    },
    "T1548.003": {
        "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "tactic": "Privilege Escalation",
    },
    "T1546.004": {
        "name": "Event Triggered Execution: Unix Shell Configuration Modification",
        "tactic": "Persistence",
    },
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion"},
}

_UNKNOWN = "unknown"


@dataclass(frozen=True)
class MitreReport:
    """Result of MITRE synthesis.

    Attributes:
        confirmed: Techniques grounded by at least one detector finding. Each
            entry is a dict with keys ``technique_id``, ``name``, ``tactic``,
            and ``cited_by`` (list of finding titles, insertion-ordered).
        unconfirmed: Valid technique ids proposed by the LLM but not backed by
            any detector finding.
    """

    confirmed: list[dict[str, object]] = field(default_factory=list)
    unconfirmed: list[str] = field(default_factory=list)


def _is_valid_technique(technique_id: str) -> bool:
    """Return True if ``technique_id`` matches the strict MITRE id form."""
    return bool(_TECHNIQUE_RE.match(technique_id))


def _catalog_entry(technique_id: str) -> dict[str, str]:
    """Return catalog metadata for an id, falling back to unknown values."""
    return CATALOG.get(technique_id, {"name": _UNKNOWN, "tactic": _UNKNOWN})


# MITRE technique evidence keys, in descending authority. Detectors historically
# emitted under three different keys; the guardrail only ever read the first, so
# techniques carried under the legacy keys (a scalar ``mitre_technique`` from the
# linux/usn detectors, a scalar ``mitre`` from lateral_movement) silently never
# reached the matrix (SFE-katy). The canonical key wins when more than one is
# present so a single finding's techniques are never double-counted.
_MITRE_KEYS = ("mitre_attack", "mitre_technique", "mitre")


def _finding_techniques(finding: dict) -> list[str]:
    """Extract technique ids from a finding dict, field-first then legacy keys.

    The first-class ``techniques`` field (SFE-fibx.4) is authoritative when
    present. Otherwise falls back to the first present of :data:`_MITRE_KEYS`
    (canonical first) in ``evidence``, accepting either a single id or a list, so
    a scalar-valued legacy key and the documented ``mitre_attack`` list are both
    honored. Never merges across sources: the highest-authority present source is
    authoritative for that finding.
    """
    field_value = finding.get("techniques")
    if field_value:
        return list(field_value)
    evidence = finding.get("evidence")
    # A well-formed finding carries a dict evidence (Finding normalizes it at
    # construction). Guard defensively so a malformed non-dict evidence yields no
    # techniques instead of AttributeError on ``evidence.get`` -- this extractor is
    # the single source both confirmed_matrix and the kill-chain gate call.
    if not isinstance(evidence, dict):
        return []
    for key in _MITRE_KEYS:
        value = evidence.get(key)
        if value is None or value == "":
            continue
        return list(value) if isinstance(value, (list, tuple)) else [value]
    return []


def confirmed_matrix(findings: list[dict]) -> MitreReport:
    """Build the confirmed MITRE matrix from detector findings only.

    Args:
        findings: Detector findings, each optionally carrying MITRE technique ids
            under ``evidence["mitre_attack"]`` (canonical, a list) or a legacy key
            (``mitre_technique`` / ``mitre``, scalar) - see :func:`_finding_techniques`.

    Returns:
        A MitreReport whose ``confirmed`` list is grounded solely by findings.
        Malformed or invented ids are dropped. ``unconfirmed`` is always empty
        here since no LLM proposals are considered.
    """
    # Preserve first-seen order of techniques and their citing findings.
    ordered_ids: list[str] = []
    citations: dict[str, list[str]] = {}

    for finding in findings:
        title = str(finding.get("title", ""))
        techniques = _finding_techniques(finding)
        for raw_id in techniques:
            technique_id = str(raw_id)
            if not _is_valid_technique(technique_id):
                continue
            if technique_id not in citations:
                citations[technique_id] = []
                ordered_ids.append(technique_id)
            if title not in citations[technique_id]:
                citations[technique_id].append(title)

    confirmed: list[dict[str, object]] = []
    for technique_id in ordered_ids:
        meta = _catalog_entry(technique_id)
        confirmed.append(
            {
                "technique_id": technique_id,
                "name": meta["name"],
                "tactic": meta["tactic"],
                "cited_by": list(citations[technique_id]),
            }
        )

    return MitreReport(confirmed=confirmed, unconfirmed=[])


def synthesize(
    detector_findings: list[dict],
    llm_proposed_techniques: list[str],
) -> MitreReport:
    """Synthesize a guarded MITRE report from detector and LLM inputs.

    Confirmed techniques come exclusively from ``detector_findings``. Any LLM
    proposed technique that is valid but not already confirmed is quarantined in
    ``unconfirmed``. Malformed LLM ids are dropped entirely.

    Args:
        detector_findings: Detector findings (see ``confirmed_matrix``).
        llm_proposed_techniques: Free-form technique ids proposed by an LLM.

    Returns:
        A MitreReport with grounded ``confirmed`` techniques and quarantined
        ``unconfirmed`` LLM proposals.
    """
    base = confirmed_matrix(detector_findings)
    confirmed_ids = {str(entry["technique_id"]) for entry in base.confirmed}

    unconfirmed: list[str] = []
    for raw_id in llm_proposed_techniques:
        technique_id = str(raw_id)
        if not _is_valid_technique(technique_id):
            continue
        if technique_id in confirmed_ids:
            continue
        if technique_id not in unconfirmed:
            unconfirmed.append(technique_id)

    return MitreReport(confirmed=base.confirmed, unconfirmed=unconfirmed)
