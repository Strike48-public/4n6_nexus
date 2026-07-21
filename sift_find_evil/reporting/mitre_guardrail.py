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


def confirmed_matrix(findings: list[dict]) -> MitreReport:
    """Build the confirmed MITRE matrix from detector findings only.

    Args:
        findings: Detector findings, each optionally carrying
            ``evidence["mitre_attack"]`` as a list of technique ids.

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
        evidence = finding.get("evidence") or {}
        techniques = evidence.get("mitre_attack") or []
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
