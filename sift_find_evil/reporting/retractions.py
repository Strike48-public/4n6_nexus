"""Render the self-correction retraction trail as a human-readable section (SFE-fibx.1).

The hardened report's ``hypothesis_ledger`` (built by
``self_correction.hypothesis_ledger.build_hypothesis_ledger``) is the machine
record of candidate elimination: each ``correction_trail`` entry is a logged,
unforgeable SUPPORTS->REFUTES ``SelfCorrection``. This turns that record into
prose so an investigator SEES the engine challenge and withdraw its own
conclusions -- the "visible skepticism" every FIND EVIL! finalist was judged on.

Pure function, no I/O: the same renderer serves the hardened report, the GUI
(SFE-fibx.12), and the primary report (SFE-fibx.13).
"""

from typing import Any

_HEADING = "## Candidate Elimination & Self-Correction"


def _cell(value: Any) -> str:
    """Sanitize an adversary-controlled value for a markdown table cell.

    Finding titles/ids embed evidence the engine did not author (file paths,
    YARA match strings, registry values). On the harden path such a title is the
    ``trigger_exec_id``, so a raw ``|`` would split the row into extra columns and
    a newline would forge a new table row. Escape ``|`` and collapse any newline
    so evidence content can never corrupt (or inject into) the rendered table.
    """
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def render_retraction_section(hypothesis_ledger: dict[str, Any]) -> str:
    """Render a candidate-elimination / retraction markdown section.

    Args:
        hypothesis_ledger: a ledger ``report_summary()`` dict, carrying
            ``correction_trail`` (ordered SelfCorrection dicts), ``retracted``
            (eliminated hypotheses), and ``self_correction_count``.

    Returns:
        A markdown section. Always includes the heading so the report structure
        is stable; an all-confirmed run (empty trail) renders an honest
        "no candidate was retracted" note rather than a blank -- absence of a
        retraction is itself a reported fact, not a gap.

    A missing/None ledger renders as an empty trail, so a reuse caller
    (GUI/SFE-fibx.12, primary report/SFE-fibx.13) can pass a raw
    ``report.get("hypothesis_ledger")`` without its own None guard.
    """
    hypothesis_ledger = hypothesis_ledger or {}
    trail = sorted(
        hypothesis_ledger.get("correction_trail", []),
        key=lambda c: c.get("sequence", 0),
    )
    retracted = hypothesis_ledger.get("retracted", [])
    count = hypothesis_ledger.get("self_correction_count", len(trail))

    lines: list[str] = [_HEADING, ""]

    if not trail:
        lines.append(
            "The verifier re-challenged every candidate; **no candidate was "
            "retracted** in this run. Each surviving finding withstood an "
            "attempt to refute it. (An empty trail is a reported result, not a "
            "gap: nothing was exonerated away.)"
        )
        lines.append("")
        return "\n".join(lines)

    plural = "s" if count != 1 else ""
    lines.append(
        f"The verifier logged **{count} self-correction{plural}** — each a "
        "candidate the engine confirmed, then withdrew on re-examination. Each "
        "row names what triggered the reversal (the tool execution when one is "
        "attached, otherwise the finding it revised)."
    )
    lines.append("")

    # Eliminated candidates (the hypotheses a retraction knocked out). The
    # statement embeds evidence content, so sanitize it like a table cell.
    if retracted:
        lines.append("**Eliminated candidates:**")
        lines.append("")
        for hyp in retracted:
            statement = hyp.get("statement") or hyp.get("id") or "unknown hypothesis"
            lines.append(f"- ~~{_cell(statement)}~~")
        lines.append("")

    # The ordered correction trail: the verdict transition, grounded reason, and
    # the triggering reference for each self-correction. Every interpolated column
    # is adversary-controlled (titles/ids carry evidence), so all pass through
    # _cell to keep the table structurally intact.
    lines.append("| # | Finding | Verdict | Reason | Triggered by |")
    lines.append("|---|---------|---------|--------|--------------|")
    for c in trail:
        seq = _cell(c.get("sequence", ""))
        finding_id = _cell(c.get("finding_id", ""))
        transition = f"{c.get('from_verdict', '?')} → {c.get('to_verdict', '?')}"
        reason = _cell(c.get("reason", ""))
        trigger = _cell(c.get("trigger_exec_id", ""))
        lines.append(
            f"| {seq} | {finding_id} | {transition} | {reason} | `{trigger}` |"
        )
    lines.append("")
    return "\n".join(lines)
