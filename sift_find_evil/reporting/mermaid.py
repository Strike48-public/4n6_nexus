"""Mermaid diagram generation for investigation reports.

GitHub renders Mermaid natively, so embedding these in the Markdown report turns
a text report into a visual one. Two diagrams:

- ``mermaid_a2a_sequence`` — an agent-to-agent sequence diagram reconstructed from
  the audit log's ``agent_message`` entries (the multi-agent execution record).
- ``mermaid_finding_flow`` — a flowchart of each finding and the verifier's verdict,
  surfacing the confidence transition (the self-correction story).

Both are pure functions over plain dicts (audit entries / finding rows), so they
have no dependency on the live engine and are unit-testable in isolation. All
label text is sanitised so it cannot break the fenced block or the diagram parse.
"""

from __future__ import annotations

from typing import Any

_FENCE_OPEN = "```mermaid"
_FENCE_CLOSE = "```"

# Per-node ``style`` directives (explicit fill + white text) are the most widely
# supported colouring mechanism — they render correctly on old Mermaid (MarkText)
# as well as GitHub/VS Code. We deliberately do NOT use a %%{init}%% theme block:
# older renderers ignore it and leave light text on a white background
# (white-on-white). Each colour pairs a dark fill with #ffffff text so contrast
# is guaranteed regardless of the renderer's default theme.
_STYLE = {
    "finding": "fill:#2c3e50,stroke:#1b2631,color:#ffffff,stroke-width:1px",
    "resolved": "fill:#1e8449,stroke:#145a32,color:#ffffff,stroke-width:2px",
    "flagged": "fill:#c0392b,stroke:#7b241c,color:#ffffff,stroke-width:2px",
    "neutral": "fill:#566573,stroke:#2c3e50,color:#ffffff,stroke-width:1px",
}


def _verdict_style(verdict: str) -> str:
    """Map a verifier verdict to a semantic node style key for colouring."""
    v = (verdict or "").lower()
    if "resolved" in v or "confirmed" in v:
        return "resolved"
    if "detected" in v or "refuted" in v or "flag" in v:
        return "flagged"
    return "neutral"


def _fence(body: str) -> str:
    """Wrap a diagram body in a ```mermaid fenced block."""
    return f"{_FENCE_OPEN}\n{body.rstrip()}\n{_FENCE_CLOSE}"


def _safe(text: Any, max_len: int = 48) -> str:
    """Sanitise a label for inclusion in a Mermaid diagram.

    Strips characters that would break the fenced block (backticks) or the
    diagram parse (newlines, quotes, brackets, the arrow/colon tokens Mermaid
    treats as syntax), collapses whitespace, and truncates over-long labels so
    diagram nodes stay readable. Returns a compact single-line token.
    """
    s = str(text) if text is not None else "?"
    for ch in ("`", '"', "\n", "\r", "[", "]", "{", "}", "|", ";", ":", "<", ">"):
        s = s.replace(ch, " ")
    s = " ".join(s.split())  # collapse whitespace
    if len(s) > max_len:
        s = s[:max_len].rstrip() + "..."
    return s or "?"


def _mid(name: str) -> str:
    """A Mermaid-safe participant/node identifier (alnum + underscore)."""
    ident = "".join(c if c.isalnum() else "_" for c in str(name))
    return ident or "node"


def mermaid_a2a_sequence(audit_entries: list[dict]) -> str:
    """Build a ```mermaid sequenceDiagram from agent_message audit entries.

    Only ``action == "agent_message"`` rows become arrows; tool invocations,
    findings, etc. are ignored (they belong to other views). Participants are
    declared in first-seen order so the diagram reads top-to-bottom sensibly.
    An empty log still yields a valid (empty) sequenceDiagram.
    """
    lines = ["sequenceDiagram", "    autonumber"]
    participants: list[str] = []
    arrows: list[str] = []

    for entry in audit_entries:
        if entry.get("action") != "agent_message":
            continue
        details = entry.get("details") or {}
        sender = details.get("sender") or entry.get("agent") or "agent"
        recipient = details.get("recipient") or "agent"
        msg_type = _safe(details.get("message_type") or "message")
        for p in (sender, recipient):
            if p not in participants:
                participants.append(p)
        arrows.append(f"    {_mid(sender)}->>{_mid(recipient)}: {msg_type}")

    for p in participants:
        lines.append(f"    participant {_mid(p)} as {_safe(p)}")
    lines.extend(arrows)
    return _fence("\n".join(lines))


def mermaid_finding_flow(findings: list[dict]) -> str:
    """Build a ```mermaid flowchart of findings and their verifier verdicts.

    Each finding becomes a node labelled with its id, artifact, and confidence
    transition (e.g. ``F-001 ransom_note.exe 0.95->0.75``), linked to a verdict
    node so a reviewer sees at a glance what self-corrected vs. stayed flagged.
    An empty finding set still yields a valid (empty) flowchart.
    """
    lines = ["flowchart TD"]
    styles: list[str] = []
    for f in findings:
        fid = _safe(f.get("finding_id") or "F-?", max_len=12)
        label = _safe(f.get("label") or "", max_len=32)
        verdict = _safe(f.get("verdict") or "reported")
        before = f.get("confidence_before")
        after = f.get("confidence_after")
        node_id = _mid(f.get("finding_id") or "F")
        verdict_id = f"{node_id}_v"
        if before is not None and after is not None:
            conf = f"confidence {before} to {after}"
        else:
            c = f.get("confidence")
            conf = f"confidence {c}" if c is not None else ""
        # Two-line node label via <br/> (a finding heading + the confidence line)
        # so nodes have visual breathing room instead of one cramped line.
        heading = f"{fid}: {label}".strip().rstrip(":")
        finding_label = f"{heading}<br/>{conf}" if conf else heading
        # Finding node -> verifier edge -> verdict node. Top-down so multiple
        # findings stack vertically and read cleanly rather than crushing across.
        lines.append(
            f'    {node_id}["{finding_label}"] -->|verifier| {verdict_id}(["{verdict}"])'
        )
        styles.append(f"    style {node_id} {_STYLE['finding']}")
        styles.append(f"    style {verdict_id} {_STYLE[_verdict_style(verdict)]}")
    lines.extend(styles)
    return _fence("\n".join(lines))
