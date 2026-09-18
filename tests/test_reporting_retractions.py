"""Human-readable render of the self-correction retraction trail (SFE-fibx.1).

The hardened report carries a ``hypothesis_ledger`` (build_hypothesis_ledger),
but a human reads prose, not JSON. This renders the candidate-elimination trail
as a first-class markdown section: what was retracted, from/to verdict, the
grounded reason, and the triggering execution id -- so the engine's
self-correction is legible, matching the finalists' "visible skepticism".

Pure function (no I/O), so .12 (GUI) and .13 (primary report) can reuse it.
"""

from sift_find_evil.reporting.retractions import render_retraction_section


def _ledger(corrections=(), retracted=(), self_correction_count=0):
    return {
        "self_correction_count": self_correction_count,
        "retracted": list(retracted),
        "confirmed": [],
        "open": [],
        "correction_trail": list(corrections),
    }


def test_none_ledger_is_treated_as_an_empty_trail():
    """A reuse caller (GUI/.12, primary report/.13) may pass a raw None; the
    renderer must not crash -- it renders the honest empty-trail note instead."""
    md = render_retraction_section(None)
    assert "## " in md
    assert "retract" in md.lower()


def test_empty_trail_renders_an_honest_no_retractions_note():
    """An all-confirmed run: the section states nothing was retracted (not blank)."""
    md = render_retraction_section(_ledger())
    assert "## " in md  # it is a real section, always present
    # It says, in words, that no candidate was eliminated -- an honest empty state.
    assert "no" in md.lower()
    assert "retract" in md.lower()


def test_retraction_renders_subject_verdict_transition_reason_and_trigger():
    corr = {
        "sequence": 1,
        "finding_id": "F-002",
        "from_verdict": "supports",
        "to_verdict": "refutes",
        "reason": "known_benign_direct_ip_infrastructure: 8.8.8.8 is a public DNS resolver",
        "trigger_exec_id": "tshark-004",
    }
    md = render_retraction_section(
        _ledger(
            corrections=[corr],
            retracted=[{"id": "H-002", "statement": "8.8.8.8 is attacker-controlled"}],
            self_correction_count=1,
        )
    )
    # The transition is shown (a reader sees SUPPORTS was withdrawn to REFUTES).
    assert "supports" in md.lower() and "refutes" in md.lower()
    # The grounded reason and the triggering execution id are both surfaced.
    assert "known_benign_direct_ip_infrastructure" in md
    assert "tshark-004" in md
    # The eliminated candidate's statement appears.
    assert "8.8.8.8 is attacker-controlled" in md


def test_adversary_controlled_title_cannot_break_the_table():
    """trigger_exec_id is a finding TITLE on the harden path, and titles embed
    adversary-controlled evidence (file paths, YARA match strings). A pipe or
    newline in any interpolated column must not corrupt the markdown table."""
    corr = {
        "sequence": 1,
        "finding_id": "F-1 | injected",
        "from_verdict": "supports",
        "to_verdict": "refutes",
        "reason": "m: benign",
        "trigger_exec_id": "YARA match: evil | on C:\\x\nrow2",
    }
    md = render_retraction_section(
        _ledger(
            corrections=[corr],
            retracted=[{"id": "H-1", "statement": "evil | <b>x</b> is malicious"}],
            self_correction_count=1,
        )
    )
    # Every rendered table row must keep exactly the 6 UNESCAPED pipes of a
    # 5-column row: a raw pipe from evidence would split cells. Escaped `\|`
    # pipes are literal content, not column separators, so discount them.
    for line in md.splitlines():
        if line.startswith("|") and "→" in line:
            unescaped = line.replace("\\|", "")
            assert unescaped.count("|") == 6, f"table row corrupted: {line!r}"
    # A newline in evidence must not create a spurious extra line.
    assert "row2" in md
    assert "\nrow2" not in md  # the newline was neutralized, not passed through


def test_prose_does_not_overclaim_execution_citation():
    """Honesty (claim audit): on the harden path the 'Triggered by' value is a
    finding identity, not always a replayable tool-exec id. The rendered prose
    must not assert every row is replayable from the custody log."""
    corr = {
        "sequence": 1,
        "finding_id": "F-1",
        "from_verdict": "supports",
        "to_verdict": "refutes",
        "reason": "m: benign",
        "trigger_exec_id": "some.exe",
    }
    md = render_retraction_section(_ledger(corrections=[corr], self_correction_count=1))
    assert "replayable from the custody log" not in md


def test_correction_trail_is_rendered_in_sequence_order():
    c1 = {
        "sequence": 1,
        "finding_id": "F-001",
        "from_verdict": "supports",
        "to_verdict": "refutes",
        "reason": "method_a: first",
        "trigger_exec_id": "t-1",
    }
    c2 = {
        "sequence": 2,
        "finding_id": "F-002",
        "from_verdict": "supports",
        "to_verdict": "refutes",
        "reason": "method_b: second",
        "trigger_exec_id": "t-2",
    }
    # Pass out of order; the renderer must present them in sequence order.
    md = render_retraction_section(
        _ledger(corrections=[c2, c1], self_correction_count=2)
    )
    assert md.index("method_a") < md.index("method_b")
