"""Guard: the beads-generated block in CLAUDE.md must not push to main.

``bd init`` regenerates the block between the BEADS INTEGRATION markers from a
stock template whose session-close step runs ``git push`` against the current
branch, which on this repo means ``main``. The repo's own workflow is PR-only
(SFE-74eu), and the block was edited by hand to match. Nothing else notices if a
regeneration silently reintroduces the direct push, so this test does.
"""

from __future__ import annotations

import re
from pathlib import Path

CLAUDE_MD = Path(__file__).resolve().parents[1] / "CLAUDE.md"
BLOCK_END = "<!-- END BEADS INTEGRATION -->"


def _beads_block() -> str:
    text = CLAUDE_MD.read_text(encoding="utf-8")
    end = text.index(BLOCK_END)
    start = text.rfind("## Beads Issue Tracker", 0, end)
    assert start != -1, "beads block heading not found before its END marker"
    return text[start:end]


SANCTIONED_PUSH = "git push -u origin HEAD"


def test_beads_block_does_not_push_directly_to_main() -> None:
    block = _beads_block()
    # Any command line that starts with `git push` (bare, `origin main`,
    # `--force`, ...) is a direct push unless it is the branch push above.
    push_lines = re.findall(r"^\s*(git push\b.*?)\s*$", block, re.MULTILINE)
    offenders = [line for line in push_lines if line != SANCTIONED_PUSH]
    assert not offenders, (
        f"CLAUDE.md beads block contains direct push command(s) {offenders}; "
        "bd regenerated the stock template. Re-apply the PR-only step 4 "
        "(SFE-74eu)."
    )
    assert "bd dolt push" not in block


def test_beads_block_routes_session_close_through_a_pr() -> None:
    block = _beads_block()
    assert SANCTIONED_PUSH in block
    assert "gh pr create" in block
