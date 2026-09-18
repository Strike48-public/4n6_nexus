# docs/archive/ — retired documentation (untracked)

This directory holds documentation retired from the **live** doc set on
2026-08-03 (beads **SFE-kpue**). The files are **kept on disk for
re-evaluation** but are **gitignored** — only this `README.md` is tracked.

## Why these were archived

They are competition-era and repo-split-era artifacts (SANS FIND EVIL! 2026
submission, one-off session logs, superseded plans, and overlapping SIFT-setup /
evidence-dataset / demo-recording clusters) that no longer reflect the current
connector product. They were creating documentation entropy: stale scenario
counts ("12 scenarios"), duplicate setup guides, and a doc-index that mapped a
mostly-obsolete set.

Nothing here is deleted — the full content lives in git history at the commit
before the move, and physically in this directory for offline review.

## What's here

The retired files were moved verbatim from `docs/`. For the categorized list
(architecture, evidence/datasets, SIFT-setup, competition, demo-recording,
session-logs), see the **archive-candidate** entries in
[../DOCUMENTATION_INDEX.md](../DOCUMENTATION_INDEX.md).

## Restoring a doc

```bash
git mv docs/archive/<FILE>.md docs/<FILE>.md   # bring it back into the tracked set
# then re-add any inbound links (README.md, START_HERE.md, etc.)
```

## Re-evaluation

The intent is to review this set later and decide, per file: **delete for good**,
**merge into a live doc**, or **restore**. Track that decision work under a
follow-up beads issue rather than letting the directory linger indefinitely.
