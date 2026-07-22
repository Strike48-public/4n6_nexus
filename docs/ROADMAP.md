# Roadmap

Tracked work is now in beads. This file previously held the roadmap because the SIFT-install beads binary was built without CGO support; that binary has since been replaced with `bd 1.0.2`, which works correctly against the Dolt-backed database in `.beads/`.

## Where the work lives

Run these from the repo root:

```
bd ready          # items you can start right now (no blockers)
bd list           # all open issues
bd blocked        # blocked items with what they're blocked on
bd show SFE-1     # full issue view including dependencies and acceptance
```

## Current state snapshot

- **SFE-F1** feature: Email-based exfiltration detection (Jean-case autonomous pass)
- **SFE-1** Promote PST parser to first-class artifact source (**ready**)
- **SFE-2** Plumb a content-reader through the engine (blocked on SFE-1)
- **SFE-3** Add EXFIL_CORRELATION contradiction type and detector (blocked on SFE-1, SFE-2, SFE-7)
- **SFE-4** CLI wiring for `--pst` and `--image` flags (blocked on SFE-3)
- **SFE-5** Re-run Jean case as acceptance test, case-agnostic criteria (blocked on SFE-4)
- **SFE-6** Automate adversarial validator as post-engine check (blocked on SFE-5)
- **SFE-7** Case-agnostic finding category taxonomy — **done**, shipped in commit `ed9e21c`

Dependency graph: SFE-F1 depends on SFE-5 → SFE-4 → SFE-3 → (SFE-1, SFE-2, SFE-7). SFE-2 depends on SFE-1. SFE-6 depends on SFE-5.

The authoritative issue descriptions, acceptance criteria, and status live in beads. Treat this file as a pointer, not a second source of truth. If beads and this file disagree, beads wins; update this file to match.
