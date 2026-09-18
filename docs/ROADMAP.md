# Roadmap

**This file is a pointer. It is not the roadmap.**

The authoritative roadmap is the **Roadmap view** of the `4n6 Nexus` GitHub
Project, which carries `Start`/`Target` dates and a `Release` axis for the
monthly cadence. Execution-level work lives in beads. Neither is duplicated here,
on purpose.

## Where the work lives

| Question | Where | How |
|---|---|---|
| What is the product committing to, and when? | `4n6 Nexus` Project, Roadmap view | group by `Release` |
| What should I pick up right now? | beads | `bd ready` |
| What is blocked, and on what? | beads | `bd blocked`, `bd show <id>` |
| What has already shipped? | `IDEAS.md`, "Status (prototyped so far)" | tracks 38 ranked ideas against the field |
| Why is work tracked this way? | [ADR-0001](adr/0001-tracker-boundary.md) | the tracker boundary |
| How is it sized, prioritized, released? | [WORKING_AGREEMENT.md](WORKING_AGREEMENT.md) | fields, views, cadence |

## Current status

**The Project exists** as a Strike48 org project, created 2026-09-16 and seeded
with the open work epics. Its Roadmap view is empty until epics carry
`Start`/`Target` dates, so **there is no dated roadmap yet**; the first dates
land with the `v0.1.0` release planning.

There are also **no releases yet**: the stated cadence is monthly; building the
release substrate (tag scheme, `CHANGELOG.md`, release workflow) is a
prerequisite for the first release, not a step within it.

## Why this file is a stub

It used to hold a snapshot of open issues. That snapshot went stale - it still
listed `SFE-1` through `SFE-7` long after they closed, while live work had moved
on several epics. A copy of a tracker is a second source of truth that decays
silently, and it decayed alongside a second undated roadmap in `README.md`.

The fix is to have one roadmap rather than to keep three in sync. If this file
and the Project ever disagree, the Project wins, and this file is wrong and should
be trimmed further.
