# Enterprise Edition Planning Documentation

This directory contains planning documents for splitting the SIFT Find Evil repository into Community and Enterprise editions.

## 🚨 START HERE

**Read documents in this order:**

1. **[CRITICAL_ARCHITECTURE_ISSUE.md](CRITICAL_ARCHITECTURE_ISSUE.md)** - BLOCKING ISSUE
   - **Problem:** Finding class in wrong module prevents clean split
   - **Solution:** Move Finding from `self_correction/engine.py` to `findings/finding.py`
   - **Status:** MUST RESOLVE BEFORE SPLIT
   - **Effort:** 3 hours
   - **Decision:** Refactor now or defer to post-demo?

2. **[SPLIT_CRITERIA.md](SPLIT_CRITERIA.md)** - What goes where
   - Community modules (parsers, detectors, findings, scenarios)
   - Enterprise modules (self_correction, MCP, approval, audit)
   - Open questions (licensing, contribution model, versioning)
   - **Status:** Draft, pending Finding refactor

3. **[REPOSITORY_SPLIT_PRD.md](REPOSITORY_SPLIT_PRD.md)** - Full implementation plan
   - Problem statement and goals
   - Technical architecture (git submodule vs PyPI)
   - Implementation phases (0-3, ~68 hours total)
   - Risk assessment and rollback plans
   - **Status:** Draft, awaiting stakeholder sign-off

## Quick Summary

### The Problem
- Current monorepo contains both open-sourceable and proprietary code
- Cannot open-source without exposing Enterprise IP
- Cannot accept community contributions without clear boundaries
- **Blocker:** Finding class architectural debt prevents split

### The Solution
1. **Phase 0:** Refactor Finding class (3 hours) [BLOCKING]
2. **Phase 1:** Create Community repo (parsers + detectors, 16 hours)
3. **Phase 2:** Create Enterprise repo (self-correction + MCP, 20 hours)
4. **Phase 3:** Validation & launch (scenarios, CI/CD, 24 hours)

**Total Effort:** ~68 hours over 4-6 weeks

### Key Decisions Needed

**Strategic (BLOCKING):**
- [ ] Licensing: Apache 2.0 or MIT for Community?
- [ ] Repository ownership: Strike48 org or personal?
- [ ] Contribution model: CLA required for PRs?
- [ ] Versioning: Synchronized or independent?

**Technical:**
- [ ] Dependency model: Git submodule (start) → PyPI (production)?
- [ ] Scenario location: All in Community or split?
- [ ] Finding refactor timing: Now or post-demo?

## Current Status

### Completed
- [x] Full codebase analysis
- [x] Dependency mapping
- [x] Architecture issue identified
- [x] Split criteria documented
- [x] PRD drafted

### Blocking
- [ ] **Finding class refactoring** (see CRITICAL_ARCHITECTURE_ISSUE.md)
- [ ] **Strategic decisions answered** (licensing, ownership, etc.)
- [ ] **Stakeholder sign-off** on PRD

### Ready After Unblock
- [ ] Phase 1: Create Community repo
- [ ] Phase 2: Create Enterprise repo
- [ ] Phase 3: Validation & launch

## Next Actions

### Option A: Refactor Now (Before Demo)
**Timeline:** +3 hours to critical path
**Pros:** Clean architecture for demo, no post-demo refactoring
**Cons:** Delays demo work

### Option B: Refactor Later (After Demo)
**Timeline:** No impact to demo, +3 hours to split timeline
**Pros:** Demo proceeds immediately
**Cons:** Demo shows architecture that will change, split more complex

### Recommendation
**See CRITICAL_ARCHITECTURE_ISSUE.md for detailed analysis and recommendation.**

## Document Index

| Document | Purpose | Status |
|----------|---------|--------|
| [CRITICAL_ARCHITECTURE_ISSUE.md](CRITICAL_ARCHITECTURE_ISSUE.md) | Finding class refactoring plan | Draft, decision needed |
| [SPLIT_CRITERIA.md](SPLIT_CRITERIA.md) | Module-by-module split boundaries | Draft, pending refactor |
| [REPOSITORY_SPLIT_PRD.md](REPOSITORY_SPLIT_PRD.md) | Full implementation plan | Draft, awaiting sign-off |
| MIGRATION_PLAN.md | Step-by-step technical guide | TBD (after decisions made) |
| DECISIONS.md | Record of strategic decisions | TBD (to be created) |

## Questions?

Contact: Jonathan Tomek (jonathan.tomek@madx.co)

---

**Last Updated:** 2026-04-26
**Next Review:** After demo completion (target: May 2026)
