# Enterprise Edition Planning Documentation

This directory contains planning documents for splitting the repository into Community and Enterprise editions of **4n6nexus** (forensics nexus).

**Note:** Repository currently uses "SIFT Find Evil" (hackathon name). Will be renamed to "4n6nexus" during split.

## 🚨 START HERE

**Read documents in this order:**

1. **[DECISIONS.md](DECISIONS.md)** - STRATEGIC DECISIONS (FINALIZED)
   - **License:** MPL-2.0 (perfect for Community + Enterprise model)
   - **Organization:** Strike48 GitHub org
   - **CLA:** None required (MPL provides protection)
   - **Versioning:** Independent (Community 1.x, Enterprise 1.x)
   - **Naming:** 4n6nexus / forensic_nexus
   - **Refactor Timing:** NOW (approved for immediate execution)
   - **Status:** ✅ FINALIZED

2. **[CRITICAL_ARCHITECTURE_ISSUE.md](CRITICAL_ARCHITECTURE_ISSUE.md)** - TECHNICAL BLOCKER (RESOLVED)
   - **Problem:** Finding class in wrong module prevents clean split
   - **Solution:** Move Finding from `self_correction/engine.py` to `findings/finding.py`
   - **Status:** ✅ COMPLETE (commit 80fb97f, all 768 tests passing)
   - **Effort:** 2.5 hours (faster than estimated)

3. **[SPLIT_CRITERIA.md](SPLIT_CRITERIA.md)** - What goes where
   - Community modules (parsers, detectors, findings, scenarios)
   - Enterprise modules (self_correction, MCP, approval, audit)
   - MPL-2.0 licensing strategy
   - **Status:** ✅ APPROVED (updated with finalized decisions)

4. **[REPOSITORY_SPLIT_PRD.md](REPOSITORY_SPLIT_PRD.md)** - Full implementation plan
   - Problem statement and goals
   - Technical architecture (git submodule → PyPI migration)
   - Implementation phases (0-3, ~68 hours total)
   - Risk assessment and rollback plans
   - **Status:** ✅ APPROVED (awaiting refactor completion before execution)

## Quick Summary

### The Problem
- Current monorepo contains both open-sourceable and proprietary code
- Cannot open-source without exposing Enterprise IP
- Cannot accept community contributions without clear boundaries
- **Blocker:** Finding class architectural debt (BEING RESOLVED NOW)

### The Solution
1. **Phase 0:** Refactor Finding class (3 hours) [IN PROGRESS]
2. **Phase 1:** Create Community repo (parsers + detectors, 16 hours) [Post-demo]
3. **Phase 2:** Create Enterprise repo (self-correction + MCP, 20 hours) [Post-demo]
4. **Phase 3:** Validation & launch (scenarios, CI/CD, 24 hours) [Post-demo]

**Total Effort:** ~68 hours over 4-6 weeks (post-demo execution)

### Strategic Decisions (✅ FINALIZED)

All decisions made and documented in [DECISIONS.md](DECISIONS.md):

1. **License:** MPL-2.0 (Mozilla Public License) ✅
   - Perfect for Community + Enterprise model
   - Protects Community code, allows Enterprise additions

2. **Organization:** Strike48 GitHub org ✅
   - Professional credibility
   - Team ownership

3. **CLA:** None required ✅
   - MPL provides sufficient protection
   - Lower friction for contributors

4. **Versioning:** Independent ✅
   - Community 1.x, Enterprise 1.x
   - Each releases on own schedule

5. **Naming:** 4n6nexus (forensics nexus) ✅
   - PyPI: `4n6nexus`
   - Import: `forensic_nexus`
   - Enterprise: `4n6nexus-enterprise`

6. **Refactor Timing:** NOW (before demo) ✅
   - Clean architecture for demo
   - Removes risk from split

## Current Status

### ✅ Completed
- [x] Full codebase analysis
- [x] Dependency mapping and visualization
- [x] Architecture issue identified
- [x] Strategic decisions finalized (see DECISIONS.md)
- [x] Split criteria documented
- [x] PRD approved
- [x] Stakeholder alignment (Jonathan Tomek approved all decisions)

### ✅ Refactor Complete
- [x] **Finding class refactoring** (completed, commit 80fb97f)
- [x] **Test validation** (all 768 tests passing)
- [x] **Documentation updates** (complete)

### 📅 Post-Refactor (Before Demo)
- [ ] Return to demo work (SFE-ajr: hackathon video)
- [ ] Complete hackathon submission

### 📅 Post-Demo (May 2026)
- [ ] Phase 1: Create Community repo
- [ ] Phase 2: Create Enterprise repo
- [ ] Phase 3: Validation & launch
- [ ] Public Community launch

## Next Actions (APPROVED)

**Decision: Refactor NOW (before demo) ✅**

**Rationale:**
- Clean architecture for demo
- No post-demo refactoring complexity
- Low risk (3 hours, automated validation)
- Demo shows "final" architecture

**Timeline:**
1. Execute Finding refactor (3 hours) - IN PROGRESS
2. Validate all tests pass (included in refactor time)
3. Update documentation (30 minutes)
4. Return to demo work with confidence

## Document Index

| Document | Purpose | Status |
|----------|---------|--------|
| [DECISIONS.md](DECISIONS.md) | ⭐ Strategic decisions record | ✅ FINALIZED |
| [CRITICAL_ARCHITECTURE_ISSUE.md](CRITICAL_ARCHITECTURE_ISSUE.md) | Finding class refactoring plan | ⏳ IN PROGRESS |
| [SPLIT_CRITERIA.md](SPLIT_CRITERIA.md) | Module-by-module split boundaries | ✅ APPROVED |
| [REPOSITORY_SPLIT_PRD.md](REPOSITORY_SPLIT_PRD.md) | Full implementation plan | ✅ APPROVED |
| [DEPENDENCY_MAP.md](DEPENDENCY_MAP.md) | Architecture visualization + checklist | ✅ COMPLETE |
| MIGRATION_PLAN.md | Step-by-step technical guide | 📅 TBD (post-refactor) |

**Legend:** ⭐ Start here | ✅ Complete | ⏳ In progress | 📅 Planned

## Questions?

Contact: Jonathan Tomek (jonathan.tomek@strike48.com)

---

**Last Updated:** 2026-04-26
**Next Review:** After demo completion (target: May 2026)
