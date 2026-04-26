# CRITICAL: Architecture Issue Blocking Clean Split

## Problem Statement

**The Finding class lives in `self_correction/engine.py` but is used by ALL detectors.**

This creates a circular dependency that prevents clean separation of Community vs Enterprise features:

```
Community Detectors
  ↓
Finding class (in self_correction/engine.py)
  ↓
Self-Correction Engine (Enterprise feature)
```

## Current Architecture

### Finding Class Location
`sift_find_evil/self_correction/engine.py` lines 48-107

### Dependencies on Finding
```python
# ALL detectors import Finding from self_correction:
from ..self_correction.engine import Finding

# Affected modules (10):
- detectors/cloud_upload_detector.py
- detectors/exfil_ratio_detector.py
- detectors/lnk_jumplist_detector.py
- detectors/memory_detector.py
- detectors/network_detector.py
- detectors/registry_detector.py
- detectors/stats_detector.py
- detectors/watchlist_detector.py
- detectors/webmail_exfil_detector.py
- detectors/yara_detector.py
```

### Also Imported By
```python
# CLI and runners:
- cli.py (indirectly via SelfCorrectionEngine)
- cli_mcp.py (indirectly via SelfCorrectionEngine)
- scenario_runner.py (indirectly via SelfCorrectionEngine)
- testing/compare_runs.py (directly: from sift_find_evil.self_correction.engine import Finding)
```

## Why This Matters

**We cannot split Community/Enterprise cleanly without refactoring first.**

### Attempted Split Without Refactoring
```
Community Repo:
├── detectors/ ✅ (want to include)
├── parsers/ ✅ (want to include)
└── self_correction/ ❌ (want to exclude, but detectors need Finding!)

Enterprise Repo:
└── self_correction/ ✅ (keep here)
```

**Result:** Community repo breaks immediately because detectors cannot import Finding.

## Solution Options

### Option A: Move Finding to findings/ (RECOMMENDED)
**Effort:** 2-3 hours
**Impact:** Clean architectural separation

```
BEFORE:
sift_find_evil/
├── findings/
│   ├── __init__.py (exports FindingCategory only)
│   └── categories.py (FindingCategory enum)
└── self_correction/
    └── engine.py (Finding class + SelfCorrectionEngine)

AFTER:
sift_find_evil/
├── findings/
│   ├── __init__.py (exports Finding + FindingCategory)
│   ├── categories.py (FindingCategory enum)
│   └── finding.py (Finding dataclass) ← NEW
└── self_correction/
    └── engine.py (SelfCorrectionEngine only, imports Finding from findings)
```

**Changes Required:**
1. Create `findings/finding.py` with Finding class
2. Update `findings/__init__.py` to export Finding
3. Update all detectors: `from ..findings import Finding, FindingCategory`
4. Update self_correction/engine.py: `from ..findings import Finding`
5. Update all tests that import Finding
6. Run full test suite (768 tests must pass)

**Why This Is Correct:**
- `findings/` is the natural home for Finding (it's already about findings!)
- FindingCategory is already there (Finding references it)
- Community detectors emit Finding objects → Community needs Finding
- Enterprise self-correction modifies Finding objects → imports from Community
- Clean dependency flow: Community ← Enterprise (not circular)

### Option B: Duplicate Finding in Both Repos
**Effort:** 1 hour
**Impact:** Maintenance nightmare

Keep Finding in self_correction/ but duplicate into Community repo.

**Problems:**
- Version drift (Community vs Enterprise Finding schemas)
- Breaking changes when schemas evolve
- Testing infrastructure becomes incompatible
- Scenarios won't work across both versions

**Verdict:** DO NOT DO THIS

### Option C: Create Core Package
**Effort:** 8 hours
**Impact:** Over-engineering for current needs

```
packages/
├── core/
│   └── findings/ (Finding + FindingCategory)
├── community/
│   ├── detectors/
│   └── parsers/
└── enterprise/
    └── self_correction/
```

**Problems:**
- Requires monorepo tooling (lerna, nx, or custom scripts)
- Complicates imports
- Overkill for 2-package split

**Verdict:** Save for later if we add more editions

## Recommended Action Plan

### Phase 1: Refactor Finding Location (MUST DO BEFORE SPLIT)
**Timeline:** Complete before demo OR before split (whichever comes first)

1. **Create findings/finding.py** (30 min)
   - Copy Finding class from engine.py lines 48-107
   - Add imports: dataclasses, datetime, List
   - Import FindingCategory from .categories

2. **Update findings/__init__.py** (5 min)
   ```python
   from .categories import FindingCategory
   from .finding import Finding
   
   __all__ = ["FindingCategory", "Finding"]
   ```

3. **Update all imports** (45 min)
   - self_correction/engine.py: `from ..findings import Finding`
   - All 10 detectors: `from ..findings import Finding`
   - testing/compare_runs.py: `from sift_find_evil.findings import Finding`
   - Search codebase for `self_correction.engine import Finding` → replace all

4. **Run tests** (15 min)
   ```bash
   pytest tests/ -v
   # All 768 tests must pass
   ```

5. **Update documentation** (15 min)
   - Add note to findings/__init__.py explaining the module
   - Update this document with "RESOLVED" status

6. **Commit** (10 min)
   ```bash
   git add sift_find_evil/findings/finding.py
   git add sift_find_evil/findings/__init__.py
   git add sift_find_evil/self_correction/engine.py
   git add sift_find_evil/detectors/*.py
   git add sift_find_evil/testing/compare_runs.py
   git commit -m "refactor: move Finding class from self_correction to findings module

   Finding is used by all detectors and is foundational to the framework,
   not specific to self-correction. This move enables clean Community/
   Enterprise split by removing circular dependency.

   - Create findings/finding.py with Finding dataclass
   - Update all imports across detectors, engine, and testing
   - All 768 tests passing
   "
   ```

### Phase 2: Validate Architecture
1. Generate new dependency map (verify no circular deps)
2. Document Community surface area (now includes Finding)
3. Update SPLIT_CRITERIA.md with corrected boundaries

### Phase 3: Proceed with Split
Only after Phase 1 complete.

## Decision Required

**Should we refactor now or defer?**

**Arguments for NOW (before demo):**
- ✅ Fixes architectural debt before it compounds
- ✅ Makes demo code cleaner (Finding in logical location)
- ✅ Enables post-demo split without additional refactoring
- ✅ Low risk: 2-3 hours, automated test verification
- ⚠️ Delays demo work by half a day

**Arguments for LATER (after demo):**
- ✅ Demo proceeds with current (working) architecture
- ✅ Split planning continues in parallel
- ⚠️ Demo shows code that will be refactored (mismatched docs)
- ⚠️ Adds refactor work to post-demo split (more complex)
- ⚠️ Risk of merge conflicts if demo work touches detectors

## Recommendation

**REFACTOR NOW, BEFORE SPLIT PLANNING.**

This is foundational architecture. Getting it right enables everything downstream:
- Accurate split documentation
- Clean Community/Enterprise boundaries  
- No last-minute surprises during split
- Demo shows "final" architecture

**Timeline Impact:** +3 hours to critical path, but removes unknown risk from split.

## Status

- [ ] Decision made (now vs later)
- [ ] Refactoring complete (if now)
- [ ] Tests passing (768/768)
- [ ] Documentation updated
- [ ] Ready for split planning
