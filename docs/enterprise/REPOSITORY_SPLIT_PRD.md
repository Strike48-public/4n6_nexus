# PRD: Repository Split - Community + Enterprise Editions

## Document Information

- **Status:** Draft
- **Created:** 2026-04-26
- **Author:** SIFT Find Evil Development Team
- **Version:** 0.1.0
- **Dependencies:** [CRITICAL_ARCHITECTURE_ISSUE.md](CRITICAL_ARCHITECTURE_ISSUE.md), [SPLIT_CRITERIA.md](SPLIT_CRITERIA.md)

---

## Executive Summary

Split the current monorepo (`sift_find_evil`) into two editions:

1. **Community Edition:** Open-source DFIR detection engine (parsers + detectors + findings framework)
2. **Enterprise Edition:** Commercial edition adding autonomous self-correction, MCP integration, and advanced features

**Critical Blocker:** Finding class architectural issue must be resolved before split (estimated 3 hours).

**Timeline:** Post-hackathon demo (target: May 2026)

---

## Problem Statement

### Current State
- Single monorepo contains both open-sourceable core detection capabilities and proprietary self-correction/MCP features
- No clear separation between Community and Enterprise functionality
- Architectural debt prevents clean split (Finding class in wrong module)

### Problems
1. **No Community Version:** Cannot open-source core DFIR detection engine
2. **No IP Protection:** Self-correction and MCP integration not separated
3. **No Community Contributions:** Cannot accept external PRs without exposing proprietary features
4. **Competitive Disadvantage:** Competitors could clone entire repo if made public
5. **Licensing Confusion:** No clear license boundaries for different features

### Impact
- Lost opportunity for community engagement and contributions
- Reduced adoption (users want to try before buying)
- Harder to build ecosystem (plugins, integrations)
- Risk of exposing proprietary IP if repo made public

---

## Goals

### Primary Goals
1. **Create open-source Community Edition** with core DFIR detection capabilities
2. **Protect Enterprise IP** (self-correction, contradiction detection, MCP integration)
3. **Enable community contributions** to core detection engine
4. **Maintain single source of truth** for shared code (avoid duplication)
5. **Zero downtime** for existing deployments during split

### Success Metrics
- [ ] Community repo fully functional standalone (all parsers + detectors work)
- [ ] Enterprise repo builds on Community foundation (inherits via git submodule or pip)
- [ ] All 768 tests pass in both repos (Community tests + Enterprise tests)
- [ ] 12/12 scenarios at F1=1.00 in both repos
- [ ] Documentation complete for both editions
- [ ] CI/CD pipelines operational for both repos
- [ ] First external Community PR merged within 90 days of launch

### Non-Goals
- Rewriting core detection logic (preserve existing algorithms)
- Breaking existing APIs (maintain backward compatibility)
- Changing test infrastructure (keep pytest + pytest-cov)
- Supporting multiple versions of Community in Enterprise (track latest only)
- Creating additional editions (Professional, Team, etc.) - only 2 editions

---

## User Personas

### Community Users
- **DFIR Analysts:** Need free tools for basic forensic analysis
- **Security Researchers:** Want to contribute detectors for new artifact types
- **Students:** Learning digital forensics, need working examples
- **Small Organizations:** Cannot afford Enterprise, want basic detection

**Needs:**
- Working standalone detection engine
- Clear documentation and examples
- Ability to run scenarios and validate installation
- Path to Enterprise if needs grow

### Enterprise Customers
- **Enterprise SOC Teams:** Need autonomous operation at scale
- **DFIR Service Providers:** Require audit trails and compliance features
- **Government Agencies:** Need self-correction and high confidence ratings
- **Incident Response Teams:** Want MCP integration for workflow automation

**Needs:**
- All Community features PLUS advanced capabilities
- Priority support and SLAs
- Audit logging and compliance features
- Human-in-the-loop approval workflows
- Ongoing updates and security patches

### Contributors (Community)
- **Open Source Developers:** Want to add parsers for new artifacts
- **Detection Engineers:** Want to contribute detection logic
- **Documentation Writers:** Want to improve docs and examples

**Needs:**
- Clear contribution guidelines
- Fast PR review cycles
- Recognition for contributions
- Transparency on Enterprise vs Community boundaries

---

## Technical Architecture

### Current Monorepo Structure
```
sift_find_evil/
├── parsers/            # 9 parsers (MFT, registry, browser, PCAP, etc.)
├── detectors/          # 10 detectors (registry, network, memory, YARA, etc.)
├── findings/           # Finding dataclass (AFTER refactor) + FindingCategory
├── self_correction/    # Self-correction engine, contradiction detector, confidence scorer
├── validation/         # Adversarial validator (Enterprise)
├── approval/           # Human-in-the-loop approval (Enterprise)
├── audit/              # Audit logging (Enterprise)
├── case/               # Case management (Enterprise)
├── mcp/                # MCP integration (Enterprise)
├── reporting/          # Advanced reporting (Enterprise)
├── disk/               # Disk analysis (exfiltration, wiping, GPT)
├── memory/             # Memory analysis (obfuscation)
├── carving/            # File carving, NSRL filtering
├── yara_scan/          # YARA rule compilation
├── validators/         # Timestamp comparison
├── testing/            # Test infrastructure
├── cli.py              # Basic CLI
├── cli_mcp.py          # MCP-enabled CLI (Enterprise)
├── scenario_runner.py  # Scenario validation
└── __main__.py         # Entry point
```

### Post-Split Architecture

#### Option A: Git Submodule (RECOMMENDED for initial split)
```
sift-find-evil-community/          # Public repo
├── sift_find_evil/
│   ├── parsers/
│   ├── detectors/
│   ├── findings/
│   ├── disk/
│   ├── memory/
│   ├── carving/
│   ├── yara_scan/
│   ├── validators/
│   ├── testing/
│   ├── cli.py
│   ├── scenario_runner.py
│   └── __main__.py
├── scenarios/
├── tests/
├── docs/
├── README.md
├── LICENSE (Apache 2.0 or MIT)
└── pyproject.toml

sift-find-evil-enterprise/         # Private repo
├── sift_find_evil_community/      # Git submodule → Community repo
├── sift_find_evil_enterprise/
│   ├── self_correction/
│   ├── validation/
│   ├── approval/
│   ├── audit/
│   ├── case/
│   ├── mcp/
│   ├── reporting/
│   └── cli_mcp.py
├── tests_enterprise/
├── docs_enterprise/
├── README.md
├── LICENSE (Proprietary)
└── pyproject.toml
```

**Pros:**
- Simple to implement (git submodule add)
- Clear separation of code ownership
- Community changes immediately visible in Enterprise
- No publishing workflow needed initially

**Cons:**
- Submodules are notoriously confusing for contributors
- Requires manual `git submodule update` after Community changes
- CI/CD must handle submodule initialization

#### Option B: PyPI Package (Recommended for production)
```
# Community as PyPI package
pip install sift-find-evil

# Enterprise depends on Community package
# pyproject.toml:
dependencies = [
    "sift-find-evil>=1.0.0,<2.0.0",
    ...
]
```

**Pros:**
- Standard Python packaging model
- Versioned dependencies (Community 1.2.0 → Enterprise 2.5.0)
- No submodule complexity
- Enterprise can pin Community version for stability

**Cons:**
- Requires publishing Community to PyPI first
- Slower feedback loop (must publish Community before testing Enterprise)
- Version management complexity
- Breaking changes in Community can break Enterprise

#### Recommended Hybrid Approach
1. **Initial Split:** Use git submodule (fast, simple)
2. **Post-Stabilization:** Migrate to PyPI package (production-ready, versioned)
3. **Development Workflow:** Use editable installs (`pip install -e`) for both

---

## Critical Blocker: Finding Class Architecture

### Problem
**Finding class lives in `self_correction/engine.py` but is imported by ALL detectors.**

```python
# Current (BROKEN for split):
from ..self_correction.engine import Finding

# All detectors depend on this import:
- cloud_upload_detector.py
- exfil_ratio_detector.py
- lnk_jumplist_detector.py
- memory_detector.py
- network_detector.py
- registry_detector.py
- stats_detector.py
- watchlist_detector.py
- webmail_exfil_detector.py
- yara_detector.py
```

### Solution
**Move Finding class from `self_correction/engine.py` to `findings/finding.py`**

See [CRITICAL_ARCHITECTURE_ISSUE.md](CRITICAL_ARCHITECTURE_ISSUE.md) for detailed refactoring plan.

**Estimated Effort:** 3 hours

**Must Complete:** Before split execution (can be before or after demo)

---

## Implementation Phases

### Phase 0: Pre-Requisites (BLOCKING)
**Duration:** 1 week
**Effort:** 8 hours

**Tasks:**
1. **Refactor Finding class** (3 hours)
   - Create `findings/finding.py`
   - Update all imports (10 detectors + engine + tests)
   - Run full test suite (768 tests must pass)
   - Commit: `refactor: move Finding from self_correction to findings`

2. **Answer open questions** (2 hours)
   - Licensing model (Apache 2.0 vs MIT for Community)
   - Contribution model (CLA required?)
   - Versioning strategy (synchronized vs independent)
   - Repository hosting (Strike48 org vs personal)
   - Package naming (`sift-find-evil` vs `sift_find_evil`)

3. **Generate dependency map** (1 hour)
   - Automated analysis of all imports
   - Verify no circular dependencies after refactor
   - Document Community surface area
   - Update SPLIT_CRITERIA.md with verified boundaries

4. **Stakeholder approval** (2 hours)
   - Present PRD to decision makers
   - Confirm licensing strategy
   - Confirm repository ownership (Strike48 org?)
   - Get budget approval (if needed for tooling/hosting)

**Deliverables:**
- [ ] Finding class refactored, all tests passing
- [ ] Open questions documented in DECISIONS.md
- [ ] Dependency map generated
- [ ] Stakeholder sign-off obtained

---

### Phase 1: Create Community Repository
**Duration:** 1 week
**Effort:** 16 hours

**Tasks:**
1. **Fork current repo → Community repo** (2 hours)
   ```bash
   # Clone current repo
   git clone git@github.com:jtomek-strike48/sift_find_evil.git sift-find-evil-community
   cd sift-find-evil-community
   
   # Remove Enterprise-only paths
   rm -rf sift_find_evil/self_correction/
   rm -rf sift_find_evil/validation/adversarial_validator.py
   rm -rf sift_find_evil/approval/
   rm -rf sift_find_evil/audit/
   rm -rf sift_find_evil/case/
   rm -rf sift_find_evil/mcp/
   rm -rf sift_find_evil/reporting/
   rm -f sift_find_evil/cli_mcp.py
   
   # Remove from git history (optional, for clean history)
   git filter-branch --tree-filter '...' --prune-empty HEAD
   ```

2. **Update imports in Community** (4 hours)
   - Remove imports to deleted modules
   - Update cli.py to remove self-correction references
   - Update scenario_runner.py (conditional self-correction import)
   - Fix tests that imported Enterprise modules

3. **Run Community test suite** (2 hours)
   ```bash
   # Remove Enterprise-only tests
   rm -rf tests/test_self_correction/
   rm -rf tests/test_validation/
   # ... etc
   
   # Run remaining tests
   pytest tests/ -v
   # Target: 700+ tests passing (some removed with Enterprise code)
   ```

4. **Update Community documentation** (4 hours)
   - README.md: Community features only, link to Enterprise
   - RUNNING.md: Remove self-correction examples
   - CLAUDE.md: Community subset of instructions
   - Create CONTRIBUTING.md for contributors
   - Create LICENSE file (Apache 2.0 or MIT)

5. **Set up Community CI/CD** (2 hours)
   - GitHub Actions workflow for tests
   - Coverage reporting (Codecov)
   - Automated PyPI publishing (later phase)

6. **Tag Community v1.0.0** (1 hour)
   ```bash
   git tag -a v1.0.0 -m "Initial Community Edition release"
   git push origin v1.0.0
   ```

**Deliverables:**
- [ ] Community repo created and functional
- [ ] 700+ tests passing in Community
- [ ] Documentation updated for Community
- [ ] CI/CD pipeline operational
- [ ] v1.0.0 tagged

---

### Phase 2: Create Enterprise Repository
**Duration:** 1 week
**Effort:** 20 hours

**Tasks:**
1. **Rename current repo → Enterprise** (1 hour)
   ```bash
   # In GitHub: Settings → Repository Name → sift-find-evil-enterprise
   # Or clone and recreate:
   git clone git@github.com:jtomek-strike48/sift_find_evil.git sift-find-evil-enterprise
   ```

2. **Add Community as git submodule** (2 hours)
   ```bash
   cd sift-find-evil-enterprise
   
   # Remove Community code from Enterprise repo
   rm -rf sift_find_evil/parsers/
   rm -rf sift_find_evil/detectors/
   rm -rf sift_find_evil/findings/
   # ... (remove all Community modules)
   
   # Add Community as submodule
   git submodule add git@github.com:jtomek-strike48/sift-find-evil-community.git sift_find_evil_community
   git submodule update --init --recursive
   ```

3. **Restructure Enterprise imports** (8 hours)
   ```python
   # Enterprise modules now import from Community:
   from sift_find_evil_community.findings import Finding, FindingCategory
   from sift_find_evil_community.parsers.mft_parser import MFTParser
   
   # Enterprise modules use enterprise namespace:
   from sift_find_evil_enterprise.self_correction import SelfCorrectionEngine
   ```

4. **Update Enterprise tests** (4 hours)
   - Update imports in test files
   - Add integration tests using Community modules
   - Run full Enterprise test suite
   - Target: 768 tests passing (Community tests + Enterprise tests)

5. **Update Enterprise documentation** (3 hours)
   - README.md: Full feature set + link to Community
   - RUNNING.md: Advanced usage with self-correction + MCP
   - docs/enterprise/: Keep all Enterprise-specific docs
   - LICENSE: Proprietary commercial license

6. **Set up Enterprise CI/CD** (2 hours)
   - GitHub Actions with submodule initialization
   - Private test coverage reporting
   - Deployment automation (if applicable)

**Deliverables:**
- [ ] Enterprise repo created with Community submodule
- [ ] All 768 tests passing in Enterprise
- [ ] Documentation updated for Enterprise
- [ ] CI/CD pipeline operational
- [ ] v2.0.0 tagged (Enterprise edition)

---

### Phase 3: Validation & Launch
**Duration:** 2 weeks
**Effort:** 24 hours

**Tasks:**
1. **Cross-repo validation** (8 hours)
   - Run all 12 scenarios in Community repo
   - Run all 12 scenarios in Enterprise repo
   - Verify F1=1.00 in both repos
   - Test Community standalone (no Enterprise dependencies)
   - Test Enterprise with Community submodule
   - Document any discrepancies

2. **Community launch preparation** (8 hours)
   - Write launch blog post
   - Create demo video (Community features)
   - Set up community forums or Discord
   - Prepare contributor onboarding docs
   - Create issue templates for bug reports / feature requests
   - Announce on relevant forums (Reddit /r/computerforensics, etc.)

3. **Enterprise migration** (4 hours)
   - Notify existing users of repo split
   - Provide migration guide (old imports → new imports)
   - Update deployment scripts
   - Test end-to-end deployment

4. **Post-launch monitoring** (4 hours)
   - Monitor Community GitHub Issues
   - Monitor Enterprise customer deployments
   - Track first external PR to Community
   - Collect feedback and iterate

**Deliverables:**
- [ ] All scenarios passing in both repos (12/12 at F1=1.00)
- [ ] Community publicly launched
- [ ] Enterprise customers migrated
- [ ] First week of post-launch support complete

---

## Risk Assessment

### High Risk

**1. Finding Class Refactoring Breaks Tests**
- **Impact:** Blocks entire split
- **Probability:** Low (automated tests catch issues)
- **Mitigation:** Run full test suite after every import change, commit atomically

**2. Submodule Confusion for Contributors**
- **Impact:** High friction for Community contributors
- **Probability:** High (submodules are notorious)
- **Mitigation:** Clear docs, consider migrating to PyPI package after stabilization

**3. Version Drift Between Community and Enterprise**
- **Impact:** Enterprise breaks when Community updates
- **Probability:** Medium (no version pinning with submodule)
- **Mitigation:** Pin Community version in Enterprise, test before updating submodule

### Medium Risk

**4. Scenarios Reference Enterprise Features**
- **Impact:** Scenarios fail in Community repo
- **Probability:** Medium (some scenarios test self-correction)
- **Mitigation:** Refactor scenarios to conditionally use self-correction if available

**5. External Contributors Submit Enterprise Features to Community**
- **Impact:** IP leakage or awkward PR rejections
- **Probability:** Low (clear boundaries in CONTRIBUTING.md)
- **Mitigation:** Clearly document Community vs Enterprise scope, suggest Enterprise trials

**6. CI/CD Breaks After Split**
- **Impact:** No automated testing, slower development
- **Probability:** Low (GitHub Actions well documented)
- **Mitigation:** Test CI/CD in separate branch before merging

### Low Risk

**7. Documentation Divergence**
- **Impact:** Confusion about which features are in which edition
- **Probability:** Medium (docs updated manually)
- **Mitigation:** Automated link checking, periodic docs review

**8. Community Adoption Lower Than Expected**
- **Impact:** Wasted effort on Community edition
- **Probability:** Low (DFIR community is active, tools are in demand)
- **Mitigation:** Aggressive marketing, demos, conference talks

---

## Rollback Plan

### If Split Fails During Phase 1 (Community Creation)
- **Action:** Delete Community repo, continue with monorepo
- **Cost:** Wasted effort (~24 hours), no customer impact

### If Split Fails During Phase 2 (Enterprise Creation)
- **Action:** Revert Enterprise repo to pre-split state, delete Community repo
- **Cost:** Wasted effort (~44 hours), no customer impact

### If Split Fails During Phase 3 (Validation)
- **Action:** Keep both repos private, fix issues before public launch
- **Cost:** Delayed launch, no customer impact if caught before public release

### Emergency Rollback (Post-Launch Issues)
- **Action:** Redirect Community repo to "Archived", point users back to monorepo
- **Cost:** Reputation damage, confusion, but users can still use monorepo

---

## Success Criteria

### Must-Have (Launch Blockers)
- [ ] Finding class refactored, all tests passing (768/768)
- [ ] Community repo functional standalone
- [ ] Enterprise repo functional with Community dependency
- [ ] All 12 scenarios at F1=1.00 in both repos
- [ ] Documentation complete for both editions
- [ ] CI/CD operational for both repos
- [ ] Licensing clear (Community: OSS, Enterprise: Proprietary)

### Should-Have (Post-Launch)
- [ ] First external Community PR merged within 90 days
- [ ] 100+ GitHub stars on Community repo within 6 months
- [ ] 5+ external contributors to Community within 1 year
- [ ] Enterprise sales tied to Community adoption (attribution tracking)

### Nice-to-Have (Future)
- [ ] Community package on PyPI (pip install sift-find-evil)
- [ ] Enterprise package on private PyPI or direct distribution
- [ ] Docker images for both editions
- [ ] Documentation site (ReadTheDocs or similar)
- [ ] Community forum or Discord server
- [ ] Annual Community contributor summit

---

## Open Questions & Decisions Needed

### Strategic Decisions (Blocking)
1. **Licensing:** Apache 2.0 or MIT for Community? → _Decision:_ ____________
2. **Repository Ownership:** Strike48 org or personal account? → _Decision:_ ____________
3. **Contribution Model:** Require CLA for Community PRs? → _Decision:_ ____________
4. **Versioning:** Synchronized or independent version numbers? → _Decision:_ ____________
5. **Package Naming:** `sift-find-evil` or `sift_find_evil`? → _Decision:_ ____________

### Technical Decisions (Important)
6. **Dependency Model:** Git submodule or PyPI package? → _Decision:_ Start with submodule, migrate to PyPI
7. **Scenario Location:** All in Community or split? → _Decision:_ ____________
8. **Import Paths:** Namespace packages or separate top-level? → _Decision:_ ____________

### Operational Decisions (Can defer)
9. **CI/CD Platform:** GitHub Actions or other? → _Decision:_ GitHub Actions (already used)
10. **Documentation Hosting:** ReadTheDocs or GitHub Pages? → _Decision:_ ____________
11. **Community Support:** GitHub Issues only or separate forum? → _Decision:_ ____________

---

## Timeline

### Critical Path
```
Week 0: Pre-requisites (Finding refactor, decisions) [BLOCKING]
  ↓
Week 1: Create Community repo
  ↓
Week 2: Create Enterprise repo
  ↓
Week 3-4: Validation & launch
```

### Milestones
- **M0 (Week 0):** Finding class refactored, tests passing, decisions made
- **M1 (Week 1):** Community v1.0.0 tagged, CI/CD operational
- **M2 (Week 2):** Enterprise v2.0.0 tagged with Community submodule
- **M3 (Week 4):** Community publicly launched, first external PR received

### Estimated Completion
- **Optimistic:** 4 weeks (all phases sequential, no blockers)
- **Realistic:** 6 weeks (some iteration, minor issues)
- **Pessimistic:** 8 weeks (major issues found, multiple refactorings)

**Target Launch:** May 2026 (post-hackathon demo)

---

## Stakeholder Sign-Off

### Required Approvals
- [ ] **Engineering Lead:** Technical architecture approved
- [ ] **Product Lead:** Feature split approved
- [ ] **Legal:** Licensing strategy approved
- [ ] **Marketing:** Go-to-market plan approved (if applicable)
- [ ] **Finance:** Budget approved (hosting, tooling costs if any)

### Document Review
- [ ] Technical accuracy verified
- [ ] Open questions answered
- [ ] Timeline agreed upon
- [ ] Risk mitigation plans approved

---

## Appendix

### Related Documents
- [CRITICAL_ARCHITECTURE_ISSUE.md](CRITICAL_ARCHITECTURE_ISSUE.md) - Finding class refactoring plan
- [SPLIT_CRITERIA.md](SPLIT_CRITERIA.md) - Detailed module-by-module split criteria
- [MIGRATION_PLAN.md](MIGRATION_PLAN.md) - Step-by-step technical migration guide (TBD)
- [DECISIONS.md](DECISIONS.md) - Record of all strategic decisions (TBD)

### Change Log
- 2026-04-26: Initial draft (v0.1.0)

---

**Status:** DRAFT - Awaiting stakeholder review and decision on open questions.
