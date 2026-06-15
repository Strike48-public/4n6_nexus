# Strategic Decisions - Community/Enterprise Split

**Date:** 2026-04-26
**Status:** FINALIZED
**Participants:** Jonathan Tomek, Development Team

---

## Summary

All strategic decisions for the Community/Enterprise split have been made and documented below. These decisions guide the implementation detailed in [REPOSITORY_SPLIT_PRD.md](REPOSITORY_SPLIT_PRD.md).

---

## 1. Licensing: MPL-2.0

**Decision:** Mozilla Public License 2.0 (MPL-2.0)

**Rationale:**
- **Perfect for Community + Enterprise model:** MPL is "weak copyleft" - modified MPL files must stay open source, but new proprietary files can be added alongside
- **Protects Community:** Modifications to Community code must remain open source
- **Enables Enterprise:** New Enterprise modules can be proprietary (self-correction, MCP, etc.)
- **Strong patent protection:** Built-in patent grant (unlike MIT)
- **Real-world proven:** Used successfully by Firefox, Servo, LibreOffice

**Why not MIT/Apache:**
- MIT/Apache allow closed-source forks of Community (undesirable)
- MPL prevents closed-source modifications while allowing proprietary additions
- Apache has more complex patent language; MPL is cleaner

**Implementation:**
```
Community repo:
├── LICENSE (MPL-2.0 full text)
├── All files with MPL-2.0 header
└── README.md (references MPL-2.0)

Enterprise repo:
├── forensic_nexus/ (git submodule, MPL-2.0)
└── enterprise/ (proprietary, commercial license)
```

**References:**
- MPL-2.0: https://www.mozilla.org/en-US/MPL/2.0/
- MPL FAQ: https://www.mozilla.org/en-US/MPL/2.0/FAQ/

---

## 2. Repository Ownership: Strike48 Organization

**Decision:** Transfer repositories to Strike48 GitHub organization

**Rationale:**
- **Credibility:** Organization-backed projects signal professionalism
- **Team ownership:** Not tied to individual developers
- **Contributor trust:** PRs go to an organization, not a person
- **Enterprise alignment:** Customers expect org-backed software
- **Future-proof:** Easy to add team members, transfer ownership

**Current State:**
- Repo currently at: `jtomek-strike48/sift_find_evil` (personal)

**Target State:**
- Community: `Strike48-public/4n6_nexus`
- Enterprise: `Strike48-public/4n6_nexus-enterprise`

**Action Required:**
- Strike48 org owner must accept repository transfer (or create repos directly in org)
- Update all documentation references from personal account to org

---

## 3. Contributor License Agreement: None Required

**Decision:** No CLA (Contributor License Agreement) required for Community contributions

**Rationale:**
- **MPL provides protection:** MPL-2.0 already ensures modifications stay open source
- **Lower friction:** No paperwork = more contributors
- **Standard for MPL projects:** Firefox, Servo, LibreOffice - none require CLA
- **Community goodwill:** CLA feels corporate, reduces enthusiasm
- **Sufficient rights:** MPL grants necessary rights for our use case

**Why CLA is unnecessary with MPL:**
- We don't need to relicense Community (stays MPL forever)
- Enterprise adds NEW files (allowed by MPL without CLA)
- Patent grant built into MPL (unlike MIT which needs CLA for patents)
- We control project direction regardless

**Alternative Considered:**
- Developer Certificate of Origin (DCO) via signed commits
- Decision: Not needed; MPL + standard GitHub ToS sufficient

**Implementation:**
- No CLA signing workflow
- CONTRIBUTING.md will reference MPL-2.0 requirements
- Standard GitHub PR process

---

## 4. Versioning Strategy: Independent

**Decision:** Community and Enterprise have independent version numbers

**Rationale:**
- **Decoupled releases:** Each product releases on its own schedule
- **Clear distinction:** Different products, different versions
- **Standard practice:** Docker, Kubernetes, Red Hat all use independent versioning
- **Semantic versioning works better:** Breaking changes in Community ≠ breaking changes in Enterprise
- **Stability:** Enterprise can pin Community version for stability

**Version Scheme:**
```
Community: 1.x.x
- Starts at 1.0.0 (initial public release)
- Semantic versioning (1.0.0 → 1.1.0 → 2.0.0)
- Release when features/fixes are ready

Enterprise: 1.x.x (independent numbering)
- Starts at 1.0.0 (Enterprise v1.0, not synchronized with Community)
- Depends on Community version range: "4n6nexus>=1.0.0,<2.0.0"
- Release independently of Community
- Update Community dependency as needed
```

**Rejected Alternative: Synchronized Versioning**
- Would force Enterprise releases whenever Community releases
- Confusing: same version numbers despite different features
- Tighter coupling, less flexibility

**Implementation:**
- `pyproject.toml` in Enterprise specifies Community dependency range
- CHANGELOG.md in each repo tracks its own versions
- Release notes reference compatible versions when relevant

---

## 5. Product Naming & Branding

**Decision:** Rename from "SIFT Find Evil" to "4n6nexus"

### Product Names

**Community Edition:**
- **Product Name:** 4n6nexus (forensics nexus)
- **Tagline:** "Open-source DFIR detection engine"
- **GitHub Repo:** `Strike48-public/4n6_nexus`
- **PyPI Package:** `4n6nexus`
- **Python Import:** `forensic_nexus` (Python identifiers can't start with numbers)

**Enterprise Edition:**
- **Product Name:** 4n6nexus Enterprise
- **Tagline:** "Autonomous DFIR with self-correction"
- **GitHub Repo:** `Strike48-public/4n6_nexus-enterprise`
- **PyPI Package:** `4n6nexus-enterprise` (or direct distribution)
- **Python Import:** `forensic_nexus_enterprise`

### Rationale

**Why "4n6nexus":**
- "4n6" = forensics (industry standard abbreviation)
- "nexus" = central point, hub, connection
- Combined: "forensics nexus" - a hub for forensic analysis

**Why "forensic_nexus" for imports:**
- Python identifiers cannot start with numbers
- Full spelling is clear and professional
- Avoids ambiguity (n6n, fn6, etc.)

**Hackathon Context:**
- Hackathon submission: "4n6nexus for SANS FIND EVIL! Hackathon"
- Demo video title references both names for SEO
- Post-hackathon: Pure "4n6nexus" branding

### Integration Context

**4n6nexus is a component of Pick:**
```
Pick (~/Code/Pick)
└── Investigation orchestration platform
    └── Integrates:
        ├── 4n6nexus ← THIS PROJECT (detection engine)
        ├── [Other forensic tools]
        └── [Workflow automation]
```

**Positioning:**
- **4n6nexus:** Autonomous detection engine (can be used standalone)
- **Pick:** Investigation orchestration layer (integrates multiple tools)
- **Relationship:** 4n6nexus is one of several forensic tools integrated into Pick

### Package Structure

```bash
# Community Installation
pip install 4n6nexus
# Installs to: site-packages/forensic_nexus/

# Usage
import forensic_nexus
from forensic_nexus.parsers import MFTParser
from forensic_nexus.detectors import RegistryDetector

# Enterprise Installation
pip install 4n6nexus-enterprise
# Installs to: site-packages/forensic_nexus_enterprise/

# Usage
import forensic_nexus_enterprise
from forensic_nexus import parsers  # Community dependency
from forensic_nexus_enterprise.self_correction import SelfCorrectionEngine
```

### Migration Plan

**Current State:**
- Repo: `sift_find_evil`
- Package: `sift_find_evil`
- Import: `import sift_find_evil`

**Target State:**
- Repo: `4n6nexus`
- Package: `4n6nexus`
- Import: `import forensic_nexus`

**Transition:**
1. Rename repo: `sift_find_evil` → `4n6nexus`
2. Rename package directory: `sift_find_evil/` → `forensic_nexus/`
3. Update all imports throughout codebase
4. Update pyproject.toml: `name = "4n6nexus"`
5. Update documentation and branding

**Timeline:** During repository split (Phase 1)

---

## 6. Refactor Timing: NOW (Before Demo)

**Decision:** Execute Finding class refactor immediately, before demo work

**Rationale:**
- **Clean architecture for demo:** Demo shows "final" architecture
- **Removes risk:** No post-demo surprises or complications
- **Low effort:** 3 hours of work with automated validation
- **Enables split:** Unblocks post-demo repository split
- **Best practice:** Fix architectural debt early

**Arguments Against Deferring:**
- Demo would show architecture that will change (documentation mismatch)
- Post-demo split would be more complex (additional refactoring step)
- Risk of merge conflicts if demo work touches detectors

**Implementation Plan:**
See [CRITICAL_ARCHITECTURE_ISSUE.md](CRITICAL_ARCHITECTURE_ISSUE.md) for detailed refactoring steps.

**Timeline:**
- Refactor execution: 3 hours
- Test validation: Included in refactor time
- Documentation update: 30 minutes
- **Total:** 3.5 hours before returning to demo work

---

## Implementation Roadmap

### Phase 0: Pre-Requisites (CURRENT)
- [x] Strategic decisions finalized
- [ ] Finding class refactored (in progress)
- [ ] Tests passing (768/768)
- [ ] Documentation updated

### Phase 1: Create Community Repo (Post-Demo)
- [ ] Rename repo to `4n6nexus`
- [ ] Transfer to community organization
- [ ] Remove Enterprise modules
- [ ] Apply MPL-2.0 license
- [ ] Update branding and documentation
- [ ] Tag v1.0.0

### Phase 2: Create Enterprise Repo (Post-Demo)
- [ ] Create `4n6nexus-enterprise` repo in Strike48 org
- [ ] Add Community as git submodule
- [ ] Configure proprietary licensing
- [ ] Update imports and dependencies
- [ ] Tag v1.0.0

### Phase 3: Validation & Launch (Post-Demo)
- [ ] All 12 scenarios at F1=1.00 in both repos
- [ ] CI/CD operational
- [ ] Documentation complete
- [ ] Community publicly launched
- [ ] Enterprise customers migrated

---

## References

- [CRITICAL_ARCHITECTURE_ISSUE.md](CRITICAL_ARCHITECTURE_ISSUE.md) - Finding refactor plan
- [SPLIT_CRITERIA.md](SPLIT_CRITERIA.md) - Module boundaries
- [REPOSITORY_SPLIT_PRD.md](REPOSITORY_SPLIT_PRD.md) - Full implementation plan
- [DEPENDENCY_MAP.md](DEPENDENCY_MAP.md) - Architecture visualization

---

## Change Log

- **2026-04-26:** Initial decisions documented
  - Licensing: MPL-2.0
  - Organization: Strike48
  - CLA: None required
  - Versioning: Independent
  - Naming: 4n6nexus / forensic_nexus
  - Refactor timing: Now (before demo)

---

**Status:** FINALIZED - Ready for implementation
**Next Step:** Execute Finding class refactor (see CRITICAL_ARCHITECTURE_ISSUE.md)
