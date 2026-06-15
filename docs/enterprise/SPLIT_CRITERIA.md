# Community vs Enterprise Split Criteria

**STATUS:** APPROVED - Ready for implementation after Finding refactor
**DECISIONS:** See [DECISIONS.md](DECISIONS.md) for finalized strategic choices

## Executive Summary

- **Product Name:** 4n6nexus (forensics nexus) - renamed from "SIFT Find Evil" (hackathon name)
- **Community Edition:** Open-source DFIR detection engine (MPL-2.0 license)
- **Enterprise Edition:** Commercial edition with self-correction, MCP integration, advanced features
- **Critical Blocker:** Finding class refactor (APPROVED for immediate execution)
- **License:** Mozilla Public License 2.0 (MPL-2.0) - perfect for Community + Enterprise model
- **Organization:** Strike48-public GitHub organization
- **Versioning:** Independent (Community 1.x, Enterprise 1.x)

## Naming Note

**Current State:** Repository and code use `sift_find_evil` (hackathon name)
**Target State:** Will be renamed to `4n6nexus` / `forensic_nexus` during split
**This document uses target names** for clarity. See [DECISIONS.md](DECISIONS.md) #5 for migration plan.

---

## Community Edition (Open Source)

### Core Principle
**"Everything needed to detect malicious activity from forensic artifacts."**

Community provides the foundational detection capabilities that work standalone:
- Parse forensic artifacts (MFT, registry, browser history, PCAP, etc.)
- Detect suspicious patterns (persistence, exfiltration, timestomping)
- Generate findings with confidence scores
- Run scenarios for validation

### Included Modules

#### Parsers (forensic_nexus/parsers/)
```
✅ browser_history_parser.py      # Chrome, Firefox, Edge history
✅ evtx_parser.py                  # Windows Event Logs
✅ evt_parser.py                   # Legacy Windows Event Logs
✅ lnk_jumplist_parser.py          # LNK files, Jump Lists
✅ mft_parser.py                   # NTFS $MFT
✅ pcap_parser.py                  # Network captures (HTTP, DNS, SMTP)
✅ prefetch_parser.py              # Windows Prefetch
✅ pst_parser.py                   # Outlook PST
✅ registry_parser.py              # Windows Registry (Run keys, Amcache, Shimcache, BAM, UserAssist)
```

#### Detectors (forensic_nexus/detectors/)
```
✅ cloud_upload_detector.py       # Cloud service uploads
✅ exfil_ratio_detector.py        # Data exfiltration ratios
✅ lnk_jumplist_detector.py       # Suspicious LNK artifacts
✅ memory_detector.py              # Memory analysis (Volatility integration)
✅ network_detector.py             # Network traffic analysis
✅ registry_detector.py            # Registry persistence, execution
✅ stats_detector.py               # Statistical outliers
✅ watchlist_detector.py           # IOC matching
✅ webmail_exfil_detector.py      # Webmail exfiltration
✅ yara_detector.py                # YARA malware scanning
```

#### Core Framework
```
✅ findings/
   ├── categories.py               # FindingCategory enum
   └── finding.py                  # Finding dataclass (AFTER refactor)

✅ validators/
   └── timestamp_comparator.py    # Timestamp validation

✅ carving/
   ├── image_content_reader.py    # Image content extraction
   └── nsrl_filter.py              # Known-good file filtering

✅ disk/
   ├── exfil_detector.py           # Disk-level exfiltration
   ├── gpt_inspector.py            # GPT partition analysis, E01 support
   └── wipe_detector.py            # Disk wiping detection

✅ yara_scan/
   └── scanner.py                  # YARA rule compilation & scanning

✅ memory/
   └── obfuscation.py              # Memory obfuscation detection
```

#### Testing Infrastructure
```
✅ scenario_runner.py              # Scenario validation framework
✅ testing/
   ├── run_regression_test.py     # Regression testing
   ├── save_results.py             # Results persistence
   └── compare_runs.py             # Run comparison (NEEDS REFACTOR: imports Finding from self_correction)

✅ scenarios/                      # ALL scenarios (synthetic, real, training)
   ├── synthetic/                  # Hand-crafted fixtures
   ├── real/                       # Downloaded evidence
   └── training/                   # Educational cases
```

#### CLI
```
✅ cli.py                          # Basic CLI (WITHOUT self-correction features)
✅ __main__.py                     # Module entry point
```

#### Documentation
```
✅ README.md                       # Community features only
✅ RUNNING.md                      # Basic usage guide
✅ docs/                           # Core detection documentation
✅ CLAUDE.md                       # AI agent instructions (Community subset)
```

### Excluded from Community

```
❌ self_correction/                # Entire module (Enterprise only)
   ├── attack_pattern_detector.py
   ├── confidence_scorer.py
   ├── contradiction_detector.py
   └── engine.py (except Finding class → moves to findings/)

❌ validation/
   └── adversarial_validator.py   # Advanced validation (Enterprise)

❌ approval/                       # Human-in-loop approval (Enterprise)
   ├── manager.py
   └── models.py

❌ audit/                          # Audit logging (Enterprise)
   └── logger.py

❌ case/                           # Case management (Enterprise)
   └── manager.py

❌ mcp/                            # MCP integration (Enterprise)
   ├── example_integration.py
   └── server.py

❌ cli_mcp.py                      # MCP-enabled CLI (Enterprise)

❌ reporting/                      # Advanced reporting (Enterprise)
   ├── generator.py
   └── models.py
```

## Enterprise Edition (Commercial)

### Core Principle
**"Autonomous DFIR with self-correction and human-in-the-loop oversight."**

Enterprise extends Community with advanced capabilities:
- Autonomous operation via MCP
- Contradiction detection across artifacts
- Self-correction and confidence adjustment
- Human-in-the-loop approval workflows
- Audit logging for compliance
- Advanced reporting

### Everything from Community PLUS

#### Self-Correction Engine
```
✅ self_correction/
   ├── attack_pattern_detector.py  # MITRE ATT&CK pattern matching
   ├── confidence_scorer.py         # Dynamic confidence scoring
   ├── contradiction_detector.py    # Cross-artifact contradiction detection
   └── engine.py                    # Self-correction orchestration (Finding moves out)
```

#### Advanced Validation
```
✅ validation/
   └── adversarial_validator.py    # Adversarial timestamp validation
```

#### Human-in-the-Loop
```
✅ approval/
   ├── manager.py                   # Approval workflow management
   └── models.py                    # Approval data models
```

#### Compliance & Audit
```
✅ audit/
   └── logger.py                    # JSONL audit logging for compliance
```

#### Case Management
```
✅ case/
   └── manager.py                   # Multi-case investigation management
```

#### MCP Integration
```
✅ mcp/
   ├── example_integration.py       # MCP integration examples
   └── server.py                    # MCP server implementation
```

#### Enhanced CLI
```
✅ cli_mcp.py                       # MCP-enabled CLI with autonomous operation
```

#### Advanced Reporting
```
✅ reporting/
   ├── generator.py                 # Report generation (HTML, PDF, JSON)
   └── models.py                    # Report data models
```

## Licensing

**Community License:** Mozilla Public License 2.0 (MPL-2.0)
- Modifications to Community code must stay open source
- New Enterprise modules can be proprietary
- Strong patent protection built-in
- See [DECISIONS.md](DECISIONS.md) #1 for rationale

**Enterprise License:** Proprietary commercial license
- Enterprise-specific modules not subject to MPL
- MPL compliance maintained for Community code

---

## Shared vs Exclusive Dependencies

### Shared External Dependencies (Both Editions)
```
# Forensic tools
pypff                               # PST parsing
pyewf                               # E01 image support
pytsk3                              # Sleuth Kit
yara-python                         # YARA scanning (optional)

# Data processing
pandas                              # Data analysis
pyarrow                             # Parquet support
scapy                               # PCAP generation

# Testing
pytest                              # Testing framework
pytest-cov                          # Coverage
```

### Enterprise-Only Dependencies
```toml
[project]
dependencies = [
    "4n6nexus>=1.0.0,<2.0.0",       # Community package (MPL-2.0 licensed)
    "anthropic-mcp-sdk>=1.0.0",     # MCP protocol integration
    # Additional Enterprise dependencies TBD
]

# Note: MPL-2.0 allows Enterprise to depend on Community
# Enterprise-specific modules are proprietary
```

## Import Path Strategy

### Current (Monorepo - using hackathon name)
```python
from sift_find_evil.parsers.mft_parser import MFTParser
from sift_find_evil.detectors.registry_detector import RegistryDetector
from sift_find_evil.self_correction.engine import SelfCorrectionEngine
```

### After Split - Community (target name)
```python
# PyPI: pip install 4n6nexus
# Import: forensic_nexus (numbers not allowed in Python identifiers)
from forensic_nexus.parsers.mft_parser import MFTParser
from forensic_nexus.detectors.registry_detector import RegistryDetector
from forensic_nexus.findings import Finding, FindingCategory
```

### After Split - Enterprise (target name)
```python
# PyPI: pip install 4n6nexus-enterprise (or direct distribution)
# Depends on: 4n6nexus>=1.0.0,<2.0.0

# Import from Community package (git submodule or pip install)
from forensic_nexus.parsers.mft_parser import MFTParser
from forensic_nexus.detectors.registry_detector import RegistryDetector
from forensic_nexus.findings import Finding, FindingCategory

# Enterprise-only imports
from forensic_nexus_enterprise.self_correction import SelfCorrectionEngine
from forensic_nexus_enterprise.mcp import MCPServer
```

## Testing Strategy

### Community Tests
```bash
# Community repo includes full test suite for Community features
pytest tests/ --cov=forensic_nexus --cov-report=term

# Target: 95%+ coverage on Community modules
```

### Enterprise Tests
```bash
# Enterprise repo includes:
# 1. Tests for Enterprise-only features (self-correction, MCP)
# 2. Integration tests using Community as dependency

pytest tests/ --cov=forensic_nexus_enterprise --cov-report=term

# Target: 95%+ coverage on Enterprise modules
# Community coverage inherited from Community repo tests
```

### Scenario Validation
**Decision Point:** Do scenarios stay in Community or move to Enterprise?

**Option A: All Scenarios in Community (RECOMMENDED)**
- ✅ Community users can validate their installation
- ✅ Scenarios test core detection logic (Community feature)
- ✅ Enterprise inherits scenarios via Community dependency
- ❌ Some scenarios may demonstrate Enterprise features (self-correction)

**Option B: Split Scenarios**
- ✅ Clear separation of Community vs Enterprise validation
- ❌ Duplication of test infrastructure
- ❌ Synthetic scenarios are fixtures, not proprietary IP

**Recommendation:** Keep ALL scenarios in Community. Enterprise scenarios that test self-correction can mock the engine or run with Community detectors only.

## Strategic Decisions (FINALIZED)

All strategic decisions have been made. See [DECISIONS.md](DECISIONS.md) for complete details.

### Summary of Decisions
1. **Licensing:** MPL-2.0 (Mozilla Public License) - enables Community protection + Enterprise additions
2. **Organization:** Strike48-public GitHub organization (transferred from personal account)
3. **CLA:** None required (MPL provides sufficient protection)
4. **Versioning:** Independent (Community 1.x, Enterprise 1.x - not synchronized)
5. **Branding:** 4n6nexus (Community) / 4n6nexus Enterprise
6. **Package Names:** `4n6nexus` (PyPI) / `forensic_nexus` (Python import)
7. **Contribution Model:** Accept Community PRs under MPL-2.0 terms
8. **Support Model:** Community (GitHub Issues), Enterprise (SLA-backed)
9. **Refactor Timing:** NOW (before demo) - APPROVED

### Technical Decisions (APPROVED)
1. **Finding Class:** REFACTORING NOW - Move to `findings/finding.py` (see CRITICAL_ARCHITECTURE_ISSUE.md)
2. **Dependency Management:** Git submodule (initial), migrate to PyPI package (production)
3. **CI/CD:** Separate GitHub Actions per repo, shared pytest patterns
4. **Documentation:** Separate docs sites (Community: ReadTheDocs, Enterprise: Private)
5. **Scenarios:** ALL in Community (12/12 scenarios, enables Community validation)

### Operational Decisions (APPROVED)
1. **Repository Hosting:**
   - Community: `Strike48-public/4n6_nexus` (public)
   - Enterprise: `Strike48-public/4n6_nexus-enterprise` (private)
   
2. **Package Distribution:**
   - Community: PyPI (`pip install 4n6nexus`)
   - Enterprise: Direct distribution or private PyPI
   - Docker: TBD (post-launch)

3. **Issue Tracking:**
   - Community: Public GitHub Issues on `Strike48-public/4n6_nexus`
   - Enterprise: Private GitHub Issues on `Strike48-public/4n6_nexus-enterprise`
   
4. **Documentation Hosting:**
   - Community: ReadTheDocs (public, automated from repo)
   - Enterprise: Private docs site (community-hosted or similar)

## Next Steps (IN PROGRESS)

### Immediate (Now)
1. **Execute Finding refactor** (see CRITICAL_ARCHITECTURE_ISSUE.md) - IN PROGRESS
2. **Validate with tests** (all 768 tests must pass)
3. **Update documentation** (reflect refactor completion)

### Post-Refactor (Before Demo)
4. **Return to demo work** (SFE-ajr: hackathon video)
5. **Complete demo submission**

### Post-Demo (May 2026)
6. **Execute repository split** (see REPOSITORY_SPLIT_PRD.md)
7. **Launch Community edition** (public on community org)
8. **Migrate Enterprise customers**
9. **Monitor and iterate**

## Status

- [x] Initial analysis complete
- [x] Strategic decisions finalized (see DECISIONS.md)
- [x] PRD drafted (see REPOSITORY_SPLIT_PRD.md)
- [x] Dependency map created (see DEPENDENCY_MAP.md)
- [ ] Finding class refactored (IN PROGRESS)
- [ ] Tests passing (768/768)
- [ ] Demo complete
- [ ] Ready for split execution
