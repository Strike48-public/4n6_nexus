# Community vs Enterprise Split Criteria

**STATUS:** Draft - pending resolution of [CRITICAL_ARCHITECTURE_ISSUE.md](CRITICAL_ARCHITECTURE_ISSUE.md)

## Executive Summary

- **Community Edition:** Open-source DFIR detection engine with parsers, detectors, and findings framework
- **Enterprise Edition:** Commercial edition adding autonomous self-correction, contradiction detection, and MCP integration
- **Critical Blocker:** Finding class must be moved from `self_correction/` to `findings/` before split (see CRITICAL_ARCHITECTURE_ISSUE.md)

## Community Edition (Open Source)

### Core Principle
**"Everything needed to detect malicious activity from forensic artifacts."**

Community provides the foundational detection capabilities that work standalone:
- Parse forensic artifacts (MFT, registry, browser history, PCAP, etc.)
- Detect suspicious patterns (persistence, exfiltration, timestomping)
- Generate findings with confidence scores
- Run scenarios for validation

### Included Modules

#### Parsers (sift_find_evil/parsers/)
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

#### Detectors (sift_find_evil/detectors/)
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
```
# MCP integration (if not open-sourced)
anthropic-mcp-sdk                   # MCP protocol

# Advanced reporting (if using proprietary tools)
# TBD based on reporting requirements
```

## Import Path Strategy

### Current (Monorepo)
```python
from sift_find_evil.parsers.mft_parser import MFTParser
from sift_find_evil.detectors.registry_detector import RegistryDetector
from sift_find_evil.self_correction.engine import SelfCorrectionEngine
```

### After Split - Community
```python
from sift_find_evil.parsers.mft_parser import MFTParser
from sift_find_evil.detectors.registry_detector import RegistryDetector
from sift_find_evil.findings import Finding, FindingCategory
```

### After Split - Enterprise
```python
# Import from Community package (git submodule or pip install)
from sift_find_evil.parsers.mft_parser import MFTParser
from sift_find_evil.detectors.registry_detector import RegistryDetector
from sift_find_evil.findings import Finding, FindingCategory

# Enterprise-only imports
from sift_find_evil_enterprise.self_correction import SelfCorrectionEngine
from sift_find_evil_enterprise.mcp import MCPServer
```

## Testing Strategy

### Community Tests
```bash
# Community repo includes full test suite for Community features
pytest tests/ --cov=sift_find_evil --cov-report=term

# Target: 95%+ coverage on Community modules
```

### Enterprise Tests
```bash
# Enterprise repo includes:
# 1. Tests for Enterprise-only features (self-correction, MCP)
# 2. Integration tests using Community as dependency

pytest tests/ --cov=sift_find_evil_enterprise --cov-report=term

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

## Open Questions

### Strategic
1. **Licensing:**
   - Community: Apache 2.0, MIT, or GPL?
   - Enterprise: Commercial/Proprietary?
   - Contributor License Agreement (CLA) for Community PRs?

2. **Contribution Model:**
   - Accept external PRs to Community?
   - Backport Enterprise fixes to Community?
   - Community members in Enterprise discussions?

3. **Support Model:**
   - Community: GitHub Issues only?
   - Enterprise: SLA-backed support?
   - Separate forums or unified?

4. **Versioning:**
   - Synchronized version numbers (Community 1.0.0 ≠ Enterprise 1.0.0)?
   - Independent release cycles?
   - Semantic versioning for both?

5. **Branding:**
   - "SIFT Find Evil Community" vs "SIFT Find Evil Enterprise"?
   - Different project names entirely?
   - Single brand with edition badges?

### Technical
1. **Finding Class:** (BLOCKER)
   - Must move from `self_correction/engine.py` to `findings/finding.py` before split
   - See [CRITICAL_ARCHITECTURE_ISSUE.md](CRITICAL_ARCHITECTURE_ISSUE.md)

2. **Dependency Management:**
   - Git submodule? (harder to maintain)
   - PyPI package? (requires publishing Community first)
   - Monorepo with separate packages? (adds tooling complexity)

3. **CI/CD:**
   - Separate GitHub Actions workflows?
   - Shared testing infrastructure?
   - Cross-repo dependency updates?

4. **Documentation:**
   - Separate docs sites or unified with feature flags?
   - API documentation generation (Sphinx, MkDocs)?
   - Community contributors document their features?

5. **Scenarios:**
   - All in Community? (recommended)
   - Split by tier (synthetic→Community, real→Enterprise)?
   - Enterprise-specific scenarios?

### Operational
1. **Repository Hosting:**
   - Community: Public GitHub (Strike48 org or personal)?
   - Enterprise: Private GitHub (Strike48 org)?
   - Transfer repos to organization accounts?

2. **Package Distribution:**
   - Community: PyPI? conda-forge?
   - Enterprise: Private PyPI? Direct distribution?
   - Docker images for both?

3. **Issue Tracking:**
   - Separate GitHub Issues?
   - Unified issue tracker with labels?
   - Private Enterprise issues?

4. **Documentation Hosting:**
   - ReadTheDocs (Community)?
   - Private docs site (Enterprise)?
   - Unified docs with auth gates?

## Next Steps

1. **CRITICAL:** Resolve Finding class architecture issue (see CRITICAL_ARCHITECTURE_ISSUE.md)
2. Answer open questions (strategic, technical, operational)
3. Create detailed migration plan (see MIGRATION_PLAN.md)
4. Generate dependency map (verify no circular dependencies post-refactor)
5. Draft PRD for repository split (see REPOSITORY_SPLIT_PRD.md)
6. Create test plan for post-split validation
7. Execute split (post-demo)

## Status

- [x] Initial analysis complete
- [ ] Finding class refactored
- [ ] Open questions answered
- [ ] Migration plan created
- [ ] PRD drafted
- [ ] Stakeholder approval
- [ ] Ready for split execution
