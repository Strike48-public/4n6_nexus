# Dependency Map - Current Architecture

**Generated:** 2026-04-26
**Status:** Pre-refactor (using sift_find_evil naming)
**Target:** Will use 4n6nexus / forensic_nexus naming after split

**Note:** This document shows current state (sift_find_evil). Post-split will use:
- Community: `4n6nexus` (PyPI) / `forensic_nexus` (import) - MPL-2.0 licensed
- Enterprise: `4n6nexus-enterprise` / `forensic_nexus_enterprise` - Proprietary

See [DECISIONS.md](DECISIONS.md) for complete naming and licensing strategy.

---

## Module Dependency Graph

### Current Architecture (PROBLEMATIC)

```
┌─────────────────────────────────────────────────────────────┐
│                     Community Modules                        │
│                                                              │
│  ┌─────────┐  ┌──────────┐  ┌────────┐  ┌────────────┐   │
│  │ Parsers │  │ Detectors│  │  Disk  │  │  Carving   │   │
│  │         │  │          │  │        │  │            │   │
│  │ • MFT   │  │ • Registry│ │• Exfil │  │ • NSRL     │   │
│  │ • Reg   │  │ • Network│  │• Wipe  │  │ • Images   │   │
│  │ • PCAP  │  │ • Memory │  │• GPT   │  │            │   │
│  │ • Browser│ │ • YARA   │  └────────┘  └────────────┘   │
│  │ • EVT/X │  │ • LNK    │                                │
│  │ • LNK   │  │ • Webmail│                                │
│  │ • PST   │  │ • Cloud  │                                │
│  │ • Prefetch│ │ • Stats │                                │
│  └─────────┘  │ • Watchlist│                              │
│                │ • ExfilRatio│                             │
│                └──────────┘                                │
│                       ↓                                     │
│                ┌──────────────┐                            │
│                │   Findings   │                            │
│                │              │                            │
│                │• FindingCategory (enum)                   │
│                └──────────────┘                            │
│                       ↓                                     │
└───────────────────────┼─────────────────────────────────────┘
                        │
                        ↓
              ❌ PROBLEM: Detectors import Finding from here
                        │
┌───────────────────────┼─────────────────────────────────────┐
│              Enterprise Modules                             │
│                       ↓                                     │
│         ┌─────────────────────────────┐                    │
│         │   self_correction/engine.py │                    │
│         │                              │                    │
│         │ • Finding (dataclass) ← WRONG LOCATION          │
│         │ • SelfCorrectionEngine       │                    │
│         └─────────────────────────────┘                    │
│                       ↑                                     │
│         ┌─────────────┴───────────────┐                    │
│         │                              │                    │
│  ┌──────────────┐           ┌─────────────────┐           │
│  │Contradiction │           │ Confidence      │           │
│  │  Detector    │           │  Scorer         │           │
│  └──────────────┘           └─────────────────┘           │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │   Approval   │  │    Audit     │  │     MCP      │   │
│  └──────────────┘  └──────────────┘  └──────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**Problem:** All detectors import `Finding` from `self_correction.engine` (Enterprise), creating circular dependency that blocks split.

---

### Target Architecture (AFTER REFACTOR)

```
┌─────────────────────────────────────────────────────────────┐
│                     Community Modules                        │
│                                                              │
│  ┌─────────┐  ┌──────────┐  ┌────────┐  ┌────────────┐   │
│  │ Parsers │  │ Detectors│  │  Disk  │  │  Carving   │   │
│  │         │  │          │  │        │  │            │   │
│  │ • MFT   │  │ • Registry│ │• Exfil │  │ • NSRL     │   │
│  │ • Reg   │  │ • Network│  │• Wipe  │  │ • Images   │   │
│  │ • PCAP  │  │ • Memory │  │• GPT   │  │            │   │
│  │ • Browser│ │ • YARA   │  └────────┘  └────────────┘   │
│  │ • EVT/X │  │ • LNK    │                                │
│  │ • LNK   │  │ • Webmail│                                │
│  │ • PST   │  │ • Cloud  │                                │
│  │ • Prefetch│ │ • Stats │                                │
│  └─────────┘  │ • Watchlist│                              │
│                │ • ExfilRatio│                             │
│                └──────────┘                                │
│                       ↓                                     │
│                ┌──────────────┐                            │
│                │   Findings   │                            │
│                │              │                            │
│                │ • FindingCategory (enum)                  │
│                │ • Finding (dataclass) ← MOVED HERE        │
│                └──────────────┘                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                        ↑
                        │ imports from Community
                        │
┌───────────────────────┼─────────────────────────────────────┐
│              Enterprise Modules                             │
│                       │                                     │
│         ┌─────────────────────────────┐                    │
│         │   self_correction/engine.py │                    │
│         │                              │                    │
│         │ • SelfCorrectionEngine       │                    │
│         │   (imports Finding from      │                    │
│         │    ..findings)               │                    │
│         └─────────────────────────────┘                    │
│                       ↑                                     │
│         ┌─────────────┴───────────────┐                    │
│         │                              │                    │
│  ┌──────────────┐           ┌─────────────────┐           │
│  │Contradiction │           │ Confidence      │           │
│  │  Detector    │           │  Scorer         │           │
│  └──────────────┘           └─────────────────┘           │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │   Approval   │  │    Audit     │  │     MCP      │   │
│  └──────────────┘  └──────────────┘  └──────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**Solution:** Finding lives in `findings/` (Community), Enterprise imports from Community. Clean one-way dependency.

---

## Detailed Import Analysis

### Files Importing Finding (Current)

**From `self_correction.engine`:**
```python
# These ALL need to change:
sift_find_evil/detectors/cloud_upload_detector.py:      from ..self_correction.engine import Finding
sift_find_evil/detectors/exfil_ratio_detector.py:      from ..self_correction.engine import Finding
sift_find_evil/detectors/lnk_jumplist_detector.py:     from ..self_correction.engine import Finding
sift_find_evil/detectors/memory_detector.py:           from ..self_correction.engine import Finding
sift_find_evil/detectors/network_detector.py:          from ..self_correction.engine import Finding
sift_find_evil/detectors/registry_detector.py:         from ..self_correction.engine import Finding
sift_find_evil/detectors/stats_detector.py:            from ..self_correction.engine import Finding
sift_find_evil/detectors/watchlist_detector.py:        from ..self_correction.engine import Finding
sift_find_evil/detectors/webmail_exfil_detector.py:    from ..self_correction.engine import Finding
sift_find_evil/detectors/yara_detector.py:             from ..self_correction.engine import Finding
sift_find_evil/testing/compare_runs.py:                from sift_find_evil.self_correction.engine import Finding
```

**After refactor (target):**
```python
# All change to:
from ..findings import Finding, FindingCategory

# Or absolute import:
from sift_find_evil.findings import Finding, FindingCategory
```

### Files Importing SelfCorrectionEngine (Enterprise only)

```python
# These are correct (Enterprise imports):
sift_find_evil/cli_mcp.py:             from .self_correction.engine import SelfCorrectionEngine
sift_find_evil/cli.py:                 from .self_correction.engine import SelfCorrectionEngine
sift_find_evil/scenario_runner.py:    from .self_correction.engine import SelfCorrectionEngine
sift_find_evil/mcp/example_integration.py: from ..self_correction.engine import SelfCorrectionEngine
```

**After split:** These stay in Enterprise repo, continue importing SelfCorrectionEngine.

---

## Module Categories

### Community (Open Source - MPL-2.0)

**License:** Mozilla Public License 2.0
- Modifications must stay open source
- Can be used in proprietary products (like Enterprise)
- Strong patent protection

```
parsers/                    # 9 modules, 0 Enterprise dependencies
detectors/                  # 10 modules, currently ALL depend on Finding (will be fixed)
findings/                   # 2 files (categories.py, finding.py after refactor)
disk/                       # 3 modules, 0 Enterprise dependencies
memory/                     # 1 module (obfuscation.py), 0 Enterprise dependencies
carving/                    # 2 modules, 0 Enterprise dependencies
yara_scan/                  # 1 module, 0 Enterprise dependencies
validators/                 # 1 module (timestamp_comparator.py), 0 Enterprise dependencies
testing/                    # 3 modules (1 needs refactor: compare_runs.py)
scenario_runner.py          # 1 file, conditionally imports SelfCorrectionEngine
cli.py                      # 1 file, currently imports SelfCorrectionEngine (will be made optional)
__main__.py                 # Entry point
```

**Total Community Lines:** ~12,000 SLOC (estimated)
**License:** MPL-2.0 (all files include MPL header)
**Repository:** `Strike48-public/4n6_nexus` (public)

### Enterprise (Proprietary)
```
self_correction/            # 4 modules (engine, contradiction_detector, confidence_scorer, attack_pattern_detector)
validation/                 # 1 module (adversarial_validator.py)
approval/                   # 2 modules (manager.py, models.py)
audit/                      # 1 module (logger.py)
case/                       # 1 module (manager.py)
mcp/                        # 2 modules (example_integration.py, server.py)
reporting/                  # 2 modules (generator.py, models.py)
cli_mcp.py                  # MCP-enabled CLI
```

**Total Enterprise Lines:** ~8,000 SLOC (estimated)
**License:** Proprietary commercial license
**Repository:** `Strike48-public/4n6_nexus-enterprise` (private)
**Depends On:** Community (4n6nexus>=1.0.0,<2.0.0) - MPL-2.0 allows this

---

## External Dependencies

### Community Dependencies (Required)
```toml
[project]
dependencies = [
    "pandas>=2.0.0",
    "pyarrow>=12.0.0",
    "pytz>=2023.3",
    "scapy>=2.5.0",
    "pytsk3>=20230717",         # Optional, for disk analysis
    "pypff>=20211114",          # Optional, for PST parsing
    "pyewf>=20201230",          # Optional, for E01 images
    "yara-python>=4.3.1",       # Optional, for YARA scanning
]

[project.optional-dependencies]
dev = [
    "pytest>=7.4.0",
    "pytest-cov>=4.1.0",
    "ruff>=0.1.0",
]
```

### Enterprise Dependencies (Additional)
```toml
[project]
dependencies = [
    "sift-find-evil>=1.0.0,<2.0.0",  # Community package
    "anthropic-mcp-sdk>=1.0.0",      # MCP integration (if not open-sourced)
    # ... any other Enterprise-only dependencies
]
```

---

## Circular Dependency Analysis

### Current (BROKEN)
```
detectors/ → self_correction.engine (Finding)
  ↑                    ↓
  └─── SelfCorrectionEngine.analyze() calls detectors
```

**This creates a cycle that prevents clean separation.**

### After Refactor (FIXED)
```
detectors/ → findings/ (Finding)
                ↑
                │
self_correction.engine → findings/ (imports Finding)
                ↓
         SelfCorrectionEngine.analyze() calls detectors
```

**One-way dependency: Community ← Enterprise (no cycle).**

---

## Validation Checklist

After refactor, run these checks:

```bash
# 1. Check for circular imports
python3 << 'EOF'
import ast
from pathlib import Path
from collections import defaultdict

imports = defaultdict(set)
for py_file in Path('sift_find_evil').rglob('*.py'):
    if '__pycache__' in str(py_file):
        continue
    try:
        with open(py_file) as f:
            tree = ast.parse(f.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module and node.module.startswith('sift_find_evil'):
                    module = str(py_file.relative_to('sift_find_evil').with_suffix('')).replace('/', '.')
                    imports[module].add(node.module)
    except:
        pass

# Detect cycles
for module, deps in sorted(imports.items()):
    for dep in deps:
        if module in imports.get(dep, set()):
            print(f"CYCLE: {module} <-> {dep}")
EOF

# 2. Check no self_correction imports in Community modules
grep -r "from.*self_correction" sift_find_evil/{parsers,detectors,findings,disk,carving,validators}/ 2>/dev/null
# Expected: No results (or only scenario_runner.py with conditional import)

# 3. Check all detectors import Finding from findings
grep -r "from.*findings.*import.*Finding" sift_find_evil/detectors/
# Expected: 10 results (one per detector)

# 4. Run full test suite
pytest tests/ -v
# Expected: All 768 tests pass
```

---

## Migration Checklist

- [ ] Create `findings/finding.py` with Finding class
- [ ] Update `findings/__init__.py` to export Finding
- [ ] Update 10 detectors: `from ..findings import Finding`
- [ ] Update `self_correction/engine.py`: `from ..findings import Finding`
- [ ] Update `testing/compare_runs.py`: `from sift_find_evil.findings import Finding`
- [ ] Run circular import check (should find 0 cycles)
- [ ] Run test suite (should pass 768/768)
- [ ] Commit refactor
- [ ] Update SPLIT_CRITERIA.md with verified boundaries
- [ ] Proceed with split planning

---

## References

- [CRITICAL_ARCHITECTURE_ISSUE.md](CRITICAL_ARCHITECTURE_ISSUE.md) - Detailed refactoring plan
- [SPLIT_CRITERIA.md](SPLIT_CRITERIA.md) - Module-by-module split boundaries
- [REPOSITORY_SPLIT_PRD.md](REPOSITORY_SPLIT_PRD.md) - Full implementation plan

---

**Generated:** 2026-04-26
**Status:** Current architecture (pre-refactor)
**Next:** Execute Finding class refactor (see CRITICAL_ARCHITECTURE_ISSUE.md)
