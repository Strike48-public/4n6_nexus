# Contributing to SIFT Find Evil

Thank you for your interest in contributing to SIFT Find Evil! This document provides guidelines for development, testing, and submitting contributions.

---

## Table of Contents

1. [Development Setup](#development-setup)
2. [Code Style](#code-style)
3. [Testing Requirements](#testing-requirements)
4. [Adding New Features](#adding-new-features)
5. [Pull Request Process](#pull-request-process)
6. [Release Process](#release-process)

---

## Development Setup

### Prerequisites

- **Python 3.10+** (tested on 3.12.2)
- **Git**
- **Optional:** SANS SIFT Workstation OVA for integration testing

### Clone and Install

```bash
# Clone repository
git clone https://github.com/Strike48-public/sift_find_evil.git
cd sift_find_evil

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt

# Verify installation
python -m sift_find_evil.cli --help
```

### Development Tools

```bash
# Code formatting
black sift_find_evil/

# Linting
ruff check sift_find_evil/

# Type checking
mypy sift_find_evil/

# Run all checks
./scripts/quality-check.sh
```

---

## Code Style

### Python Standards

**PEP 8 Compliance:**
- 88 character line length (Black default)
- 4 spaces for indentation (no tabs)
- Snake_case for functions/variables
- PascalCase for classes
- UPPER_SNAKE_CASE for constants

**Type Hints:**
```python
def analyze_artifacts(
    mft_entries: list[MFTEntry],
    prefetch_entries: list[PrefetchEntry],
    evtx_entries: list[EventLogEntry],
) -> list[Finding]:
    """Analyze forensic artifacts and detect contradictions.
    
    Args:
        mft_entries: MFT entries from MFTECmd
        prefetch_entries: Prefetch entries from PECmd
        evtx_entries: Event Log entries from EvtxECmd
    
    Returns:
        List of findings with confidence scores
    """
    pass
```

**Docstrings:**
- Use Google-style docstrings
- Include type information in Args/Returns sections
- Provide examples for complex functions

**Immutability:**
```python
from dataclasses import dataclass

@dataclass(frozen=True)  # Immutable
class Finding:
    title: str
    severity: str
    confidence: float
```

**Error Handling:**
```python
# Explicit error handling
try:
    entries = parser.parse_csv(csv_path)
except FileNotFoundError:
    logger.error(f"CSV file not found: {csv_path}")
    raise
except csv.Error as exc:
    logger.error(f"CSV parsing failed: {exc}")
    raise

# Don't silently swallow errors
# WRONG:
try:
    do_something()
except Exception:
    pass  # ❌ Silent failure

# RIGHT:
try:
    do_something()
except SpecificException as exc:
    logger.error(f"Operation failed: {exc}")
    raise  # ✅ Re-raise or handle explicitly
```

---

## Testing Requirements

### Test Coverage

**Minimum 85% line coverage required** (enforced by CI via `--cov-fail-under=85`).
Current: ~91% on a core install, ~95% with the forensic extras installed.

```bash
# Run tests with coverage
pytest --cov=sift_find_evil --cov-report=html

# View coverage report
open htmlcov/index.html
```

Pure-rendering UI modules (`tui_app.py`, `tui/*`) and thin CLI/driver wrappers
are omitted from the coverage gate (see `[tool.coverage.run]` in
`pyproject.toml`); their behavior is covered by the Pilot-driven tests in
`tests/test_tui.py`. The detection library and orchestration layer are measured
directly.

### Test Organization

```
tests/
├── unit/                  # Unit tests
│   ├── test_parsers.py
│   ├── test_detectors.py
│   └── test_self_correction.py
├── integration/           # Integration tests
│   ├── test_scenario_harness.py
│   └── test_cli.py
├── fixtures/              # Synthetic test data
│   ├── synthetic_mft.csv
│   ├── synthetic_prefetch.csv
│   └── synthetic_evtx.csv
└── scenario_harness.py    # Automated validation
```

### Writing Tests

**Unit Test Example:**
```python
import pytest
from pathlib import Path
from sift_find_evil.parsers import MFTParser

def test_mft_parser_basic():
    parser = MFTParser()
    entries = parser.parse_csv(Path("tests/fixtures/mft_sample.csv"))
    
    assert len(entries) > 0
    assert entries[0].file_name == "malware.exe"
    assert entries[0].si_modified is not None

def test_mft_parser_missing_file():
    parser = MFTParser()
    
    with pytest.raises(FileNotFoundError):
        parser.parse_csv(Path("nonexistent.csv"))
```

**Scenario Test Example:**
```python
from sift_find_evil.scenario_runner import run_scenario_path

def test_ransomware_scenario():
    report = run_scenario_path(Path("scenarios/synthetic/02_ransomware"))
    
    assert report.passed
    assert report.precision == 1.00
    assert report.recall == 1.00
    assert report.f1 == 1.00
    assert report.findings_count == 5
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/unit/test_parsers.py

# Run specific test
pytest tests/unit/test_parsers.py::test_mft_parser_basic

# Run with verbose output
pytest -v

# Run with coverage
pytest --cov=sift_find_evil

# Run scenario harness
PYTHONPATH=. python3 tests/scenario_harness.py
```

---

## Adding New Features

### Adding a New Detector

**1. Create detector class:**
```python
# sift_find_evil/detectors/my_detector.py
from ..self_correction.models import Finding

class MyDetector:
    """Detect suspicious activity in custom artifacts."""
    
    def analyze(self, artifacts: list, **kwargs) -> list[Finding]:
        """Analyze artifacts and return findings.
        
        Args:
            artifacts: List of artifact objects
            **kwargs: Additional detector-specific parameters
        
        Returns:
            List of findings with confidence scores
        """
        findings = []
        
        for artifact in artifacts:
            if self._is_suspicious(artifact):
                finding = Finding(
                    title=f"Suspicious Activity: {artifact.name}",
                    severity="high",
                    confidence=0.85,
                    category="custom_category",
                    finding_type="indicator",
                    description="...",
                    evidence={"artifact": artifact.to_dict()},
                    reasoning_chain=[
                        "Step 1: Analyzed artifact",
                        "Step 2: Detected anomaly",
                        "Step 3: Calculated confidence"
                    ],
                )
                findings.append(finding)
        
        return findings
    
    def _is_suspicious(self, artifact) -> bool:
        """Check if artifact is suspicious."""
        # Implement detection logic
        pass
```

**2. Add tests:**
```python
# tests/unit/test_my_detector.py
import pytest
from sift_find_evil.detectors import MyDetector

def test_my_detector():
    detector = MyDetector()
    artifacts = [...]  # Create test artifacts
    
    findings = detector.analyze(artifacts)
    
    assert len(findings) > 0
    assert findings[0].severity == "high"
    assert findings[0].confidence >= 0.80
```

**3. Integrate with CLI:**
```python
# sift_find_evil/cli.py
analyze_parser.add_argument(
    "--custom-artifacts",
    help="Path to custom artifact CSV"
)

# In cmd_analyze():
if args.custom_artifacts:
    custom_artifacts = CustomParser().parse_csv(Path(args.custom_artifacts))
    findings.extend(MyDetector().analyze(custom_artifacts))
```

### Adding a New Parser

**1. Create parser class:**
```python
# sift_find_evil/parsers/my_parser.py
import csv
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

@dataclass
class MyArtifact:
    field1: str
    field2: datetime
    field3: int

class MyParser:
    """Parse custom forensic tool CSV output."""
    
    def parse_csv(self, csv_path: Path) -> list[MyArtifact]:
        """Parse CSV file into artifact models.
        
        Args:
            csv_path: Path to CSV file
        
        Returns:
            List of artifact objects
        """
        artifacts = []
        
        with open(csv_path, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                artifact = MyArtifact(
                    field1=row["field1"],
                    field2=datetime.fromisoformat(row["field2"]),
                    field3=int(row["field3"])
                )
                artifacts.append(artifact)
        
        return artifacts
```

**2. Add tests:**
```python
# tests/unit/test_my_parser.py
from sift_find_evil.parsers import MyParser

def test_my_parser():
    parser = MyParser()
    artifacts = parser.parse_csv(Path("tests/fixtures/my_artifact.csv"))
    
    assert len(artifacts) > 0
    assert artifacts[0].field1 == "expected_value"
```

### Adding a Forensic Tool (MCP Extension)

**This is how you extend the agent's capabilities — by adding a tool at the MCP
boundary, not by giving an agent a shell.** A tool added here automatically
inherits the architectural guardrails (read-only allowlist, evidence-path
containment, circuit breaker, audit logging), and the analyst agents pick it up
for free because their `tools:` allowlist uses the `mcp__sift-find-evil__*`
wildcard. No agent edits required.

> **Why not just give an agent `Bash`?** That would let it run any command and
> bypass the guardrails — reopening the exact hole the architecture exists to
> close (the "architectural, not prompt-based" guarantee). The MCP server *is*
> the extension point. Add tools here and the guarantee holds.

**1. Declare a read-only policy** in `default_policies()`
(`sift_find_evil/mcp/server.py`). List the *complete* set of flags the tool may
run with — deny-by-default means anything you don't list is rejected, so simply
omit any write/modify flag:

```python
"tshark": ToolPolicy(
    allowed_flags={"-r", "-Y", "-T", "-e", "-E", "-q", "-z", "fields"},
    path_flags={"-r"},                 # -r's value is an INPUT path: contained to evidence root
    value_flags={"-Y", "-T", "-e", "-E", "-z"},  # consume a value, not allowlist-checked
),
# Note: tshark's capture-WRITE flag (-w) is simply not listed -> unreachable.
```

`path_flags` are containment-checked (must resolve inside the evidence root);
`value_flags` consume their following token without checking it (formats, field
names, output dirs). A flag in neither set is a bare switch.

**2. Register it as a typed MCP tool** in `build_fastmcp()` (same file). Each tool
delegates to `server.run_tool`, so the guardrails and audit are unavoidable:

```python
@mcp.tool()
def tshark(pcap_file: str, correlation_id: str, display_filter: str = "",
           agent: str = "network_analyst") -> dict:
    """Extract read-only fields from a PCAP (no capture write)."""
    args = ["-r", pcap_file]
    if display_filter:
        args += ["-Y", display_filter]
    args += ["-T", "fields", "-e", "ip.src", "-e", "ip.dst"]
    return server.run_tool("tshark", args, agent=agent, correlation_id=correlation_id)
```

**3. That's it for wiring.** The agents already reach it via the wildcard. To grant
it to a *new* agent, add `mcp__sift-find-evil__<tool>` (or `mcp__sift-find-evil__*`)
to that agent's `tools:` list — never add `Bash`/`Write`/`Edit`.

**4. Test the guardrail inheritance** (the contract that makes this safe):

```python
# A read-only call inside the evidence root succeeds;
# the write flag (-w) is rejected with GuardrailViolation — no extra code needed.
def test_added_tool_inherits_readonly_guardrail(server, evidence_root, monkeypatch):
    ...  # see tests/test_mcp_server.py::test_added_tool_inherits_readonly_guardrail
```

`tests/test_mcp_fastmcp.py::test_registered_tools_match_default_policies` also
enforces that every policy has a registered tool and vice versa, so the two seams
can't drift apart.

> **On output/write paths:** the guardrail forbids modifying *evidence*, not all
> writes. Only `path_flags` (input paths) are containment-checked; an output flag
> like `--csv /out` is allowed (see `mftecmd`). A tool that carves files or writes
> a CSV report is fine — it just cannot write back into the evidence root.

### Adding a New Scenario

**1. Create scenario directory:**
```
scenarios/synthetic/13_my_scenario/
├── scenario.yaml
├── fixtures/
│   ├── mft.csv
│   ├── prefetch.csv
│   └── evtx.csv
└── expected_findings.json
```

**2. Define scenario.yaml:**
```yaml
name: "My Scenario"
tier: synthetic
description: "Detect suspicious activity in my scenario"
artifacts:
  mft: fixtures/mft.csv
  prefetch: fixtures/prefetch.csv
  evtx: fixtures/evtx.csv
expected_findings:
  - title: "Suspicious Activity: example.exe"
    severity: high
    min_confidence: 0.75
```

**3. Create expected_findings.json:**
```json
{
  "expected_findings": [
    {
      "title": "Suspicious Activity: example.exe",
      "severity": "high",
      "min_confidence": 0.75
    }
  ]
}
```

**4. Run validation:**
```bash
python -m sift_find_evil.cli run --scenario scenarios/synthetic/13_my_scenario

# Or run all scenarios
PYTHONPATH=. python3 tests/scenario_harness.py
```

---

## Pull Request Process

### Before Submitting

1. **Run all quality checks:**
```bash
# Format code
black sift_find_evil/

# Lint
ruff check sift_find_evil/

# Type check
mypy sift_find_evil/

# Run tests
pytest --cov=sift_find_evil

# Run scenario harness
PYTHONPATH=. python3 tests/scenario_harness.py
```

2. **Update documentation:**
   - Add docstrings to new functions/classes
   - Update README.md if adding CLI commands
   - Update ARCHITECTURE.md if changing core design
   - Add examples to EXAMPLES.md if applicable

3. **Write tests:**
   - Unit tests for new functions/classes
   - Integration tests for CLI commands
   - Scenario tests for new detectors
   - Maintain 85%+ coverage

### PR Template

```markdown
## Description

Brief description of changes.

## Type of Change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing

- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Scenario tests added/updated
- [ ] All tests passing
- [ ] Coverage >= 85%

## Checklist

- [ ] Code follows PEP 8 style guide
- [ ] Code formatted with Black
- [ ] Linting passes (ruff)
- [ ] Type hints added
- [ ] Docstrings added
- [ ] Tests added
- [ ] Documentation updated
- [ ] Scenario harness passes (12/12 @ F1=1.00)
```

### Review Process

1. **Automated checks:** CI/CD runs on all PRs
   - ruff linting
   - pytest with coverage
   - Scenario harness validation

2. **Code review:** Maintainers review for:
   - Code quality and style
   - Test coverage
   - Documentation completeness
   - Performance implications

3. **Approval:** At least one maintainer approval required

4. **Merge:** Squash and merge to maintain clean history

---

## Release Process

### Version Numbers

**Semantic Versioning:** `MAJOR.MINOR.PATCH`

- **MAJOR:** Breaking changes
- **MINOR:** New features (backward compatible)
- **PATCH:** Bug fixes (backward compatible)

### Release Checklist

1. **Update version:**
   - `sift_find_evil/__init__.py` - `__version__ = "1.1.0"`
   - `docs/ARCHITECTURE.md` - Document Version
   - `README.md` - Version badges

2. **Update CHANGELOG:**
   ```markdown
   ## [1.1.0] - 2026-04-23
   ### Added
   - Human-in-the-loop approval workflow
   - Case management with SHA-256 verification
   - Audit logging for chain-of-custody
   - Report generation (Markdown, HTML)
   
   ### Changed
   - CLI now requires explicit approval before report generation
   
   ### Fixed
   - None
   ```

3. **Run full test suite:**
   ```bash
   pytest --cov=sift_find_evil
   PYTHONPATH=. python3 tests/scenario_harness.py
   ```

4. **Create Git tag:**
   ```bash
   git tag -a v1.1.0 -m "Release v1.1.0: Hackathon Features"
   git push origin v1.1.0
   ```

5. **Create GitHub release:**
   - Title: `v1.1.0 - Hackathon Features`
   - Description: Copy from CHANGELOG.md
   - Attach: `sift_find_evil-1.1.0.tar.gz` (optional)

---

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and harassment-free environment for all contributors.

### Standards

**Positive behavior:**
- Using welcoming and inclusive language
- Being respectful of differing viewpoints
- Gracefully accepting constructive criticism
- Focusing on what is best for the community

**Unacceptable behavior:**
- Trolling, insulting/derogatory comments, personal attacks
- Public or private harassment
- Publishing others' private information without permission

### Enforcement

Violations may result in temporary or permanent ban from the project.

---

## Getting Help

- **GitHub Issues:** https://github.com/jtomek-strike48/sift_find_evil/issues
- **Documentation:** [README.md](../README.md), [ARCHITECTURE.md](ARCHITECTURE.md)
- **Email:** hackathon@example.com

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Last Updated:** 2026-04-23
