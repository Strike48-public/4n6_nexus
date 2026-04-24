# Repository Management Strategy

**Status:** Approved for implementation
**Date:** 2026-04-24
**Owner:** Core team

## Overview

This document describes how we manage the split between open-source (Community Edition) and proprietary (Professional/Enterprise) codebases for 4n6Nexus.

## Current State

- **Repository:** `sift_find_evil` (private)
- **Location:** `/home/jtomek/Code/sift_find_evil`
- **Contents:** All code (community + enterprise)
- **License:** Mixed (to be split)

## Target State

### Repository Structure

```
4n6nexus/4n6nexus                    (PUBLIC - Community Edition)
├── sift_find_evil/                   Core platform
│   ├── mcp/                          MCP safety layer
│   ├── self_correction/              Self-correction engine
│   ├── detectors/                    5 basic detectors only
│   ├── parsers/                      Tool integrations
│   ├── case_management/              Basic case handling
│   └── cli.py                        CLI interface
├── tests/                            Test harness + 5 scenarios
├── docs/                             Community documentation
├── scripts/setup/                    Installation scripts
├── LICENSE                           MIT License
└── README.md                         Community README

4n6nexus/4n6nexus-enterprise         (PRIVATE - Enterprise Edition)
├── sift_find_evil/
│   ├── detectors/
│   │   └── memory/                   Memory forensics (7+ detectors)
│   ├── correlation/                  Advanced correlation engine
│   ├── web_ui/                       Web dashboard
│   ├── api/                          REST API
│   └── enterprise/                   Team features, RBAC, SSO
├── tests/scenarios/real/             Real evidence scenarios
├── docs/                             Internal documentation
├── LICENSE                           Proprietary
└── README.md                         Enterprise README
```

### Repository Relationships

**Option 1: Git Submodule (Recommended for Now)**
```bash
# Enterprise repo includes community as submodule
cd 4n6nexus-enterprise
git submodule add https://github.com/4n6nexus/4n6nexus.git community

# Enterprise imports from community
from community.sift_find_evil.mcp import MCPClient
```

**Option 2: Python Package (Long-Term Goal)**
```bash
# Publish community to PyPI
pip install 4n6nexus

# Enterprise depends on it
# requirements.txt
4n6nexus>=1.0.0,<2.0.0
```

## File Split Mapping

### Community Edition (Open Source - MIT)

| Current Path | New Path | Reason |
|-------------|----------|---------|
| `sift_find_evil/mcp/` | `sift_find_evil/mcp/` | Core safety layer |
| `sift_find_evil/self_correction/` | `sift_find_evil/self_correction/` | Core self-correction |
| `sift_find_evil/detectors/base.py` | `sift_find_evil/detectors/base.py` | Detector framework |
| `sift_find_evil/detectors/timestomping.py` | `sift_find_evil/detectors/timestomping.py` | Basic detector |
| `sift_find_evil/detectors/suspicious_ext.py` | `sift_find_evil/detectors/suspicious_ext.py` | Basic detector |
| `sift_find_evil/detectors/hidden_files.py` | `sift_find_evil/detectors/hidden_files.py` | Basic detector |
| `sift_find_evil/detectors/file_size.py` | `sift_find_evil/detectors/file_size.py` | Basic detector |
| `sift_find_evil/detectors/timeline.py` | `sift_find_evil/detectors/timeline.py` | Basic detector |
| `sift_find_evil/parsers/` | `sift_find_evil/parsers/` | Tool integrations |
| `sift_find_evil/case_management/` | `sift_find_evil/case_management/` | Basic case handling |
| `sift_find_evil/cli.py` | `sift_find_evil/cli.py` | CLI interface (basic commands only) |
| `tests/scenario_harness.py` | `tests/scenario_harness.py` | Test framework |
| `tests/scenarios/synthetic/` (5 scenarios) | `tests/scenarios/synthetic/` | Validation scenarios |
| `docs/ARCHITECTURE_DIAGRAM.md` | `docs/ARCHITECTURE.md` | System design |
| `docs/README_COMMUNITY.md` | `README.md` | Community README |
| `scripts/setup/` | `scripts/setup/` | Installation scripts |
| `LICENSE` (create new) | `LICENSE` | MIT License |
| `.gitignore` | `.gitignore` | Python gitignore |
| `pyproject.toml` (create new) | `pyproject.toml` | Package metadata |
| `requirements.txt` (subset) | `requirements.txt` | Core dependencies |

### Enterprise Edition (Proprietary)

| Path | Reason |
|------|--------|
| `sift_find_evil/detectors/memory/` | Memory forensics (competitive advantage) |
| `sift_find_evil/correlation/advanced/` | Advanced correlation logic |
| `sift_find_evil/integrations/` | SIEM, ticketing, threat intel |
| `sift_find_evil/web_ui/` | Web dashboard |
| `sift_find_evil/api/` | REST API |
| `sift_find_evil/enterprise/` | RBAC, SSO, reporting |
| `tests/scenarios/real/` | Real evidence scenarios |
| `docs/OPEN_SOURCE_STRATEGY.md` | Internal strategy doc |
| All other internal docs | Internal only |

## Implementation Plan

### Phase 1: Document & Prepare (Today)

1. ✅ Create this document
2. Create split script (`scripts/create_community_repo.sh`)
3. Create enterprise rename script
4. Review with team

### Phase 2: Create Community Repo (Day 2)

1. Run split script to create `../4n6nexus` directory
2. Create GitHub repo: `4n6nexus/4n6nexus`
3. Push community code
4. Verify CI/CD passes
5. Test clean installation

### Phase 3: Rename Enterprise Repo (Day 3)

1. Rename current repo: `sift_find_evil` → `4n6nexus-enterprise`
2. Update all internal references
3. Add community repo as submodule (or document manual sync)
4. Update documentation

### Phase 4: Competition Submission (Day 4-5)

1. Record demo video
2. Submit to Devpost with public community repo
3. Monitor for feedback

## Split Script

### scripts/create_community_repo.sh

```bash
#!/usr/bin/env bash
# Create Community Edition repository from current codebase

set -euo pipefail

# Configuration
CURRENT_REPO="/home/jtomek/Code/sift_find_evil"
COMMUNITY_REPO="/home/jtomek/Code/4n6nexus"
TEMP_DIR=$(mktemp -d)

echo "=== 4n6Nexus Community Edition Repository Creator ==="
echo ""
echo "Current repo: $CURRENT_REPO"
echo "Community repo: $COMMUNITY_REPO"
echo "Temp directory: $TEMP_DIR"
echo ""

# Verify we're in the right place
if [[ ! -d "$CURRENT_REPO/sift_find_evil" ]]; then
  echo "ERROR: Current directory is not sift_find_evil repo"
  exit 1
fi

# Create community repo structure
echo "Creating community repository structure..."
mkdir -p "$COMMUNITY_REPO"
cd "$COMMUNITY_REPO"

# Initialize git
git init
echo "# 4n6Nexus Community Edition" > README.md
git add README.md
git commit -m "Initial commit"

# Copy core platform files
echo ""
echo "Copying core platform files..."

# MCP safety layer
cp -r "$CURRENT_REPO/sift_find_evil/mcp" sift_find_evil/mcp
echo "✓ MCP safety layer"

# Self-correction engine
cp -r "$CURRENT_REPO/sift_find_evil/self_correction" sift_find_evil/self_correction
echo "✓ Self-correction engine"

# Detectors (basic only)
mkdir -p sift_find_evil/detectors
cp "$CURRENT_REPO/sift_find_evil/detectors/__init__.py" sift_find_evil/detectors/
cp "$CURRENT_REPO/sift_find_evil/detectors/base.py" sift_find_evil/detectors/
cp "$CURRENT_REPO/sift_find_evil/detectors/timestomping.py" sift_find_evil/detectors/
cp "$CURRENT_REPO/sift_find_evil/detectors/suspicious_ext.py" sift_find_evil/detectors/
cp "$CURRENT_REPO/sift_find_evil/detectors/hidden_files.py" sift_find_evil/detectors/
cp "$CURRENT_REPO/sift_find_evil/detectors/file_size.py" sift_find_evil/detectors/
cp "$CURRENT_REPO/sift_find_evil/detectors/timeline.py" sift_find_evil/detectors/
echo "✓ Basic detectors (5)"

# Parsers
cp -r "$CURRENT_REPO/sift_find_evil/parsers" sift_find_evil/parsers
echo "✓ Parsers"

# Case management
cp -r "$CURRENT_REPO/sift_find_evil/case_management" sift_find_evil/case_management
echo "✓ Case management"

# CLI (basic commands only - may need manual editing)
cp "$CURRENT_REPO/sift_find_evil/cli.py" sift_find_evil/cli.py
echo "✓ CLI interface"

# Copy test framework
echo ""
echo "Copying test framework..."
mkdir -p tests
cp "$CURRENT_REPO/tests/scenario_harness.py" tests/
cp -r "$CURRENT_REPO/tests/scenarios/synthetic" tests/scenarios/
echo "✓ Test harness + synthetic scenarios"

# Copy documentation
echo ""
echo "Copying documentation..."
mkdir -p docs
cp "$CURRENT_REPO/docs/ARCHITECTURE_DIAGRAM.md" docs/ARCHITECTURE.md
cp "$CURRENT_REPO/docs/README_COMMUNITY.md" README.md
cp "$CURRENT_REPO/docs/logo_banner.svg" docs/
echo "✓ Community documentation"

# Copy setup scripts
echo ""
echo "Copying setup scripts..."
cp -r "$CURRENT_REPO/scripts/setup" scripts/
echo "✓ Installation scripts"

# Create LICENSE (MIT)
echo ""
echo "Creating MIT License..."
cat > LICENSE << 'EOF'
MIT License

Copyright (c) 2024 4n6Nexus Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
EOF
echo "✓ MIT License"

# Create .gitignore
echo ""
echo "Creating .gitignore..."
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# Virtual environments
venv/
env/
ENV/
.venv

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# Testing
.pytest_cache/
.coverage
htmlcov/
.tox/

# Case data
/cases/
*.E01
*.raw
*.dd
*.mem

# Logs
*.log
audit.jsonl
EOF
echo "✓ .gitignore"

# Create pyproject.toml
echo ""
echo "Creating pyproject.toml..."
cat > pyproject.toml << 'EOF'
[build-system]
requires = ["setuptools>=68.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "4n6nexus"
version = "1.0.0"
description = "Autonomous DFIR with Architectural Self-Correction"
readme = "README.md"
requires-python = ">=3.11"
license = {text = "MIT"}
authors = [
    {name = "4n6Nexus Contributors"},
]
keywords = ["dfir", "forensics", "incident-response", "automation", "mcp"]
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Information Technology",
    "Intended Audience :: Science/Research",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Security",
    "Topic :: System :: Monitoring",
]

dependencies = [
    "click>=8.1.0",
    "pydantic>=2.0.0",
    "rich>=13.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.4.0",
    "pytest-cov>=4.1.0",
    "black>=23.0.0",
    "ruff>=0.1.0",
    "mypy>=1.5.0",
]

[project.urls]
Homepage = "https://4n6nexus.dev"
Documentation = "https://docs.4n6nexus.dev"
Repository = "https://github.com/4n6nexus/4n6nexus"
"Bug Tracker" = "https://github.com/4n6nexus/4n6nexus/issues"

[project.scripts]
4n6nexus = "sift_find_evil.cli:main"

[tool.setuptools.packages.find]
where = ["."]
include = ["sift_find_evil*"]

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]
addopts = "--cov=sift_find_evil --cov-report=html --cov-report=term"

[tool.black]
line-length = 100
target-version = ['py311']

[tool.ruff]
line-length = 100
target-version = "py311"
select = ["E", "F", "W", "I", "N", "UP"]
EOF
echo "✓ pyproject.toml"

# Create requirements.txt (subset)
echo ""
echo "Creating requirements.txt..."
cat > requirements.txt << 'EOF'
# Core dependencies
click>=8.1.0
pydantic>=2.0.0
rich>=13.0.0

# Optional dependencies (uncomment as needed)
# pandas>=2.0.0  # For CSV parsing
# numpy>=1.24.0  # For numerical analysis
EOF
echo "✓ requirements.txt"

# Create CONTRIBUTING.md
echo ""
echo "Creating CONTRIBUTING.md..."
cat > CONTRIBUTING.md << 'EOF'
# Contributing to 4n6Nexus

We welcome contributions from the DFIR community!

## How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-detector`)
3. Write tests first (TDD approach, 80% coverage minimum)
4. Implement your feature
5. Run tests (`pytest tests/`)
6. Run linters (`ruff check . && black --check .`)
7. Submit a pull request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/4n6nexus.git
cd 4n6nexus

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Run linters
ruff check .
black --check .
```

## Code Style

- Follow PEP 8
- Use Black for formatting (line length: 100)
- Use Ruff for linting
- Use type hints (mypy checked)
- Write docstrings (Google style)

## Testing

- Write tests first (TDD)
- Minimum 80% code coverage
- Use pytest for all tests
- Add test scenarios for new detectors

## Pull Request Process

1. Update documentation if needed
2. Add tests for new features
3. Ensure all tests pass
4. Update CHANGELOG.md
5. Request review from maintainers

## Code of Conduct

- Be respectful and professional
- Focus on technical merit
- Help others learn
- Follow the DFIR community standards

## Questions?

Open a GitHub Discussion or reach out to hello@4n6nexus.dev
EOF
echo "✓ CONTRIBUTING.md"

# Git commit
echo ""
echo "Committing files to git..."
git add .
git commit -m "feat: initial community edition

- Core MCP safety layer
- Self-correction engine
- 5 basic detectors
- Test harness with synthetic scenarios
- Complete documentation
- MIT License

Built on SANS SIFT Workstation + MCP Protocol
Submission for FIND EVIL! Hackathon"

echo ""
echo "=== Community Repository Created Successfully ==="
echo ""
echo "Location: $COMMUNITY_REPO"
echo ""
echo "Next steps:"
echo "1. Review the repository: cd $COMMUNITY_REPO"
echo "2. Test installation: pip install -e ."
echo "3. Run tests: pytest tests/"
echo "4. Create GitHub repo and push"
echo ""
echo "GitHub commands:"
echo "  cd $COMMUNITY_REPO"
echo "  git remote add origin https://github.com/4n6nexus/4n6nexus.git"
echo "  git branch -M main"
echo "  git push -u origin main"
echo ""
```

### scripts/rename_enterprise_repo.sh

```bash
#!/usr/bin/env bash
# Rename current repo from sift_find_evil to 4n6nexus-enterprise

set -euo pipefail

CURRENT_REPO="/home/jtomek/Code/sift_find_evil"
NEW_NAME="4n6nexus-enterprise"
NEW_REPO="/home/jtomek/Code/$NEW_NAME"

echo "=== Rename Enterprise Repository ==="
echo ""
echo "Current: $CURRENT_REPO"
echo "New: $NEW_REPO"
echo ""

# Verify we're in the right place
if [[ ! -d "$CURRENT_REPO/.git" ]]; then
  echo "ERROR: Not a git repository"
  exit 1
fi

cd "$CURRENT_REPO"

# Check for uncommitted changes
if [[ -n $(git status --porcelain) ]]; then
  echo "ERROR: Uncommitted changes detected. Commit or stash first."
  git status
  exit 1
fi

echo "Moving repository directory..."
cd ..
mv sift_find_evil "$NEW_NAME"
cd "$NEW_NAME"

echo "✓ Directory renamed"

# Update remote URL (if GitHub repo exists)
echo ""
echo "Update GitHub remote URL manually:"
echo "  1. Rename repo on GitHub: sift_find_evil → 4n6nexus-enterprise"
echo "  2. Run: git remote set-url origin https://github.com/YOUR_ORG/4n6nexus-enterprise.git"
echo ""

# Update README
if [[ -f "README.md" ]]; then
  echo "Updating README.md..."
  sed -i 's/sift_find_evil/4n6nexus-enterprise/g' README.md
  sed -i 's/SIFT Find Evil/4n6Nexus Enterprise Edition/g' README.md
  git add README.md
  git commit -m "docs: rename to 4n6nexus-enterprise"
  echo "✓ README updated"
fi

echo ""
echo "=== Repository Renamed Successfully ==="
echo ""
echo "Location: $NEW_REPO"
echo ""
echo "Next steps:"
echo "1. Update GitHub repo name (Settings → Repository name)"
echo "2. Update remote URL: git remote set-url origin <new-url>"
echo "3. Verify: git remote -v"
echo "4. Update any CI/CD references"
echo ""
```

## Maintenance Workflow

### Syncing Bug Fixes

**When you fix a bug in community code:**

```bash
# Option A: If using Git Submodule
cd 4n6nexus-enterprise
git submodule update --remote community
git add community
git commit -m "chore: update community submodule (bug fixes)"

# Option B: If using Manual Copy
cd 4n6nexus  # Community repo
git pull
# Copy changed files to enterprise repo manually
cd ../4n6nexus-enterprise
cp ../4n6nexus/sift_find_evil/mcp/client.py sift_find_evil/mcp/
git add sift_find_evil/mcp/client.py
git commit -m "fix: sync MCP timeout handling from community"
```

### Adding Enterprise Features

**Only in enterprise repo:**

```bash
cd 4n6nexus-enterprise
# Add new memory forensics detector
# No need to touch community repo
git add sift_find_evil/detectors/memory/new_detector.py
git commit -m "feat: add memory injection detector"
```

### Backporting Community PRs

**When community contributors add features:**

```bash
# Community repo (public)
cd 4n6nexus
git checkout -b feature/new-basic-detector
# Contributor implements feature
git add sift_find_evil/detectors/new_detector.py
git commit -m "feat: add registry modification detector"
git push origin feature/new-basic-detector

# Review PR, merge to main

# Enterprise repo (private)
cd ../4n6nexus-enterprise
git submodule update --remote community  # Pull latest
# OR manually copy if not using submodule
```

## Security Considerations

### Preventing Leaks

1. **Never commit enterprise code to community repo**
   - Review every commit before pushing
   - Use `.gitignore` to exclude enterprise directories
   - CI checks for leaked paths

2. **Code review checklist**
   - No memory forensics logic
   - No advanced correlation algorithms
   - No web UI components
   - No enterprise integrations

3. **Automated checks**
   - CI fails if enterprise paths detected in community repo
   - Pre-commit hook warns about sensitive files

### Access Control

- **Community repo:** Public on GitHub
- **Enterprise repo:** Private, team-only access
- **CI/CD secrets:** Separate for each repo
- **PyPI publishing:** Only community package

## Release Strategy

### Community Edition

- **Version:** Semantic versioning (1.0.0, 1.1.0, 2.0.0)
- **Cadence:** Monthly minor releases, patches as needed
- **Process:** Tag → GitHub Release → PyPI publish
- **CHANGELOG:** Public, all changes documented

### Enterprise Edition

- **Version:** Independent from community (could be 2.x while community is 1.x)
- **Cadence:** Quarterly major releases
- **Process:** Internal release process
- **CHANGELOG:** Private, customer-facing only

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2024-04-24 | Use Git Submodule for now | Simple, low overhead during competition |
| 2024-04-24 | Split repositories (not monorepo) | Clear separation, easier access control |
| 2024-04-24 | Keep 5 basic detectors in community | Demonstrates capability without giving away IP |
| 2024-04-24 | Memory forensics stays private | Core competitive advantage |

## Questions & Answers

**Q: Can community contributors see enterprise code?**
A: No, enterprise repo is private.

**Q: Can we merge community PRs without review?**
A: No, all PRs must be reviewed for quality and scope.

**Q: What if someone forks community and builds competing product?**
A: That's allowed (MIT license). Our advantage is advanced features + support.

**Q: Should we accept community PRs for advanced features?**
A: Depends - evaluate if it belongs in community or enterprise tier.

**Q: How do we handle security vulnerabilities in community code?**
A: Fix in community repo first (public disclosure after fix), then sync to enterprise.

---

**Document Owner:** Core Team
**Last Updated:** 2026-04-24
**Next Review:** After competition submission
