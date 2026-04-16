# Contributing to SIFT Find Evil

Thank you for your interest in contributing to SIFT Find Evil! This document provides guidelines for contributing to the project.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/yourusername/sift-find-evil.git
   cd sift-find-evil
   ```
3. **Set up development environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

## Development Workflow

### Branching Strategy

- `main` - Production-ready code, hackathon submission version
- `develop` - Active development branch
- `feature/*` - New features (e.g., `feature/timeline-reconstruction`)
- `fix/*` - Bug fixes (e.g., `fix/timestamp-parsing`)
- `docs/*` - Documentation updates (e.g., `docs/prd-section-3`)

### Making Changes

1. **Create a feature branch** from `develop`:
   ```bash
   git checkout develop
   git pull origin develop
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following coding standards (see below)

3. **Write tests** for new functionality:
   ```bash
   # Unit tests
   pytest tests/unit/test_your_feature.py

   # Integration tests
   pytest tests/integration/test_your_feature.py
   ```

4. **Ensure code quality**:
   ```bash
   # Run all tests
   pytest

   # Check code coverage (target: 80%+)
   pytest --cov=sift_find_evil --cov-report=html

   # Format code
   black src/sift_find_evil tests/

   # Lint code
   pylint src/sift_find_evil

   # Type checking
   mypy src/sift_find_evil
   ```

5. **Commit changes** with descriptive messages:
   ```bash
   git add .
   git commit -m "feat: Add cross-artifact timestamp validation

   - Implement MFT vs Prefetch timestamp comparison
   - Add contradiction detection logic
   - Include unit tests with 90% coverage
   - Update audit logging for validation events
   "
   ```

6. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Open a Pull Request** on GitHub targeting `develop` branch

## Coding Standards

### Python Style Guide

- **Follow PEP 8** for code style
- **Use type hints** for all function signatures
- **Docstrings** for all modules, classes, and functions (Google style)
- **Maximum line length:** 100 characters
- **Use Black** for automatic formatting

Example:
```python
def parse_mft_timestamp(file_path: str) -> datetime:
    """Parse MFT $STANDARD_INFORMATION timestamp for a file.

    Args:
        file_path: Path to the file within the mounted disk image.

    Returns:
        Parsed timestamp in UTC as datetime object.

    Raises:
        FileNotFoundError: If file does not exist in MFT.
        TimestampParseError: If timestamp format is invalid.
    """
    # Implementation here
    pass
```

### Testing Requirements

- **Minimum 80% code coverage** for all new code
- **Unit tests** for all functions with complex logic
- **Integration tests** for features that invoke Protocol SIFT MCP tools
- **Test file naming:** `test_<module_name>.py`
- **Test function naming:** `test_<function_name>_<scenario>()`

Example:
```python
def test_parse_mft_timestamp_valid_format():
    """Test MFT timestamp parsing with valid format."""
    timestamp = parse_mft_timestamp("/path/to/file.txt")
    assert isinstance(timestamp, datetime)
    assert timestamp.tzinfo == timezone.utc

def test_parse_mft_timestamp_missing_file():
    """Test MFT timestamp parsing when file does not exist."""
    with pytest.raises(FileNotFoundError):
        parse_mft_timestamp("/nonexistent/file.txt")
```

### Commit Message Format

Use conventional commits:

```
<type>: <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Build process, tooling, dependencies

**Example:**
```
feat: Implement uncertainty budget self-correction

- Track cumulative uncertainty across analysis steps
- Trigger re-investigation when threshold (0.25) exceeded
- Add confidence scoring to all findings
- Update audit logs to include uncertainty metrics

Closes #42
```

## Pull Request Guidelines

### PR Checklist

Before submitting a PR, ensure:

- [ ] All tests pass (`pytest`)
- [ ] Code coverage ≥80% (`pytest --cov`)
- [ ] Code formatted with Black
- [ ] No linting errors (`pylint`)
- [ ] Type checking passes (`mypy`)
- [ ] Documentation updated (docstrings, README, PRD if applicable)
- [ ] Audit logging added for key decisions
- [ ] Commit messages follow conventional format
- [ ] PR description explains the change and why it's needed

### PR Description Template

```markdown
## Description
Brief description of what this PR does.

## Related Issues
Closes #123
Related to #456

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
Describe how you tested this change:
- Unit tests added/updated
- Integration tests added/updated
- Manual testing performed (describe scenarios)

## Screenshots (if applicable)
Add screenshots for UI changes or demo-worthy features.

## Checklist
- [ ] Tests pass
- [ ] Code coverage ≥80%
- [ ] Documentation updated
- [ ] Audit logging added
```

## Issue Guidelines

### Reporting Bugs

Use the **Bug Report** template and include:
- Description of the bug
- Steps to reproduce
- Expected behavior
- Actual behavior
- Environment details (OS, Python version, SIFT tools version)
- Logs or error messages

### Requesting Features

Use the **New Feature or Tool Wrapper** template and include:
- User story (who needs this and why)
- Technical approach
- Dependencies
- Testing strategy

### Documenting TTPs

Use the **TTP / Process Documentation** template and include:
- Context / when to use
- Step-by-step procedure
- Decision points
- Tools used
- Expected outputs
- Lessons learned

## Hackathon-Specific Guidelines

For contributions before June 15, 2026 deadline:

1. **Priority:** Focus on MUST-HAVE features (see PRD Section 2.5)
2. **Demo-readiness:** Ensure features can be demonstrated in ≤60 seconds
3. **Audit logging:** All features must log decisions, tool calls, and reasoning
4. **Self-correction:** If building self-correction features, use the **Self-Correction Scenario** template
5. **Accuracy:** Test on NIST CFReDS dataset and update accuracy report

## Code Review Process

1. **Automated checks** run on all PRs (tests, linting, coverage)
2. **Manual review** by project maintainer (usually within 48 hours)
3. **Feedback addressed** - update PR based on review comments
4. **Approved and merged** to `develop` branch
5. **Release to main** when stable and ready for hackathon submission

## Community Guidelines

- **Be respectful** and constructive in all interactions
- **Ask questions** if requirements are unclear
- **Share knowledge** - document your learnings in TTPs
- **Celebrate wins** - recognize contributions from others

## Getting Help

- **GitHub Issues:** https://github.com/yourusername/sift-find-evil/issues
- **Documentation:** See [docs/](docs/) directory
- **Questions:** Open a GitHub Discussion or issue with `question` label

Thank you for contributing to SIFT Find Evil!
