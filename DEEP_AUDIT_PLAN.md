# Deep Code Audit & Documentation Plan

**Goal**: Professional-grade code quality and documentation for production readiness

**Date**: 2026-04-18  
**Previous Audit**: Basic cleanup complete (linting, agent notes, security scan)  
**Next Level**: Deep code review, comprehensive documentation, test quality

---

## Why Go Deeper?

Initial cleanup covered:
- ✅ Surface-level issues (linting, formatting)
- ✅ Agent notes removal
- ✅ Basic security scan

**Not yet covered**:
- ❌ Code logic review (correctness, bugs)
- ❌ Architecture consistency
- ❌ Comprehensive documentation
- ❌ Test quality and completeness
- ❌ API documentation
- ❌ User guides and examples

---

## Phase 1: Deep Code Review (2-3 hours)

### 1.1 Function-by-Function Logic Review

**Goal**: Review actual code logic for correctness, not just style

**Areas to examine**:

#### Timestamp Handling
- [ ] UTC vs local timezone consistency
- [ ] Null/missing timestamp handling
- [ ] Leap seconds and edge cases
- [ ] Format parsing robustness

#### File Hashing
- [ ] Memory efficiency for large files
- [ ] Error handling for unreadable files
- [ ] Hash algorithm consistency
- [ ] Buffer size optimization

#### Correlation Logic
- [ ] Time window boundaries (inclusive/exclusive)
- [ ] Hash matching accuracy
- [ ] False positive scenarios
- [ ] Edge cases (empty lists, single items)

#### Evidence Chain
- [ ] Reasoning chain completeness
- [ ] Contradiction detection accuracy
- [ ] Confidence calculation correctness
- [ ] Evidence preservation

**Method**:
```bash
# Review each core module systematically
# 1. Read function
# 2. Identify edge cases
# 3. Check if tests cover them
# 4. Write tests for gaps
# 5. Fix any bugs found
```

### 1.2 Error Handling Audit

**Goal**: Ensure all error paths are handled properly

**Check for**:
- [ ] Bare try/except blocks
- [ ] Errors that are swallowed silently
- [ ] Missing error messages
- [ ] Unclear error messages
- [ ] Errors that expose internal details to users
- [ ] Missing validation on inputs

**Example issues to find**:
```python
# Bad: Silent failure
try:
    process_file(path)
except:
    pass  # BUG: No logging, no re-raise

# Good: Proper handling
try:
    process_file(path)
except FileNotFoundError as e:
    logger.error(f"File not found: {path}")
    raise
except PermissionError as e:
    logger.error(f"Permission denied: {path}")
    raise
```

### 1.3 Edge Case Analysis

**Goal**: Find edge cases that aren't tested

**Scenarios**:
- [ ] Empty input files
- [ ] Single-entry datasets
- [ ] Very large files (>1GB)
- [ ] Corrupted file formats
- [ ] Missing required fields
- [ ] Duplicate entries
- [ ] Out-of-order timestamps
- [ ] Timezone edge cases (DST transitions)
- [ ] Null bytes in strings
- [ ] Unicode edge cases

**Method**: Create test cases for each scenario

### 1.4 Performance Review

**Goal**: Identify performance bottlenecks and optimization opportunities

**Profile**:
```bash
# Profile key operations
python -m cProfile -o profile.stats scripts/analyze_circl_executables.py
python -c "import pstats; p = pstats.Stats('profile.stats'); p.sort_stats('cumulative').print_stats(30)"
```

**Check**:
- [ ] O(n²) loops that should be O(n)
- [ ] Repeated file I/O
- [ ] Unnecessary object creation
- [ ] Missing caching opportunities
- [ ] Inefficient data structures

### 1.5 Architecture Consistency

**Goal**: Ensure patterns are consistent across codebase

**Review**:
- [ ] Data classes follow same pattern
- [ ] Error handling is consistent
- [ ] Logging is consistent
- [ ] Return types are consistent (dict vs object)
- [ ] Function naming conventions
- [ ] Module organization

**Common inconsistencies to find**:
```python
# Inconsistent return types
def parse_a() -> list[Entry]:  # Returns objects
def parse_b() -> list[dict]:   # Returns dicts (inconsistent)

# Inconsistent error handling
def read_a():
    if not path.exists():
        raise FileNotFoundError()  # Raises exception

def read_b():
    if not path.exists():
        return None  # Returns None (inconsistent)
```

---

## Phase 2: Test Quality Improvement (2-3 hours)

### 2.1 Coverage Analysis

**Goal**: Increase coverage from 60% to 80%+

**Target modules** (currently <80%):
```
exfil_detector.py          40% → 80%
image_content_reader.py    24% → 80%
prefetch_parser.py         55% → 80%
evtx_parser.py            63% → 80%
mft_parser.py             67% → 80%
gpt_inspector.py          68% → 80%
```

**Method**:
1. Run coverage with missing lines: `pytest --cov-report=html`
2. Open htmlcov/index.html
3. For each module, identify untested lines
4. Write tests to cover them

### 2.2 Test Quality Review

**Goal**: Ensure tests are actually testing behavior, not just coverage

**Bad test examples**:
```python
# Bad: Just calling the function
def test_parse():
    result = parse_file("test.csv")
    assert result is not None  # Not testing behavior!

# Good: Testing actual behavior
def test_parse_extracts_timestamps():
    result = parse_file("test.csv")
    assert len(result) == 3
    assert result[0].timestamp == datetime(2026, 1, 1, 12, 0, 0)
    assert result[0].file_path == "C:\\Windows\\explorer.exe"
```

**Review each test for**:
- [ ] Tests behavior, not implementation
- [ ] Clear test name describing what's tested
- [ ] Single logical assertion per test
- [ ] Uses AAA pattern (Arrange, Act, Assert)
- [ ] Doesn't test multiple things
- [ ] Has clear failure messages

### 2.3 Missing Test Scenarios

**Goal**: Identify scenarios that have no tests

**Categories to check**:
- [ ] Happy path (basic success case)
- [ ] Edge cases (empty, single, large)
- [ ] Error cases (file not found, corrupt data)
- [ ] Boundary conditions (time windows, thresholds)
- [ ] Integration between modules
- [ ] Regression tests for known bugs

**Example**:
```python
# If we find this code:
if time_delta <= 60:
    return 0.95
elif time_delta <= 180:
    return 0.90
else:
    return 0.85

# We need tests for:
test_confidence_at_60_seconds()      # Boundary
test_confidence_at_61_seconds()      # Just after boundary
test_confidence_at_180_seconds()     # Boundary
test_confidence_at_181_seconds()     # Just after boundary
test_confidence_very_large_delta()   # Far from boundary
```

### 2.4 Test Fixtures and Helpers

**Goal**: Reduce test duplication with good fixtures

**Current issues**:
- Duplicate test data creation
- Repeated setup code
- Hard to maintain tests

**Improvements**:
```python
# Create reusable fixtures
@pytest.fixture
def sample_mft_entries():
    """Returns realistic MFT entries for testing."""
    return [
        MFTEntry(
            file_path="C:\\Windows\\explorer.exe",
            file_size=4194304,
            si_modified=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            fn_modified=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        ),
        # ... more entries
    ]
```

---

## Phase 3: Comprehensive Documentation (3-4 hours)

### 3.1 Docstring Coverage

**Goal**: Every public function has complete docstring

**Format** (Google style):
```python
def correlate_hashes(
    file_hashes: dict[str, tuple[MFTEntry, str]],
    emails: list[EmailMessage],
    time_window_seconds: int,
) -> list[ExfilMatch]:
    """Correlate file hashes with email attachment hashes.

    Searches for files that were modified and then sent as email
    attachments within a specified time window. Uses SHA-256 hash
    matching for file identification.

    Args:
        file_hashes: Dictionary mapping SHA-256 hash to (MFT entry, hash).
            The MFT entry contains file metadata including modification time.
        emails: List of email messages with attachments to check.
            Only emails with submit_time or delivery_time are processed.
        time_window_seconds: Maximum time difference (in seconds) between
            file modification and email send time. Typical value: 300.

    Returns:
        List of ExfilMatch objects, one per correlated file-to-email pair.
        Sorted by time_delta_seconds (smallest first). Empty list if no
        correlations found.

    Raises:
        ValueError: If time_window_seconds is negative.

    Example:
        >>> file_hashes = {
        ...     "abc123...": (mft_entry_1, "abc123..."),
        ...     "def456...": (mft_entry_2, "def456..."),
        ... }
        >>> emails = [email_msg_1, email_msg_2]
        >>> matches = correlate_hashes(file_hashes, emails, 300)
        >>> print(f"Found {len(matches)} correlations")
        Found 2 correlations
    """
```

**Required elements**:
- [ ] One-line summary
- [ ] Detailed description
- [ ] Args with types and descriptions
- [ ] Returns with type and description
- [ ] Raises (if applicable)
- [ ] Example (for complex functions)

**Check coverage**:
```bash
pydocstyle sift_find_evil/ --convention=google
```

### 3.2 Module Documentation

**Goal**: Every module has clear purpose and usage

**Required** in each module's docstring:
```python
"""Module name - One-line purpose.

Longer description of what this module does, why it exists,
and how it fits into the larger system.

Typical usage example:

    from sift_find_evil.parsers import mft_parser
    
    entries = mft_parser.parse_mft_csv("mft.csv")
    for entry in entries:
        print(f"{entry.file_path}: {entry.si_modified}")

Key concepts:
    - MFT Entry: Represents a file system entry
    - $STANDARD_INFORMATION: NTFS timestamp attribute
    - $FILE_NAME: NTFS filename attribute
    - Timestomping: Detecting timestamp manipulation
"""
```

### 3.3 Architecture Documentation

**Goal**: Clear system architecture documentation

**Create** `docs/ARCHITECTURE.md`:
```markdown
# System Architecture

## Overview
[High-level description]

## Components

### Parsers
Parse forensic tool output (CSV, JSON) into Python objects.

- mft_parser.py: MFTECmd CSV → MFTEntry objects
- pst_parser.py: PST files → EmailMessage objects
- pcap_parser.py: PCAP files → HTTPRequest/DNSQuery objects

### Detectors
Analyze parsed data for suspicious patterns.

- exfil_detector.py: File-to-email correlation
- wipe_detector.py: GPT partition table analysis

### Validators
Cross-check findings for consistency.

- adversarial_validator.py: Challenge CRITICAL findings
- timestamp_comparator.py: Detect timestamp anomalies

## Data Flow
[Diagrams showing how data flows through system]

## Design Patterns
[Patterns used and why]
```

### 3.4 User Guides

**Goal**: Step-by-step guides for common tasks

**Create**:

#### `docs/USER_GUIDE.md`
- Installation
- Quick start
- Common workflows
- Troubleshooting

#### `docs/EXAMPLES.md`
- M57 Jean exfiltration analysis
- CIRCL wiped disk recovery
- Nitroba harassment investigation

#### `docs/API_REFERENCE.md`
- All public functions
- Classes and data structures
- Return types and exceptions

### 3.5 Code Comments

**Goal**: Add comments only where behavior is non-obvious

**When to comment**:
- ✅ Explain WHY, not WHAT
- ✅ Document workarounds for bugs
- ✅ Explain complex algorithms
- ✅ Note performance considerations

**When NOT to comment**:
- ❌ Obvious code (`i += 1  # increment i`)
- ❌ Redundant with function name
- ❌ Outdated comments (comment rot)
- ❌ Commented-out code (use git)

**Example**:
```python
# Bad comment (explains WHAT)
# Calculate time delta in seconds
time_delta = (email_time - file_time).total_seconds()

# Good comment (explains WHY)
# Time delta must be positive (file modified before email sent).
# Negative deltas indicate causality violation or clock skew.
time_delta = (email_time - file_time).total_seconds()
if time_delta < 0:
    logger.warning(f"Causality violation: {time_delta}s")
```

---

## Phase 4: API and Type Safety (2 hours)

### 4.1 Type Annotation Coverage

**Goal**: 100% type annotation coverage

**Check current coverage**:
```bash
mypy sift_find_evil/ --strict --show-error-codes
```

**Add missing annotations**:
```python
# Before
def process(data):
    return [x for x in data if x > 0]

# After
def process(data: list[int]) -> list[int]:
    return [x for x in data if x > 0]
```

### 4.2 API Consistency

**Goal**: Consistent API across all parsers

**Standardize**:
- [ ] All parsers return list[Entry]
- [ ] All parsers take Path as input
- [ ] All parsers raise same exceptions
- [ ] All parsers have parse() function

**Example**:
```python
# Consistent API pattern
class Parser(Protocol):
    def parse(self, input_path: Path) -> list[Entry]:
        """Parse input file and return list of entries."""
        ...
```

### 4.3 Public vs Private API

**Goal**: Clear distinction between public and internal

**Convention**:
- Public: No underscore prefix
- Private: Single underscore prefix `_internal_func()`
- Very private: Double underscore `__really_internal()`

**Document public API** in `__all__`:
```python
__all__ = [
    "parse_mft_csv",
    "MFTEntry",
    "TimestampComparator",
]
```

---

## Phase 5: Compliance and Best Practices (1-2 hours)

### 5.1 License and Attribution

**Check**:
- [ ] LICENSE file present
- [ ] All source files have license header
- [ ] Third-party code attributed
- [ ] Dependencies licenses compatible

### 5.2 Security Best Practices

**Review**:
- [ ] Input validation on all user inputs
- [ ] Path traversal protection
- [ ] Command injection protection
- [ ] Secrets not in code
- [ ] Secure defaults

### 5.3 Forensic Integrity

**DFIR-specific checks**:
- [ ] Read-only evidence access
- [ ] Hash verification before analysis
- [ ] Chain of custody preserved
- [ ] All operations logged
- [ ] Timestamps in UTC
- [ ] No evidence modification

---

## Execution Strategy

### Option A: Systematic (Recommended)
Do phases sequentially for thoroughness:
1. Deep code review (2-3 hrs)
2. Test improvements (2-3 hrs)
3. Documentation (3-4 hrs)
4. API/types (2 hrs)
5. Compliance (1-2 hrs)

**Total: 10-14 hours over 2-3 days**

### Option B: High-Impact First
Prioritize most valuable improvements:
1. Docstrings (2 hrs) - immediate value
2. User guide (2 hrs) - usability
3. Test coverage to 80% (3 hrs) - quality
4. Architecture docs (2 hrs) - understanding

**Total: 9 hours focused work**

### Option C: Iterative
Small improvements each session:
- Day 1: Code review + docstrings (3 hrs)
- Day 2: Tests + examples (3 hrs)
- Day 3: Docs + API polish (3 hrs)

**Total: 9 hours spread over 3 days**

---

## Success Criteria

### Code Quality
- [ ] Zero linting errors (ruff, mypy)
- [ ] 80%+ test coverage
- [ ] All tests passing
- [ ] No known bugs

### Documentation Quality
- [ ] 100% docstring coverage on public functions
- [ ] Architecture document complete
- [ ] User guide with examples
- [ ] API reference generated

### Professional Ready
- [ ] Production-grade error handling
- [ ] Comprehensive logging
- [ ] Clear separation of concerns
- [ ] Consistent patterns throughout

---

## Which approach should we take?

**Recommendations**:
- **For immediate improvements**: Option B (High-Impact First)
- **For thorough audit**: Option A (Systematic)
- **For ongoing improvement**: Option C (Iterative)

**What's your preference?**
