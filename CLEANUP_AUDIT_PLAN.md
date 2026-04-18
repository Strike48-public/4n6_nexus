# Project Cleanup & Code Audit Plan

**Date**: 2026-04-18  
**Status**: All backlog work complete, ready for cleanup

---

## 1. Agent Planning Notes Cleanup

**Issue**: Temporary session planning documents in root directory

**Agent Notes to Remove**:
```
ADDITIONAL_SOURCES_RESEARCH.md
CFREDS_SOLUTION_SUMMARY.md
DFIR_TRAINING_QUICK_START.md
DFIR_TRAINING_RESEARCH_FINDINGS.md
DOWNLOAD_PRIORITY_QUICK_REFERENCE.md
NEXT_STEPS.md
```

**Permanent Documentation to Keep**:
```
AGENTS.md
CLAUDE.md
CONTRIBUTING.md
GITHUB_PROJECT_SETUP.md
IMPLEMENTATION_SUMMARY.md
PROJECT_STATUS.md
README.md
SESSION_STATUS.md
```

**Action**: Delete agent notes, commit cleanup

---

## 2. Incomplete Download Scripts Cleanup

**Issue**: Multiple download scripts in untracked state

**Files**:
```
docs/CFREDS_DOWNLOAD_GUIDE.md
scripts/download-cfreds.sh
scripts/download-dfir-training-guide.md
scripts/download-dfir-training.sh
scripts/setup-dfir-training.sh
scripts/verify-cfreds-urls.sh
```

**Decision Required**:
- [ ] **Option A**: Complete and commit these scripts (for future DFIR training downloads)
- [ ] **Option B**: Delete these scripts (defer to future work)
- [ ] **Option C**: Move to `scripts/wip/` directory for future consideration

**Recommendation**: Option B (delete) - These were exploratory work for future dataset downloads, not required for current hackathon submission

---

## 3. Code Quality Audit

### Python Code Review

**Run automated checks**:
```bash
# Linting
ruff check sift_find_evil/ tests/

# Type checking
mypy sift_find_evil/

# Security scanning
bandit -r sift_find_evil/

# Code complexity
radon cc sift_find_evil/ -a -nb
```

**Manual review areas**:
- Dead code / unused imports
- TODO comments requiring action
- Hardcoded values that should be constants
- Missing docstrings on public functions
- Error handling completeness

### Test Coverage Analysis

```bash
# Generate coverage report
pytest --cov=sift_find_evil --cov-report=html --cov-report=term-missing

# Review uncovered code
open htmlcov/index.html
```

**Target**: Maintain 80%+ coverage

---

## 4. Documentation Audit

### README.md Review

**Checklist**:
- [ ] Installation instructions accurate
- [ ] Usage examples work
- [ ] NSRL section clear about manual download workaround
- [ ] Links to documentation valid
- [ ] Badge URLs working

### Documentation Completeness

**Check docs/ directory**:
```bash
ls -la docs/
```

**Verify**:
- [ ] All referenced docs exist
- [ ] No broken internal links
- [ ] Examples match current CLI interface
- [ ] API documentation up to date

---

## 5. Git History Cleanup

### Commit Message Quality

**Review recent commits**:
```bash
git log --oneline -20
```

**Check for**:
- Clear, descriptive messages
- Proper conventional commit format
- No WIP or fixup commits
- Co-authored attribution correct

### Branch Hygiene

```bash
# Check for stale branches
git branch -a

# Check for unmerged work
git branch --no-merged
```

---

## 6. Dependency Audit

### requirements.txt Review

```bash
cat requirements.txt
```

**Verify**:
- [ ] All dependencies actually used
- [ ] Version pinning appropriate
- [ ] No security vulnerabilities (pip audit)
- [ ] Development dependencies separated

**Run security check**:
```bash
pip install pip-audit
pip-audit
```

---

## 7. File System Organization

### Directory Structure Review

```bash
tree -L 2 -I '__pycache__|*.pyc'
```

**Check for**:
- Consistent naming conventions
- Logical organization
- No duplicate functionality
- Clear separation of concerns

### Test Organization

```bash
ls -la tests/
```

**Verify**:
- Test files match source file names
- No orphaned tests
- Clear test organization

---

## 8. Code Smells to Hunt

### Common Issues

**Search for potential problems**:
```bash
# TODO comments
grep -rn "TODO" sift_find_evil/

# FIXME comments
grep -rn "FIXME" sift_find_evil/

# Hardcoded paths
grep -rn "/home/" sift_find_evil/
grep -rn "C:\\" sift_find_evil/

# Print statements (should use logging)
grep -rn "print(" sift_find_evil/

# Long functions (>50 lines)
find sift_find_evil/ -name "*.py" -exec wc -l {} \; | sort -rn | head -20
```

---

## 9. Security Audit

### Secrets Detection

```bash
# Check for potential secrets
grep -rn "password" sift_find_evil/
grep -rn "api_key" sift_find_evil/
grep -rn "secret" sift_find_evil/

# Check git history for leaked secrets
git log -S "password" --all
```

### Input Validation

**Review**:
- File path handling (no path traversal)
- User input sanitization
- Command injection prevention
- SQL injection prevention (if applicable)

---

## 10. Performance Audit

### Potential Bottlenecks

**Areas to review**:
- File I/O operations (buffering, chunking)
- Hash computation (parallelization opportunities)
- NSRL loading (optimize data structures)
- Memory usage for large files

**Profiling**:
```bash
# Profile CIRCL analysis
python -m cProfile -o profile.stats scripts/analyze_circl_executables.py
python -c "import pstats; p = pstats.Stats('profile.stats'); p.sort_stats('cumulative').print_stats(20)"
```

---

## 11. Testing Gaps

### Missing Test Coverage

**Check for**:
- Error path testing
- Edge case coverage
- Integration test completeness
- Mock usage appropriateness

### Test Quality

**Review**:
- Test names descriptive
- AAA pattern followed (Arrange-Act-Assert)
- No flaky tests
- Appropriate use of fixtures

---

## 12. Documentation Debt

### Docstring Coverage

```bash
# Check for missing docstrings
pydocstyle sift_find_evil/
```

**Ensure**:
- All public functions documented
- Parameters and return types described
- Examples where helpful

---

## Execution Plan

### Phase 1: Quick Wins (30 minutes)

1. **Delete agent planning notes** (5 min)
2. **Delete incomplete download scripts** (5 min)
3. **Run automated linters** (10 min)
4. **Fix obvious issues** (10 min)

### Phase 2: Code Quality (60 minutes)

5. **Manual code review** (30 min)
6. **Test coverage analysis** (15 min)
7. **Documentation review** (15 min)

### Phase 3: Deep Audit (90 minutes)

8. **Security audit** (30 min)
9. **Performance review** (30 min)
10. **Dependency audit** (30 min)

---

## Prioritization

**Must Do (Critical)**:
- ✅ Delete agent planning notes
- ✅ Run linters and fix issues
- ✅ Check test coverage
- ✅ Documentation accuracy

**Should Do (Important)**:
- Security audit
- Code smell elimination
- Dependency review

**Nice to Have (Optional)**:
- Performance profiling
- Advanced test coverage improvements
- Extensive documentation expansion

---

## Success Criteria

- [ ] No agent planning notes in root
- [ ] All linters pass (ruff, mypy, bandit)
- [ ] 80%+ test coverage maintained
- [ ] Documentation accurate and complete
- [ ] No security vulnerabilities
- [ ] Clean git history
- [ ] All scripts executable and working

---

**Ready to execute?** Start with Phase 1 (Quick Wins)
