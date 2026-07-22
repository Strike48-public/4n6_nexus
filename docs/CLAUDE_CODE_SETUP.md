# Claude Code Setup for DFIR Development

This guide documents the Claude Code configuration optimized for forensic detection engine development.

## Overview

The sift_find_evil project uses **synthetic fixtures** for testing rather than processing real evidence files. This enables:
- ✅ Fast CI/CD execution (seconds vs. minutes)
- ✅ Deterministic test results (no tool version mismatches)
- ✅ No multi-GB evidence files in the repository
- ✅ Same detection logic validation as real evidence

However, the permission configuration **anticipates real forensic tool usage** when needed.

---

## Permission Strategy

### Current Configuration (`.claude/settings.json`)

The project uses **pre-authorized permissions** for development tools:

```json
{
  "permissions": {
    "allow": [
      "Bash(pytest *)",
      "Bash(python -m pytest *)",
      "Bash(python3 -m pytest *)",
      "Bash(ruff check *)",
      "Bash(ruff format *)",
      "Bash(mypy *)",
      "Bash(bd ready *)",
      "Bash(bd list *)",
      "Bash(bd show *)",
      "Bash(bd stats *)",
      "Bash(bd doctor *)",
      "Bash(bd blocked *)",
      "Bash(bd prime *)"
    ],
    "allowedTools": {
      "Read": {
        "allowed": ["**/*.py", "**/*.md", "**/*.json", "**/*.yaml", "**/*.yml", "**/*.txt"]
      },
      "Edit": {
        "allowed": [
          "sift_find_evil/**/*.py",
          "tests/**/*.py",
          "scenarios/**/*.json",
          "docs/**/*.md"
        ]
      },
      "Write": {
        "allowed": [
          "sift_find_evil/**/*.py",
          "tests/**/*.py",
          "docs/**/*.md"
        ]
      }
    }
  }
}
```

### Why Pre-Authorize Development Tools?

**No permission prompts during development** means:
- Faster TDD cycles (pytest runs instantly)
- Seamless code quality checks (ruff, mypy)
- Smooth issue tracking (beads CLI)

---

## Forensic Tool Permission Template

### When Real Evidence Processing is Needed

If you need to process actual forensic evidence (not synthetic testing), add these **forensic tool permissions** to your **user-level settings** (`~/.claude/settings.json`):

```json
{
  "permissions": {
    "allow": [
      "Bash(vol.py *)",
      "Bash(volatility *)",
      "Bash(fls *)",
      "Bash(icat *)",
      "Bash(ils *)",
      "Bash(istat *)",
      "Bash(ifind *)",
      "Bash(ffind *)",
      "Bash(fsstat *)",
      "Bash(blkcat *)",
      "Bash(blkls *)",
      "Bash(blkstat *)",
      "Bash(mmls *)",
      "Bash(mmstat *)",
      "Bash(tsk_recover *)",
      "Bash(log2timeline.py *)",
      "Bash(psort.py *)",
      "Bash(pinfo.py *)",
      "Bash(bulk_extractor *)",
      "Bash(foremost *)",
      "Bash(photorec *)",
      "Bash(yara *)",
      "Bash(strings *)",
      "Bash(hexdump *)",
      "Bash(xxd *)",
      "Bash(grep *)",
      "Bash(rg *)",
      "Bash(find *)",
      "Bash(exiftool *)",
      "Bash(md5sum *)",
      "Bash(sha1sum *)",
      "Bash(sha256sum *)",
      "Bash(sha512sum *)",
      "Bash(ssdeep *)",
      "Write(./analysis/*)",
      "Write(./reports/*)",
      "Write(./exports/*)"
    ],
    "deny": [
      "Read(./secrets/**)",
      "Read(./**/*.key)",
      "Read(./**/*.pem)",
      "Bash(rm -rf *)",
      "Bash(dd *)",
      "Write(/cases/**)",
      "Write(/mnt/**)",
      "Write(/media/**)",
      "Write(/evidence/**)"
    ]
  }
}
```

### Why User-Level, Not Project-Level?

**Forensic tools belong in `~/.claude/settings.json` (user-level) because:**

1. **Cross-project applicability** - Volatility, TSK, Plaso work across all forensic projects
2. **Security-sensitive** - Forensic tool permissions shouldn't be checked into version control
3. **User-specific** - Only forensic analysts need these tools, not developers working on detection logic

**Project-level `.claude/settings.json` is for:**
- Project-specific development tools (pytest, ruff, mypy, bd)
- File path restrictions (only edit `sift_find_evil/**/*.py`)
- Project-specific hooks (bd prime on session start)

---

## Evidence Directory Protection

### Critical: Evidence Directories are Write-Protected

The `deny` section prevents accidental modification of evidence:

```json
"deny": [
  "Write(/cases/**)",
  "Write(/mnt/**)",
  "Write(/media/**)",
  "Write(/evidence/**)"
]
```

**All forensic output goes to:**
- `./analysis/` - Analysis scripts and intermediate data
- `./reports/` - Final forensic reports
- `./exports/` - Exported artifacts (timelines, carved files, etc.)

### Why This Matters

**Chain of custody requirements:**
- Evidence files must remain unmodified
- All forensic operations must be read-only
- Outputs must be clearly separated from evidence

---

## Auto-Allowed Commands (No Permission Needed)

These commands **never prompt** - they're automatically allowed by Claude Code:

### File Operations
- `cat`, `head`, `tail`, `wc`, `stat`, `file`, `ls`, `find`, `grep`, `rg`

### Git Operations
- `git status`, `git log`, `git diff`, `git show`, `git blame`, `git branch`
- `git tag`, `git remote`, `git ls-files`, `git config --get`

### System Commands
- `pwd`, `whoami`, `ps`, `df`, `du`, `which`, `echo`, `date`

**You don't need to add these to your allowlist** - they work out of the box.

---

## PostToolUse Hooks (Auto-Format/Lint)

### Python Files (Already Active)

When you edit Python files, these hooks run automatically (configured in `~/.claude/settings.json`):

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "command": "if echo \"$FILE_PATH\" | grep -q '\\.py$'; then ruff format \"$FILE_PATH\" 2>/dev/null || true; fi",
        "description": "Auto-format Python files with ruff"
      },
      {
        "matcher": "Write|Edit",
        "command": "if echo \"$FILE_PATH\" | grep -q '\\.py$'; then ruff check --fix \"$FILE_PATH\" 2>/dev/null || true; fi",
        "description": "Auto-lint Python files with ruff"
      },
      {
        "matcher": "Write|Edit",
        "command": "if echo \"$FILE_PATH\" | grep -q '\\.py$'; then mypy \"$FILE_PATH\" 2>/dev/null || true; fi",
        "description": "Type-check Python files with mypy"
      }
    ]
  }
}
```

These hooks ensure:
- ✅ Consistent code formatting (PEP 8)
- ✅ Linting errors caught immediately
- ✅ Type errors surfaced during development

---

## Elixir Files (Recently Added)

Elixir auto-formatting and linting hooks are now active:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "command": "if echo \"$FILE_PATH\" | grep -qE '\\.(ex|exs)$'; then cd \"$(dirname \"$FILE_PATH\")\" && while [ ! -f mix.exs ] && [ \"$PWD\" != \"/\" ]; do cd ..; done; if [ -f mix.exs ]; then mix format \"$FILE_PATH\" 2>/dev/null || true; fi; fi",
        "description": "Auto-format Elixir files with mix format"
      },
      {
        "matcher": "Write|Edit",
        "command": "if echo \"$FILE_PATH\" | grep -qE '\\.(ex|exs)$'; then cd \"$(dirname \"$FILE_PATH\")\" && while [ ! -f mix.exs ] && [ \"$PWD\" != \"/\" ]; do cd ..; done; if [ -f mix.exs ]; then mix credo suggest --strict \"$FILE_PATH\" 2>/dev/null || true; fi; fi",
        "description": "Lint Elixir files with Credo"
      }
    ]
  }
}
```

**Note:** These hooks navigate to the project root (where `mix.exs` lives) before running mix commands.

---

## Session Hooks

### PreCompact & SessionStart (Beads Integration)

```json
{
  "hooks": {
    "PreCompact": [
      {
        "hooks": [
          {
            "command": "bd prime",
            "type": "command"
          }
        ]
      }
    ],
    "SessionStart": [
      {
        "hooks": [
          {
            "command": "bd prime",
            "type": "command"
          }
        ]
      }
    ]
  }
}
```

**What `bd prime` does:**
- Loads the active issue from the beads database
- Surfaces it to Claude's context window
- Enables natural language references ("this issue", "the bug")

---

## Development Workflow

### 1. TDD Approach (Mandatory)

```bash
# Write test first (RED)
/tdd

# Implement detection to pass test (GREEN)
# Tests run automatically via pytest permission

# Refactor (IMPROVE)
/code-review

# Verify coverage
/test-coverage
```

### 2. Code Quality Pipeline

```bash
# Before committing
/quality-gate

# Expected checks:
# - Test coverage >= 80%
# - No security issues
# - Python code quality (ruff, mypy)
# - No dead code
```

### 3. Issue Tracking (Beads)

```bash
# List open issues
bd list

# Show current issue
bd show

# Mark as done
bd close
```

---

## Common Workflows

### Adding a New Detection

```bash
# 1. Plan the detection
/prp-plan

# 2. Create synthetic fixture
# Add to scenarios/synthetic/<scenario_name>/

# 3. Write test first (TDD)
/tdd

# 4. Verify coverage
/test-coverage

# 5. Code review
/code-review

# 6. Security review (if external data)
/security-review

# 7. Commit with context
/prp-commit "add <detection_name> for <attack_technique>"
```

### Debugging Detection Failures

```bash
# 1. Review the fixture
cat scenarios/synthetic/<scenario>/memory_fixtures/<file>.json

# 2. Run single scenario
PYTHONPATH=. python3 tests/scenario_harness.py -k <scenario_name>

# 3. Check detection logic
/code-review

# 4. Verify test isolation
/tdd
```

---

## Model Selection for DFIR Work

### Recommended Models

**Sonnet 4.6** (default) for:
- Standard detection logic development
- Test generation
- Code review
- Documentation

**Opus 4.8** with extended thinking (`[1m]`) for:
- Complex multi-scenario correlation analysis
- Adversarial validation (false positive hunting)
- Novel attack pattern research

**Haiku 4.5** for:
- Batch processing forensic logs
- Quick syntax checks
- Routine code formatting

---

## Security Considerations

### Never Commit These to Git

❌ `.claude/settings.local.json` - Contains user-specific MCP server configs  
❌ Forensic tool permissions in project settings - Belongs in `~/.claude/settings.json`  
❌ Evidence file paths or hashes - Use synthetic fixtures instead  

### Always Git-Track These

✅ `.claude/settings.json` - Project-specific development tool permissions  
✅ `.claude/agents/` - Custom domain expert agents  
✅ `scenarios/synthetic/` - Synthetic test fixtures  

---

## Troubleshooting

### "Permission denied" for pytest

**Symptom:** Claude prompts for permission to run pytest  
**Solution:** Ensure `Bash(pytest *)` is in `.claude/settings.json`

### "Cannot modify evidence files"

**Symptom:** Write operations blocked in `/cases/`, `/mnt/`, etc.  
**Solution:** This is **correct behavior**. Write to `./analysis/`, `./reports/`, or `./exports/` instead.

### "Volatility not found"

**Symptom:** vol.py commands fail  
**Solution:** Forensic tools aren't installed by default. See `SIFT_SETUP_GUIDE.md` for installation instructions.

### Hooks not running

**Symptom:** Python files not auto-formatted  
**Solution:** Check `~/.claude/settings.json` has PostToolUse hooks configured (see above)

---

## Related Documentation

- `SIFT_SETUP_GUIDE.md` - Installing forensic tools (Volatility, TSK, Plaso, etc.)
- `CLAUDE.md` - Root-level Claude Code instructions and workflow conventions
- `TRY_IT_OUT.md` - Quick start guide for running scenarios
- `USER_GUIDE.md` - End-user detection engine usage
- `CONTRIBUTING.md` - Contribution guidelines

---

*Last updated: 2026-06-12*
