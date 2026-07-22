# Error Handling System - Architecture Design

**Status:** Design Complete, Ready for Implementation  
**Date:** 2026-04-25  
**Version:** 1.0

---

## Executive Summary

Production-grade error handling system for 4n6nexus (forensic analysis tool) that:
- Works offline (forensic labs are often airgapped)
- Learns from community feedback
- Provides AI-powered diagnostics
- Maintains analyst anonymity
- Shows sophistication to competition judges

---

## Design Decisions

### 1. Error Report Structure

**Complete error report includes:**

**Header:**
- Report ID (unique identifier)
- Generated timestamp (UTC)
- Tool version (4n6nexus vX.X.X)
- Case ID ([REDACTED])

**Error Summary:**
- Error type (RuntimeError, UnicodeDecodeError, etc.)
- Severity (info/warning/medium/high/critical)
- Artifact type (mft/prefetch/evtx/memory)
- Impact description
- Error message

**Occurrence Pattern:**
- First seen timestamp
- Total occurrences
- Unique analysts affected
- Frequency (per day, last 30 days)

**System Context:**
- OS, Python version
- Memory: Total + used at error
- CPU: Cores + utilization at error
- Tool chain versions

**Evidence Context (Sanitized):**
- Image type (E01, dd, AFF4)
- Size (GB)
- OS detected (Windows 10 Pro Build 19042)
- Filesystem (NTFS, FAT32, etc.)
- Acquisition tool

**Tool History:**
- Installation date
- Previous successful analyses count
- Previous errors count
- Last successful analysis timestamp

**Tool Execution Context:**
- Sanitized command lines for each tool
- Which tools succeeded/failed

**Stack Trace (Sanitized):**
- Smart truncation (4n6nexus frames + error frame only)
- Sanitized local variables (diagnostic values only)
- PII variables removed (hostname, case_id, etc.)

**Recovery Action:**
- Knowledge base match (if any)
- Auto-recovery attempted
- Strict mode status
- Final result (success/partial/failure)

**AI Diagnostics (Optional):**
- Root cause analysis
- Regression detection
- Immediate fix (code/config)
- Long-term prevention strategy

---

### 2. PII Sanitization

**Approach:** Hybrid (context-aware + pattern-based)

**Sanitization Rules:**

**Preserve:**
- Tool paths: `4n6nexus/parsers/evtx_parser.py` (diagnostic value)
- Artifact filenames: `Security.evtx` (type identification)
- Numeric values: sizes, counts, row numbers (diagnostic)
- OS metadata: Windows version, build (diagnostic)

**Redact:**
- Case paths: `/cases/acme-breach/...` → `[CASE_DIR]`
- Hostnames: `DC01.victim.com` → `[REDACTED]`
- Case IDs: `ACME-2026-001` → `[REDACTED]`
- Analyst names: `john.smith` → `[ANALYST]`
- Domains: `victim.com` → `[DOMAIN]`
- Emails: `analyst@company.com` → `[EMAIL]`
- IP addresses: `192.168.1.100` → `[IP]`

**Remove:**
- PII variables with no diagnostic value (hostname, case_id)
- Keep only variables useful for debugging

**Implementation:**
```python
class PIISanitizer:
    def __init__(self, case_dir, case_id):
        self.case_dir = case_dir
        self.case_id = case_id
        self.hostnames = set()
    
    def sanitize_path(self, path):
        if "4n6nexus/" in path:
            return path  # Preserve tool structure
        return Path(path).name  # Just filename
    
    def sanitize_text(self, text):
        # Context-aware
        text = text.replace(str(self.case_dir), "[CASE_DIR]")
        text = text.replace(self.case_id, "[REDACTED]")
        
        # Pattern-based
        text = re.sub(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', '[EMAIL]', text)
        text = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP]', text)
        
        return text
```

---

### 3. Knowledge Base Schema

**Format:** YAML (read-only, version-controlled)  
**Statistics:** SQLite database (runtime, local)

**YAML Structure:**

```yaml
# 4n6nexus/errors.yaml
version: "1.0"
last_updated: "2026-04-25"

known_errors:
  - id: pecmd_windows_only              # Required: Unique ID
    pattern: "Non-Windows platforms"    # Required: Match string
    pattern_type: substring              # Optional: substring (default) or regex
    error_type: RuntimeError             # Required: Python exception type
    artifact_type: prefetch              # Required: mft/prefetch/evtx/memory
    tool: PECmd                          # Optional: Tool name
    severity: info                       # Required: info/warning/medium/high/critical
    recovery_action: skip                # Required: skip/retry_*/fail/custom_function
    message: "PECmd requires Windows"    # Required: User-facing message
    added: "2026-04-25"                  # Optional: Date added
    added_by: "c577e43"                  # Optional: Git commit
    
  - id: evtx_timeout_large
    pattern: "timeout after \\d+s"
    pattern_type: regex
    error_type: TimeoutError
    artifact_type: evtx
    severity: warning
    recovery_action: retry_with_timeout
    retry_params:
      timeout: 900
      max_retries: 1
    message: "Large Event Log - retrying with 15min timeout"
```

**Recovery Actions:**
- `skip` - Skip artifact, continue
- `retry_with_timeout` - Retry with extended timeout
- `retry_with_encoding` - Retry with different encoding
- `retry_with_params` - Retry with custom params
- `fail` - Stop analysis (critical errors only)
- `custom_function` - Call whitelisted Python function

**Statistics Database:**
```sql
-- ~/.4n6nexus/error-stats.db
CREATE TABLE error_occurrences (
    error_id TEXT,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    occurrence_count INTEGER,
    analyst_count INTEGER,
    last_context JSON
);
```

---

### 4. Upload Endpoint

**Architecture:** Local queue (offline-safe) + GitHub Issues

**Workflow:**
```
1. Error occurs → Report saved to queue
   ~/.4n6nexus/error-reports/queue/er_abc123.md

2. Analyst syncs when online
   4n6nexus sync-telemetry

3. Reports uploaded to GitHub Issues
   POST https://api.github.com/repos/yourorg/4n6nexus/issues
   (Using embedded bot token with issues:write scope)

4. GitHub issue created with sanitized report
```

**Analyst Identity:**
- Pseudonymous auto-generated ID: `analyst_7f3a9d2b`
- Stored in `~/.4n6nexus/config.yaml`
- Optional contact email for follow-up
- Fully anonymous by default

**Configuration:**
```yaml
# ~/.4n6nexus/config.yaml
analyst_id: analyst_7f3a9d2b  # Auto-generated UUID
contact_email: null            # Optional
telemetry_enabled: true        # Opt-out available
create_github_issues: true
```

**Security:**
- Bot token embedded in code (issues:write scope only)
- Rate limited by GitHub (5,000 requests/hour)
- Revocable/rotatable if abused
- Alternative: Manual upload via `--dry-run`

**Future Enhancement:**
- API server with dashboard (internal discussion needed)
- Email notifications on critical errors
- Error frequency analytics

---

### 5. AI Diagnostics

**LLM:** Claude Sonnet 4 (best technical reasoning)

**When Enabled:** `--enable-ai-diagnostics` flag

**Context Sent to LLM:**
- Error details (type, message, severity)
- Sanitized stack trace with local variables
- Artifact context (type, size, tool)
- System context (OS, Python, resources)
- Tool history (previous successes, errors)
- Similar errors from knowledge base

**Prompt Template:**
```
You are a forensic tool debugging assistant. Analyze this error in context.

Error Details:
- Type: UnicodeDecodeError
- Message: 'utf-8' codec can't decode byte 0xff at position 1234
- Artifact: Event Log (Security.evtx, 251MB)
- Tool: EvtxECmd 1.5.0.0

Stack Trace:
[sanitized stack with local variables]

Tool History:
- Previous successful analyses: 52
- Previous errors: 3 (different types)
- Last success: 2026-04-24 (yesterday)

Similar Errors:
- 2 similar UnicodeDecodeError reports found in knowledge base

Provide:
1. Root cause analysis (what is causing this error?)
2. Why is this happening now? (regression? edge case? setup issue?)
3. Immediate fix (code changes or configuration)
4. Long-term prevention strategy
```

**Token Budget:**
- Input: ~500-1000 tokens (error context)
- Output: 500 tokens (standard), 1000 for complex errors
- Cost: ~$0.01 per diagnosis (acceptable)

**Caching:**
- Cache diagnoses for identical error signatures
- Reduce cost for recurring errors

**Output Format:**
```markdown
## AI Diagnostics

**Root Cause:**
Event Log contains non-UTF-8 characters, likely from malware with 
obfuscated command-line arguments.

**Why Now:**
This is not a regression. The tool has always had this limitation.
You're analyzing an APT scenario with malicious binaries that use 
binary data in process command lines.

**Immediate Fix:**
```python
# 4n6nexus/parsers/evtx_parser.py, line 245
- text = row.get("Payload").decode('utf-8')
+ text = row.get("Payload").decode('utf-8', errors='replace')
```

**Long-Term Prevention:**
1. Add encoding detection before parsing
2. Support multiple encodings (latin-1, cp1252)
3. Add known_errors.yaml entry for this pattern
```

---

## Error Handling Flow

```
┌─────────────────────────────────────────────────────┐
│ 1. Error Occurs During Analysis                    │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│ 2. Check Knowledge Base (errors.yaml)              │
│    - Match error pattern                           │
│    - Get recovery action                           │
└─────────────────────────────────────────────────────┘
                      ↓
              ┌───────┴───────┐
              │               │
         Known Error      Unknown Error
              │               │
              ↓               ↓
┌──────────────────┐  ┌──────────────────┐
│ 3a. Auto-Recover │  │ 3b. Check Mode   │
│ - Execute action │  │ - Strict mode?   │
│ - Log warning    │  │   → Stop         │
│ - Continue       │  │ - Default?       │
└──────────────────┘  │   → Degrade      │
                      └──────────────────┘
                              ↓
                 ┌────────────────────────┐
                 │ 4. Generate Report     │
                 │ - Capture context      │
                 │ - Sanitize PII         │
                 │ - Save to queue        │
                 └────────────────────────┘
                              ↓
                 ┌────────────────────────┐
                 │ 5. AI Diagnostics?     │
                 │ (if enabled)           │
                 │ - Send to Claude       │
                 │ - Get analysis         │
                 │ - Append to report     │
                 └────────────────────────┘
                              ↓
                 ┌────────────────────────┐
                 │ 6. Update Statistics   │
                 │ - Increment count      │
                 │ - Track frequency      │
                 │ - Store in SQLite      │
                 └────────────────────────┘
                              ↓
                 ┌────────────────────────┐
                 │ 7. Sync (when online)  │
                 │ - Upload to GitHub     │
                 │ - Create issue         │
                 │ - Mark as synced       │
                 └────────────────────────┘
```

---

## File Structure

```
4n6nexus/
├── error_handling/
│   ├── __init__.py
│   ├── knowledge_base.py          # Load errors.yaml + stats
│   ├── reporter.py                # Generate error reports
│   ├── sanitizer.py               # PII sanitization
│   ├── recovery.py                # Execute recovery actions
│   ├── recovery_functions.py      # Whitelisted custom functions
│   ├── ai_diagnostics.py          # Claude integration
│   └── uploader.py                # Sync to GitHub
├── errors.yaml                     # Known error definitions
└── cli.py                          # Add sync-telemetry command

~/.4n6nexus/
├── config.yaml                     # User configuration
├── error-stats.db                  # Occurrence statistics
└── error-reports/
    ├── queue/                      # Pending uploads
    │   ├── er_abc123.md
    │   └── er_def456.md
    └── synced/                     # Successfully uploaded
        └── er_abc123.md
```

---

## CLI Commands

```bash
# Analysis with error handling
4n6nexus analyze-live --case-id test --windows-mount /mnt/evidence
4n6nexus analyze-live --strict-mode                    # Fail fast on unknown errors
4n6nexus analyze-live --enable-ai-diagnostics         # Include AI analysis

# Error report management
4n6nexus sync-telemetry                                # Upload queued reports
4n6nexus sync-telemetry --dry-run                     # Generate markdown for manual upload
4n6nexus list-errors                                   # Show queued reports
4n6nexus show-error er_abc123                         # View report details

# Configuration
4n6nexus config set telemetry_enabled false           # Disable telemetry
4n6nexus config set analyst_id null                   # Disable analyst tracking
4n6nexus reset-id                                      # Generate new analyst ID
```

---

## Implementation Phases

### Phase 1: Core Error Handling (This Session)
- ✅ PECmd graceful degradation (DONE)
- ✅ --strict-mode flag (DONE)
- Build ErrorReporter class
- Build PIISanitizer class
- Build KnowledgeBase loader (YAML + SQLite)
- Add error report generation

### Phase 2: Recovery System
- Build RecoveryEngine
- Add recovery_functions.py with whitelisted handlers
- Implement retry strategies (timeout, encoding, params)
- Add errors.yaml with initial known errors

### Phase 3: Telemetry Upload
- Build GitHub Issues uploader
- Add sync-telemetry command
- Implement local queue management
- Add analyst_id generation

### Phase 4: AI Diagnostics
- Integrate Claude API
- Build prompt templates
- Implement diagnosis caching
- Add --enable-ai-diagnostics flag

### Phase 5: Documentation & Polish
- Create ERROR_HANDLING.md user guide
- Create IMPROVEMENT_CYCLE.md for judges
- Add examples to README
- Create video demo

---

## Competition Value

**Judge Talking Points:**

1. **Production-Grade Error Handling**
   - Works offline (forensic labs are airgapped)
   - Graceful degradation vs. fail-fast (configurable)
   - PII sanitization (analyst privacy)

2. **Community Learning System**
   - Errors contribute to knowledge base
   - Tool improves over time
   - Similar to crash reporting in commercial software

3. **AI-Powered Diagnostics**
   - Claude analyzes errors in context
   - Suggests immediate fixes
   - Detects regressions automatically

4. **Analyst-Centric Design**
   - Anonymous by default
   - Pseudonymous tracking (pattern detection)
   - Optional contact for follow-up
   - Complete opt-out available

5. **Engineering Sophistication**
   - Hybrid knowledge base (Python + YAML)
   - Smart error recovery (skip/retry/fail)
   - Context-aware PII sanitization
   - Offline-first architecture

---

## Success Metrics

**Tool Improvement:**
- Time to fix common errors (hours → minutes)
- False positive rate reduction
- User satisfaction scores

**Community Engagement:**
- Error reports submitted per month
- Unique analysts contributing
- Knowledge base growth (new patterns added)

**Technical:**
- Average diagnosis time (should be < 5 seconds)
- Error report size (should be < 50KB)
- GitHub API rate limit usage (should be < 10% of limit)

---

**Status:** Ready for implementation  
**Next Steps:** Build Phase 1 components (ErrorReporter, PIISanitizer, KnowledgeBase)
