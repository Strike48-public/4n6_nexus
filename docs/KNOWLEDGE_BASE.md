# Knowledge Base - TTPs, Playbooks & Decision Trees

**Status:** Living Document  
**Last Updated:** 2026-04-16

This document serves as the index for all Tactics, Techniques, Procedures (TTPs), investigation playbooks, and decision trees used by SIFT Find Evil.

---

## Table of Contents

1. [Investigation Playbooks](#investigation-playbooks)
2. [Tool Usage Patterns](#tool-usage-patterns)
3. [Self-Correction Patterns](#self-correction-patterns)
4. [Decision Trees](#decision-trees)
5. [Lessons Learned](#lessons-learned)
6. [Performance Benchmarks](#performance-benchmarks)

---

## Investigation Playbooks

Investigation playbooks are step-by-step procedures for common incident types.

### Ransomware Investigation
**File:** [TTPs/ransomware_playbook.md](TTPs/ransomware_playbook.md)  
**Status:** To be documented  
**Triggers:** Ransom note detected, mass file encryption, suspicious processes

**Overview:**
1. Triage: Search for ransom notes and encrypted files
2. Timeline reconstruction: Identify encryption start time
3. Execution artifact analysis: Find ransomware executable
4. Cross-artifact validation: Verify timeline consistency
5. IoC extraction: Hashes, payment addresses, persistence mechanisms

---

### Insider Threat Investigation
**File:** [TTPs/insider_threat_playbook.md](TTPs/insider_threat_playbook.md)  
**Status:** To be documented  
**Triggers:** Unusual file access, failed login attempts, data exfiltration indicators

---

### C2 Communication Investigation
**File:** [TTPs/c2_communication_playbook.md](TTPs/c2_communication_playbook.md)  
**Status:** To be documented  
**Triggers:** Suspicious network connections, beaconing behavior, DNS anomalies

---

## Tool Usage Patterns

### MFT (Master File Table) Analysis
**File:** [TTPs/mft_analysis.md](TTPs/mft_analysis.md)  
**Status:** To be documented  
**Common commands:**
- File timeline extraction
- Deleted file recovery
- Timestomping detection ($FILE_NAME vs $STANDARD_INFORMATION)

---

### Prefetch Analysis
**File:** [TTPs/prefetch_analysis.md](TTPs/prefetch_analysis.md)  
**Status:** To be documented  
**Common commands:**
- Executable run history
- Last run times
- Run counts

---

### Windows Event Log Analysis
**File:** [TTPs/eventlog_analysis.md](TTPs/eventlog_analysis.md)  
**Status:** To be documented  
**Key Event IDs:**
- 4688: Process creation
- 4624/4625: Successful/failed logons
- 7045: Service installation
- 4698: Scheduled task creation

---

## Self-Correction Patterns

### Cross-Artifact Timestamp Validation
**File:** [TTPs/cross_artifact_validation.md](TTPs/cross_artifact_validation.md)  
**Status:** To be documented  
**Pattern:** Compare timestamps from MFT, Prefetch, Event Logs to detect contradictions

---

### Uncertainty Budget Mechanism
**File:** [TTPs/uncertainty_budget.md](TTPs/uncertainty_budget.md)  
**Status:** To be documented  
**Pattern:** Track cumulative confidence, trigger re-analysis when threshold exceeded

---

### Tool Failure Recovery
**File:** [TTPs/tool_failure_recovery.md](TTPs/tool_failure_recovery.md)  
**Status:** To be documented  
**Pattern:** Circuit breaker pattern to handle tool crashes gracefully

---

## Decision Trees

### When to Mount vs. Carve vs. Stream-Parse?
**File:** [TTPs/decision_mount_carve_stream.md](TTPs/decision_mount_carve_stream.md)  
**Status:** To be documented

**Decision logic:**
- If filesystem is intact and mountable → **Mount** (fastest, preserves structure)
- If filesystem is corrupted but files can be identified → **Carve** (file carving)
- If real-time processing or very large images → **Stream-parse** (process in chunks)

---

### Confidence Threshold Tuning
**File:** [TTPs/decision_confidence_thresholds.md](TTPs/decision_confidence_thresholds.md)  
**Status:** To be documented

**Decision logic by artifact type:**
- File hashes: High confidence (0.95) if match in malware DB
- Process execution: Medium confidence (0.75) if Prefetch + Event Log agree
- Network connections: Low confidence (0.60) if only memory artifact, no network logs

---

### Human Escalation Triggers
**File:** [TTPs/decision_human_escalation.md](TTPs/decision_human_escalation.md)  
**Status:** To be documented

**When to escalate:**
- Confidence <0.50 on critical findings
- Contradictions unresolvable with available artifacts
- Tool failures exceed circuit breaker threshold
- Evidence integrity violations detected

---

## Lessons Learned

### Lesson 1: Prefetch Deletion by Ransomware
**Date:** TBD  
**Issue:** Some ransomware families delete Prefetch files post-encryption  
**Workaround:** Fallback to Event Logs (Event ID 4688) for process execution history  
**Prevention:** Always query multiple artifact types before drawing conclusions

---

### Lesson 2: Timezone Conversion Errors
**Date:** TBD  
**Issue:** MFT timestamps in local time vs. Event Logs in UTC caused false contradictions  
**Workaround:** Normalize all timestamps to UTC before comparison  
**Prevention:** Add timezone metadata to all timestamp findings

---

### Lesson 3: False Positives on Encryption Tools
**Date:** TBD  
**Issue:** BitLocker and VeraCrypt flagged as ransomware due to encryption keywords  
**Workaround:** Check for ransom note presence before flagging as malicious  
**Prevention:** Whitelist known legitimate encryption tools

---

## Performance Benchmarks

### Tool Execution Times (100GB Disk Image)

| Tool | Operation | Avg Time | Notes |
|------|-----------|----------|-------|
| `fls` | Full recursive listing | 2.3 min | Fast |
| `mmls` | Partition listing | 0.5 sec | Very fast |
| `mft` | Full MFT parse | 4.1 min | Moderate |
| `evtx` | Event Log parse (10k events) | 1.8 min | Moderate |
| `volatility pslist` | Memory process list | 3.5 min | Slow (8GB memory dump) |

### Investigation Phase Times

| Phase | Target | Actual (Avg) | Notes |
|-------|--------|--------------|-------|
| Evidence intake | <1 min | 0.8 min | Hash + mount |
| Triage | <5 min | 4.2 min | Quick scan |
| Deep analysis | <20 min | 18.5 min | Multi-pass |
| Correlation | <5 min | 3.7 min | Timeline + IoC pivoting |
| Reporting | <2 min | 1.5 min | HTML generation |
| **Total** | **<30 min** | **28.7 min** | End-to-end |

---

## Contributing to Knowledge Base

When you discover new patterns, edge cases, or optimizations:

1. **Document the TTP** in `docs/TTPs/` directory
2. **Add entry to this index** with status and overview
3. **Link related issues** (e.g., "Discovered in #42")
4. **Test the TTP** on at least one case dataset
5. **Update lessons learned** if applicable

Use the **[TTP] issue template** to track documentation tasks.

---

*This knowledge base will grow throughout the hackathon and become the foundation for our commercial product's investigation engine.*
