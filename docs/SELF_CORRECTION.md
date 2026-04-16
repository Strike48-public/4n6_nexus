# Self-Correction Mechanisms

**Status:** Design Complete, Implementation In Progress  
**Last Updated:** 2026-04-16

This document describes all self-correction mechanisms implemented in SIFT Find Evil - the star feature that differentiates our hackathon entry.

---

## Overview

Self-correction is the ability of the autonomous agent to detect its own mistakes, contradictions, and low-confidence conclusions, then autonomously re-investigate to resolve them **without human intervention**.

**Key principle:** Self-correction is **architectural**, not prompt-based. We use concrete detection logic, thresholds, and resolution strategies - not LLM prompting alone.

---

## Self-Correction Scenarios

### 1. Cross-Artifact Timestamp Validation

**Type:** Contradiction Detection  
**Priority:** P0 (Critical) - MVP star feature for demo video

**Trigger:**
Timestamps from different artifact types (MFT, Prefetch, Event Logs, memory) show causality violations or significant discrepancies.

**Example Scenario:**
- MFT shows `evil.exe` modified at 2026-04-15 10:00:00
- Prefetch shows `evil.exe` last run at 2026-04-15 09:55:00
- Contradiction: File modified **after** the program that modified it ran (impossible)

**Detection Logic:**
```python
def detect_timestamp_contradiction(file_finding: Finding, 
                                   process_finding: Finding) -> Optional[Contradiction]:
    """Detect causality violations in timestamps."""
    
    file_time = file_finding.evidence["mft_timestamp"]
    process_time = process_finding.evidence["prefetch_last_run"]
    
    # Check for causality violation
    if file_time < process_time:
        return Contradiction(
            type="timestamp_causality_violation",
            findings=[file_finding, process_finding],
            severity="high",
            confidence_impact=-0.45,  # Drop from 0.85 to 0.40
            reasoning="File modification timestamp precedes executable run time"
        )
    
    # Check for significant discrepancy (>5 minutes)
    time_diff = abs((file_time - process_time).total_seconds())
    if time_diff > 300:  # 5 minutes
        return Contradiction(
            type="timestamp_discrepancy",
            findings=[file_finding, process_finding],
            severity="medium",
            confidence_impact=-0.25,  # Drop from 0.85 to 0.60
            reasoning=f"Timestamps differ by {time_diff}s (>5min threshold)"
        )
    
    return None
```

**Response Logic:**
1. Log contradiction with both timestamps and source artifacts
2. Reduce confidence scores for both findings (0.85 → 0.40)
3. Add to re-investigation queue with priority P1
4. Query additional artifact (Event Logs Event ID 4688) as tiebreaker
5. Compare all 3 timestamps:
   - If Event Log matches MFT → Trust MFT, flag Prefetch as potentially corrupted
   - If Event Log matches Prefetch → Trust Prefetch, flag MFT timestomping
   - If Event Log is different from both → Flag all as low-confidence, escalate
6. Update confidence based on resolution (0.40 → 0.85 if resolved, 0.40 → 0.50 if unresolved)
7. Log complete reasoning chain in audit trail

**Demo Value:**
- ✅ Shows autonomous detection of logical impossibility (effect before cause)
- ✅ Demonstrates multi-source correlation (3 artifact types: MFT, Prefetch, Event Logs)
- ✅ Shows real-time confidence degradation + recovery
- ✅ Proves architectural self-correction (concrete logic, not prompt-based)
- ✅ Generates compelling visual: confidence meter drops from 0.85 → 0.40 → 0.85

**Status:** Design complete, awaiting implementation (Issue #12)

---

### 2. Uncertainty Budget Threshold

**Type:** Cumulative Confidence Tracking  
**Priority:** P2 (Medium) - Should-have for competitive advantage

**Trigger:**
Cumulative uncertainty across all findings exceeds threshold, indicating investigation quality degradation.

**Example Scenario:**
- Agent makes 5 findings with confidence scores: 0.90, 0.85, 0.70, 0.65, 0.60
- Average confidence: 0.74
- Cumulative uncertainty: 1.0 - 0.74 = 0.26
- Threshold: 0.25
- Budget exceeded by 0.01 → Trigger re-analysis

**Detection Logic:**
```python
def check_uncertainty_budget(findings: List[Finding], 
                             threshold: float = 0.25) -> bool:
    """Check if cumulative uncertainty exceeds acceptable threshold."""
    
    if not findings:
        return False
    
    # Calculate average confidence
    avg_confidence = sum(f.confidence for f in findings) / len(findings)
    
    # Calculate cumulative uncertainty
    uncertainty = 1.0 - avg_confidence
    
    # Log current budget
    audit_log.info("Uncertainty budget check",
                  avg_confidence=avg_confidence,
                  uncertainty=uncertainty,
                  threshold=threshold,
                  num_findings=len(findings))
    
    return uncertainty > threshold
```

**Response Logic:**
1. Identify all low-confidence findings (<0.75)
2. Sort by confidence (lowest first)
3. Re-investigate bottom 25% of findings
4. For each finding:
   - Query additional artifact types not yet examined
   - Apply alternative analysis techniques
   - Cross-validate with other findings
5. Recalculate uncertainty budget after re-investigation
6. If still above threshold after 2 re-investigation rounds, escalate to human

**Demo Value:**
- ✅ Shows proactive quality control (agent notices its own uncertainty)
- ✅ Demonstrates real-time confidence tracking
- ✅ Generates visual: uncertainty budget meter fills → triggers re-analysis → empties
- ✅ Proves architectural constraint (threshold-based trigger, not prompt)

**Status:** Design complete, implementation queued (Issue #13)

---

### 3. Tool Failure Recovery (Circuit Breaker)

**Type:** Reliability & Fault Tolerance  
**Priority:** P1 (High) - Critical for robust autonomous execution

**Trigger:**
Tool invocation fails (timeout, crash, invalid output) multiple times.

**Example Scenario:**
- Agent calls `volatility pslist` on memory dump
- First attempt: Timeout after 5 minutes
- Second attempt: Timeout after 5 minutes
- Third attempt: Timeout after 5 minutes
- Circuit breaker opens → Disable `volatility pslist` for this investigation
- Log architectural failure for post-mortem

**Detection Logic:**
```python
class CircuitBreaker:
    """Circuit breaker pattern for tool failure recovery."""
    
    def __init__(self, tool_name: str, max_failures: int = 3, 
                 timeout_seconds: int = 300):
        self.tool_name = tool_name
        self.max_failures = max_failures
        self.timeout_seconds = timeout_seconds
        self.failure_count = 0
        self.disabled = False
        self.last_failure_time = None
    
    def call_tool(self, *args, **kwargs):
        """Invoke tool with circuit breaker protection."""
        
        if self.disabled:
            audit_log.error(f"{self.tool_name} circuit breaker OPEN",
                          failure_count=self.failure_count)
            raise ToolDisabledError(
                f"{self.tool_name} disabled after {self.failure_count} failures"
            )
        
        try:
            # Apply timeout
            with timeout(self.timeout_seconds):
                result = invoke_mcp_tool(self.tool_name, *args, **kwargs)
            
            # Success - reset failure count
            if self.failure_count > 0:
                audit_log.info(f"{self.tool_name} recovered",
                             previous_failures=self.failure_count)
            self.failure_count = 0
            return result
            
        except (TimeoutError, subprocess.CalledProcessError, Exception) as e:
            self.failure_count += 1
            self.last_failure_time = datetime.now()
            
            audit_log.warning(f"{self.tool_name} failed",
                            failure_count=self.failure_count,
                            max_failures=self.max_failures,
                            error=str(e))
            
            # Open circuit breaker if max failures reached
            if self.failure_count >= self.max_failures:
                self.disabled = True
                audit_log.critical(f"{self.tool_name} circuit breaker OPENED",
                                 failure_count=self.failure_count,
                                 tool_disabled=True)
            
            raise
```

**Response Logic:**
1. Log tool failure with error details
2. Increment failure counter for this tool
3. If failure count < max (3):
   - Retry with backoff (wait 5s, 10s, 20s)
4. If failure count >= max:
   - Open circuit breaker (disable tool)
   - Log architectural failure
   - Attempt fallback tool if available:
     - `volatility pslist` fails → Try `volatility psscan`
     - `fls` fails → Try `ils`
   - If no fallback available, mark findings as "incomplete - tool failure"
5. Continue investigation with remaining tools
6. Flag in final report: "Memory analysis incomplete due to tool failure"

**Demo Value:**
- ✅ Shows robust fault tolerance (agent doesn't crash on tool failures)
- ✅ Demonstrates architectural constraint (failure counter, not prompt)
- ✅ Proves graceful degradation (continue with reduced capabilities)

**Status:** Design complete, implementation queued (Issue #17)

---

### 4. Evidence Integrity Violation Detection

**Type:** Security & Chain-of-Custody  
**Priority:** P1 (High) - Critical for legal defensibility

**Trigger:**
Evidence hash changes between intake and analysis, indicating modification.

**Example Scenario:**
- Evidence intake: `disk.dd` has SHA256 hash `abc123...`
- Before analysis: Verify hash → Still `abc123...`
- After analysis: Verify hash → Changed to `def456...`
- Violation detected → Abort investigation, log critical security event

**Detection Logic:**
```python
def verify_evidence_integrity(evidence_id: str) -> bool:
    """Verify evidence has not been modified since intake."""
    
    evidence = evidence_store.get(evidence_id)
    original_hash = evidence.metadata["sha256_hash"]
    
    # Recompute hash
    current_hash = compute_sha256(evidence.file_path)
    
    if current_hash != original_hash:
        audit_log.critical("Evidence integrity violation detected",
                          evidence_id=evidence_id,
                          original_hash=original_hash,
                          current_hash=current_hash,
                          action="investigation_aborted")
        
        # Abort investigation immediately
        raise EvidenceIntegrityViolationError(
            f"Evidence {evidence_id} modified during investigation"
        )
    
    return True
```

**Response Logic:**
1. Detect hash mismatch
2. Log critical security event with both hashes
3. Abort investigation immediately (do not continue)
4. Generate incident report: "Evidence integrity violation - investigation invalid"
5. Escalate to human (potential security breach or tool bug)
6. Review audit logs to identify which tool/action may have caused modification
7. If bug in MCP wrapper, file critical issue

**Demo Value:**
- ✅ Shows proactive security monitoring
- ✅ Demonstrates architectural guarantee (hash verification, not prompt)
- ✅ Proves chain-of-custody integrity

**Status:** Design complete, implementation queued

---

### 5. Confidence Degradation Over Time

**Type:** Staleness Detection  
**Priority:** P3 (Low) - Nice-to-have for future product

**Trigger:**
Findings become stale (e.g., IoC lookups more than 24 hours old), reducing confidence.

**Example Scenario:**
- Day 1: Hash lookup in VirusTotal → "Clean" (confidence: 0.90)
- Day 3: Re-query VirusTotal → "Malicious" (confidence: 0.95)
- Conclusion: Hash was initially clean, became known-bad later
- Action: Re-investigate all findings related to this hash

**Status:** Out of scope for hackathon MVP, planned for Phase 2

---

## Self-Correction Metrics (Demo Video)

To win the judging criteria, our demo video must show:

| Metric | Target | Status |
|--------|--------|--------|
| **Number of self-correction instances** | ≥3 | Design: 3 (timestamp, uncertainty, tool failure) |
| **Types of self-correction** | ≥2 different types | Design: 3 types |
| **Confidence degradation shown** | Visual meter drops | To be implemented |
| **Confidence recovery shown** | Visual meter recovers | To be implemented |
| **Reasoning chains in logs** | 100% of corrections logged | To be implemented |
| **Autonomous resolution** | 0 human interventions | Design: Yes |

---

## Testing Self-Correction

### Test Case: Synthetic Ransomware with Timestamp Contradiction

**Setup:**
1. Create disk image with:
   - `evil.exe` in MFT with modified time 10:00:00
   - Prefetch for `evil.exe` with last run time 09:55:00
   - Event Log 4688 with process creation 09:55:03

**Expected Behavior:**
1. Agent detects MFT + Prefetch timestamp contradiction
2. Confidence drops from 0.85 to 0.40
3. Agent queries Event Logs as tiebreaker
4. Event Log matches Prefetch (09:55:03 ≈ 09:55:00)
5. Agent concludes: MFT timestamp is incorrect (possibly timestomping)
6. Confidence for Prefetch finding restored to 0.85
7. MFT finding flagged as "low confidence - potential timestomping"
8. Complete reasoning chain logged

**Verification:**
- Check audit logs for contradiction detection event
- Check audit logs for Event Log query with reasoning
- Check final report for timestomping flag
- Verify confidence scores in state file

---

## Implementation Checklist

- [ ] Cross-artifact timestamp validation (Issue #12)
- [ ] Uncertainty budget mechanism (Issue #13)
- [ ] Circuit breaker for tool failures (Issue #17)
- [ ] Evidence integrity verification (built into Evidence Store)
- [ ] Real-time confidence meter visualization (for demo video)
- [ ] Test cases for all 3 MVP self-correction scenarios
- [ ] Audit log entries for all self-correction events
- [ ] Demo video script sections for each self-correction instance

---

*Self-correction is our competitive advantage. Every scenario must be tested, logged, and demo-ready.*
