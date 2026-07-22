# Adversarial Validator Design

## Overview

An automated validation layer that critically examines CRITICAL findings before they're reported to the user. Each finding undergoes a structured "attack each claim" review to catch errors in reasoning, evidence, or confidence scoring.

## Motivation

The manual validator pass on Jean caught three real errors:
1. Incorrect file hash (typo in SHA-256)
2. Overstated confidence (timing window too large)
3. Missing alternative explanation (backup software)

These errors would have undermined the credibility of the entire analysis. An automated validator can catch similar errors systematically before findings reach the user.

## Scope

**In Scope**:
- Validate CRITICAL findings only (highest impact)
- Check evidence completeness
- Verify reasoning chain logic
- Challenge confidence scores
- Identify missing alternative explanations
- Flag unsupported claims

**Out of Scope** (for initial design):
- Validating MEDIUM/LOW findings (too many, lower impact)
- Re-running detectors (validation is post-detection)
- Modifying findings (validator only flags issues)
- Interactive user prompts (fully automated)

## Architecture

### High-Level Flow

```
Engine Detectors
    ↓
Raw Findings (all severities)
    ↓
[Filter: CRITICAL only]
    ↓
Adversarial Validator
    ↓
Validated Findings + Validation Reports
    ↓
CLI Output
```

### Validator Structure

```python
class AdversarialValidator:
    """Systematically challenge CRITICAL findings to catch errors."""
    
    def validate(self, finding: Finding) -> ValidationReport:
        checks = [
            self._check_evidence_completeness(finding),
            self._check_reasoning_logic(finding),
            self._check_confidence_justification(finding),
            self._check_alternative_explanations(finding),
            self._check_temporal_consistency(finding),
            self._check_hash_format(finding),
        ]
        return ValidationReport(finding, checks)
```

## Validation Checks

### 1. Evidence Completeness

**Purpose**: Ensure all claims have supporting evidence

**Checks**:
- Every reasoning step references evidence dict keys
- Hash claims include full hash (not truncated)
- Timestamps include timezone info
- File paths are fully qualified (not relative)
- All referenced artifacts exist in evidence

**Example**:
```python
def _check_evidence_completeness(self, finding: Finding) -> ValidationCheck:
    issues = []
    
    # Check reasoning references evidence
    for step in finding.reasoning_chain:
        if "SHA-256" in step or "hash" in step.lower():
            # Reasoning mentions hash - evidence must contain it
            if not any("sha256" in k or "hash" in k for k in finding.evidence):
                issues.append("Reasoning mentions hash but evidence lacks hash field")
    
    # Check hash format (must be 64 hex chars)
    for key, value in finding.evidence.items():
        if "sha256" in key.lower() and isinstance(value, str):
            if not re.match(r'^[a-f0-9]{64}$', value):
                issues.append(f"Invalid SHA-256 format: {value}")
    
    return ValidationCheck("evidence_completeness", issues)
```

### 2. Reasoning Logic

**Purpose**: Identify logical fallacies or unsupported leaps

**Checks**:
- Each step follows from previous step
- No circular reasoning
- Conclusions match evidence
- Causal claims have temporal support (cause before effect)
- Quantitative claims match evidence numbers

**Example**:
```python
def _check_reasoning_logic(self, finding: Finding) -> ValidationCheck:
    issues = []
    
    # Check temporal causality for exfiltration claims
    if finding.category == FindingCategory.DATA_EXFILTRATION:
        if "emailed" in finding.description:
            # Must have file_modified < email_sent
            file_time = finding.evidence.get("file_modified")
            email_time = finding.evidence.get("email_sent")
            
            if file_time and email_time:
                if file_time >= email_time:
                    issues.append(
                        f"Causality violation: file modified {file_time} "
                        f"after email sent {email_time}"
                    )
    
    return ValidationCheck("reasoning_logic", issues)
```

### 3. Confidence Justification

**Purpose**: Challenge confidence scores that may be overconfident

**Checks**:
- 0.95 confidence requires near-deterministic evidence
- Time windows must be narrow (<60s for 0.95)
- Multiple independent evidence sources
- No contradictory evidence ignored
- Confidence calculation matches stated rationale

**Example**:
```python
def _check_confidence_justification(self, finding: Finding) -> ValidationCheck:
    issues = []
    
    if finding.confidence >= 0.95:
        # Very High confidence requires exceptional evidence
        if finding.category == FindingCategory.DATA_EXFILTRATION:
            time_delta = finding.evidence.get("time_delta_seconds")
            
            if time_delta and time_delta > 60:
                issues.append(
                    f"Confidence 0.95 with {time_delta}s delta too high. "
                    f"Time window >60s suggests 0.90 more appropriate."
                )
    
    return ValidationCheck("confidence_justification", issues)
```

### 4. Alternative Explanations

**Purpose**: Ensure competing hypotheses were considered

**Checks**:
- Backup software (for file-to-email correlation)
- Automated sync (for file transfers)
- Legitimate admin tools (for process injection)
- System maintenance (for timestamp anomalies)

**Example**:
```python
def _check_alternative_explanations(self, finding: Finding) -> ValidationCheck:
    issues = []
    
    if finding.category == FindingCategory.DATA_EXFILTRATION:
        # Check if backup software possibility was addressed
        reasoning_text = " ".join(finding.reasoning_chain).lower()
        
        if "backup" not in reasoning_text and "sync" not in reasoning_text:
            # High time delta + no mention of backup = missed alternative
            time_delta = finding.evidence.get("time_delta_seconds", 0)
            if time_delta > 120:
                issues.append(
                    "Alternative explanation not addressed: automated backup "
                    "software could explain >2min delay"
                )
    
    return ValidationCheck("alternative_explanations", issues)
```

### 5. Temporal Consistency

**Purpose**: Verify timestamps are internally consistent

**Checks**:
- All timestamps have timezone or all are naive (no mixing)
- Timestamps follow logical sequence (save before send)
- Time deltas computed correctly
- No timezone conversion errors

**Example**:
```python
def _check_temporal_consistency(self, finding: Finding) -> ValidationCheck:
    issues = []
    
    # Check timezone consistency
    timestamps = []
    for key, value in finding.evidence.items():
        if "time" in key.lower() or "modified" in key.lower():
            if isinstance(value, str):
                try:
                    dt = datetime.fromisoformat(value)
                    timestamps.append((key, dt))
                except:
                    pass
    
    # All timestamps should have same timezone awareness
    if timestamps:
        aware = [dt.tzinfo is not None for _, dt in timestamps]
        if not (all(aware) or not any(aware)):
            issues.append("Mixed timezone-aware and naive timestamps")
    
    return ValidationCheck("temporal_consistency", issues)
```

### 6. Hash Format Validation

**Purpose**: Catch hash typos and format errors

**Checks**:
- SHA-256 is exactly 64 hex characters
- MD5 is exactly 32 hex characters
- No spaces, dashes, or other separators
- Lowercase hex only (or consistent casing)

**Example**:
```python
def _check_hash_format(self, finding: Finding) -> ValidationCheck:
    issues = []
    
    for key, value in finding.evidence.items():
        if "sha256" in key.lower() or "sha-256" in key.lower():
            if not isinstance(value, str):
                issues.append(f"{key} should be string, got {type(value)}")
                continue
            
            if not re.match(r'^[a-f0-9]{64}$', value):
                issues.append(
                    f"Invalid SHA-256 in {key}: {value} "
                    f"(expected 64 hex chars)"
                )
    
    return ValidationCheck("hash_format", issues)
```

## Validation Report Format

```python
@dataclass
class ValidationCheck:
    """Single validation check result."""
    check_name: str
    issues: list[str]  # Empty if passed
    
    @property
    def passed(self) -> bool:
        return len(self.issues) == 0


@dataclass
class ValidationReport:
    """Complete validation report for a finding."""
    finding: Finding
    checks: list[ValidationCheck]
    validation_timestamp: datetime
    
    @property
    def passed(self) -> bool:
        """All checks passed."""
        return all(check.passed for check in self.checks)
    
    @property
    def critical_issues(self) -> list[str]:
        """Issues that invalidate the finding."""
        # Evidence completeness and reasoning logic are critical
        critical_check_names = ["evidence_completeness", "reasoning_logic", "hash_format"]
        issues = []
        for check in self.checks:
            if check.check_name in critical_check_names:
                issues.extend(check.issues)
        return issues
    
    @property
    def warnings(self) -> list[str]:
        """Issues that weaken but don't invalidate the finding."""
        warning_check_names = ["confidence_justification", "alternative_explanations", "temporal_consistency"]
        warnings = []
        for check in self.checks:
            if check.check_name in warning_check_names:
                warnings.extend(check.issues)
        return warnings
```

## Integration Points

### CLI Integration

```python
def cmd_analyze(args):
    # ... existing parsing ...
    
    # Run detectors
    findings = engine.analyze(...)
    
    # Validate CRITICAL findings
    validator = AdversarialValidator()
    validated_findings = []
    validation_reports = []
    
    for finding in findings:
        if finding.severity == "critical":
            report = validator.validate(finding)
            validation_reports.append(report)
            
            if report.critical_issues:
                # Finding failed validation - log but suppress
                logger.warning(
                    f"CRITICAL finding failed validation: {finding.title}\n"
                    f"  Issues: {report.critical_issues}"
                )
                # Don't add to validated_findings
            else:
                # Finding passed - include with validation notes
                if report.warnings:
                    # Attach warnings to finding metadata
                    finding.metadata["validation_warnings"] = report.warnings
                validated_findings.append(finding)
        else:
            # Non-CRITICAL findings pass through unvalidated
            validated_findings.append(finding)
    
    # Display validated findings
    _render_findings(validated_findings)
    
    # Optionally show validation summary
    if args.verbose:
        _render_validation_summary(validation_reports)
```

### Output Format

**Passed Validation**:
```
[Finding 1] Data exfiltration detected: 1 file(s) emailed within 300s
  Severity: CRITICAL
  Category: data_exfiltration
  Confidence: 0.95 (Very High)
  ✓ Validation: PASSED (6 checks)
```

**Failed Validation** (suppressed):
```
[SUPPRESSED] Data exfiltration detected: ...
  Reason: Failed validation
  Issues:
    - Invalid SHA-256 format: abc123 (expected 64 hex chars)
    - Causality violation: file modified after email sent
```

**Warnings** (included with notes):
```
[Finding 1] Data exfiltration detected: ...
  ✓ Validation: PASSED with warnings
    ⚠ Confidence 0.95 with 180s delta may be too high
    ⚠ Alternative explanation not addressed: automated backup
```

## Performance Considerations

- Validation adds ~10ms per CRITICAL finding (negligible)
- Jean case: 1 CRITICAL finding → <10ms overhead
- Typical case: 3-5 CRITICAL findings → <50ms overhead
- Regex checks are cached for performance
- No file I/O or network calls

## Testing Strategy

### Unit Tests

```python
def test_hash_format_validation():
    """Valid SHA-256 passes, invalid fails."""
    validator = AdversarialValidator()
    
    # Valid hash
    finding1 = Finding(
        evidence={"file_sha256": "a" * 64}
    )
    check = validator._check_hash_format(finding1)
    assert check.passed
    
    # Invalid hash (too short)
    finding2 = Finding(
        evidence={"file_sha256": "abc123"}
    )
    check = validator._check_hash_format(finding2)
    assert not check.passed
    assert "expected 64 hex chars" in check.issues[0]
```

### Integration Tests

```python
def test_jean_exfil_passes_validation():
    """Jean m57biz.xls exfiltration finding passes all checks."""
    # Run detector
    finding = detect_exfiltration(...)
    
    # Validate
    validator = AdversarialValidator()
    report = validator.validate(finding)
    
    assert report.passed
    assert len(report.critical_issues) == 0
```

## Future Enhancements

### Phase 2: Machine Learning Validation

- Train classifier on validated vs rejected findings
- Learn which evidence patterns correlate with false positives
- Adaptive confidence adjustment based on historical accuracy

### Phase 3: Cross-Finding Validation

- Check for contradictory findings (same artifact, conflicting interpretations)
- Validate finding relationships (does finding A support or contradict B?)
- Timeline consistency across all findings

### Phase 4: External Knowledge Validation

- Check file hashes against VirusTotal
- Verify tool signatures against known-good lists (NSRL)
- Validate IP addresses against threat intelligence feeds

## Security Considerations

- Validator must not leak information (no external API calls)
- Validation logs should be sanitized (no full file paths or hashes in default output)
- Failed validation should not expose evidence to unprivileged users

## Success Metrics

**Quantitative**:
- False positive rate reduction: Target 50% (from manual validation experience)
- Validation overhead: <100ms per analysis run
- Zero false negatives (valid findings incorrectly suppressed)

**Qualitative**:
- User trust: Findings that pass validation should feel credible
- Debuggability: Validation failures should clearly explain the issue
- Maintainability: Adding new checks should be straightforward

## Implementation Roadmap

### Phase 1: Core Validator (This Issue - SFE-6)
- ✓ Design document (this file)
- Next: Implement `AdversarialValidator` class
- Next: Add 6 core validation checks
- Next: Integrate into CLI
- Next: Test on Jean case

### Phase 2: Expanded Checks
- Add category-specific validators
- Add cross-artifact consistency checks
- Add statistical anomaly detection

### Phase 3: Adaptive Validation
- Learn from user feedback (which findings were actually correct?)
- Adjust validation thresholds based on historical accuracy
- A/B test different validation strategies

## References

- Original validator pass discussion: Jean case analysis (SFE-5)
- CRITICAL finding examples: Jean exfiltration (SFE-F1), CIRCL wipe (SFE-83h)
- Detection architecture: `docs/AGENT_ARCHITECTURE_RECOMMENDATION.md`

---

**Status**: Design Complete - Ready for Implementation  
**Next Steps**: Create implementation issue (SFE-XXX: Implement adversarial validator)  
**Estimated Effort**: 4-6 hours (validator class + 6 checks + CLI integration + tests)
