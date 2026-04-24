# Security Verification Guide

**Purpose:** How to verify that 4n6Nexus is secured and has not been tampered with
**Audience:** Security reviewers, team members, users
**Last Updated:** 2026-04-24

---

## Overview

This document answers: **"How do we verify that the system is secured and not tampered with?"**

We address four critical security domains:
1. **Evidence Integrity** - Ensuring analyzed evidence hasn't been modified
2. **Tool Integrity** - Verifying 4n6Nexus software itself is authentic
3. **Audit Trail Integrity** - Proving findings are legitimate and traceable
4. **Runtime Security** - Protecting the system during execution

---

## 1. Evidence Integrity Verification

### Read-Only Enforcement (Architectural)

**How it works:**
```python
# sift_find_evil/mcp/safety.py
class SafetyLayer:
    def verify_read_only(self, path: str) -> bool:
        """Verify evidence is mounted read-only."""
        import os
        
        # Check mount options
        with open('/proc/mounts', 'r') as f:
            for line in f:
                if path in line and 'ro' not in line:
                    raise SecurityError(f"Evidence not mounted read-only: {path}")
        
        # Verify filesystem is read-only
        test_file = os.path.join(path, '.write_test')
        try:
            with open(test_file, 'w') as f:
                f.write('test')
            # If we got here, filesystem is writable (BAD)
            raise SecurityError(f"Evidence filesystem is writable: {path}")
        except (IOError, OSError):
            # Expected - filesystem is read-only (GOOD)
            pass
        
        return True
```

**Verification checklist:**
- [ ] Evidence mounted with `ro` (read-only) flag
- [ ] Write attempts fail immediately
- [ ] MCP client logs read-only verification in audit log
- [ ] Filesystem immutability enforced at OS level

**Manual verification:**
```bash
# Check mount options
mount | grep /mnt/evidence
# Should show: /dev/loop0 on /mnt/evidence type ntfs (ro,...)

# Attempt write (should fail)
touch /mnt/evidence/test.txt
# Expected: touch: cannot touch '/mnt/evidence/test.txt': Read-only file system

# Verify in audit log
cat /cases/case-001/audit.jsonl | jq 'select(.event == "read_only_verification")'
```

### Cryptographic Hashing

**How it works:**
Every tool execution's output is hashed with SHA-256:

```json
{
  "timestamp": "2024-04-24T14:32:10.123456Z",
  "event": "tool_execution",
  "details": {
    "tool": "MFTECmd",
    "command": "MFTECmd.exe -f /mnt/evidence/$MFT --csv /cases/case-001/mft_output",
    "exit_code": 0,
    "output_sha256": "a3d5f7b9c1e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4",
    "read_only_verified": true
  }
}
```

**Verification:**
```bash
# Verify output hasn't been modified
sha256sum /cases/case-001/mft_output/output.csv
# Compare with audit log hash

cat /cases/case-001/audit.jsonl | jq -r 'select(.details.tool == "MFTECmd") | .details.output_sha256'
# Hashes must match
```

### Evidence Source Tracking

**Chain of custody metadata:**
```json
{
  "case_id": "case-001",
  "evidence_sources": [
    {
      "type": "E01",
      "path": "/media/evidence/disk.E01",
      "sha256": "original_image_hash",
      "acquisition_date": "2024-01-15T10:00:00Z",
      "acquired_by": "Analyst Name",
      "chain_of_custody_id": "COC-2024-001"
    }
  ],
  "mount_verification": {
    "read_only": true,
    "verified_at": "2024-04-24T14:30:00Z"
  }
}
```

---

## 2. Tool Integrity Verification

### Software Supply Chain Security

**Community Edition (Open Source):**

#### Package Signature Verification

```bash
# When we publish to PyPI (after competition)
pip install 4n6nexus

# Verify package signature
pip download --no-deps 4n6nexus
gpg --verify 4n6nexus-1.0.0.tar.gz.asc 4n6nexus-1.0.0.tar.gz

# Import our public key first
gpg --keyserver keys.openpgp.org --recv-keys FINGERPRINT
```

#### Git Commit Signing

All commits are signed with GPG:

```bash
# Verify commit signatures
git log --show-signature

# Verify specific commit
git verify-commit 855c21f
```

#### Reproducible Builds

```bash
# Build from source
git clone https://github.com/4n6nexus/4n6nexus.git
cd 4n6nexus
git checkout v1.0.0  # Specific release tag

# Build
python -m build

# Compare hash with official release
sha256sum dist/4n6nexus-1.0.0.tar.gz
# Compare with published hash on GitHub release page
```

#### Dependency Verification

```bash
# Check for known vulnerabilities
pip install safety
safety check -r requirements.txt

# Verify dependency integrity
pip install pip-audit
pip-audit
```

### Source Code Auditing

**Community Edition advantages:**
- Full source code available for review
- No obfuscation or binary blobs
- Community can audit and verify
- All dependencies are open source

**Audit checklist:**
- [ ] Review MCP safety layer (`sift_find_evil/mcp/`)
- [ ] Review self-correction logic (`sift_find_evil/self_correction/`)
- [ ] Review detector implementations (`sift_find_evil/detectors/`)
- [ ] Check for backdoors, command injection, privilege escalation
- [ ] Verify no network calls to external servers (unless documented)
- [ ] Review cryptographic implementations (use standard libraries)

### Container Image Verification

```bash
# Docker images signed with Docker Content Trust
export DOCKER_CONTENT_TRUST=1
docker pull 4n6nexus/4n6nexus:1.0.0

# Verify image signature
docker trust inspect 4n6nexus/4n6nexus:1.0.0

# Scan for vulnerabilities
docker scan 4n6nexus/4n6nexus:1.0.0
```

---

## 3. Audit Trail Integrity

### Append-Only Logging

**Implementation:**
```python
# sift_find_evil/mcp/audit.py
class AuditLogger:
    def __init__(self, log_path: str):
        self.log_path = log_path
        # Open in append mode only
        self.log_file = open(log_path, 'a')
    
    def log_event(self, event: dict):
        """Log event to JSONL (append-only)."""
        # Add timestamp if not present
        if 'timestamp' not in event:
            event['timestamp'] = datetime.utcnow().isoformat() + 'Z'
        
        # Write as single line JSON
        json.dump(event, self.log_file)
        self.log_file.write('\n')
        self.log_file.flush()
        os.fsync(self.log_file.fileno())  # Force write to disk
```

**Key properties:**
- Logs are append-only (no modification or deletion)
- Each line is independently parseable JSON
- Filesystem sync after each write
- Timestamps in UTC for consistency

**Verification:**
```bash
# Verify log file hasn't been truncated
stat /cases/case-001/audit.jsonl
# Check file size increases over time (never decreases)

# Verify chronological ordering
cat /cases/case-001/audit.jsonl | jq -r '.timestamp' | sort -c
# Should be sorted (no errors)

# Check for gaps in timestamps
cat /cases/case-001/audit.jsonl | jq -r '.timestamp' | awk 'NR>1{print $0, prev} {prev=$0}'
# Look for suspicious time jumps
```

### Finding Traceability

**Every finding traces back to source:**

```json
{
  "finding_id": "FINDING-001",
  "title": "Timestomping Detection: backdoor.exe",
  "evidence_sources": [
    {
      "audit_log_entry": "2024-04-24T14:32:10.123456Z",
      "tool": "MFTECmd",
      "output_file": "/cases/case-001/mft_output/output.csv",
      "output_sha256": "a3d5f7b9c1e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4",
      "line_number": 15432
    }
  ]
}
```

**Verification workflow:**
1. Find the finding in `findings.json`
2. Extract `audit_log_entry` timestamp and `tool` name
3. Find corresponding entry in `audit.jsonl`
4. Verify output hash matches
5. Open output file and verify line number
6. Confirm finding is based on actual tool output

**Command:**
```bash
# Trace finding back to source
FINDING_ID="FINDING-001"
AUDIT_TIMESTAMP=$(jq -r --arg id "$FINDING_ID" '.[] | select(.finding_id == $id) | .evidence_sources[0].audit_log_entry' findings.json)

# Find audit log entry
cat audit.jsonl | jq --arg ts "$AUDIT_TIMESTAMP" 'select(.timestamp == $ts)'

# Verify output hash
OUTPUT_HASH=$(jq -r --arg ts "$AUDIT_TIMESTAMP" 'select(.timestamp == $ts) | .details.output_sha256' audit.jsonl)
sha256sum /cases/case-001/mft_output/output.csv
# Compare hashes
```

### Tamper Detection

**If audit log is modified, it's detectable:**

```bash
# Hash entire audit log
sha256sum /cases/case-001/audit.jsonl > /cases/case-001/audit.jsonl.sha256

# Later, verify integrity
sha256sum -c /cases/case-001/audit.jsonl.sha256
# If modified: "audit.jsonl: FAILED"
```

**Advanced: Merkle tree for individual entries:**
```python
# Each entry includes hash of previous entry
{
  "timestamp": "2024-04-24T14:32:15.000000Z",
  "event": "tool_execution",
  "previous_entry_hash": "sha256_of_previous_line",
  "details": {...}
}
```

This makes it impossible to modify or delete entries without detection.

---

## 4. Runtime Security

### Isolation & Sandboxing

**Analysis runs in isolated environment:**

```bash
# Docker container (recommended)
docker run --rm -it \
  --read-only \  # Container filesystem is read-only
  --tmpfs /tmp:rw,noexec,nosuid,size=1G \  # Temp space (no execution)
  -v /evidence:/evidence:ro \  # Evidence read-only
  -v /cases:/cases:rw \  # Cases writable (audit logs)
  4n6nexus/4n6nexus:1.0.0

# VM isolation (SIFT Workstation)
# Evidence on separate network share (read-only mount)
# Analysis VM has no internet access during investigation
```

### Privilege Separation

**Principle of least privilege:**

```bash
# Run as non-root user
adduser --system --no-create-home forensics
chown forensics:forensics /cases

# Run analysis as non-privileged user
su - forensics -c "4n6nexus analyze --case-id case-001"
```

### Network Isolation

**No network access during analysis:**

```bash
# Disable network (if analyzing malware)
iptables -A OUTPUT -j DROP

# Or run in air-gapped environment
# Evidence transferred via USB (not network)
```

### Timeout Guards

**Prevent infinite loops / resource exhaustion:**

```python
# sift_find_evil/mcp/safety.py
def execute_with_timeout(command: str, timeout: int = 600):
    """Execute command with timeout."""
    import subprocess
    
    try:
        result = subprocess.run(
            command,
            shell=False,  # No shell injection
            timeout=timeout,
            capture_output=True
        )
        return result
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"Command exceeded {timeout}s timeout: {command}")
```

### Circuit Breaker

**Stop execution if tools repeatedly fail:**

```python
# sift_find_evil/mcp/safety.py
class CircuitBreaker:
    def __init__(self, max_failures: int = 3):
        self.failures = 0
        self.max_failures = max_failures
    
    def record_failure(self):
        self.failures += 1
        if self.failures >= self.max_failures:
            raise CircuitBreakerError("Too many consecutive failures, stopping execution")
    
    def record_success(self):
        self.failures = 0  # Reset on success
```

---

## 5. Verification Checklist

### Before Analysis

- [ ] **Evidence integrity verified**
  - [ ] Evidence mounted read-only
  - [ ] Original evidence hash documented
  - [ ] Chain of custody recorded
  
- [ ] **Tool integrity verified**
  - [ ] 4n6Nexus installed from trusted source (PyPI, official GitHub)
  - [ ] Package signature verified (if available)
  - [ ] Dependencies scanned for vulnerabilities
  
- [ ] **Environment secured**
  - [ ] Running in isolated VM or container
  - [ ] Network access disabled (if analyzing malware)
  - [ ] Non-privileged user account

### During Analysis

- [ ] **Runtime monitoring**
  - [ ] Audit log is being written
  - [ ] No unexpected network connections
  - [ ] CPU/memory usage reasonable
  - [ ] No writes to evidence filesystem

### After Analysis

- [ ] **Output verification**
  - [ ] Audit log complete (no gaps in timestamps)
  - [ ] All tool executions logged
  - [ ] Output hashes match audit log
  - [ ] Findings traceable to source

- [ ] **Integrity checks**
  - [ ] Evidence hash unchanged
  - [ ] Audit log hash recorded
  - [ ] No modifications to evidence filesystem

---

## 6. Threat Model

### What We Protect Against

✅ **Evidence tampering** - Read-only mounts prevent modification
✅ **Tool output tampering** - Cryptographic hashes detect changes
✅ **Audit log tampering** - Append-only + hashing
✅ **Malicious tools** - MCP safety layer sandboxes execution
✅ **Resource exhaustion** - Timeouts and circuit breakers
✅ **Privilege escalation** - Non-root execution

### What We Don't Protect Against (Out of Scope)

❌ **Compromised SIFT VM** - If entire VM is compromised, all bets are off
❌ **Malicious forensic tools** - We trust MFTECmd, PECmd, etc. are legitimate
❌ **Physical access attacks** - Assumes workstation is physically secured
❌ **Insider threats with admin access** - Assumes analysts are trusted

### Assumptions

1. **SIFT VM is trustworthy** - Running on secure hardware
2. **Forensic tools are genuine** - Downloaded from official sources
3. **Analyst is trusted** - Has legitimate access to evidence
4. **Network is untrusted** - Evidence analyzed offline when possible
5. **Storage is persistent** - Audit logs stored on durable storage

---

## 7. Independent Verification

### Third-Party Audit (Enterprise Edition)

For high-stakes investigations, Enterprise Edition supports:

**Independent verification by second analyst:**
```bash
# Analyst 1 generates audit log and findings
4n6nexus analyze --case-id case-001 --evidence /evidence/disk.E01

# Analyst 2 verifies independently
4n6nexus verify --case-id case-001 --audit-log /cases/case-001/audit.jsonl

# Outputs:
# ✓ Evidence integrity verified (hashes match)
# ✓ All tool executions reproducible
# ✓ No tampering detected
# ✓ Findings trace to source
```

**Court-admissible verification:**
- Export audit log and findings
- Independent expert verifies:
  - Evidence wasn't modified (read-only verification)
  - Tool outputs match hashes
  - Findings derive from tool outputs (not fabricated)
  - No gaps or inconsistencies in audit trail

---

## 8. Compliance & Standards

### NIST Guidelines

Follows NIST SP 800-86 (Guide to Integrating Forensic Techniques into Incident Response):
- Evidence preservation (read-only)
- Chain of custody documentation
- Tool validation
- Audit trail requirements

### ISO/IEC 27037

Follows ISO/IEC 27037 (Guidelines for identification, collection, acquisition and preservation of digital evidence):
- Evidence handling procedures
- Integrity verification
- Documentation requirements

### ACPO Principles (UK)

Follows ACPO Good Practice Guide for Digital Evidence:
1. No action should change data on original media
2. Person accessing original data must be competent
3. Audit trail of all processes applied to evidence
4. Person in charge ensures compliance with law and principles

---

## 9. Security Contact

**Report security vulnerabilities:**
- Email: security@4n6nexus.dev
- PGP Key: [Public key fingerprint]
- Response time: 48 hours for critical issues

**Do NOT:**
- Open public GitHub issues for security vulnerabilities
- Exploit vulnerabilities in production systems
- Share vulnerability details publicly before fix

**Responsible disclosure:**
1. Report privately to security@4n6nexus.dev
2. Wait for acknowledgment (48 hours)
3. Coordinate disclosure timeline
4. Public disclosure after fix is released

---

## Summary

**4n6Nexus security is verified through:**

1. **Evidence Integrity** - Read-only enforcement + cryptographic hashing
2. **Tool Integrity** - Open source + package signatures + reproducible builds
3. **Audit Trail Integrity** - Append-only logging + finding traceability
4. **Runtime Security** - Isolation + timeouts + circuit breakers

**Key verification commands:**
```bash
# Verify evidence is read-only
mount | grep /mnt/evidence | grep "ro"

# Verify output hashes match
sha256sum /cases/case-001/mft_output/output.csv
cat /cases/case-001/audit.jsonl | jq -r '.details.output_sha256'

# Verify audit log integrity
sha256sum /cases/case-001/audit.jsonl

# Trace finding to source
jq '.[] | select(.finding_id == "FINDING-001")' findings.json
```

**For court-admissible investigations:**
- Complete audit trail in JSONL format
- All findings traceable to tool output
- Cryptographic hashes prove integrity
- Independent verification possible

---

**Document Owner:** Security Team
**Last Updated:** 2026-04-24
**Next Review:** After security audit
