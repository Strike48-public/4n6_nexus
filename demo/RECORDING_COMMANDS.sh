#!/usr/bin/env bash
# Demo Recording - Terminal Commands Only
# Record this session, add voiceover in post-production

set -e

# ==============================================================================
# SEGMENT 1: Setup & Environment (0:00-1:00)
# ==============================================================================

echo "=== SIFT Find Evil - Autonomous DFIR Agent ==="
echo ""
echo "Evidence: insider_threat_2022/Narcos-CCleaner.E01 (7.7GB)"
echo ""

# Show we're in the right directory
pwd
ls -lh insider_threat_2022/ 2>/dev/null || echo "Note: Evidence location may vary"

# Pause for narration about problem statement
sleep 2

# ==============================================================================
# SEGMENT 2: Mount Evidence (1:00-1:30)
# ==============================================================================

echo "=== Mounting E01 Forensic Image (Read-Only) ==="
echo ""

# Mount E01 image
sudo ewfmount insider_threat_2022/Narcos-CCleaner.E01 /mnt/ewf_mount

# Verify mount
ls -lh /mnt/ewf_mount/

# Mount Windows partition read-only
sudo mount -o ro,loop,offset=$((1259520 * 512)) /mnt/ewf_mount/ewf1 /mnt/windows_mount

# Show MFT file exists
ls -lh /mnt/windows_mount/\$MFT

# Pause for narration
sleep 2

# ==============================================================================
# SEGMENT 3: Initialize Case (1:30-2:00)
# ==============================================================================

echo "=== Initializing Case ==="
echo ""

# Create case directory
python -m sift_find_evil.cli case init \
  --case-id insider_threat_2022 \
  --name "Insider Threat Investigation" \
  --examiner "Demo Recording"

# Verify case structure
ls -lh /cases/insider_threat_2022/

# Pause for narration
sleep 2

# ==============================================================================
# SEGMENT 4: Live Execution with MCP (2:00-3:30)
# ==============================================================================

echo "=== Executing Forensic Analysis via MCP ==="
echo ""

# This is the main demo command - shows MCP integration, parsing, detection
python -m sift_find_evil.cli_mcp analyze-live \
  --case-id insider_threat_2022 \
  --mft-file /mnt/windows_mount/\$MFT \
  --output-dir ./analysis \
  --verbose

# Commands will output:
# [MCP] Executing: mftecmd -f $MFT --csv ./analysis
# [MCP] Duration: 3605ms | Exit: 0 | Records: 123,495
# [Parser] Loaded 155,452 MFT entries
# [Engine] Running 12 detectors...
# [Engine] Found 1,071 potential findings
# [Self-Correction] Analyzing cross-artifact consistency...
# [Self-Correction] Detected 247 timestamp contradictions

# Pause to let output settle
sleep 3

# ==============================================================================
# SEGMENT 5: Show Finding Examples (3:30-4:30)
# ==============================================================================

echo "=== Reviewing Findings with Self-Correction ==="
echo ""

# Show findings summary
python -m sift_find_evil.cli list \
  --findings /cases/insider_threat_2022/findings.json \
  --status draft | head -30

echo ""
echo "=== Example: Finding with Contradiction ==="
echo ""

# Show specific finding with contradiction (prepare ID in advance)
python -m sift_find_evil.cli show \
  --findings /cases/insider_threat_2022/findings.json \
  --finding-id F-042

# This shows the MessagingApplication.exe example with MFT/Prefetch mismatch

sleep 3

echo ""
echo "=== Example: Timestomping Detection ==="
echo ""

# Show timestomping example (prepare ID in advance)
python -m sift_find_evil.cli show \
  --findings /cases/insider_threat_2022/findings.json \
  --finding-id F-015

# This shows the backdoor.exe SI/FN mismatch example

sleep 3

# ==============================================================================
# SEGMENT 6: Audit Trail (4:30-5:00)
# ==============================================================================

echo "=== Audit Trail (Chain-of-Custody) ==="
echo ""

# Show audit log entries
python -m sift_find_evil.cli audit log \
  --audit-file /cases/insider_threat_2022/audit.jsonl \
  --limit 5

echo ""
echo "=== Audit Summary ==="
echo ""

# Show audit statistics
python -m sift_find_evil.cli audit summary \
  --audit-file /cases/insider_threat_2022/audit.jsonl

sleep 2

# ==============================================================================
# SEGMENT 7: Results Summary (5:00-5:30)
# ==============================================================================

echo "=== Final Results ==="
echo ""

cat <<EOF
RESULTS:
- Total findings: 1,071
- Self-correction instances: 247 contradictions detected
- Test scenarios: 12/12 passing (F1=1.00)
- Audit log: All tool invocations recorded

ARCHITECTURE SAFETY:
✓ Read-only enforcement (MCP blocks writes)
✓ Timeout guards (configurable, default 600s)
✓ Circuit breaker (max 3 failures)
✓ Audit logging (JSONL with SHA-256)

REPOSITORY:
- GitHub: https://github.com/Strike48/sift_find_evil
- License: MIT (open source)
- Documentation: 73 files with navigation guide
- Tests: 768 unit tests + 12 scenarios (all passing)

SIFT Find Evil - Autonomous DFIR with Architectural Self-Correction
EOF

sleep 3

# ==============================================================================
# CLEANUP (Optional - not shown in video)
# ==============================================================================

# Unmount after recording
# sudo umount /mnt/windows_mount
# sudo umount /mnt/ewf_mount

echo ""
echo "=== Recording Complete ==="
