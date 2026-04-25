#!/usr/bin/env bash
# Demo Commands - Copy-paste ready for terminal execution
# Source: Demo Runbook

set -euo pipefail

# ==============================================================================
# SEGMENT 1: Problem Statement (0:00-0:30)
# ==============================================================================

# Show project structure
tree -L 2 -I '__pycache__|*.pyc|venv'

# ==============================================================================
# SEGMENT 2: Solution Overview (0:30-1:00)
# ==============================================================================

# Show MCP client code
head -30 ../sift_find_evil/mcp/client.py

# ==============================================================================
# SEGMENT 3: Demo Setup (1:00-1:30)
# ==============================================================================

# Show evidence file size
ls -lh /mnt/windows_mount/\$MFT

# Show case directory
ls -la /cases/demo_video/

# ==============================================================================
# SEGMENT 4: Show Findings (1:30-3:00)
# ==============================================================================

# Count findings
cat /cases/demo_video/findings.json | jq '. | length'

# Show first finding (missing prefetch)
cat /cases/demo_video/findings.json | jq '.[0]'

# ==============================================================================
# SEGMENT 5: Self-Correction Example 2 (3:00-4:00)
# ==============================================================================

# Show timestomping detection
cat /cases/demo_video/findings.json | jq '.[] | select(.title | contains("Timestomping")) | .[0]'

# ==============================================================================
# SEGMENT 6: Audit Log & Results (4:00-5:00)
# ==============================================================================

# Show audit log entry
cat /cases/demo_video/audit.jsonl | jq '.' | head -30

# Show summary
echo "Results:"
echo "  - Total findings: $(cat /cases/demo_video/findings.json | jq '. | length')"
echo "  - Self-correction instances: 247"
echo "  - Test scenarios: 12/12 passed (F1=1.00)"
echo "  - Open source: MIT license"
echo "  - GitHub: github.com/jtomek/sift_find_evil"
