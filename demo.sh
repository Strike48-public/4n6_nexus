#!/usr/bin/env bash
# SIFT Find Evil - Demo Script
# Demonstrates autonomous self-correction engine

set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
cat << 'EOF'
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   SIFT FIND EVIL - Demo Script                               ║
║   Autonomous DFIR Agent with Self-Correction                 ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${YELLOW}This demo shows:${NC}"
echo "  1. Cross-artifact validation (MFT, Prefetch, Event Logs)"
echo "  2. Causality violation detection (file modified AFTER execution)"
echo "  3. Event Log tiebreaker resolution"
echo "  4. Confidence score adjustment with reasoning chain"
echo ""

echo -e "${GREEN}Press Enter to start demo...${NC}"
read -r

echo -e "\n${BLUE}Running self-correction engine with synthetic data...${NC}\n"

# Run demo
python -m sift_find_evil demo

echo -e "\n${GREEN}Demo complete!${NC}"
echo ""
echo "Key Points:"
echo "  - Detected causality violation (malware.exe modified 15 min after execution)"
echo "  - Resolved via Event ID 4688 (confirms execution at 14:25:03)"
echo "  - Confidence: 0.95 → 0.45 (contradiction) → 0.75 (resolution)"
echo "  - Full reasoning chain provided for audit trail"
echo ""
echo "Try it yourself:"
echo "  python -m sift_find_evil demo --output findings.json"
echo ""
