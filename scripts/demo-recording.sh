#!/usr/bin/env bash
# Canned demo runner for SIFT Find Evil.
#
# Runs the three demo beats with paced output and section headers so a presenter
# can narrate over it without typing live. Safe fallback if a live demo misbehaves.
#
# Usage:
#   ./scripts/demo-recording.sh           # interactive (pauses between beats)
#   ./scripts/demo-recording.sh --auto    # no pauses, for screen recording

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

AUTO=0
[[ "${1:-}" == "--auto" ]] && AUTO=1

# Colors (fall back to plain if not a tty)
if [[ -t 1 ]]; then
  BLUE='\033[0;34m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
else
  BLUE=''; GREEN=''; YELLOW=''; BOLD=''; NC=''
fi

section() {
  echo ""
  echo -e "${BLUE}${BOLD}======================================================================${NC}"
  echo -e "${BLUE}${BOLD}  $1${NC}"
  echo -e "${BLUE}${BOLD}======================================================================${NC}"
  echo ""
}

pause() {
  if [[ "$AUTO" -eq 0 ]]; then
    echo ""
    echo -e "${GREEN}Press Enter to continue...${NC}"
    read -r
  else
    sleep 2
  fi
}

# Ensure we run under the venv interpreter if present, else system python3.
PY="python3"
if [[ -x "$REPO_ROOT/venv/bin/python" ]]; then
  PY="$REPO_ROOT/venv/bin/python"
fi

section "SIFT Find Evil - Demo"
echo -e "${YELLOW}Autonomous DFIR detection with architectural self-correction.${NC}"
echo "Three beats: (1) self-correction, (2) validation, (3) the TUI."
pause

section "Beat 1/3 - Self-correction engine"
echo -e "${YELLOW}A file that executed BEFORE it was modified is a causality violation.${NC}"
echo -e "${YELLOW}Watch the engine detect it, drop confidence, resolve via Event Log,${NC}"
echo -e "${YELLOW}and log the full reasoning chain.${NC}"
echo ""
"$PY" -m sift_find_evil demo
pause

section "Beat 2/3 - Scenario validation harness"
echo -e "${YELLOW}Fifteen attack scenarios validated against hand-authored ground truth.${NC}"
echo -e "${YELLOW}Watch for: F1=1.00, zero false positives, zero false negatives.${NC}"
echo ""
PYTHONPATH=. "$PY" tests/scenario_harness.py
pause

section "Beat 3/3 - Interactive TUI"
echo -e "${YELLOW}The terminal UI: evidence selection, live progress, findings panel.${NC}"
if [[ "$AUTO" -eq 1 ]]; then
  echo "(skipped in --auto mode; the TUI is interactive)"
else
  echo -e "${GREEN}Launch the TUI now? Press Enter to launch, or Ctrl+C to stop here.${NC}"
  echo "(Inside the TUI, press 'q' to quit and return.)"
  read -r
  "$PY" demo_tui.py || true
fi

section "Demo complete"
echo "Key points:"
echo "  - Self-correction resolved a causality violation (0.95 -> 0.45 -> 0.75)"
echo "  - 15 scenarios, F1=1.00, 0 false positives"
echo "  - Same detection logic runs on real evidence (requirements-forensic.txt)"
echo ""
