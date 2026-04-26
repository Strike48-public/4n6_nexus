#!/usr/bin/env bash
# Compare two batch test runs to check for determinism
# Usage: ./compare-batch-runs.sh <run1_timestamp> <run2_timestamp>

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }
section() { echo -e "\n${BLUE}======================================================================${NC}"; echo -e "${BLUE}  $*${NC}"; echo -e "${BLUE}======================================================================${NC}\n"; }

# Parse arguments
if [ $# -ne 2 ]; then
    error "Usage: $0 <run1_timestamp> <run2_timestamp>"
    echo "Example: $0 FINAL-2026-04-26_03-52-54 2026-04-26_11-27-23"
    exit 1
fi

RUN1="$1"
RUN2="$2"
RESULTS_DIR="test-results/usb-batch"

# Verify runs exist
if [ ! -d "$RESULTS_DIR/$RUN1" ]; then
    error "Run 1 not found: $RESULTS_DIR/$RUN1"
    exit 1
fi

if [ ! -d "$RESULTS_DIR/$RUN2" ]; then
    error "Run 2 not found: $RESULTS_DIR/$RUN2"
    exit 1
fi

section "Comparing Batch Test Runs"
info "Run 1: $RUN1"
info "Run 2: $RUN2"
echo ""

# Create comparison output
COMPARE_FILE="$RESULTS_DIR/comparison-${RUN1}-vs-${RUN2}.md"

cat > "$COMPARE_FILE" << EOF
# Batch Test Comparison

**Run 1:** $RUN1
**Run 2:** $RUN2
**Comparison Date:** $(date +%Y-%m-%d\ %H:%M:%S)

---

## Summary Comparison

EOF

# Compare summaries
section "Comparing Summaries"

if [ -f "$RESULTS_DIR/$RUN1/SUMMARY.md" ]; then
    PASS1=$(grep "Passed:" "$RESULTS_DIR/$RUN1/SUMMARY.md" | grep -oP '\d+' || echo "0")
    FAIL1=$(grep "Failed:" "$RESULTS_DIR/$RUN1/SUMMARY.md" | grep -oP '\d+' || echo "0")
    SKIP1=$(grep "Skipped:" "$RESULTS_DIR/$RUN1/SUMMARY.md" | grep -oP '\d+' || echo "0")
else
    PASS1="N/A"; FAIL1="N/A"; SKIP1="N/A"
fi

if [ -f "$RESULTS_DIR/$RUN2/SUMMARY.md" ]; then
    PASS2=$(grep "Passed:" "$RESULTS_DIR/$RUN2/SUMMARY.md" | grep -oP '\d+' || echo "0")
    FAIL2=$(grep "Failed:" "$RESULTS_DIR/$RUN2/SUMMARY.md" | grep -oP '\d+' || echo "0")
    SKIP2=$(grep "Skipped:" "$RESULTS_DIR/$RUN2/SUMMARY.md" | grep -oP '\d+' || echo "0")
else
    PASS2="N/A"; FAIL2="N/A"; SKIP2="N/A"
fi

cat >> "$COMPARE_FILE" << EOF
| Metric | Run 1 | Run 2 | Match |
|--------|-------|-------|-------|
| Passed | $PASS1 | $PASS2 | $([ "$PASS1" = "$PASS2" ] && echo "✓" || echo "✗") |
| Failed | $FAIL1 | $FAIL2 | $([ "$FAIL1" = "$FAIL2" ] && echo "✓" || echo "✗") |
| Skipped | $SKIP1 | $SKIP2 | $([ "$SKIP1" = "$SKIP2" ] && echo "✓" || echo "✗") |

---

## Scenario-by-Scenario Comparison

EOF

# Compare individual scenarios
section "Comparing Individual Scenarios"

SCENARIOS=($(ls "$RESULTS_DIR/$RUN1"/*.log 2>/dev/null | xargs -n1 basename | sed 's/.log$//' || true))

if [ ${#SCENARIOS[@]} -eq 0 ]; then
    warn "No scenario logs found in Run 1"
    echo "No scenarios to compare" >> "$COMPARE_FILE"
else
    for scenario in "${SCENARIOS[@]}"; do
        info "Comparing: $scenario"

        LOG1="$RESULTS_DIR/$RUN1/${scenario}.log"
        LOG2="$RESULTS_DIR/$RUN2/${scenario}.log"

        cat >> "$COMPARE_FILE" << EOF
### $scenario

EOF

        if [ ! -f "$LOG1" ]; then
            echo "- **Run 1:** Not found" >> "$COMPARE_FILE"
        elif [ ! -f "$LOG2" ]; then
            echo "- **Run 1:** Found" >> "$COMPARE_FILE"
            echo "- **Run 2:** Not found" >> "$COMPARE_FILE"
        else
            # Extract pass/fail status
            STATUS1=$(grep -oP "(PASS|FAIL)" "$LOG1" | tail -1 || echo "UNKNOWN")
            STATUS2=$(grep -oP "(PASS|FAIL)" "$LOG2" | tail -1 || echo "UNKNOWN")

            # Extract timing if available
            TIME1=$(grep -oP "PASS \(\d+s\)" "$LOG1" | grep -oP "\d+" || echo "N/A")
            TIME2=$(grep -oP "PASS \(\d+s\)" "$LOG2" | grep -oP "\d+" || echo "N/A")

            cat >> "$COMPARE_FILE" << EOF
| Metric | Run 1 | Run 2 | Match |
|--------|-------|-------|-------|
| Status | $STATUS1 | $STATUS2 | $([ "$STATUS1" = "$STATUS2" ] && echo "✓" || echo "✗") |
| Time | ${TIME1}s | ${TIME2}s | $([ "$TIME1" = "$TIME2" ] && echo "✓" || echo "~") |

EOF

            # Check for differences in log output (excluding timestamps)
            if diff -u <(grep -v "^\[" "$LOG1" | sort) <(grep -v "^\[" "$LOG2" | sort) > /dev/null 2>&1; then
                echo "- **Log content:** Identical (excluding timestamps)" >> "$COMPARE_FILE"
            else
                echo "- **Log content:** Different (see detailed diff below)" >> "$COMPARE_FILE"
                echo "" >> "$COMPARE_FILE"
                echo '```diff' >> "$COMPARE_FILE"
                diff -u <(grep -v "^\[" "$LOG1" | sort) <(grep -v "^\[" "$LOG2" | sort) | head -50 >> "$COMPARE_FILE" || true
                echo '```' >> "$COMPARE_FILE"
            fi
            echo "" >> "$COMPARE_FILE"
        fi
    done
fi

cat >> "$COMPARE_FILE" << EOF

---

## Determinism Analysis

EOF

# Analyze determinism
if [ "$PASS1" = "$PASS2" ] && [ "$FAIL1" = "$FAIL2" ] && [ "$SKIP1" = "$SKIP2" ]; then
    cat >> "$COMPARE_FILE" << EOF
✓ **DETERMINISTIC:** Both runs produced identical pass/fail/skip counts.

EOF
    info "Determinism: PASS - Identical counts"
else
    cat >> "$COMPARE_FILE" << EOF
✗ **NON-DETERMINISTIC:** Runs produced different pass/fail/skip counts.

**Issues to investigate:**
- Different scenarios passed/failed between runs
- Environment differences
- Non-deterministic detection logic
- Timing-dependent behavior

EOF
    warn "Determinism: FAIL - Different counts"
fi

section "Comparison Complete"
info "Report saved to: $COMPARE_FILE"
echo ""

# Display summary
cat "$COMPARE_FILE"
