#!/usr/bin/env bash
# Batch test all scenarios from USB evidence drive
# Runs on SIFT VM, discovers and tests all available scenarios

set -euo pipefail

# Configuration
USB_MOUNT="${USB_MOUNT:-/mnt/usb-evidence/sift_evidence}"
WORK_DIR="${WORK_DIR:-$HOME/sift_project}"
RESULTS_BASE="${RESULTS_BASE:-$HOME/batch-test-results}"
VENV_PATH="${VENV_PATH:-$HOME/sift_find_evil_env}"
MAX_SCENARIO_SIZE="${MAX_SCENARIO_SIZE:-120000000000}"  # 120GB max per scenario

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

# Results tracking
TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
RUN_DIR="$RESULTS_BASE/$TIMESTAMP"
SUMMARY_FILE="$RUN_DIR/SUMMARY.md"
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
declare -a PASSED_SCENARIOS
declare -a FAILED_SCENARIOS
declare -a SKIPPED_SCENARIOS

# Initialize results directory
mkdir -p "$RUN_DIR"

info "Batch testing USB evidence scenarios"
info "USB Mount: $USB_MOUNT"
info "Work Directory: $WORK_DIR"
info "Results: $RUN_DIR"
echo ""

# Check USB mount
if [ ! -d "$USB_MOUNT" ]; then
    error "USB mount not found: $USB_MOUNT"
    error "Mount USB drive first: sudo mount /dev/sda1 /mnt/usb-evidence"
    exit 1
fi

# Discover all scenario.yaml files
section "Discovering Scenarios"
mapfile -t SCENARIOS < <(find "$USB_MOUNT" -name "scenario.yaml" -type f | sort)

if [ ${#SCENARIOS[@]} -eq 0 ]; then
    error "No scenario.yaml files found in $USB_MOUNT"
    exit 1
fi

info "Found ${#SCENARIOS[@]} scenarios:"
for scenario in "${SCENARIOS[@]}"; do
    scenario_dir=$(dirname "$scenario")
    scenario_name=$(basename "$scenario_dir")
    echo "  - $scenario_name"
done

# Activate Python venv
section "Activating Environment"
if [ ! -d "$VENV_PATH" ]; then
    error "Virtual environment not found: $VENV_PATH"
    error "Run: python3 -m venv $VENV_PATH && pip install -r requirements.txt"
    exit 1
fi

source "$VENV_PATH/bin/activate"
info "Python: $(which python3)"
info "sift_find_evil: $(python3 -c 'import sift_find_evil; print(sift_find_evil.__file__)' 2>/dev/null || echo 'NOT INSTALLED')"

# Function to get evidence size
get_evidence_size() {
    local scenario_dir="$1"
    local evidence_dir="$scenario_dir/evidence"

    if [ ! -d "$evidence_dir" ]; then
        echo "0"
        return
    fi

    # Get total size in bytes
    du -sb "$evidence_dir" 2>/dev/null | awk '{print $1}' || echo "0"
}

# Function to check if scenario is ready
check_scenario_ready() {
    local scenario_file="$1"
    local scenario_dir=$(dirname "$scenario_file")

    # Check for required evidence files
    if ! grep -q "required: true" "$scenario_file" 2>/dev/null; then
        return 0  # No required files
    fi

    # Extract required file paths
    local required_files
    mapfile -t required_files < <(python3 -c "
import yaml, sys
with open('$scenario_file') as f:
    data = yaml.safe_load(f)
    for entry in data.get('evidence', []):
        if entry.get('required'):
            print(entry.get('path', ''))
" 2>/dev/null || echo "")

    # Check if all required files exist
    for rel_path in "${required_files[@]}"; do
        if [ -z "$rel_path" ]; then
            continue
        fi

        local full_path="$scenario_dir/$rel_path"
        if [ ! -f "$full_path" ]; then
            return 1  # Missing required file
        fi
    done

    return 0  # All required files present
}

# Function to test one scenario
test_scenario() {
    local scenario_file="$1"
    local scenario_dir=$(dirname "$scenario_file")
    local scenario_name=$(basename "$scenario_dir")

    section "Testing: $scenario_name"

    # Check if scenario is ready
    if ! check_scenario_ready "$scenario_file"; then
        warn "Scenario has missing required evidence files"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        SKIPPED_SCENARIOS+=("$scenario_name (missing evidence)")
        return 1
    fi

    # Check evidence size
    local evidence_size
    evidence_size=$(get_evidence_size "$scenario_dir")
    local size_gb=$((evidence_size / 1000000000))

    info "Evidence size: ${size_gb}GB"

    if [ "$evidence_size" -gt "$MAX_SCENARIO_SIZE" ]; then
        warn "Scenario too large (${size_gb}GB > $((MAX_SCENARIO_SIZE / 1000000000))GB limit), skipping"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        SKIPPED_SCENARIOS+=("$scenario_name (too large: ${size_gb}GB)")
        return 1
    fi

    # Run analysis directly from USB (no copy to avoid disk space issues)
    info "Running analysis directly from USB..."
    local start_time=$(date +%s)

    if timeout 3600 python3 -m sift_find_evil.cli run \
        --scenario "$scenario_dir" \
        > "$RUN_DIR/${scenario_name}.log" 2>&1; then

        local end_time=$(date +%s)
        local duration=$((end_time - start_time))

        info "PASS (${duration}s)"
        PASS_COUNT=$((PASS_COUNT + 1))
        PASSED_SCENARIOS+=("$scenario_name (${duration}s)")

        return 0
    else
        local exit_code=$?
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))

        if [ $exit_code -eq 124 ]; then
            error "TIMEOUT after 1 hour"
            FAIL_COUNT=$((FAIL_COUNT + 1))
            FAILED_SCENARIOS+=("$scenario_name (timeout)")
        else
            error "FAIL (exit code: $exit_code, ${duration}s)"
            FAIL_COUNT=$((FAIL_COUNT + 1))
            FAILED_SCENARIOS+=("$scenario_name (exit $exit_code)")
        fi

        return 1
    fi
}

# Run all scenarios
section "Running Scenarios"
for scenario in "${SCENARIOS[@]}"; do
    test_scenario "$scenario" || true
    echo ""
done

# Generate summary report
section "Generating Summary"

cat > "$SUMMARY_FILE" <<EOF
# USB Evidence Batch Test Summary

**Date:** $(date '+%Y-%m-%d %H:%M:%S')
**Run ID:** $TIMESTAMP

---

## Overview

- **Total Scenarios**: ${#SCENARIOS[@]}
- **Passed**: $PASS_COUNT
- **Failed**: $FAIL_COUNT
- **Skipped**: $SKIP_COUNT

---

## Passed Scenarios

EOF

if [ $PASS_COUNT -gt 0 ]; then
    for scenario in "${PASSED_SCENARIOS[@]}"; do
        echo "- $scenario" >> "$SUMMARY_FILE"
    done
else
    echo "(none)" >> "$SUMMARY_FILE"
fi

cat >> "$SUMMARY_FILE" <<EOF

---

## Failed Scenarios

EOF

if [ $FAIL_COUNT -gt 0 ]; then
    for scenario in "${FAILED_SCENARIOS[@]}"; do
        echo "- $scenario" >> "$SUMMARY_FILE"
    done
else
    echo "(none)" >> "$SUMMARY_FILE"
fi

cat >> "$SUMMARY_FILE" <<EOF

---

## Skipped Scenarios

EOF

if [ $SKIP_COUNT -gt 0 ]; then
    for scenario in "${SKIPPED_SCENARIOS[@]}"; do
        echo "- $scenario" >> "$SUMMARY_FILE"
    done
else
    echo "(none)" >> "$SUMMARY_FILE"
fi

cat >> "$SUMMARY_FILE" <<EOF

---

## Detailed Results

Individual scenario results are saved in:
\`$RUN_DIR/\`

Test-results with findings are saved in:
\`test-results/\` (timestamped directories)

---

## Next Steps

1. Review failed scenarios: \`cat $RUN_DIR/*.log | grep ERROR\`
2. Check detailed findings: \`find test-results/ -name "findings.json"\`
3. Generate aggregate report: \`python -m sift_find_evil.cli review --results-dir test-results/\`

EOF

# Display summary
section "Batch Test Complete"
cat "$SUMMARY_FILE"

info "Summary saved to: $SUMMARY_FILE"
info "Logs saved to: $RUN_DIR/"

exit 0
