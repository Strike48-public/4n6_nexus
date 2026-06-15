#!/usr/bin/env bash
set -euo pipefail

echo "=== Cleaning up 4n6_nexus_public for public release ==="

# 1. Remove large evidence files
echo "Removing large evidence files..."
git rm -rf scenarios/training/network_intrusion/evidence/ 2>/dev/null || true
git rm -rf scenarios/real/m57-jean/evidence/ 2>/dev/null || true
git rm -rf scenarios/real/circl-2023-wiped/evidence/ 2>/dev/null || true
git rm -rf scenarios/real/nitroba/evidence/ 2>/dev/null || true

# Keep .gitkeep files
mkdir -p scenarios/training/network_intrusion/evidence
mkdir -p scenarios/real/m57-jean/evidence
mkdir -p scenarios/real/circl-2023-wiped/evidence
mkdir -p scenarios/real/nitroba/evidence
touch scenarios/training/network_intrusion/evidence/.gitkeep
touch scenarios/real/m57-jean/evidence/.gitkeep
touch scenarios/real/circl-2023-wiped/evidence/.gitkeep
touch scenarios/real/nitroba/evidence/.gitkeep

# 2. Remove enterprise planning docs
echo "Removing enterprise planning docs..."
git rm -rf docs/enterprise/ 2>/dev/null || true

# 3. Remove session planning files
echo "Removing session planning files..."
git rm -f START_HERE_NEXT_SESSION.md CRITICAL_PATH.md BATCH_TESTING.md REGRESSION_TESTING.md 2>/dev/null || true
git rm -f TUI_*.md 2>/dev/null || true

# 4. Remove analysis artifacts
echo "Removing analysis artifacts..."
git rm -rf analysis/sweep/ 2>/dev/null || true
git rm -f analysis/*.json analysis/*.py analysis/*.log 2>/dev/null || true

# 5. Remove editor swap files
echo "Removing swap files..."
find . -name "*.swp" -o -name "*.swo" | xargs git rm -f 2>/dev/null || true

# 6. Remove large binary files
echo "Removing OVA/VMDK files..."
git rm -f sift-2026.03.24.ova sift-disk1.vmdk sift.ovf 2>/dev/null || true

echo "=== Cleanup complete ==="
