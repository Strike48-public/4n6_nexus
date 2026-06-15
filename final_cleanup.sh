#!/usr/bin/env bash
set -euo pipefail

echo "Final cleanup - removing evidence-derived artifacts..."

# Remove analysis sweep directory (4+ GB of MFT/EVTX artifacts)
rm -rf analysis/sweep

# Remove other analysis artifacts
rm -f analysis/*.json
rm -f analysis/*.log
rm -f analysis/*.py

# Update .gitignore
cat >> .gitignore << 'EOF'

# Evidence files (large binaries)
scenarios/training/**/evidence/*.dmp
scenarios/training/**/evidence/*.pcap
scenarios/training/**/evidence/*.7z
scenarios/real/**/evidence/*.E01
scenarios/real/**/evidence/*.E02
scenarios/real/**/evidence/*.pcap
!scenarios/**/evidence/.gitkeep

# Analysis artifacts (evidence-derived)
analysis/sweep/
analysis/*.json
analysis/*.log

# Session planning
START_HERE_*.md
CRITICAL_PATH.md
TUI_*.md

# Editor files
*.swp
*.swo
EOF

echo "Cleanup complete!"
du -sh --exclude=.git .
echo ""
echo "Total with .git history:"
du -sh .
