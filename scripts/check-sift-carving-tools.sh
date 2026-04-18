#!/usr/bin/env bash
# Check availability of SIFT carving tools

set -euo pipefail

echo "SIFT Carving Tools Availability Check"
echo "======================================"
echo ""

tools=(
    "foremost:File carving by header/footer"
    "scalpel:Enhanced foremost with config"
    "binwalk:Firmware/embedded file extraction"
    "photorec:Signature-based file recovery"
    "bulk_extractor:Bulk data extraction"
    "tsk_recover:Sleuth Kit file recovery"
)

available=0
missing=0

for tool_info in "${tools[@]}"; do
    tool="${tool_info%%:*}"
    desc="${tool_info#*:}"
    
    if command -v "$tool" >/dev/null 2>&1; then
        path=$(command -v "$tool")
        version=$("$tool" --version 2>&1 | head -1 || echo "version unknown")
        echo "[FOUND] $tool - $desc"
        echo "        Path: $path"
        echo "        Version: $version"
        echo ""
        ((available++))
    else
        echo "[MISSING] $tool - $desc"
        echo ""
        ((missing++))
    fi
done

echo "======================================"
echo "Summary: $available available, $missing missing"
echo ""

if [ $available -eq 0 ]; then
    echo "RECOMMENDATION: Install carving tools via apt:"
    echo "  sudo apt-get update"
    echo "  sudo apt-get install foremost scalpel binwalk testdisk"
    echo "  (bulk_extractor may require separate repository)"
    exit 1
else
    echo "At least one carving tool is available."
    exit 0
fi
