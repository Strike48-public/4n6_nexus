#!/usr/bin/env bash
set -euo pipefail

echo "Removing large evidence files..."

# Remove all evidence files
rm -rf scenarios/training/network_intrusion/evidence/*
rm -rf scenarios/real/m57-jean/evidence/*
rm -rf scenarios/real/circl-2023-wiped/evidence/*
rm -rf scenarios/real/nitroba/evidence/*

# Recreate .gitkeep files
touch scenarios/training/network_intrusion/evidence/.gitkeep
touch scenarios/real/m57-jean/evidence/.gitkeep
touch scenarios/real/circl-2023-wiped/evidence/.gitkeep
touch scenarios/real/nitroba/evidence/.gitkeep

echo "Evidence files removed. Checking size..."
du -sh .
