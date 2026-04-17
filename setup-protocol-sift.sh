#!/usr/bin/env bash
# Protocol SIFT Installation Script
# Run this inside the SIFT VM after logging in

set -euo pipefail

echo "========================================="
echo "Protocol SIFT Installation"
echo "========================================="

# Install Node.js (required for Claude Code)
echo "[1/4] Installing Node.js..."
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verify Node.js
node --version
npm --version

# Install Claude Code CLI
echo "[2/4] Installing Claude Code CLI..."
sudo npm install -g @anthropic-ai/claude-code

# Verify Claude Code
claude --version

# Install Protocol SIFT
echo "[3/4] Installing Protocol SIFT..."
curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash

# Verify Protocol SIFT Installation
echo "[4/4] Verifying installation..."
ls -la ~/.claude/CLAUDE.md
ls ~/.claude/skills/

echo "========================================="
echo "Installation Complete!"
echo "========================================="
echo ""
echo "Next steps:"
echo "1. Set up Anthropic API key in ~/.claude/.credentials.json"
echo "2. Test tool execution"
echo ""
