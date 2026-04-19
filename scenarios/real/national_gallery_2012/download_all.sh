#!/usr/bin/env bash
# Download National Gallery DC 2012 scenario evidence from Digital Corpora.
# Delegates to the generic scenario downloader, which reads the evidence
# list out of scenario.yaml (authoritative URLs + sizes).
#
# Full scenario page: https://digitalcorpora.org/corpora/scenarios/2012-ngdc/
# S3 prefix: corpora/scenarios/2012-ngdc/
# Total size: ~12 GB (final-day subset only)
#
# Usage:
#   ./download_all.sh            # fetch every file in scenario.yaml
#   ./download_all.sh --dry-run  # list what would be fetched

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

exec "$REPO_ROOT/scripts/download-corpora/download-scenario.sh" "$SCRIPT_DIR" "$@"
