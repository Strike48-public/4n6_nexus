#!/usr/bin/env bash
# Download M57 Patents Scenario evidence from Digital Corpora.
# Delegates to the generic scenario downloader, which reads the
# evidence list out of scenario.yaml (authoritative URLs + sizes).
#
# Full scenario page: https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/
# S3 prefix: corpora/scenarios/2009-m57-patents/drives-redacted/
# Total size: ~45 GB (final-day redacted subset only)
#
# Usage:
#   ./download_all.sh            # fetch every file in scenario.yaml
#   ./download_all.sh --dry-run  # list what would be fetched
#
# To cherry-pick a single custodian, edit scenario.yaml or download
# directly via curl -fLC - <url>.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

exec "$REPO_ROOT/scripts/download-corpora/download-scenario.sh" "$SCRIPT_DIR" "$@"
