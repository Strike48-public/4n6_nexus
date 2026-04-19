#!/usr/bin/env bash
# download-scenario.sh
# Fetch every evidence file listed in a scenario's scenario.yaml.
#
# Usage:
#   scripts/download-corpora/download-scenario.sh <scenario-dir> [--dry-run] [--required-only]
#
# Example:
#   scripts/download-corpora/download-scenario.sh scenarios/real/m57-patents
#   scripts/download-corpora/download-scenario.sh scenarios/real/national_gallery_2012 --dry-run
#
# Behavior:
#   - Reads evidence[].path and evidence[].download_url from scenario.yaml
#   - Skips files that already exist on disk
#   - Uses curl -fLC - (resume supported) with a progress bar
#   - Verifies sha256 when present in the manifest; logs the computed hash
#     when not (so it can be pinned back into the manifest)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

usage() {
  grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

[[ $# -ge 1 ]] || usage

SCENARIO_DIR=""
DRY_RUN=0
REQUIRED_ONLY=0

for arg in "$@"; do
  case "$arg" in
    --dry-run)       DRY_RUN=1 ;;
    --required-only) REQUIRED_ONLY=1 ;;
    -h|--help)       usage ;;
    *)
      if [[ -z "$SCENARIO_DIR" ]]; then
        SCENARIO_DIR="$arg"
      else
        error "Unknown argument: $arg"
        usage
      fi
      ;;
  esac
done

if [[ ! -d "$SCENARIO_DIR" ]]; then
  # Allow relative paths from repo root
  if [[ -d "$REPO_ROOT/$SCENARIO_DIR" ]]; then
    SCENARIO_DIR="$REPO_ROOT/$SCENARIO_DIR"
  else
    error "Not a directory: $SCENARIO_DIR"
    exit 2
  fi
fi

MANIFEST="$SCENARIO_DIR/scenario.yaml"
if [[ ! -f "$MANIFEST" ]]; then
  error "No scenario.yaml in $SCENARIO_DIR"
  exit 2
fi

# Parse the evidence list with Python (PyYAML not required — use a narrow
# parser for our known schema, falling back to yaml if installed).
PARSED="$(python3 - "$MANIFEST" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text()

try:
    import yaml  # type: ignore
    doc = yaml.safe_load(text)
    entries = doc.get("evidence", []) or []
except Exception:
    entries = []
    current = None
    in_evidence = False
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        stripped = line.lstrip()
        if line.startswith("evidence:"):
            in_evidence = True
            continue
        if in_evidence and not line.startswith(" ") and not line.startswith("\t"):
            in_evidence = False
        if not in_evidence:
            continue
        if stripped.startswith("- "):
            if current is not None:
                entries.append(current)
            current = {}
            stripped = stripped[2:]
        if current is None:
            continue
        if ":" in stripped:
            k, _, v = stripped.partition(":")
            current[k.strip()] = v.strip()
    if current is not None:
        entries.append(current)

for e in entries:
    p = e.get("path", "")
    u = e.get("download_url", "")
    s = e.get("sha256")
    r = str(e.get("required", "false")).lower()
    if s in (None, "null", ""):
        s = ""
    print(f"{p}\t{u}\t{s}\t{r}")
PY
)"

if [[ -z "$PARSED" ]]; then
  error "No evidence entries parsed from $MANIFEST"
  exit 3
fi

info "Scenario: $(basename "$SCENARIO_DIR")"
info "Manifest: $MANIFEST"
[[ $DRY_RUN -eq 1 ]]       && info "Mode: DRY RUN (no downloads)"
[[ $REQUIRED_ONLY -eq 1 ]] && info "Mode: required evidence only"
echo ""

total=0
skipped=0
downloaded=0
failed=0
verified=0

while IFS=$'\t' read -r rel_path url sha required; do
  [[ -z "$rel_path" ]] && continue
  [[ "$url" == "null" || -z "$url" ]] && { warn "No URL for $rel_path, skipping"; continue; }
  if [[ $REQUIRED_ONLY -eq 1 && "$required" != "true" ]]; then
    continue
  fi

  total=$((total + 1))
  dest="$SCENARIO_DIR/$rel_path"
  dest_dir="$(dirname "$dest")"

  if [[ -f "$dest" ]]; then
    info "Already present: $rel_path"
    skipped=$((skipped + 1))
    if [[ -n "$sha" ]]; then
      actual="$(sha256sum "$dest" | awk '{print $1}')"
      if [[ "$actual" == "$sha" ]]; then
        success "  sha256 verified"
        verified=$((verified + 1))
      else
        error "  sha256 MISMATCH — expected $sha, got $actual"
        failed=$((failed + 1))
      fi
    fi
    continue
  fi

  echo ""
  info "Fetching $rel_path"
  info "  URL: $url"
  if [[ $DRY_RUN -eq 1 ]]; then
    continue
  fi

  mkdir -p "$dest_dir"
  if curl -fL -C - --progress-bar -o "$dest" "$url"; then
    success "  Downloaded"
    downloaded=$((downloaded + 1))
    if [[ -n "$sha" ]]; then
      actual="$(sha256sum "$dest" | awk '{print $1}')"
      if [[ "$actual" == "$sha" ]]; then
        success "  sha256 verified: $actual"
        verified=$((verified + 1))
      else
        error "  sha256 MISMATCH — expected $sha, got $actual"
        failed=$((failed + 1))
      fi
    else
      actual="$(sha256sum "$dest" | awk '{print $1}')"
      info "  sha256 (record in manifest): $actual"
    fi
  else
    error "  Download failed: $url"
    failed=$((failed + 1))
  fi
done <<< "$PARSED"

echo ""
echo "========================================"
info "Summary for $(basename "$SCENARIO_DIR")"
info "  total entries:   $total"
info "  already present: $skipped"
info "  downloaded:      $downloaded"
info "  sha256 verified: $verified"
if [[ $failed -gt 0 ]]; then
  error "  failures:        $failed"
  exit 1
fi
success "Done."
