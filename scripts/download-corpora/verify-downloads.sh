#!/usr/bin/env bash
# verify-downloads.sh
# Verifies integrity of downloaded Digital Corpora files using checksums
#
# Searches for *-md5.txt and *-sha1.txt files and validates downloads
# against provided hashes

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEST_DIR="$REPO_ROOT/practice_images"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() {
  echo -e "${BLUE}[INFO]${NC} $*"
}

success() {
  echo -e "${GREEN}[OK]${NC} $*"
}

warn() {
  echo -e "${YELLOW}[WARN]${NC} $*"
}

error() {
  echo -e "${RED}[ERROR]${NC} $*" >&2
}

# Counters for summary
TOTAL_VERIFIED=0
TOTAL_FAILED=0
TOTAL_MISSING=0

verify_hashes() {
  local hashfile="$1"
  local hashtype=$(echo "$hashfile" | grep -o "md5\|sha1\|sha256")
  local dir=$(dirname "$hashfile")

  info "Verifying $hashtype hashes in: $dir"
  cd "$dir"

  local verified=0
  local failed=0
  local missing=0

  # Read hash file line by line
  while IFS= read -r line; do
    # Skip empty lines and comments
    [[ -z "$line" || "$line" =~ ^# ]] && continue

    # Parse hash and filename
    local hash=$(echo "$line" | awk '{print $1}')
    local filename=$(echo "$line" | awk '{print $2}' | sed 's/^\*//')

    if [[ ! -f "$filename" ]]; then
      error "  MISSING: $filename"
      ((missing++))
      continue
    fi

    # Compute hash
    local computed_hash=""
    case "$hashtype" in
      md5)
        computed_hash=$(md5sum "$filename" | awk '{print $1}')
        ;;
      sha1)
        computed_hash=$(sha1sum "$filename" | awk '{print $1}')
        ;;
      sha256)
        computed_hash=$(sha256sum "$filename" | awk '{print $1}')
        ;;
    esac

    # Compare hashes
    if [[ "$hash" == "$computed_hash" ]]; then
      success "  OK: $filename"
      ((verified++))
    else
      error "  FAILED: $filename"
      error "    Expected: $hash"
      error "    Got:      $computed_hash"
      ((failed++))
    fi
  done < "$(basename "$hashfile")"

  # Update global counters
  TOTAL_VERIFIED=$((TOTAL_VERIFIED + verified))
  TOTAL_FAILED=$((TOTAL_FAILED + failed))
  TOTAL_MISSING=$((TOTAL_MISSING + missing))

  echo ""
  info "Summary for $dir:"
  echo "  Verified: $verified"
  echo "  Failed:   $failed"
  echo "  Missing:  $missing"
  echo ""
}

main() {
  echo ""
  echo "=========================================="
  echo " Digital Corpora Download Verification"
  echo "=========================================="
  echo ""

  if [[ ! -d "$DEST_DIR" ]]; then
    error "Download directory not found: $DEST_DIR"
    error "Please run download-phase1-critical.sh first"
    exit 1
  fi

  info "Searching for hash files in: $DEST_DIR"
  echo ""

  # Find all hash files
  local hashfiles=$(find "$DEST_DIR" -type f \( -name "*-md5.txt" -o -name "*-sha1.txt" -o -name "*-sha256.txt" \) 2>/dev/null)

  if [[ -z "$hashfiles" ]]; then
    warn "No hash files found in $DEST_DIR"
    echo ""
    echo "Hash files are typically named:"
    echo "  - zipfilelist-md5.txt"
    echo "  - zipfilelist-sha1.txt"
    echo "  - *-checksums.txt"
    echo ""
    echo "They are downloaded alongside the actual data files."
    echo ""
    exit 0
  fi

  # Verify each hash file
  while IFS= read -r hashfile; do
    verify_hashes "$hashfile"
  done <<< "$hashfiles"

  echo ""
  echo "=========================================="
  echo " Verification Complete"
  echo "=========================================="
  echo ""
  echo "GLOBAL SUMMARY:"
  echo "  Total Verified: $TOTAL_VERIFIED files"
  echo "  Total Failed:   $TOTAL_FAILED files"
  echo "  Total Missing:  $TOTAL_MISSING files"
  echo ""

  if [[ $TOTAL_FAILED -gt 0 ]]; then
    error "Some files failed verification!"
    echo ""
    echo "Recommended actions:"
    echo "  1. Re-download failed files"
    echo "  2. Check disk space and filesystem health"
    echo "  3. Verify network connection was stable during download"
    echo ""
    exit 1
  elif [[ $TOTAL_MISSING -gt 0 ]]; then
    warn "Some files are missing"
    echo ""
    echo "Recommended actions:"
    echo "  1. Re-run the appropriate download script"
    echo "  2. Check if downloads were interrupted"
    echo ""
    exit 1
  else
    success "All files verified successfully!"
    echo ""
    echo "Your Digital Corpora download is complete and verified."
    echo ""
    echo "Next steps:"
    echo "  1. Extract archives as needed:"
    echo "     - unzip *.zip"
    echo "     - tar -xzf *.tar.gz"
    echo "  2. Review scenario documentation at:"
    echo "     https://digitalcorpora.org/corpora/scenarios/"
    echo "  3. Start with Nitroba scenario (smallest)"
    echo "  4. Progress to M57-Jean, then M57-Patents"
    echo ""
    exit 0
  fi
}

main "$@"
