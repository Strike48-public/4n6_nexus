#!/usr/bin/env bash
# Download and verify CFReDS (NIST) forensic reference datasets
# URL: https://cfreds.nist.gov/
#
# Known Issue: NIST URLs may change periodically. If downloads fail with HTML
# responses or 403/404 errors, visit https://cfreds.nist.gov/ manually to find
# current download links and update the URLs in this script.
#
# See: docs/CFREDS_DOWNLOAD_GUIDE.md for troubleshooting and manual download steps.

set -euo pipefail

# Configuration
CFREDS_DEST="${CFREDS_DEST:-/cases/cfreds}"
CFREDS_BASE="https://cfreds.nist.gov"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Output functions
info() { echo -e "${BLUE}[INFO]${NC} $*" >&2; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $*" >&2; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }

# Check dependencies
check_deps() {
  local missing=()
  for cmd in wget sha1sum unzip file; do
    if ! command -v "$cmd" &>/dev/null; then
      missing+=("$cmd")
    fi
  done

  if [ ${#missing[@]} -gt 0 ]; then
    error "Missing required commands: ${missing[*]}"
  fi
}

# Verify URL returns actual file, not HTML error page
verify_url() {
  local url="$1"
  local name="$2"

  info "Verifying URL accessibility for $name..."

  # Use HEAD request to check content type
  local content_type
  content_type=$(wget --spider --server-response "$url" 2>&1 | grep -i "Content-Type:" | tail -1 | cut -d':' -f2- | xargs || echo "unknown")

  # Check if we got HTML (error page) instead of binary
  if echo "$content_type" | grep -qi "text/html"; then
    warn "$name URL returns HTML instead of binary file"
    warn "URL: $url"
    warn "Content-Type: $content_type"
    warn ""
    warn "This indicates the URL structure may have changed."
    warn "Please visit https://cfreds.nist.gov/ to find the current download link."
    warn "See docs/CFREDS_DOWNLOAD_GUIDE.md for manual download instructions."
    return 1
  fi

  # Check for error responses
  if wget --spider "$url" 2>&1 | grep -qi "404\|403\|500"; then
    warn "$name URL returned an error (404/403/500)"
    warn "URL: $url"
    warn "Please verify the URL is correct and accessible."
    return 1
  fi

  success "$name URL is accessible"
  return 0
}

# Download with verification
download_dataset() {
  local name="$1"
  local url="$2"
  local checksum_url="$3"
  local dest_dir="$4"

  info "=== Downloading $name ==="

  # Verify URL before attempting download
  if ! verify_url "$url" "$name"; then
    error "URL verification failed for $name. Skipping download."
    return 1
  fi

  info "Downloading $name..."
  mkdir -p "$dest_dir"
  cd "$dest_dir"

  # Download main file
  local filename
  filename=$(basename "$url")
  if [ -f "$filename" ]; then
    warn "$filename already exists, skipping download"
  else
    if ! wget -c --progress=bar:force "$url"; then
      error "Failed to download $name from $url"
      return 1
    fi

    # Verify downloaded file is not HTML
    if file "$filename" | grep -qi "HTML"; then
      error "Downloaded file is HTML (error page), not the expected binary"
      error "File: $filename"
      error "URL structure may have changed. See docs/CFREDS_DOWNLOAD_GUIDE.md"
      rm -f "$filename"
      return 1
    fi
  fi

  # Download and verify checksum if provided
  if [ -n "$checksum_url" ]; then
    local checksum_file
    checksum_file=$(basename "$checksum_url")

    if [ ! -f "$checksum_file" ]; then
      if ! wget -c "$checksum_url" 2>/dev/null; then
        warn "Checksum file not available for $name"
      fi
    fi

    if [ -f "$checksum_file" ]; then
      info "Verifying integrity of $filename..."

      # Handle checksum files with full paths
      if grep -q "/" "$checksum_file"; then
        warn "Checksum file contains paths, extracting filenames..."
        sed 's|.*/||' "$checksum_file" > "${checksum_file}.fixed"
        checksum_file="${checksum_file}.fixed"
      fi

      if sha1sum -c "$checksum_file" 2>/dev/null | grep -q "OK"; then
        success "$name verified successfully"
      else
        error "$name integrity check FAILED"
        return 1
      fi
    fi
  else
    warn "No checksum available for $name - cannot verify integrity"
  fi

  # Report size
  local size
  size=$(du -h "$filename" | cut -f1)
  success "$name downloaded: $size"
}

# Display banner
show_banner() {
  echo ""
  echo "=========================================="
  echo " CFReDS Dataset Download Script"
  echo "=========================================="
  echo ""
  info "Source: https://cfreds.nist.gov/"
  info "Destination: $CFREDS_DEST"
  info ""
  warn "Note: NIST URLs may change periodically."
  warn "If downloads fail, see: docs/CFREDS_DOWNLOAD_GUIDE.md"
  echo ""
}

# Main execution
main() {
  show_banner

  check_deps

  # Create base directory
  mkdir -p "$CFREDS_DEST"

  local success_count=0
  local fail_count=0

  # Dataset 1: Data Leakage Case
  info "=== Dataset 1: Data Leakage Case ==="
  if download_dataset \
    "Data Leakage Case" \
    "$CFREDS_BASE/data_leakage_case/data-leakage-case.dd.zip" \
    "$CFREDS_BASE/data_leakage_case/data-leakage-case.sha1" \
    "$CFREDS_DEST/data_leakage"; then
    ((success_count++))
  else
    ((fail_count++))
  fi
  echo ""

  # Dataset 2: Hacking Case (SCHARDT)
  info "=== Dataset 2: Linux Hacking Case ==="
  if download_dataset \
    "Hacking Case (SCHARDT)" \
    "$CFREDS_BASE/Hacking_Case/SCHARDT.zip" \
    "$CFREDS_BASE/Hacking_Case/SCHARDT.sha1" \
    "$CFREDS_DEST/hacking_case"; then
    ((success_count++))
  else
    ((fail_count++))
  fi
  echo ""

  # Dataset 3: Memory Analysis Images (optional - commented out by default)
  # Uncomment if needed for Volatility training
  # info "=== Dataset 3: Memory Analysis Images ==="
  # if download_dataset \
  #   "Memory Images 2008" \
  #   "$CFREDS_BASE/mem/memory-images-2008.zip" \
  #   "" \
  #   "$CFREDS_DEST/memory_dumps"; then
  #   ((success_count++))
  # else
  #   ((fail_count++))
  # fi
  # echo ""

  # Summary
  echo ""
  echo "=========================================="
  echo " Download Summary"
  echo "=========================================="
  success "Successfully downloaded: $success_count dataset(s)"
  if [ $fail_count -gt 0 ]; then
    warn "Failed downloads: $fail_count dataset(s)"
  fi
  echo ""

  if [ $success_count -gt 0 ]; then
    info "Downloaded datasets:"
    find "$CFREDS_DEST" -type f \( -name "*.zip" -o -name "*.dd" \) 2>/dev/null | while read -r file; do
      size=$(du -h "$file" | cut -f1)
      echo "  - $(basename "$file"): $size"
    done

    echo ""
    info "Next steps:"
    info "  1. Extract archives: unzip <file>.zip"
    info "  2. Mount images: sudo mount -o ro,loop <image>.dd /mnt/forensics"
    info "  3. Run analysis tools (fls, icat, etc.)"
    info ""
    info "Total storage used:"
    du -sh "$CFREDS_DEST"
  fi

  if [ $fail_count -gt 0 ]; then
    echo ""
    warn "Some downloads failed."
    warn "Please see docs/CFREDS_DOWNLOAD_GUIDE.md for manual download instructions."
    warn "Visit https://cfreds.nist.gov/ to verify current URLs."
    exit 1
  fi

  success "All downloads completed successfully!"
}

# Handle script interruption
trap 'error "Download interrupted"' INT TERM

# Execute
main "$@"
