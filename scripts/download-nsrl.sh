#!/usr/bin/env bash
# Download and extract NSRL (National Software Reference Library) database
# URL: https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl
#
# The NSRL RDS provides hash sets for known-good software (Windows, Office, etc.)
# This enables filtering of legitimate system files during carved file analysis.
#
# Storage requirements:
#   - Modern RDS: 2-3 GB download, 8-12 GB extracted
#   - Full RDS: 5-10 GB download, 30-50 GB extracted
#
# This script downloads Modern RDS by default (recommended for most users).

set -euo pipefail

# Configuration
NSRL_DEST="${NSRL_DEST:-$HOME/.sift_find_evil/nsrl}"
NSRL_VERSION="${NSRL_VERSION:-modern}"  # "modern" or "full"

# NIST provides RDS releases quarterly
# These URLs need to be updated when new releases are published
# Check https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl for latest
#
# KNOWN ISSUE (2026-04-18): NIST S3 URLs may return 403 Forbidden
# If download fails, manually download from:
#   https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl-download
# Then place NSRLFile.txt in ~/.sift_find_evil/nsrl/
MODERN_RDS_URL="https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/rds_modernm/RDS_modern.iso"
MODERN_RDS_SHA256_URL="https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/rds_modernm/RDS_modern.iso.sha256"

FULL_RDS_URL="https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/current/RDS_iso.zip"
FULL_RDS_SHA256_URL="https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/current/RDS_iso.zip.sha256"

# Output functions
info() { echo "[*] $*"; }
success() { echo "[+] $*"; }
error() { echo "[!] ERROR: $*" >&2; exit 1; }
warn() { echo "[!] WARNING: $*"; }
banner() {
  echo ""
  echo "=========================================="
  echo "$*"
  echo "=========================================="
  echo ""
}

# Check dependencies
check_deps() {
  local missing=()
  for cmd in wget sha256sum unzip; do
    if ! command -v "$cmd" &>/dev/null; then
      missing+=("$cmd")
    fi
  done

  if [ ${#missing[@]} -gt 0 ]; then
    error "Missing required commands: ${missing[*]}"
  fi

  # Check for 7z (optional, for ISO extraction)
  if ! command -v 7z &>/dev/null; then
    warn "7z not found - ISO extraction may require manual mounting"
    warn "Install with: sudo apt-get install p7zip-full"
  fi
}

# Check available disk space
check_space() {
  local required_gb="$1"
  local dest_dir="$2"

  local available_gb
  available_gb=$(df -BG "$dest_dir" | tail -1 | awk '{print $4}' | sed 's/G//')

  if [ "$available_gb" -lt "$required_gb" ]; then
    error "Insufficient disk space. Required: ${required_gb}GB, Available: ${available_gb}GB"
  fi

  info "Disk space check: ${available_gb}GB available (${required_gb}GB required)"
}

# Download with progress and resume support
download_file() {
  local url="$1"
  local dest="$2"

  if [ -f "$dest" ]; then
    warn "File already exists: $dest"
    info "Resuming download if incomplete..."
  fi

  info "Downloading: $url"
  wget -c --progress=bar:force "$url" -O "$dest" || error "Download failed"
}

# Verify SHA-256 checksum
verify_checksum() {
  local file="$1"
  local checksum_url="$2"

  local checksum_file="${file}.sha256"

  info "Downloading checksum file..."
  wget -q "$checksum_url" -O "$checksum_file" || {
    warn "Checksum file not available, skipping verification"
    return 0
  }

  info "Verifying integrity..."
  if sha256sum -c "$checksum_file"; then
    success "Integrity verification PASSED"
    rm "$checksum_file"
    return 0
  else
    error "Integrity verification FAILED - file may be corrupted"
  fi
}

# Extract ISO using 7z
extract_iso() {
  local iso_file="$1"
  local dest_dir="$2"

  if ! command -v 7z &>/dev/null; then
    warn "7z not available for extraction"
    info "Manual extraction required:"
    info "  sudo mkdir /mnt/nsrl"
    info "  sudo mount -o loop '$iso_file' /mnt/nsrl"
    info "  cp /mnt/nsrl/*.txt '$dest_dir/'"
    info "  sudo umount /mnt/nsrl"
    return 1
  fi

  info "Extracting ISO..."
  mkdir -p "$dest_dir"
  7z x -o"$dest_dir" "$iso_file" '*.txt' || error "Extraction failed"
  success "Extraction complete"
}

# Download Modern RDS (recommended)
download_modern_rds() {
  local dest="$NSRL_DEST"
  mkdir -p "$dest"

  banner "Downloading NSRL Modern RDS"

  info "Destination: $dest"
  info "Download size: ~2-3 GB"
  info "Extracted size: ~8-12 GB"

  check_space 15 "$dest"

  local iso_file="$dest/RDS_modern.iso"

  # Download ISO
  if ! download_file "$MODERN_RDS_URL" "$iso_file"; then
    error "Download failed. NIST S3 URLs may have changed. Manual workaround:\n  1. Visit: https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl-download\n  2. Download Modern RDS ISO\n  3. Extract NSRLFile.txt to: $dest/"
  fi

  # Verify checksum
  verify_checksum "$iso_file" "$MODERN_RDS_SHA256_URL"

  # Extract
  extract_iso "$iso_file" "$dest"

  # Verify extraction
  if [ -f "$dest/NSRLFile.txt" ]; then
    success "NSRL Modern RDS installed successfully"
    info "Database location: $dest/NSRLFile.txt"
    info "You can now use --use-nsrl flag with sift-find-evil"

    # Show sample size
    local line_count
    line_count=$(wc -l < "$dest/NSRLFile.txt")
    info "Hash database contains $(printf "%'d" "$line_count") entries"
  else
    error "NSRLFile.txt not found after extraction"
  fi

  # Cleanup ISO (optional)
  info "Keeping ISO file for future use: $iso_file"
  info "To save space, you can delete it: rm '$iso_file'"
}

# Download Full RDS (comprehensive but large)
download_full_rds() {
  local dest="$NSRL_DEST"
  mkdir -p "$dest"

  banner "Downloading NSRL Full RDS"

  warn "Full RDS is VERY large (30-50 GB extracted)"
  warn "Consider Modern RDS instead: $0 modern"

  info "Destination: $dest"
  info "Download size: ~5-10 GB"
  info "Extracted size: ~30-50 GB"

  check_space 60 "$dest"

  local zip_file="$dest/RDS_iso.zip"
  local iso_file="$dest/RDS.iso"

  # Download ZIP
  download_file "$FULL_RDS_URL" "$zip_file"

  # Verify checksum
  verify_checksum "$zip_file" "$FULL_RDS_SHA256_URL"

  # Extract ZIP to get ISO
  info "Extracting ZIP archive..."
  unzip -o "$zip_file" -d "$dest" || error "ZIP extraction failed"

  # Extract ISO
  extract_iso "$iso_file" "$dest"

  # Verify extraction
  if [ -f "$dest/NSRLFile.txt" ]; then
    success "NSRL Full RDS installed successfully"
    info "Database location: $dest/NSRLFile.txt"
    info "You can now use --use-nsrl flag with sift-find-evil"

    # Show sample size
    local line_count
    line_count=$(wc -l < "$dest/NSRLFile.txt")
    info "Hash database contains $(printf "%'d" "$line_count") entries"
  else
    error "NSRLFile.txt not found after extraction"
  fi

  # Cleanup archives (optional)
  info "Keeping archive files for future use"
  info "To save space, delete: rm '$zip_file' '$iso_file'"
}

# Show usage
show_usage() {
  cat << EOF
NSRL Database Download Script

Downloads NSRL RDS (Reference Data Set) for known-good file filtering.

Usage:
  $0 [modern|full]

Arguments:
  modern    Download Modern RDS (2-3 GB, recommended)
  full      Download Full RDS (5-10 GB, comprehensive)

Environment Variables:
  NSRL_DEST    Installation directory (default: ~/.sift_find_evil/nsrl)

Examples:
  $0 modern                    # Download Modern RDS (recommended)
  NSRL_DEST=/data/nsrl $0 full # Download Full RDS to custom location

After installation:
  sift-find-evil analyze --image disk.E01 --use-nsrl

More information:
  https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl
EOF
}

# Main execution
main() {
  local mode="${1:-modern}"

  case "$mode" in
    modern)
      check_deps
      download_modern_rds
      ;;
    full)
      check_deps
      download_full_rds
      ;;
    -h|--help|help)
      show_usage
      exit 0
      ;;
    *)
      error "Unknown mode: $mode (use 'modern' or 'full')"
      ;;
  esac

  echo ""
  success "NSRL download complete!"
  info "Database ready at: $NSRL_DEST/NSRLFile.txt"
}

main "$@"
