#!/usr/bin/env bash
# download-phase3-selective.sh
# Selective download of specialized/large datasets from Digital Corpora
#
# Phase 3: Selective datasets (variable size, 3 GB - 800 GB)
# - Legacy mobile devices
# - Android 7
# - Full Govdocs1 corpus (WARNING: ~250 GB)
# - DEFCON CTF PCAPs (WARNING: ~50 GB)
# - SAFEDOCS PDF corpus (WARNING: ~500 GB)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASE_URL="https://downloads.digitalcorpora.org/corpora"
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

# Download with resume support
download_file() {
  local url="$1"
  local dest="$2"
  local desc="${3:-Downloading file}"

  info "$desc"
  if wget -c --progress=bar:force "$url" -P "$dest" 2>&1; then
    success "Downloaded: $(basename "$url")"
    return 0
  else
    error "Failed to download: $url"
    return 1
  fi
}

# Download directory recursively
download_directory() {
  local url="$1"
  local dest="$2"
  local desc="${3:-Downloading directory}"

  info "$desc"
  if wget -r -np -nH --cut-dirs=3 -R "index.html*" --progress=bar:force "$url" -P "$dest" 2>&1; then
    success "Downloaded directory: $url"
    return 0
  else
    error "Failed to download directory: $url"
    return 1
  fi
}

# Individual download functions
download_android7() {
  warn "Android 7 is an older version - consider if still needed"
  echo "Size: ~3 GB"
  read -p "Continue? (yes/no): " confirm
  if [[ "$confirm" == "yes" ]]; then
    download_file "$BASE_URL/mobile/android_7.tar.gz" "$DEST_DIR/mobile/android" "Downloading Android 7"
  fi
}

download_legacy_mobile() {
  info "Legacy mobile devices from Norwegian University"
  echo "  - Nokia 6230 (~50 MB)"
  echo "  - Sony Ericsson P800 (~80 MB)"
  echo "  - Sony Ericsson T68i (~30 MB)"
  echo "  - Sony Ericsson T630 (~200 MB x2)"
  echo "Total: ~560 MB"
  read -p "Continue? (yes/no): " confirm
  if [[ "$confirm" == "yes" ]]; then
    mkdir -p "$DEST_DIR/mobile/legacy"
    for device in Nokia_6230 SE_P800 SE_T68i SE_T630; do
      download_file "$BASE_URL/mobile/$device.zip" "$DEST_DIR/mobile/legacy" "  Downloading $device"
    done
    success "Legacy mobile devices downloaded"
  fi
}

download_full_govdocs1() {
  error "WARNING: Full Govdocs1 is approximately 250 GB"
  warn "This will take many hours and significant disk space"
  echo ""
  echo "Consider alternatives:"
  echo "  - Phase 1 includes 10 development subsets (2.5 GB)"
  echo "  - Phase 2 includes JPEG subset (20 GB)"
  echo "  - Individual type subsets available at:"
  echo "    $BASE_URL/files/govdocs1/by_type/"
  echo ""
  read -p "Still want to download full corpus? (yes/no): " confirm
  if [[ "$confirm" == "yes" ]]; then
    read -p "Type 'CONFIRM' to proceed: " double_confirm
    if [[ "$double_confirm" == "CONFIRM" ]]; then
      mkdir -p "$DEST_DIR/files/govdocs1/full"
      download_directory "$BASE_URL/files/govdocs1/" "$DEST_DIR/files/govdocs1/full" "Downloading full Govdocs1 corpus"
    else
      warn "Download cancelled - confirmation failed"
    fi
  fi
}

download_defcon_ctf() {
  error "WARNING: DEFCON 20 CTF PCAPs are approximately 50 GB"
  warn "This is specialized CTF data - only useful if doing CTF training"
  echo ""
  read -p "Continue? (yes/no): " confirm
  if [[ "$confirm" == "yes" ]]; then
    mkdir -p "$DEST_DIR/network/pcaps/defcon_ctf"
    download_directory "$BASE_URL/packets/2012-defcon/" "$DEST_DIR/network/pcaps/defcon_ctf" "Downloading DEFCON 20 CTF"
  fi
}

download_safedocs() {
  error "WARNING: SAFEDOCS corpus is approximately 500 GB"
  error "This is specialized PDF security research data"
  warn "Only download if you need comprehensive PDF corpus"
  echo ""
  echo "SAFEDOCS includes:"
  echo "  - CC-MAIN-2021-31-PDF-UNTRUNCATED (~500 GB)"
  echo "  - Metadata and analysis tools"
  echo ""
  read -p "Continue? (yes/no): " confirm
  if [[ "$confirm" == "yes" ]]; then
    read -p "Type 'CONFIRM' to proceed: " double_confirm
    if [[ "$double_confirm" == "CONFIRM" ]]; then
      mkdir -p "$DEST_DIR/files/safedocs"
      download_directory "$BASE_URL/files/cc-main-2021-31-pdf-untruncated/" "$DEST_DIR/files/safedocs" "Downloading SAFEDOCS corpus"
    else
      warn "Download cancelled - confirmation failed"
    fi
  fi
}

download_unsafe_docs() {
  warn "UNSAFE-DOCS contains malformed/malicious PDFs"
  echo "Size: ~50 GB (estimated)"
  echo "Use case: PDF security research, malware analysis"
  echo ""
  read -p "Continue? (yes/no): " confirm
  if [[ "$confirm" == "yes" ]]; then
    mkdir -p "$DEST_DIR/files/unsafe_docs"
    download_directory "$BASE_URL/files/cc-main-2021-31-unsafe/" "$DEST_DIR/files/unsafe_docs" "Downloading UNSAFE-DOCS corpus"
  fi
}

main() {
  echo ""
  echo "=========================================="
  echo " Digital Corpora Phase 3: Selective"
  echo "=========================================="
  echo ""
  info "This script allows selective download of specialized datasets"
  warn "Some datasets are very large (50-500 GB)"
  echo ""

  if [[ ! -d "$DEST_DIR/mobile" ]]; then
    error "Phase 1 destination directory not found: $DEST_DIR"
    error "Please run download-phase1-critical.sh first"
    exit 1
  fi

  PS3="Select dataset to download (or 0 to exit): "
  options=(
    "Android 7 (~3 GB) - Older version for compatibility testing"
    "Legacy Nokia/Sony Ericsson phones (~560 MB) - Historical devices"
    "Full Govdocs1 corpus (WARNING: ~250 GB) - Complete file collection"
    "DEFCON 20 CTF PCAPs (WARNING: ~50 GB) - CTF training data"
    "SAFEDOCS PDF corpus (WARNING: ~500 GB) - PDF security research"
    "UNSAFE-DOCS malicious PDFs (~50 GB) - Malware analysis"
    "Show all options again"
    "Quit"
  )

  while true; do
    echo ""
    select opt in "${options[@]}"; do
      case $REPLY in
        1)
          download_android7
          break
          ;;
        2)
          download_legacy_mobile
          break
          ;;
        3)
          download_full_govdocs1
          break
          ;;
        4)
          download_defcon_ctf
          break
          ;;
        5)
          download_safedocs
          break
          ;;
        6)
          download_unsafe_docs
          break
          ;;
        7)
          # Redisplay menu
          break
          ;;
        8)
          echo ""
          success "Exiting Phase 3 download script"
          echo ""
          echo "Summary:"
          echo "  Phase 1 (Critical): ~140 GB essential training data"
          echo "  Phase 2 (High): ~100 GB additional important datasets"
          echo "  Phase 3 (Selective): Variable size, specialized data"
          echo ""
          info "Run verify-downloads.sh to check all downloaded files"
          exit 0
          ;;
        *)
          error "Invalid option: $REPLY"
          break
          ;;
      esac
    done
  done
}

main "$@"
