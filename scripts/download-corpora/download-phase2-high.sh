#!/usr/bin/env bash
# download-phase2-high.sh
# Downloads additional important DFIR training datasets from Digital Corpora
#
# Phase 2: High Priority datasets (~100 GB)
# - Android 13, 8, 9
# - 2018-2019 scenarios (Lone Wolf, Narcos, Owl, Tuck)
# - NPS Language Drives
# - Govdocs1 JPEG subset

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

# Download with resume support and progress
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

main() {
  echo ""
  echo "=========================================="
  echo " Digital Corpora Phase 2: High Priority"
  echo "=========================================="
  echo ""
  info "Total size: ~100 GB"
  info "Destination: $DEST_DIR"
  info "Prerequisite: Phase 1 should be completed first"
  echo ""

  if [[ ! -d "$DEST_DIR/mobile" ]]; then
    error "Phase 1 destination directory not found: $DEST_DIR"
    error "Please run download-phase1-critical.sh first"
    exit 1
  fi

  read -p "Continue with Phase 2 download? (yes/no): " confirm
  if [[ "$confirm" != "yes" ]]; then
    warn "Download cancelled by user"
    exit 0
  fi

  # Track progress
  TOTAL_STEPS=10
  CURRENT_STEP=0

  # Mobile - Android 13
  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] Android 13 (~40 GB)"
  download_directory "$BASE_URL/mobile/android_13/" "$DEST_DIR/mobile/android/android_13" "Downloading Android 13 image"

  # Mobile - Android 8, 9
  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] Android 8 (~4 GB)"
  download_file "$BASE_URL/mobile/android_8.tar.gz" "$DEST_DIR/mobile/android" "Downloading Android 8 image"

  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] Android 9 (~5 GB)"
  download_file "$BASE_URL/mobile/android_9.tar.gz" "$DEST_DIR/mobile/android" "Downloading Android 9 image"

  # Scenarios - 2018-2019
  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] Lone Wolf 2018 Scenario (~8 GB)"
  download_directory "$BASE_URL/scenarios/2018-lone-wolf/" "$DEST_DIR/scenarios/lone_wolf_2018" "Downloading Lone Wolf 2018 scenario"

  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] Narcos 2019 Scenario (~6 GB)"
  download_directory "$BASE_URL/scenarios/2019-narcos/" "$DEST_DIR/scenarios/narcos_2019" "Downloading Narcos 2019 scenario"

  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] Owl 2019 Scenario (~10 GB)"
  download_directory "$BASE_URL/scenarios/2019-owl/" "$DEST_DIR/scenarios/owl_2019" "Downloading Owl 2019 scenario"

  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] Tuck 2019 Scenario (~5 GB)"
  download_directory "$BASE_URL/scenarios/2019-tuck/" "$DEST_DIR/scenarios/tuck_2019" "Downloading Tuck 2019 scenario"

  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] NPS Language Drives 2011 (~2 GB)"
  download_directory "$BASE_URL/scenarios/2011-nps-language-drives/" "$DEST_DIR/scenarios/nps_language_2011" "Downloading NPS Language Drives"

  # Files - Govdocs1 JPEG subset
  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] Govdocs1 JPEG Subset (~20 GB)"
  download_file "$BASE_URL/files/govdocs1/by_type/files.jpeg.tar" "$DEST_DIR/files/govdocs1" "Downloading Govdocs1 JPEG subset"

  echo ""
  echo "=========================================="
  success "Phase 2 Download Complete!"
  echo "=========================================="
  echo ""
  info "Downloaded to: $DEST_DIR"
  echo ""
  echo "Next steps:"
  echo "  1. Run verify-downloads.sh to check file integrity"
  echo "  2. Extract archives (tar -xzf for .tar.gz, unzip for .zip)"
  echo "  3. Review new scenario narratives at:"
  echo "     https://digitalcorpora.org/corpora/scenarios/"
  echo "  4. Practice with 2018-2019 scenarios (modern techniques)"
  echo "  5. Use JPEG subset for image forensics training"
  echo "  6. Run download-phase3-selective.sh if needed"
  echo ""
}

main "$@"
