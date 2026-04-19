#!/usr/bin/env bash
# download-phase2-high.sh
# Downloads additional important DFIR training datasets from Digital Corpora
#
# Phase 2: High Priority datasets (~100 GB)
# - Android 13, 8, 9 (reference/mobile/android)
# - 2018-2019 scenarios (real/lone_wolf_2018, real/narcos_2019, real/owl_2019, real/tuck_2019)
# - NPS Language Drives 2011 (real/nps_language_2011)
# - Govdocs1 JPEG subset (reference/govdocs)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASE_URL="https://downloads.digitalcorpora.org/corpora"
SCENARIOS_DIR="$REPO_ROOT/scenarios"
REAL_DIR="$SCENARIOS_DIR/real"
REF_DIR="$SCENARIOS_DIR/reference"

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

setup_directories() {
  info "Setting up Phase 2 directories..."
  mkdir -p "$REF_DIR"/mobile/android
  mkdir -p "$REF_DIR"/govdocs
  mkdir -p "$REAL_DIR"/{lone_wolf_2018,narcos_2019,owl_2019,tuck_2019,nps_language_2011}/evidence
  success "Directories created"
}

main() {
  echo ""
  echo "=========================================="
  echo " Digital Corpora Phase 2: High Priority"
  echo "=========================================="
  echo ""
  info "Total size: ~100 GB"
  info "Scenarios root: $SCENARIOS_DIR"
  info "Prerequisite: Phase 1 should be completed first"
  echo ""

  if [[ ! -d "$REF_DIR/mobile" ]]; then
    error "Phase 1 reference directory not found: $REF_DIR/mobile"
    error "Please run download-phase1-critical.sh first"
    exit 1
  fi

  read -p "Continue with Phase 2 download? (yes/no): " confirm
  if [[ "$confirm" != "yes" ]]; then
    warn "Download cancelled by user"
    exit 0
  fi

  setup_directories

  TOTAL_STEPS=10
  CURRENT_STEP=0

  # ---- Reference: Mobile Android ----
  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] Android 13 (~40 GB)"
  download_directory "$BASE_URL/mobile/android_13/" "$REF_DIR/mobile/android/android_13" "Downloading Android 13 image"

  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] Android 8 (~4 GB)"
  download_file "$BASE_URL/mobile/android_8.tar.gz" "$REF_DIR/mobile/android" "Downloading Android 8 image"

  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] Android 9 (~5 GB)"
  download_file "$BASE_URL/mobile/android_9.tar.gz" "$REF_DIR/mobile/android" "Downloading Android 9 image"

  # ---- Real scenarios 2018-2019 ----
  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] Lone Wolf 2018 Scenario (~8 GB)"
  download_directory "$BASE_URL/scenarios/2018-lone-wolf/" "$REAL_DIR/lone_wolf_2018/evidence" "Downloading Lone Wolf 2018 scenario"

  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] Narcos 2019 Scenario (~6 GB)"
  download_directory "$BASE_URL/scenarios/2019-narcos/" "$REAL_DIR/narcos_2019/evidence" "Downloading Narcos 2019 scenario"

  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] Owl 2019 Scenario (~10 GB)"
  download_directory "$BASE_URL/scenarios/2019-owl/" "$REAL_DIR/owl_2019/evidence" "Downloading Owl 2019 scenario"

  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] Tuck 2019 Scenario (~5 GB)"
  download_directory "$BASE_URL/scenarios/2019-tuck/" "$REAL_DIR/tuck_2019/evidence" "Downloading Tuck 2019 scenario"

  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] NPS Language Drives 2011 (~2 GB)"
  download_directory "$BASE_URL/scenarios/2011-nps-language-drives/" "$REAL_DIR/nps_language_2011/evidence" "Downloading NPS Language Drives"

  # ---- Reference: Govdocs1 JPEG ----
  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] Govdocs1 JPEG Subset (~20 GB)"
  download_file "$BASE_URL/files/govdocs1/by_type/files.jpeg.tar" "$REF_DIR/govdocs" "Downloading Govdocs1 JPEG subset"

  echo ""
  echo "=========================================="
  success "Phase 2 Download Complete!"
  echo "=========================================="
  echo ""
  info "Downloaded under: $SCENARIOS_DIR"
  echo ""
  echo "Next steps:"
  echo "  1. Run verify-downloads.sh to check file integrity"
  echo "  2. Extract archives (tar -xzf for .tar.gz, unzip for .zip)"
  echo "  3. Create scenarios/real/<name>/scenario.yaml for new scenarios"
  echo "  4. Practice with 2018-2019 scenarios (modern techniques)"
  echo "  5. Run download-phase3-selective.sh if needed"
  echo ""
}

main "$@"
