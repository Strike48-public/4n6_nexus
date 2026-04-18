#!/usr/bin/env bash
# download-phase1-critical.sh
# Downloads essential DFIR training datasets from Digital Corpora
#
# Phase 1: Critical datasets (~140 GB)
# - Modern Android/iOS images
# - NPS test disk images
# - Core scenarios (Nitroba, M57-Jean, M57-Patents, National Gallery)
# - Govdocs1 development subsets
# - Network test files
# - SQLite forensic corpus

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

# Create directory structure
setup_directories() {
  info "Setting up directory structure..."
  mkdir -p "$DEST_DIR"/{mobile/{android,ios,legacy},disk_images/{nps_test_images,circl},scenarios,files/govdocs1/subsets,network/pcaps,sql}
  success "Directories created"
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

# Download directory recursively (for S3 listings)
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
  echo " Digital Corpora Phase 1: Critical"
  echo "=========================================="
  echo ""
  info "Total size: ~140 GB"
  info "Destination: $DEST_DIR"
  info "This will take several hours depending on connection speed"
  echo ""

  read -p "Continue with Phase 1 download? (yes/no): " confirm
  if [[ "$confirm" != "yes" ]]; then
    warn "Download cancelled by user"
    exit 0
  fi

  setup_directories

  # Track progress
  TOTAL_STEPS=15
  CURRENT_STEP=0

  # Mobile - Android
  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] Android 10 (~8 GB)"
  download_directory "$BASE_URL/mobile/android_10/" "$DEST_DIR/mobile/android/android_10" "Downloading Android 10 image"

  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] Android 11 (~11 GB)"
  download_file "$BASE_URL/mobile/android_11.zip" "$DEST_DIR/mobile/android" "Downloading Android 11 image"

  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] Android 12 (~42 GB)"
  download_file "$BASE_URL/mobile/android_12.zip" "$DEST_DIR/mobile/android" "Downloading Android 12 image"

  # Mobile - iOS
  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] iOS 13.3.1 (~10 GB)"
  download_directory "$BASE_URL/mobile/ios_13_3_1/" "$DEST_DIR/mobile/ios/ios_13_3_1" "Downloading iOS 13.3.1 image"

  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] iOS 13.4.1 (~10 GB)"
  download_directory "$BASE_URL/mobile/ios_13_4_1/" "$DEST_DIR/mobile/ios/ios_13_4_1" "Downloading iOS 13.4.1 image"

  # Disk Images - NPS
  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] NPS Test Images (~24 GB total)"
  for img in canon2 casper-rw hfsjtest1 ntfs1 ubnist1 domexusers domexusers-redacted; do
    info "  Downloading nps-2009-$img..."
    download_directory "$BASE_URL/drives/nps-2009-$img/" "$DEST_DIR/disk_images/nps_test_images/$img" "  NPS $img"
  done

  # NPS emails
  info "  Downloading nps-2010-emails..."
  download_directory "$BASE_URL/drives/nps-2010-emails/" "$DEST_DIR/disk_images/nps_test_images/emails" "  NPS emails"

  # CIRCL
  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] CIRCL Wiped Disk (~1 GB)"
  download_directory "$BASE_URL/drives/circl-2023-wiped/" "$DEST_DIR/disk_images/circl" "Downloading CIRCL wiped disk exercise"

  # Scenarios
  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] Nitroba Harassment Scenario (~53 MB)"
  download_directory "$BASE_URL/scenarios/nitroba/" "$DEST_DIR/scenarios/nitroba" "Downloading Nitroba scenario"

  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] M57-Jean Scenario (~3 GB)"
  download_directory "$BASE_URL/scenarios/2009-m57-jean/" "$DEST_DIR/scenarios/m57-jean" "Downloading M57-Jean scenario"

  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] M57-Patents Scenario (~15 GB)"
  download_directory "$BASE_URL/scenarios/2009-m57-patents/" "$DEST_DIR/scenarios/m57-patents" "Downloading M57-Patents scenario"

  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] National Gallery 2012 Scenario (~5 GB)"
  download_directory "$BASE_URL/scenarios/2012-ngdc/" "$DEST_DIR/scenarios/national_gallery_2012" "Downloading National Gallery 2012 scenario"

  # Files - Govdocs1 subsets
  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] Govdocs1 Development Subsets (~2.5 GB)"
  for i in {0..9}; do
    info "  Downloading subset$i.zip..."
    download_file "$BASE_URL/files/govdocs1/threads/subset$i.zip" "$DEST_DIR/files/govdocs1/subsets" "  Govdocs1 subset $i"
  done

  # Network
  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] 5 GB TCP Connection Test (5 GB)"
  download_file "$BASE_URL/packets/5gb-tcp-connection.pcap.gz" "$DEST_DIR/network/pcaps" "Downloading 5 GB TCP test file"

  # SQL
  CURRENT_STEP=$((CURRENT_STEP + 1))
  echo ""
  echo "[$CURRENT_STEP/$TOTAL_STEPS] SQLite Forensic Corpus (~500 MB)"
  download_directory "$BASE_URL/sql/sqlite-forensic-corpus/" "$DEST_DIR/sql/sqlite_corpus" "Downloading SQLite forensic corpus"

  echo ""
  echo "=========================================="
  success "Phase 1 Download Complete!"
  echo "=========================================="
  echo ""
  info "Downloaded to: $DEST_DIR"
  echo ""
  echo "Next steps:"
  echo "  1. Run verify-downloads.sh to check file integrity"
  echo "  2. Extract archives as needed (unzip, tar -xzf)"
  echo "  3. Review scenario narratives:"
  echo "     https://digitalcorpora.org/corpora/scenarios/"
  echo "  4. Start with Nitroba (smallest, focused scenario)"
  echo "  5. Progress to M57-Jean, then M57-Patents"
  echo "  6. Run download-phase2-high.sh for additional datasets"
  echo ""
}

main "$@"
