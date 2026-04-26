#!/usr/bin/env bash
# Extract archived evidence on USB drive for batch testing

set -euo pipefail

USB_MOUNT="${USB_MOUNT:-/mnt/usb-evidence/sift_evidence}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }
section() { echo -e "\n${BLUE}======================================================================${NC}"; echo -e "${BLUE}  $*${NC}"; echo -e "${BLUE}======================================================================${NC}\n"; }

section "Extracting USB Evidence Archives"

info "USB Mount: $USB_MOUNT"
echo

# Check USB mount
if [ ! -d "$USB_MOUNT" ]; then
    error "USB mount not found: $USB_MOUNT"
    exit 1
fi

# Check extraction tools
if ! command -v 7z &> /dev/null; then
    error "7z not found. Install with: sudo apt install p7zip-full"
    exit 1
fi

if ! command -v unzip &> /dev/null; then
    error "unzip not found. Install with: sudo apt install unzip"
    exit 1
fi

# Function to extract archive
extract_archive() {
    local archive="$1"
    local target_dir=$(dirname "$archive")
    local archive_name=$(basename "$archive")

    info "Extracting: $archive_name"
    info "Target: $target_dir"

    # Check if already extracted
    local base_name="${archive_name%.*}"
    if [ -d "$target_dir/$base_name" ] || [ -f "$target_dir/${base_name}.E01" ] || [ -f "$target_dir/${base_name}.dd" ]; then
        warn "Already extracted: $archive_name"
        return 0
    fi

    # Extract based on file type (use sudo for root-owned USB)
    if [[ "$archive" == *.7z ]]; then
        if sudo 7z x "$archive" -o"$target_dir" -y; then
            info "Extracted: $archive_name"
            return 0
        else
            error "Failed to extract: $archive_name"
            return 1
        fi
    elif [[ "$archive" == *.zip ]]; then
        if sudo unzip -q "$archive" -d "$target_dir"; then
            info "Extracted: $archive_name"
            return 0
        else
            error "Failed to extract: $archive_name"
            return 1
        fi
    else
        warn "Unknown archive format: $archive_name"
        return 1
    fi
}

# Extract blue_team_challenge archives
section "blue_team_challenge"
if [ -f "$USB_MOUNT/blue_team_challenge/evidence/aamemend.7z" ]; then
    extract_archive "$USB_MOUNT/blue_team_challenge/evidence/aamemend.7z"
fi
if [ -f "$USB_MOUNT/blue_team_challenge/evidence/alison_ws.7z" ]; then
    extract_archive "$USB_MOUNT/blue_team_challenge/evidence/alison_ws.7z"
fi

# Extract ransomware_2021 archive
section "ransomware_2021"
if [ -f "$USB_MOUNT/ransomware_2021/evidence/Forensic_Image_Files.zip" ]; then
    extract_archive "$USB_MOUNT/ransomware_2021/evidence/Forensic_Image_Files.zip"
fi

# Extract national_gallery_2012 carry-phone
section "national_gallery_2012 (carry-phone)"
if [ -f "$USB_MOUNT/national_gallery_2012/evidence/carry-phone/carry-phone-2012-07-15-final.zip" ]; then
    extract_archive "$USB_MOUNT/national_gallery_2012/evidence/carry-phone/carry-phone-2012-07-15-final.zip"
fi

section "Extraction Complete"

# Show what's now available
info "Checking extracted evidence..."
echo

for scenario in blue_team_challenge ransomware_2021 national_gallery_2012; do
    if [ -d "$USB_MOUNT/$scenario/evidence" ]; then
        echo "=== $scenario ==="
        find "$USB_MOUNT/$scenario/evidence" -type f \( -name "*.E01" -o -name "*.dd" -o -name "*.raw" \) 2>/dev/null | head -5 || echo "No E01/DD/raw files found"
        echo
    fi
done

info "Ready for batch testing"
info "Run: ./scripts/run-batch-test-on-sift.sh"
