#!/usr/bin/env bash
# Download M57 Patents Scenario files from Digital Corpora
# Source: https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/

set -euo pipefail

BASE_URL="https://downloads.digitalcorpora.org/corpora/scenarios/m57-patents"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/evidence"
mkdir -p "$OUTPUT_DIR"

# Color output functions
info() { echo -e "\033[0;34m[INFO]\033[0m $*"; }
success() { echo -e "\033[0;32m[OK]\033[0m $*"; }
warn() { echo -e "\033[0;33m[WARN]\033[0m $*"; }
error() { echo -e "\033[0;31m[ERROR]\033[0m $*"; }

echo "======================================================================="
echo "M57 Patents Scenario Downloader"
echo "======================================================================="
echo "Output directory: $OUTPUT_DIR"
echo ""

# Parse command line arguments
TARGET="${1:-help}"

show_help() {
    cat << EOF
Usage: $0 [target]

Targets:
  all       Download all evidence (disk images, USBs, network, memory, docs)
  jean      Download Jean's evidence only (primary suspect)
  pat       Download Pat's evidence only
  terry     Download Terry's evidence only
  charlie   Download Charlie's evidence only
  jo        Download Jo's evidence only
  network   Download network captures only
  memory    Download memory dumps only
  docs      Download teaching materials only
  help      Show this help message

Examples:
  $0 jean       # Download Jean's laptop and USB
  $0 all        # Download everything (50-100 GB!)
  $0 network    # Download network captures only

Note: Total download size for 'all' is approximately 50-100 GB
EOF
    exit 0
}

# Function to download with verification
download_file() {
    local url="$1"
    local output_file="$2"
    local expected_md5="${3:-}"

    # Create subdirectories if needed
    local output_dir
    output_dir="$(dirname "$output_file")"
    mkdir -p "$output_dir"

    if [ -f "$output_file" ]; then
        info "File already exists: $(basename "$output_file")"
        if [ -n "$expected_md5" ]; then
            local actual_md5
            actual_md5=$(md5sum "$output_file" | awk '{print $1}')
            if [ "$actual_md5" = "$expected_md5" ]; then
                success "MD5 verified: $actual_md5"
            else
                warn "MD5 mismatch!"
                warn "Expected: $expected_md5"
                warn "Got:      $actual_md5"
            fi
        else
            info "No hash provided for verification"
        fi
        echo ""
        return 0
    fi

    info "Downloading: $(basename "$output_file")"
    info "URL: $url"

    if curl -fL --progress-bar -o "$output_file" "$url"; then
        success "Downloaded successfully"

        # Get file size
        local size
        size=$(du -h "$output_file" | cut -f1)
        info "Size: $size"

        if [ -n "$expected_md5" ]; then
            info "Verifying MD5 hash..."
            local actual_md5
            actual_md5=$(md5sum "$output_file" | awk '{print $1}')
            if [ "$actual_md5" = "$expected_md5" ]; then
                success "MD5 verified: $actual_md5"
            else
                error "MD5 verification failed!"
                error "Expected: $expected_md5"
                error "Got:      $actual_md5"
                warn "Removing corrupted file..."
                rm -f "$output_file"
                return 1
            fi
        else
            info "Calculating MD5 for future verification..."
            local actual_md5
            actual_md5=$(md5sum "$output_file" | awk '{print $1}')
            info "MD5: $actual_md5"
        fi
    else
        error "Download failed: $url"
        return 1
    fi

    echo ""
    return 0
}

# Function to download a character's complete evidence
download_character() {
    local name="$1"
    local subdir="$2"

    echo "======================================================================="
    echo "Downloading ${name^^}'S EVIDENCE"
    echo "======================================================================="
    echo ""

    # Laptop/Desktop images
    info "Downloading disk images..."
    download_file \
        "$BASE_URL/$subdir/$subdir.E01" \
        "$OUTPUT_DIR/$name/${subdir}.E01" \
        ""

    download_file \
        "$BASE_URL/$subdir/$subdir.E02" \
        "$OUTPUT_DIR/$name/${subdir}.E02" \
        ""

    # Some images have E03 segment
    if [ "$name" = "jean" ]; then
        download_file \
            "$BASE_URL/$subdir/$subdir.E03" \
            "$OUTPUT_DIR/$name/${subdir}.E03" \
            ""
    fi

    # USB drive
    info "Downloading USB drive..."
    download_file \
        "$BASE_URL/usb-drives/$name-usb-2009-12-11.E01" \
        "$OUTPUT_DIR/$name/${name}-usb-2009-12-11.E01" \
        ""

    success "${name^^}'s evidence download complete"
    echo ""
}

# Function to download network captures
download_network() {
    echo "======================================================================="
    echo "DOWNLOADING NETWORK CAPTURES"
    echo "======================================================================="
    echo ""

    info "Network captures are in directory format"
    info "Attempting to list available files..."

    local net_dir="$OUTPUT_DIR/network"
    mkdir -p "$net_dir"

    # Try to get directory listing
    warn "Note: Network capture download requires browsing the directory"
    warn "Visit: $BASE_URL/net/"
    warn "Download individual PCAP files manually or use wget -r"

    echo ""
    echo "Example command to download all network captures:"
    echo "  wget -r -np -nc -P \"$net_dir\" \"$BASE_URL/net/\""
    echo ""
}

# Function to download memory dumps
download_memory() {
    echo "======================================================================="
    echo "DOWNLOADING MEMORY DUMPS"
    echo "======================================================================="
    echo ""

    info "Memory dumps are in directory format"
    info "Attempting to list available files..."

    local ram_dir="$OUTPUT_DIR/memory"
    mkdir -p "$ram_dir"

    warn "Note: Memory dump download requires browsing the directory"
    warn "Visit: $BASE_URL/ram/"
    warn "Download individual memory files manually or use wget -r"

    echo ""
    echo "Example command to download all memory dumps:"
    echo "  wget -r -np -nc -P \"$ram_dir\" \"$BASE_URL/ram/\""
    echo ""
}

# Function to download teaching materials
download_docs() {
    echo "======================================================================="
    echo "DOWNLOADING TEACHING MATERIALS"
    echo "======================================================================="
    echo ""

    local docs_dir="$OUTPUT_DIR/docs"
    mkdir -p "$docs_dir"

    download_file \
        "$BASE_URL/scenario.pdf" \
        "$docs_dir/scenario.pdf" \
        ""

    download_file \
        "$BASE_URL/guide.pdf" \
        "$docs_dir/investigation_guide.pdf" \
        ""

    info "Downloading solution guide (password protected)..."
    download_file \
        "$BASE_URL/solution.pdf" \
        "$docs_dir/solution.pdf" \
        ""

    echo ""
    info "Note: Solution PDF requires faculty password"
    info "Password info: https://digitalcorpora.org/corpora/scenarios/obtaining-solutions/"
    echo ""
}

# Main execution
case "$TARGET" in
    help|--help|-h)
        show_help
        ;;

    jean)
        download_character "jean" "nps-2008-jean"
        ;;

    pat)
        download_character "pat" "nps-2009-pat"
        ;;

    terry)
        download_character "terry" "nps-2009-terry"
        ;;

    charlie)
        download_character "charlie" "nps-2009-charlie"
        ;;

    jo)
        download_character "jo" "nps-2009-jo"
        ;;

    network)
        download_network
        ;;

    memory)
        download_memory
        ;;

    docs)
        download_docs
        ;;

    all)
        warn "WARNING: This will download 50-100 GB of data!"
        echo -n "Continue? [y/N] "
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            info "Download cancelled"
            exit 0
        fi

        download_character "jean" "nps-2008-jean"
        download_character "pat" "nps-2009-pat"
        download_character "terry" "nps-2009-terry"
        download_character "charlie" "nps-2009-charlie"
        download_character "jo" "nps-2009-jo"
        download_network
        download_memory
        download_docs

        echo "======================================================================="
        success "ALL DOWNLOADS COMPLETE"
        echo "======================================================================="
        ;;

    *)
        error "Unknown target: $TARGET"
        echo ""
        show_help
        ;;
esac

echo ""
info "Download location: $OUTPUT_DIR"
info "Verify file integrity using: md5sum <filename>"
echo ""
info "Next steps:"
echo "  1. Verify downloaded files"
echo "  2. Mount E01 images with ewfmount or FTK Imager"
echo "  3. Begin analysis with Autopsy/Sleuth Kit"
echo "  4. Review SCENARIO_INFO.md for investigation guidance"
echo ""
success "Script complete"
