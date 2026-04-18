#!/usr/bin/env bash
# Verify downloaded M57 Patents Scenario files
# Generates hash inventory and checks file integrity

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HASH_FILE="$SCRIPT_DIR/file_hashes.txt"

# Color output
info() { echo -e "\033[0;34m[INFO]\033[0m $*"; }
success() { echo -e "\033[0;32m[OK]\033[0m $*"; }
warn() { echo -e "\033[0;33m[WARN]\033[0m $*"; }
error() { echo -e "\033[0;31m[ERROR]\033[0m $*"; }

echo "======================================================================="
echo "M57 Patents Scenario - File Verification"
echo "======================================================================="
echo ""

# Function to calculate and display hashes for a file
verify_file() {
    local filepath="$1"

    if [ ! -f "$filepath" ]; then
        warn "File not found: $filepath"
        return 1
    fi

    local filename
    filename=$(basename "$filepath")
    local filesize
    filesize=$(du -h "$filepath" | cut -f1)

    info "File: $filename"
    info "Size: $filesize"
    info "Calculating hashes..."

    local md5hash sha1hash sha256hash
    md5hash=$(md5sum "$filepath" | awk '{print $1}')
    sha1hash=$(sha1sum "$filepath" | awk '{print $1}')
    sha256hash=$(sha256sum "$filepath" | awk '{print $1}')

    echo "  MD5:    $md5hash"
    echo "  SHA1:   $sha1hash"
    echo "  SHA256: $sha256hash"
    echo ""

    # Append to hash file
    {
        echo "File: $filename"
        echo "Path: $filepath"
        echo "Size: $filesize"
        echo "MD5:    $md5hash"
        echo "SHA1:   $sha1hash"
        echo "SHA256: $sha256hash"
        echo "Date:   $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
        echo "---"
    } >> "$HASH_FILE"
}

# Initialize hash file
> "$HASH_FILE"
echo "M57 Patents Scenario - File Hash Inventory" > "$HASH_FILE"
echo "Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")" >> "$HASH_FILE"
echo "=============================================" >> "$HASH_FILE"
echo "" >> "$HASH_FILE"

# Find all downloaded files
info "Searching for downloaded evidence files..."
echo ""

file_count=0

# Jean's files
if [ -d "$SCRIPT_DIR/jean" ]; then
    echo "=== JEAN'S EVIDENCE ==="
    for file in "$SCRIPT_DIR/jean"/*.E0*; do
        [ -f "$file" ] && verify_file "$file" && ((file_count++))
    done
fi

# Pat's files
if [ -d "$SCRIPT_DIR/pat" ]; then
    echo "=== PAT'S EVIDENCE ==="
    for file in "$SCRIPT_DIR/pat"/*.E0*; do
        [ -f "$file" ] && verify_file "$file" && ((file_count++))
    done
fi

# Terry's files
if [ -d "$SCRIPT_DIR/terry" ]; then
    echo "=== TERRY'S EVIDENCE ==="
    for file in "$SCRIPT_DIR/terry"/*.E0*; do
        [ -f "$file" ] && verify_file "$file" && ((file_count++))
    done
fi

# Charlie's files
if [ -d "$SCRIPT_DIR/charlie" ]; then
    echo "=== CHARLIE'S EVIDENCE ==="
    for file in "$SCRIPT_DIR/charlie"/*.E0*; do
        [ -f "$file" ] && verify_file "$file" && ((file_count++))
    done
fi

# Jo's files
if [ -d "$SCRIPT_DIR/jo" ]; then
    echo "=== JO'S EVIDENCE ==="
    for file in "$SCRIPT_DIR/jo"/*.E0*; do
        [ -f "$file" ] && verify_file "$file" && ((file_count++))
    done
fi

# Network captures
if [ -d "$SCRIPT_DIR/network" ]; then
    echo "=== NETWORK CAPTURES ==="
    for file in "$SCRIPT_DIR/network"/*.pcap; do
        [ -f "$file" ] && verify_file "$file" && ((file_count++))
    done
fi

# Memory dumps
if [ -d "$SCRIPT_DIR/memory" ]; then
    echo "=== MEMORY DUMPS ==="
    for file in "$SCRIPT_DIR/memory"/*; do
        [ -f "$file" ] && verify_file "$file" && ((file_count++))
    done
fi

# Teaching materials
if [ -d "$SCRIPT_DIR/docs" ]; then
    echo "=== TEACHING MATERIALS ==="
    for file in "$SCRIPT_DIR/docs"/*.pdf; do
        [ -f "$file" ] && verify_file "$file" && ((file_count++))
    done
fi

echo "======================================================================="
if [ $file_count -eq 0 ]; then
    warn "No evidence files found!"
    warn "Have you run ./download_all.sh yet?"
else
    success "Verified $file_count files"
    success "Hash inventory saved to: $HASH_FILE"
fi
echo "======================================================================="
echo ""

info "To share or compare hashes:"
echo "  cat $HASH_FILE"
echo ""
info "To verify against Digital Corpora published hashes:"
echo "  Visit: https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/"
echo ""
