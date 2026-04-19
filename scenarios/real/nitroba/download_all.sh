#!/usr/bin/env bash
# Download all Nitroba University Harassment Scenario files from Digital Corpora
# Source: https://digitalcorpora.org/corpora/scenarios/nitroba-university-harassment-scenario/

set -euo pipefail

BASE_URL="https://downloads.digitalcorpora.org/corpora/scenarios/2008-nitroba"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
DOCS_DIR="$SCRIPT_DIR/teaching_materials"
mkdir -p "$EVIDENCE_DIR" "$DOCS_DIR"

echo "Nitroba Scenario Downloader"
echo "Evidence:           $EVIDENCE_DIR"
echo "Teaching materials: $DOCS_DIR"
echo ""

# Function to download with verification
download_file() {
    local url="$1"
    local output_file="$2"
    local expected_md5="$3"

    if [ -f "$output_file" ]; then
        echo "[SKIP] $output_file already exists"
        if [ -n "$expected_md5" ]; then
            local actual_md5
            actual_md5=$(md5sum "$output_file" | awk '{print $1}')
            if [ "$actual_md5" = "$expected_md5" ]; then
                echo "       MD5 verified: $actual_md5"
            else
                echo "       WARNING: MD5 mismatch!"
                echo "       Expected: $expected_md5"
                echo "       Got:      $actual_md5"
            fi
        fi
        echo ""
        return 0
    fi

    echo "[DOWNLOAD] $(basename "$output_file")"
    echo "           URL: $url"

    if curl -fL -o "$output_file" "$url"; then
        echo "           Downloaded successfully"

        if [ -n "$expected_md5" ]; then
            local actual_md5
            actual_md5=$(md5sum "$output_file" | awk '{print $1}')
            if [ "$actual_md5" = "$expected_md5" ]; then
                echo "           MD5 verified: $actual_md5"
            else
                echo "           ERROR: MD5 verification failed!"
                echo "           Expected: $expected_md5"
                echo "           Got:      $actual_md5"
                rm -f "$output_file"
                return 1
            fi
        fi
    else
        echo "           ERROR: Download failed"
        return 1
    fi

    echo ""
    return 0
}

echo "=== Primary Evidence ==="
echo ""

# PCAP file with hash verification
download_file \
    "$BASE_URL/nitroba.pcap" \
    "$EVIDENCE_DIR/nitroba.pcap" \
    "9981827f11968773ff815e39f5458ec8"

echo "=== Teaching Materials ==="
echo ""

download_file "$BASE_URL/slides.pdf" "$DOCS_DIR/slides.pdf" ""
download_file "$BASE_URL/slides.ppt" "$DOCS_DIR/slides.ppt" ""
download_file "$BASE_URL/slides.key" "$DOCS_DIR/slides.key" ""

echo "=== Solutions (Require Faculty Password) ==="
echo ""

download_file "$BASE_URL/nitroba-solution.pdf" "$DOCS_DIR/nitroba-solution.pdf" ""
download_file \
    "$BASE_URL/Nitroba%20Harassment%20Lab%20scenarios.pdf" \
    "$DOCS_DIR/Nitroba_Harassment_Lab_scenarios.pdf" \
    ""
download_file \
    "$BASE_URL/Nitroba%20Harassment%20Lab%20scenarios%20with%20Solution.pdf" \
    "$DOCS_DIR/Nitroba_Harassment_Lab_scenarios_with_Solution.pdf" \
    ""

echo "=== Download Complete ==="
echo ""
echo "Evidence in:           $EVIDENCE_DIR"
echo "Teaching materials in: $DOCS_DIR"
echo ""
echo "Verify PCAP hashes:"
echo "  MD5:    9981827f11968773ff815e39f5458ec8"
echo "  SHA1:   65656392412add15f93f8585197a8998aaeb50a1"
echo "  SHA256: 2b77a9eaefc1d6af163d1ba793c96dbccacb04e6befdf1a0b01f8c67553ec2fb"
echo ""
echo "Note: Solution PDFs require faculty passwords from:"
echo "      https://digitalcorpora.org/corpora/scenarios/obtaining-solutions/"
