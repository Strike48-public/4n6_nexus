#!/usr/bin/env bash
# Download all Nitroba University Harassment Scenario files from Digital Corpora
# Source: https://digitalcorpora.org/corpora/scenarios/nitroba-university-harassment-scenario/

set -euo pipefail

BASE_URL="https://downloads.digitalcorpora.org/corpora/scenarios/2008-nitroba"
OUTPUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Nitroba Scenario Downloader"
echo "Output directory: $OUTPUT_DIR"
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

cd "$OUTPUT_DIR"

echo "=== Primary Evidence ==="
echo ""

# PCAP file with hash verification
download_file \
    "$BASE_URL/nitroba.pcap" \
    "nitroba.pcap" \
    "9981827f11968773ff815e39f5458ec8"

echo "=== Teaching Materials ==="
echo ""

# Problem introduction slides
download_file \
    "$BASE_URL/slides.pdf" \
    "slides.pdf" \
    ""

download_file \
    "$BASE_URL/slides.ppt" \
    "slides.ppt" \
    ""

download_file \
    "$BASE_URL/slides.key" \
    "slides.key" \
    ""

echo "=== Solutions (Require Faculty Password) ==="
echo ""

# Teacher's solution (password protected)
download_file \
    "$BASE_URL/nitroba-solution.pdf" \
    "nitroba-solution.pdf" \
    ""

# Expanded scenarios
download_file \
    "$BASE_URL/Nitroba%20Harassment%20Lab%20scenarios.pdf" \
    "Nitroba_Harassment_Lab_scenarios.pdf" \
    ""

download_file \
    "$BASE_URL/Nitroba%20Harassment%20Lab%20scenarios%20with%20Solution.pdf" \
    "Nitroba_Harassment_Lab_scenarios_with_Solution.pdf" \
    ""

echo "=== Download Complete ==="
echo ""
echo "Files downloaded to: $OUTPUT_DIR"
echo ""
echo "Verify PCAP hashes:"
echo "  MD5:    9981827f11968773ff815e39f5458ec8"
echo "  SHA1:   65656392412add15f93f8585197a8998aaeb50a1"
echo "  SHA256: 2b77a9eaefc1d6af163d1ba793c96dbccacb04e6befdf1a0b01f8c67553ec2fb"
echo ""
echo "Note: Solution PDFs require faculty passwords from:"
echo "      https://digitalcorpora.org/corpora/scenarios/obtaining-solutions/"
