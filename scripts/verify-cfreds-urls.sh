#!/usr/bin/env bash
# Verify CFReDS download URLs are accessible
# Run this before attempting full downloads to check URL validity

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
error() { echo -e "${RED}[FAIL]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

# CFReDS URLs to verify
declare -A URLS=(
  ["Data Leakage Case"]="https://cfreds.nist.gov/data_leakage_case/data-leakage-case.dd.zip"
  ["Data Leakage SHA1"]="https://cfreds.nist.gov/data_leakage_case/data-leakage-case.sha1"
  ["Hacking Case (SCHARDT)"]="https://cfreds.nist.gov/Hacking_Case/SCHARDT.zip"
  ["Hacking Case SHA1"]="https://cfreds.nist.gov/Hacking_Case/SCHARDT.sha1"
)

check_url() {
  local name="$1"
  local url="$2"

  # Use spider mode to check without downloading
  local response
  response=$(wget --spider --server-response "$url" 2>&1 || true)

  # Check for HTTP errors
  if echo "$response" | grep -qi "404 Not Found"; then
    error "$name: 404 Not Found"
    return 1
  fi

  if echo "$response" | grep -qi "403 Forbidden"; then
    error "$name: 403 Forbidden"
    return 1
  fi

  if echo "$response" | grep -qi "500 Internal Server Error"; then
    error "$name: 500 Internal Server Error"
    return 1
  fi

  # Check content type
  local content_type
  content_type=$(echo "$response" | grep -i "Content-Type:" | tail -1 | cut -d':' -f2- | xargs || echo "unknown")

  if echo "$content_type" | grep -qi "text/html"; then
    warn "$name: Returns HTML (likely error page)"
    warn "  Content-Type: $content_type"
    return 1
  fi

  # Check if we got a success response
  if echo "$response" | grep -qi "HTTP.*200 OK"; then
    success "$name: Accessible"
    if [ -n "$content_type" ] && [ "$content_type" != "unknown" ]; then
      echo "    Content-Type: $content_type"
    fi
    return 0
  fi

  warn "$name: Unknown status"
  return 1
}

main() {
  echo ""
  echo "=========================================="
  echo " CFReDS URL Verification"
  echo "=========================================="
  echo ""
  info "Checking accessibility of CFReDS download URLs..."
  echo ""

  local success_count=0
  local fail_count=0
  local total=${#URLS[@]}

  for name in "${!URLS[@]}"; do
    url="${URLS[$name]}"
    if check_url "$name" "$url"; then
      ((success_count++))
    else
      ((fail_count++))
      echo "    URL: $url"
    fi
    echo ""
  done

  echo "=========================================="
  echo " Summary"
  echo "=========================================="
  echo "Total URLs checked: $total"
  success "Accessible: $success_count"

  if [ $fail_count -gt 0 ]; then
    error "Failed: $fail_count"
    echo ""
    warn "Some URLs are not accessible."
    warn ""
    warn "This may indicate:"
    warn "  - NIST changed URL structure"
    warn "  - Files moved to different location"
    warn "  - Temporary server issues"
    warn ""
    warn "Next steps:"
    warn "  1. Visit https://cfreds.nist.gov/ in browser"
    warn "  2. Navigate to dataset pages manually"
    warn "  3. Find current download links"
    warn "  4. Update scripts/download-cfreds.sh with new URLs"
    warn ""
    warn "See docs/CFREDS_DOWNLOAD_GUIDE.md for detailed instructions."
    exit 1
  else
    echo ""
    success "All URLs are accessible!"
    info "You can proceed with: ./scripts/download-cfreds.sh"
  fi
}

main "$@"
