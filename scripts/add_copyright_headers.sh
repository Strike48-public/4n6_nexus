#!/usr/bin/env bash
# Add copyright headers to source files

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=== Adding Copyright Headers ==="
echo ""
echo "Repository: $REPO_ROOT"
echo ""

# Python files
echo "Processing Python files..."
find "$REPO_ROOT/sift_find_evil" -name "*.py" -type f | while read -r file; do
  # Skip if already has copyright
  if grep -q "Copyright (c)" "$file" 2>/dev/null; then
    echo "  ⊘ Already has header: ${file#$REPO_ROOT/}"
    continue
  fi

  # Check if file has shebang
  has_shebang=false
  if head -1 "$file" | grep -q "^#!"; then
    has_shebang=true
  fi

  # Create temp file
  temp_file="$file.tmp"

  if [ "$has_shebang" = true ]; then
    # Preserve shebang, add copyright after
    head -1 "$file" > "$temp_file"
    cat >> "$temp_file" << 'HEADER'
# Copyright (c) 2024 4n6Nexus Contributors
# SPDX-License-Identifier: MIT

HEADER
    tail -n +2 "$file" >> "$temp_file"
  else
    # Add copyright at top
    cat > "$temp_file" << 'HEADER'
# Copyright (c) 2024 4n6Nexus Contributors
# SPDX-License-Identifier: MIT

HEADER
    cat "$file" >> "$temp_file"
  fi

  # Replace original
  mv "$temp_file" "$file"
  echo "  ✓ Added header: ${file#$REPO_ROOT/}"
done

echo ""
echo "=== Copyright Headers Added ==="
echo ""
echo "Review changes:"
echo "  git diff sift_find_evil/"
echo ""
echo "Commit changes:"
echo "  git add sift_find_evil/"
echo "  git commit -m 'chore: add copyright headers to source files'"
echo ""
