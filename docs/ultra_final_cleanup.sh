#!/usr/bin/env bash
set -euo pipefail

cd /home/jtomek/Code/4n6_nexus_public

echo "=== Ultra-final cleanup ==="

# Keep ONLY 4n6_nexus_final.png (the submission logo)
rm -f 4n6_nexus_clean.png 4n6_nexus_clean.svg
rm -f 4n6_nexus_logo_3x2.svg 4n6_nexus_logo.png  
rm -f 4n6nexus.png
rm -f logo_banner.svg
rm -f sift_find_evil_logo.png sift_find_evil_logo.svg

# Remove all cleanup scripts
rm -f cleanup*.sh final*.sh remove*.sh ultra*.sh

# Remove editor temp files
rm -f .*.swp

# Remove real_examples if empty
if [ -d "real_examples" ] && [ -z "$(ls -A real_examples)" ]; then
    rm -rf real_examples
fi

echo ""
echo "Logo: 4n6_nexus_final.png"
ls -lh 4n6_nexus_final.png
echo ""
echo "Root .md files:"
ls -1 *.md | wc -l
echo "files"
