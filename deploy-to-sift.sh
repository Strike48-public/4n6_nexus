#!/usr/bin/env bash
# Deploy sift_find_evil to SIFT OVA
# Run from host machine: ./deploy-to-sift.sh

set -euo pipefail

SIFT_HOST="sansforensics@192.168.122.76"
SIFT_PASSWORD="forensics"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REMOTE_DIR="/home/sansforensics/sift_find_evil"

echo "========================================="
echo "Deploying sift_find_evil to SIFT OVA"
echo "========================================="

# Step 1: Create deployment tarball (exclude large files)
echo "[1/5] Creating deployment tarball..."
cd "$REPO_DIR"
tar czf /tmp/sift_find_evil_deploy.tar.gz \
  --exclude='.git' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='.pytest_cache' \
  --exclude='sift-*.ova' \
  --exclude='scenarios/*/evidence/*' \
  --exclude='.beads' \
  --exclude='.claude' \
  --exclude='htmlcov' \
  --exclude='.coverage' \
  .

echo "  Tarball size: $(du -h /tmp/sift_find_evil_deploy.tar.gz | cut -f1)"

# Step 2: Copy tarball to SIFT OVA
echo "[2/5] Copying to SIFT OVA (192.168.122.76)..."
sshpass -p "$SIFT_PASSWORD" scp -o StrictHostKeyChecking=no \
  /tmp/sift_find_evil_deploy.tar.gz "$SIFT_HOST:/tmp/"

# Step 3: Extract on SIFT OVA
echo "[3/5] Extracting on SIFT OVA..."
sshpass -p "$SIFT_PASSWORD" ssh -o StrictHostKeyChecking=no "$SIFT_HOST" bash <<'REMOTE_SCRIPT'
cd /home/sansforensics
rm -rf sift_find_evil
mkdir -p sift_find_evil
cd sift_find_evil
tar xzf /tmp/sift_find_evil_deploy.tar.gz
rm /tmp/sift_find_evil_deploy.tar.gz
REMOTE_SCRIPT

# Step 4: Install dependencies
echo "[4/5] Installing Python dependencies..."
sshpass -p "$SIFT_PASSWORD" ssh -o StrictHostKeyChecking=no "$SIFT_HOST" bash <<'REMOTE_SCRIPT'
cd /home/sansforensics/sift_find_evil

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Verify installation
python -m sift_find_evil.cli --help
REMOTE_SCRIPT

# Step 5: Run validation
echo "[5/5] Running scenario harness validation..."
sshpass -p "$SIFT_PASSWORD" ssh -o StrictHostKeyChecking=no "$SIFT_HOST" bash <<'REMOTE_SCRIPT'
cd /home/sansforensics/sift_find_evil
source venv/bin/activate

# Run scenario harness
PYTHONPATH=. python3 tests/scenario_harness.py
REMOTE_SCRIPT

echo ""
echo "========================================="
echo "Deployment Complete!"
echo "========================================="
echo ""
echo "To access SIFT OVA:"
echo "  ssh sansforensics@192.168.122.76"
echo "  cd ~/sift_find_evil"
echo "  source venv/bin/activate"
echo ""
echo "Next steps:"
echo "  1. Configure MCP integration"
echo "  2. Test with real forensic tools"
echo "  3. Run demo scenario"
echo ""
