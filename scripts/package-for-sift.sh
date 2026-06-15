#!/usr/bin/env bash
# Package sift_find_evil for deployment on SIFT Workstation

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PACKAGE_NAME="sift_find_evil"
VERSION=$(grep -E "^version\s*=" setup.py 2>/dev/null | cut -d'"' -f2 || echo "0.1.0")
BUILD_DIR="$REPO_ROOT/dist"
PACKAGE_DIR="$BUILD_DIR/${PACKAGE_NAME}-${VERSION}-sift"

echo "=========================================="
echo "  Packaging SIFT Find Evil for SIFT OVA"
echo "=========================================="
echo ""
echo "Version: $VERSION"
echo "Build directory: $BUILD_DIR"
echo ""

# Clean previous builds
echo "[1/7] Cleaning previous builds..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
mkdir -p "$PACKAGE_DIR"

# Copy source code
echo "[2/7] Copying source code..."
cp -r "$REPO_ROOT/sift_find_evil" "$PACKAGE_DIR/"
cp -r "$REPO_ROOT/tests" "$PACKAGE_DIR/"
cp -r "$REPO_ROOT/scenarios" "$PACKAGE_DIR/"
cp -r "$REPO_ROOT/rules" "$PACKAGE_DIR/"
cp -r "$REPO_ROOT/scripts" "$PACKAGE_DIR/"

# Copy documentation
echo "[3/7] Copying documentation..."
cp "$REPO_ROOT/README.md" "$PACKAGE_DIR/"
cp "$REPO_ROOT/INSTALL_SIFT.md" "$PACKAGE_DIR/"
cp "$REPO_ROOT/CLAUDE.md" "$PACKAGE_DIR/" 2>/dev/null || true
cp "$REPO_ROOT/requirements.txt" "$PACKAGE_DIR/"
cp "$REPO_ROOT/pyproject.toml" "$PACKAGE_DIR/" 2>/dev/null || true

# Copy evidence (if present, exclude large files)
echo "[4/7] Checking for evidence files..."
if [ -d "$REPO_ROOT/scenarios/real/circl-2023-wiped/evidence" ]; then
    echo "  - Including sample evidence (small files only)"
    mkdir -p "$PACKAGE_DIR/scenarios/real/circl-2023-wiped/evidence"
    # Only include small sample files (<100MB)
    find "$REPO_ROOT/scenarios/real/circl-2023-wiped/evidence" -type f -size -100M \
        -exec cp {} "$PACKAGE_DIR/scenarios/real/circl-2023-wiped/evidence/" \;
fi

# Create install script
echo "[5/7] Creating install script..."
cat > "$PACKAGE_DIR/install.sh" <<'INSTALL_EOF'
#!/usr/bin/env bash
# SIFT Find Evil Installer for SIFT Workstation

set -euo pipefail

echo "=========================================="
echo "  SIFT Find Evil Installer"
echo "=========================================="
echo ""

# Check if running on SIFT
if [ ! -f /etc/os-release ]; then
    echo "ERROR: Cannot determine OS. Is this a SIFT Workstation?"
    exit 1
fi

source /etc/os-release
if [[ ! "$NAME" =~ "Ubuntu" ]]; then
    echo "WARNING: This installer is designed for Ubuntu (SIFT Workstation)"
    echo "Detected: $NAME $VERSION"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check Python version
python_version=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
required_version="3.10"

if ! awk -v ver="$python_version" -v req="$required_version" 'BEGIN{exit(ver<req)}'; then
    echo "ERROR: Python $required_version+ required. Found: $python_version"
    exit 1
fi

echo "Detected Python $python_version - OK"
echo ""

# Install dependencies
echo "[1/4] Installing Python dependencies..."
pip3 install --user -r requirements.txt

# Install in development mode
echo "[2/4] Installing sift_find_evil package..."
pip3 install --user -e .

# Create workspace
echo "[3/4] Creating workspace directories..."
mkdir -p ~/dfir-workspace/{evidence,analysis,reports,test-results}

# Verify installation
echo "[4/4] Verifying installation..."
if python3 -m sift_find_evil.cli --help > /dev/null 2>&1; then
    echo ""
    echo "=========================================="
    echo "  Installation Complete!"
    echo "=========================================="
    echo ""
    echo "Workspace created: ~/dfir-workspace/"
    echo ""
    echo "Quick start:"
    echo "  1. Run demo: python3 -m sift_find_evil.cli demo"
    echo "  2. Read guide: cat INSTALL_SIFT.md"
    echo "  3. Run tests: pytest tests/"
    echo ""
    echo "To add to PATH permanently:"
    echo "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc"
    echo "  source ~/.bashrc"
    echo ""
else
    echo ""
    echo "ERROR: Installation verification failed"
    echo "Try running: pip3 install --user -e ."
    exit 1
fi
INSTALL_EOF

chmod +x "$PACKAGE_DIR/install.sh"

# Create README for package
echo "[6/7] Creating package README..."
cat > "$PACKAGE_DIR/README_PACKAGE.md" <<'README_EOF'
# SIFT Find Evil - SIFT Workstation Package

This package contains the SIFT Find Evil autonomous DFIR detection engine.

## Installation

1. Extract this package:
   ```bash
   cd sift_find_evil-*-sift
   ```

2. Run installer:
   ```bash
   ./install.sh
   ```

3. Verify installation:
   ```bash
   python3 -m sift_find_evil.cli demo
   ```

## Documentation

- `INSTALL_SIFT.md` - Complete installation and usage guide
- `README.md` - Project overview and architecture
- `scenarios/` - Sample forensic scenarios

## Requirements

- SIFT Workstation (Ubuntu 20.04+ with forensic tools)
- Python 3.10+
- ~500 MB disk space for dependencies

## Quick Start

```bash
# Run demonstration
python3 -m sift_find_evil.cli demo

# Analyze evidence image
python3 -m sift_find_evil.cli analyze \
    --image /cases/suspect.E01 \
    --output ~/dfir-workspace/findings.json

# Run scenario
python3 -m sift_find_evil.cli run \
    --scenario scenarios/real/circl-2023-wiped/
```

## Support

- GitHub: https://github.com/Strike48-public/4n6_nexus
- Issues: https://github.com/Strike48-public/4n6_nexus/issues
README_EOF

# Create tarball
echo "[7/7] Creating tarball..."
cd "$BUILD_DIR"
tar -czf "${PACKAGE_NAME}-${VERSION}-sift.tar.gz" "${PACKAGE_NAME}-${VERSION}-sift"

echo ""
echo "=========================================="
echo "  Package Created Successfully!"
echo "=========================================="
echo ""
echo "Package: $BUILD_DIR/${PACKAGE_NAME}-${VERSION}-sift.tar.gz"
echo "Size: $(du -h "$BUILD_DIR/${PACKAGE_NAME}-${VERSION}-sift.tar.gz" | cut -f1)"
echo ""
echo "To deploy on SIFT Workstation:"
echo "  1. Copy tarball to SIFT VM"
echo "  2. Extract: tar -xzf ${PACKAGE_NAME}-${VERSION}-sift.tar.gz"
echo "  3. Install: cd ${PACKAGE_NAME}-${VERSION}-sift && ./install.sh"
echo ""
