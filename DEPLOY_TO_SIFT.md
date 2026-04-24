# Deploy sift_find_evil to SIFT OVA

Manual deployment steps for transferring detection engine to SIFT OVA environment.

## Prerequisites

- SIFT OVA running at 192.168.122.76
- SSH access: `sansforensics@192.168.122.76` (password: forensics)
- Protocol SIFT MCP server already configured

## Deployment Steps

### 1. Create deployment package

```bash
cd /home/jtomek/Code/sift_find_evil

# Create tarball excluding large files
tar czf /tmp/sift_find_evil.tar.gz \
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
```

### 2. Copy to SIFT OVA

```bash
# Copy tarball
scp /tmp/sift_find_evil.tar.gz sansforensics@192.168.122.76:/tmp/
# Password: forensics
```

### 3. SSH into SIFT OVA

```bash
ssh sansforensics@192.168.122.76
# Password: forensics
```

### 4. Extract and setup (run on SIFT OVA)

```bash
# Extract
cd ~
rm -rf sift_find_evil
mkdir -p sift_find_evil
cd sift_find_evil
tar xzf /tmp/sift_find_evil.tar.gz
rm /tmp/sift_find_evil.tar.gz

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Verify installation
python -m sift_find_evil.cli --help
```

### 5. Validate deployment

```bash
# Still on SIFT OVA, with venv activated
cd ~/sift_find_evil
source venv/bin/activate

# Run scenario harness
PYTHONPATH=. python3 tests/scenario_harness.py

# Expected output: 12/12 scenarios @ F1=1.00
```

## Next Steps: MCP Integration

Once deployed, configure MCP integration:

1. **Verify MCP server** - Check Protocol SIFT MCP is running
2. **Create MCP wrappers** - Add Python clients for forensic tools
3. **Update detectors** - Wire to MCP instead of fixtures
4. **Test with real tools** - Run Volatility, TSK, Plaso via MCP

## Troubleshooting

**Python version mismatch:**
```bash
python3 --version  # Should be 3.10+
```

**Missing dependencies:**
```bash
sudo apt update
sudo apt install python3-pip python3-venv
```

**Import errors:**
```bash
# Make sure venv is activated
source ~/sift_find_evil/venv/bin/activate
which python  # Should show ~/sift_find_evil/venv/bin/python
```

## Files on SIFT OVA

After deployment:
```
/home/sansforensics/
└── sift_find_evil/
    ├── sift_find_evil/     # Python package
    ├── tests/              # Test suite
    ├── scenarios/          # Test scenarios
    ├── docs/               # Documentation
    ├── venv/               # Virtual environment
    └── requirements.txt    # Dependencies
```
