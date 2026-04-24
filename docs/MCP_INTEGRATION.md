## MCP Integration Guide

This guide explains how to use the MCP (Model Context Protocol) integration for executing forensic tools directly on evidence.

---

## Overview

**Problem:** The detection engine currently analyzes pre-parsed CSV fixtures, not raw evidence.

**Solution:** MCP integration executes forensic tools (MFTECmd, PECmd, EvtxECmd, Volatility) directly on evidence files with safety guards.

**Architecture:**
```
Evidence Files → MCP Client → Forensic Tools → CSV/JSON → Parsers → Detection Engine
                     ↓
                Audit Logger (JSONL)
```

---

## Components

### 1. MCP Client (`sift_find_evil/mcp/client.py`)

Executes forensic tools with safety guards:
- **Read-only enforcement** - Blocks write operations
- **Timeout guards** - Default 5 minutes per tool
- **Circuit breaker** - Stops after 3 consecutive failures
- **Audit logging** - All invocations logged to JSONL

### 2. Tool Wrappers (`sift_find_evil/mcp/tools.py`)

Pre-built wrappers for:
- **VolatilityTool** - pslist, netscan, malfind, cmdline
- **SleuthKitTool** - fls, icat, mmls, mactime
- **EZToolsTool** - MFTECmd, PECmd, EvtxECmd
- **PlasoTool** - log2timeline, psort

### 3. Detection Pipeline (`sift_find_evil/mcp/example_integration.py`)

End-to-end workflow:
1. Execute tools via MCP
2. Parse tool output (CSV/JSON)
3. Run self-correction engine
4. Return findings

### 4. CLI (`sift_find_evil/cli_mcp.py`)

Command-line interface for MCP-based analysis.

---

## Usage

### Basic Example

```bash
# Activate virtual environment
cd ~/sift_find_evil
source venv/bin/activate

# Run MCP analysis
python -m sift_find_evil.cli_mcp analyze-live \
  --case-id INC-2026-001 \
  --mft-file /evidence/disk.E01/C/$MFT \
  --prefetch-dir /evidence/disk.E01/C/Windows/Prefetch \
  --evtx-file /evidence/disk.E01/C/Windows/System32/winevt/Logs/Security.evtx \
  --output-dir /cases/INC-2026-001/analysis
```

### With Memory Analysis

```bash
python -m sift_find_evil.cli_mcp analyze-live \
  --case-id INC-2026-002 \
  --mft-file /evidence/$MFT \
  --memory-file /evidence/memory.raw \
  --output-dir ./analysis
```

### Custom Timeout

```bash
# Increase timeout for large evidence files
python -m sift_find_evil.cli_mcp analyze-live \
  --case-id INC-2026-003 \
  --mft-file /evidence/large-disk/$MFT \
  --timeout 600 \
  --output-dir ./analysis
```

---

## Output

### Files Generated

```
analysis/
├── MFT.csv                  # MFTECmd output
├── Prefetch.csv             # PECmd output
├── EventLog.csv             # EvtxECmd output
├── pslist.json              # Volatility pslist (if memory)
├── netscan.json             # Volatility netscan (if memory)
├── findings.json            # Detection engine findings
└── audit.jsonl              # Audit log (all tool invocations)
```

### Audit Log Format

```jsonl
{"timestamp": "2026-04-24T01:30:00.000000", "action": "tool_invocation", "examiner": "sansforensics", "details": {"tool": "mftecmd", "command": "mftecmd -f /evidence/$MFT --csv /cases/analysis", "exit_code": 0, "duration_ms": 1234, "output_hash": "5a5c4332e5167d2d", "working_dir": "/cases/INC-2026-001"}}
{"timestamp": "2026-04-24T01:30:15.000000", "action": "tool_invocation", "examiner": "sansforensics", "details": {"tool": "pecmd", "command": "pecmd -d /evidence/Prefetch --csv /cases/analysis", "exit_code": 0, "duration_ms": 567, "output_hash": "3d8f9e2b1a4c6f5e", "working_dir": "/cases/INC-2026-001"}}
```

---

## Safety Features

### 1. Read-Only Enforcement

MCP client blocks any write operations:

```python
# Blocked operations
--write, -w, --modify, --delete, -d
```

**Example blocked command:**
```
mftecmd -f /evidence/$MFT --write output.csv  # ❌ BLOCKED
```

### 2. Timeout Guards

Default timeout: 5 minutes per tool

```python
# Configurable via timeout_seconds parameter
mcp = MCPClient(timeout_seconds=600)  # 10 minutes
```

### 3. Circuit Breaker

Stops execution after 3 consecutive failures:

```python
# Automatically triggered
RuntimeError: Circuit breaker open: 3 consecutive failures
```

**Reset manually:**
```python
pipeline.mcp.reset_circuit_breaker()
```

### 4. Audit Logging

All tool invocations logged to JSONL:
- Tool name
- Full command
- Exit code
- Duration (milliseconds)
- Output hash (first 16 chars of SHA-256)
- stdout/stderr (first 1KB)

---

## Integration with Existing Workflow

### Before MCP (Fixture-Based)

```python
from sift_find_evil.parsers import MFTParser

parser = MFTParser()
entries = parser.parse_csv("pre-generated-mft.csv")
```

### After MCP (Live Analysis)

```python
from sift_find_evil.mcp import MCPDetectionPipeline

pipeline = MCPDetectionPipeline(
    case_id="INC-2026-001",
    audit_log_path=Path("/cases/audit.jsonl"),
)

# Execute MFTECmd via MCP, parse output
entries = pipeline.analyze_mft(
    mft_file=Path("/evidence/$MFT"),
    output_dir=Path("/cases/analysis"),
)
```

---

## Troubleshooting

### Tool Not Found

**Error:**
```
FileNotFoundError: [Errno 2] No such file or directory: 'mftecmd'
```

**Solution:**
```bash
# Check if tool is installed
which mftecmd

# If not found, install EZ Tools
sudo apt install dotnet-runtime-8.0
# Download and install MFTECmd from https://ericzimmerman.github.io/
```

### Timeout Errors

**Error:**
```
TimeoutError: Tool mftecmd exceeded timeout of 300s
```

**Solution:**
```bash
# Increase timeout
python -m sift_find_evil.cli_mcp analyze-live \
  --timeout 600 \
  ...
```

### Circuit Breaker Open

**Error:**
```
RuntimeError: Circuit breaker open: 3 consecutive failures
```

**Solution:**
1. Check audit log for failure details
2. Fix underlying issue (missing tool, bad path, etc.)
3. Restart pipeline (circuit breaker resets automatically on new instance)

### CSV Not Found

**Error:**
```
FileNotFoundError: MFTECmd CSV not found: /cases/analysis/MFT.csv
```

**Solution:**
- Check tool executed successfully (exit_code 0)
- Verify output directory exists and is writable
- Check stdout/stderr in audit log for tool errors

---

## Best Practices

### 1. Use Dedicated Output Directory

```bash
# Per-case output directory
mkdir -p /cases/INC-2026-001/analysis
python -m sift_find_evil.cli_mcp analyze-live \
  --output-dir /cases/INC-2026-001/analysis \
  ...
```

### 2. Review Audit Log

```bash
# View recent tool invocations
tail -f /cases/INC-2026-001/analysis/audit.jsonl

# Count tool failures
grep '"exit_code": [1-9]' audit.jsonl | wc -l
```

### 3. Incremental Analysis

```bash
# Run MFT analysis first
python -m sift_find_evil.cli_mcp analyze-live \
  --case-id INC-2026-001 \
  --mft-file /evidence/$MFT \
  --output-dir ./analysis

# Add Prefetch later
python -m sift_find_evil.cli_mcp analyze-live \
  --case-id INC-2026-001 \
  --prefetch-dir /evidence/Prefetch \
  --output-dir ./analysis
```

### 4. Test with Small Evidence First

```bash
# Test MCP integration with small files
python -m sift_find_evil.cli_mcp analyze-live \
  --case-id TEST-001 \
  --mft-file /tmp/small-mft \
  --output-dir /tmp/test-output
```

---

## Next Steps

1. **Deploy to SIFT OVA** - See [DEPLOY_TO_SIFT.md](../DEPLOY_TO_SIFT.md)
2. **Run demo** - Test MCP with synthetic evidence
3. **Analyze real evidence** - Process actual case files
4. **Review audit logs** - Verify tool invocations

---

## API Reference

### MCPClient

```python
from sift_find_evil.mcp import MCPClient

mcp = MCPClient(
    audit_logger=audit_logger,    # Optional: AuditLogger instance
    timeout_seconds=300,           # Command timeout
    max_failures=3,                # Circuit breaker threshold
)

result = mcp.execute_tool(
    tool="mftecmd",
    command=["mftecmd", "-f", "mft", "--csv", "output"],
    working_dir=Path("/cases"),
)
```

### MCPDetectionPipeline

```python
from sift_find_evil.mcp import MCPDetectionPipeline

pipeline = MCPDetectionPipeline(
    case_id="INC-2026-001",
    audit_log_path=Path("/cases/audit.jsonl"),
    timeout_seconds=300,
)

# Analyze MFT
mft_entries = pipeline.analyze_mft(
    mft_file=Path("/evidence/$MFT"),
    output_dir=Path("/cases/analysis"),
)

# Analyze Prefetch
prefetch_entries = pipeline.analyze_prefetch(
    prefetch_dir=Path("/evidence/Prefetch"),
    output_dir=Path("/cases/analysis"),
)

# Analyze Event Logs
evtx_entries = pipeline.analyze_evtx(
    evtx_file=Path("/evidence/Security.evtx"),
    output_dir=Path("/cases/analysis"),
)

# Analyze Memory
memory_results = pipeline.analyze_memory(
    memory_file=Path("/evidence/memory.raw"),
    output_dir=Path("/cases/analysis"),
)
```

---

**Last Updated:** 2026-04-24
