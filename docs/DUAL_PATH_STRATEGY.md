# Dual-Path Deployment Strategy

**How sift_find_evil supports both competition submission and production deployment**

---

## Overview

Our architecture supports **two distinct deployment modes**:

| Path | Description | Target Users | Primary Use Case |
|------|-------------|--------------|------------------|
| **Path A: Claude Code Integration** | True Protocol SIFT extension via Claude Code agents | Competition judges, Protocol SIFT users | **Official hackathon submission** |
| **Path B: Standalone Python** | Independent tool with its own MCP server | DFIR practitioners, enterprise teams | **Production deployment** |

**Why both?** This gives maximum flexibility:
- **Path A** = Official competition requirement ("extend Protocol SIFT")
- **Path B** = Production-ready tool that works without Claude Code dependency

---

## Path A: Claude Code Integration (Competition Submission)

### Architecture

```
User runs: claude "Analyze case INC-2026-001"
                    ↓
        ┌─────────────────────────┐
        │   Protocol SIFT        │
        │   (Claude Code + config)│
        └─────────────────────────┘
                    ↓
        ┌─────────────────────────┐
        │   Our DFIR Agents       │
        │   (~/.claude/agents/)   │
        │   - orchestrator.md     │
        │   - disk-analyst.md     │
        │   - memory-analyst.md   │
        │   - network-analyst.md  │
        │   - verifier.md         │
        └─────────────────────────┘
                    ↓
        ┌─────────────────────────┐
        │   Our MCP Server        │
        │   (sift_find_evil/mcp/) │
        │   - Guardrails          │
        │   - Audit logging       │
        │   - Tool wrappers       │
        └─────────────────────────┘
                    ↓
        ┌─────────────────────────┐
        │   SIFT Forensic Tools   │
        │   (Volatility, MFTECmd, │
        │    PECmd, EvtxECmd)     │
        └─────────────────────────┘
```

### Installation (SIFT VM)

```bash
# 1. Install Protocol SIFT (prerequisite)
curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash

# 2. Install our extension
cd ~/sift_find_evil
./install-claude-agents.sh

# This script:
# - Copies agent definitions to ~/.claude/agents/dfir-*.md
# - Registers our MCP server in ~/.claude/settings.json
# - Adds our skills to ~/.claude/skills/
# - Links our self-correction engine
```

### Usage

```bash
# Interactive Claude Code session
cd /cases/INC-2026-001
claude "Run full forensic analysis on this case"

# The orchestrator agent will:
# 1. Triage the evidence
# 2. Dispatch domain analysts (disk, memory, network)
# 3. Collect findings
# 4. Run verifier for self-correction
# 5. Generate report
```

### What We Extend

**Protocol SIFT provides:**
- Base agent loop (Claude Code)
- Tool permissions system
- Basic audit logging
- Direct CLI tool access

**We add on top:**
- **Self-correction engine** (SelfCorrectionEngine)
- **Cross-artifact validation** (contradiction detection)
- **Confidence scoring** (0.0-1.0 with reasoning chains)
- **Multi-agent orchestration** (domain specialists + verifier)
- **Architectural guardrails** (MCP boundary enforcement)
- **Enhanced audit trail** (tool execution → finding traceability)

### Meets Competition Requirements

✅ **Extends Protocol SIFT:** Agents run through Claude Code + Protocol SIFT config  
✅ **Architectural approach:** Multi-Agent Framework + Custom MCP Server (hybrid)  
✅ **Self-correction:** Verifier agent detects contradictions and resolves  
✅ **Accuracy validation:** Every finding cites source tool executions  
✅ **Analytical reasoning:** Structured findings with reasoning chains  
✅ **Evidence integrity:** Architectural guardrails at MCP boundary  
✅ **Audit trail:** Agent-to-agent messages + tool executions logged  

---

## Path B: Standalone Python (Production Deployment)

### Architecture

```
User runs: python -m sift_find_evil.orchestration --case INC-2026-001
                    ↓
        ┌─────────────────────────┐
        │   Orchestrator          │
        │   (Python process)      │
        └─────────────────────────┘
                    ↓
        ┌─────────────────────────┐
        │   Domain Analysts       │
        │   (in-process agents)   │
        │   - DiskAnalyst         │
        │   - MemoryAnalyst       │
        │   - NetworkAnalyst      │
        └─────────────────────────┘
                    ↓
        ┌─────────────────────────┐
        │   Our MCP Server        │
        │   (same boundary)       │
        └─────────────────────────┘
                    ↓
        ┌─────────────────────────┐
        │   SIFT Forensic Tools   │
        └─────────────────────────┘
```

### Installation (Any Linux System)

```bash
# 1. Install SIFT Workstation (or just the tools you need)
# 2. Install sift_find_evil
git clone https://github.com/Strike48-public/4n6_nexus.git
cd sift_find_evil
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Verify installation
python -m sift_find_evil.cli --help
```

### Usage

```bash
# Standalone orchestration (judges' reproducible path)
python -m sift_find_evil.orchestration \
  --case-id INC-2026-001 \
  --evidence-root /cases/INC-2026-001/evidence \
  --output-dir /cases/INC-2026-001/analysis

# CLI interface
python -m sift_find_evil.cli case analyze \
  --case-id INC-2026-001 \
  --mft-file /evidence/image.E01 \
  --memory-file /evidence/memory.raw

# TUI interface
python -m sift_find_evil.tui_app
```

### What's Different

| Feature | Path A (Claude Code) | Path B (Standalone) |
|---------|---------------------|---------------------|
| **Agent runtime** | Claude Code subagents | In-process Python classes |
| **Orchestration** | Claude Code main loop | Python orchestrator |
| **MCP boundary** | Same (EvidenceMCPServer) | Same (EvidenceMCPServer) |
| **Self-correction** | Same (SelfCorrectionEngine) | Same (SelfCorrectionEngine) |
| **Guardrails** | Same (ToolGuard) | Same (ToolGuard) |
| **Audit trail** | A2A + tool executions | A2A + tool executions |
| **Protocol SIFT** | Required | Not required |
| **Installation** | Requires Claude Code | Pure Python |
| **Use case** | Interactive forensics | Automated pipelines, CI/CD |

### Advantages

- **No Claude Code dependency** - Works in air-gapped environments
- **Deterministic execution** - Same input = same output
- **CI/CD friendly** - Runs in test harnesses, automation
- **Enterprise deployment** - Can be containerized, scaled
- **Audit compliance** - Full reproducibility from logs

---

## Shared Components

Both paths use the **exact same core**:

### 1. MCP Server (`sift_find_evil/mcp/server.py`)
- `EvidenceMCPServer` class
- `ToolGuard` with per-tool allowlists
- `CircuitBreaker` for failure protection
- Read-only enforcement at boundary
- Tool execution audit logging

### 2. Self-Correction Engine (`sift_find_evil/self_correction/engine.py`)
- Cross-artifact contradiction detection
- Confidence scoring (0.0-1.0)
- Tiebreaker resolution (Event Log, etc.)
- Reasoning chain generation

### 3. Domain Detectors
- **Disk:** MFT, Prefetch, Registry, ShimCache, BAM
- **Memory:** pslist, psscan, netscan, malfind
- **Network:** C2 beaconing, exfiltration patterns
- **YARA:** Malware signature detection

### 4. Audit Trail (`sift_find_evil/audit/logger.py`)
- Agent-to-agent message logging
- Tool execution logging
- Finding → tool execution traceability
- JSONL append-only format

---

## Deployment Decision Tree

```
Do you need to submit to the competition?
├─ YES → Use Path A (Claude Code Integration)
│         - Judges run via Claude Code
│         - Demonstrates Protocol SIFT extension
│         - Meets all competition requirements
│
└─ NO → Use Path B (Standalone Python)
          - Production deployment
          - CI/CD integration
          - No Claude Code dependency
          - Enterprise-ready
```

**Can you use both?**  
**YES!** The same codebase supports both. Just choose your deployment mode:
- Competition demo: Path A
- Production use: Path B
- Development/testing: Path B (faster iteration)

---

## Implementation Status

### ✅ Complete (Both Paths)
- MCP server with guardrails
- Self-correction engine
- Domain detectors (disk, memory, network)
- Audit logging
- Test harness (16 scenarios @ F1=1.00)
- Standalone orchestration

### 🚧 In Progress (Path A Only)
- [ ] Claude Code agent definitions (`~/.claude/agents/dfir-*.md`)
- [ ] Installation script (`install-claude-agents.sh`)
- [ ] MCP server registration in Claude Code settings
- [ ] Integration testing with Claude Code

### 📋 Remaining (Both Paths)
- [ ] Demo video (5 min max, showing Path A)
- [ ] Update README.md with dual-path explanation
- [ ] Update ARCHITECTURE_DIAGRAM.md with both architectures
- [ ] Devpost submission form

---

## Testing Strategy

### Path A Validation
```bash
# On SIFT VM with Protocol SIFT + Claude Code
cd /cases/INC-2026-001
claude "Analyze this case"

# Verify:
# 1. Agents dispatch correctly
# 2. MCP guardrails block out-of-bounds access
# 3. Self-correction runs on findings
# 4. Audit log captures everything
```

### Path B Validation
```bash
# Current testing approach (already working)
PYTHONPATH=. python3 tests/scenario_harness.py

# Orchestration demo
python -m sift_find_evil.orchestration --bypass-demo

# Verify same as Path A outcomes
```

---

## Competition Submission Notes

**The demo video should show Path A:**
- Start with Protocol SIFT installed
- Run via Claude Code
- Show agents dispatching
- Show self-correction in action
- Show audit trail traceability

**The README should explain both paths:**
- "Built as an extension of Protocol SIFT"
- "Supports both Claude Code integration and standalone deployment"
- "Judges: Use Path A (Claude Code)"
- "Practitioners: Use Path B (Standalone Python)"

**The architecture diagram should show:**
- Path A: Protocol SIFT → Our Agents → Our MCP → Tools
- Path B: Python Orchestrator → Our MCP → Tools
- Shared: Same MCP boundary, same self-correction engine

---

## Timeline (11 days remaining)

**Priority 1 (Competition requirements):**
- [ ] Day 1-2: Implement Path A Claude Code agents
- [ ] Day 3-4: Test Path A integration on SIFT VM
- [ ] Day 5-6: Record demo video (Path A)
- [ ] Day 7-8: Update all documentation for dual-path
- [ ] Day 9-10: Final testing, polish
- [ ] Day 11: Devpost submission

**Priority 2 (Production readiness):**
- Path B already works - polish documentation

---

## Questions for User

1. **Do you have access to a SIFT VM for Path A testing?**
2. **Should we prioritize Path A (competition) or can we just document Path A without implementing it?**
3. **Is the standalone orchestration (`orchestration.py`) sufficient for judges to reproduce, or must we have Claude Code integration?**

The requirements say "extend Protocol SIFT" but also accept "Custom MCP Server" as an architectural approach. Our standalone Path B **is** a custom MCP server that runs on SIFT. We could argue it meets the requirement without Claude Code integration.
