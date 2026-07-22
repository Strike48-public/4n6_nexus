# Agent Architecture Recommendation

## Current State Analysis

### Agents We Have
1. **network-investigator** (custom) - PCAP forensics, HTTP session analysis, attribution

### Agents We Use From System
- **general-purpose** - Complex multi-step tasks, research
- **code-reviewer** - Code quality after writing
- **planner** - Feature planning and architecture
- **tdd-guide** - Test-driven development
- **security-reviewer** - Security analysis

### Engine Capabilities (No Agent Needed)
- Disk forensics (MFT, PST, Prefetch, EventLog parsing)
- Hash correlation (file content ↔ email attachments)
- Wipe detection (GPT partition table analysis)
- Exfiltration detection (save-then-email patterns)
- Network forensics (HTTP, DNS, SMTP extraction)

## Recommendation: **Keep Agent Count Low (2-3 Specialized)**

### Why Minimal Agents is Better

**Current approach is working well:**
- ✅ Engine handles 90% of forensic analysis
- ✅ One specialized agent (network-investigator) for complex workflows
- ✅ System agents (code-reviewer, planner) for development tasks
- ✅ Clean separation: parsing in engine, orchestration in agents

**Problems with too many agents:**
- ❌ Coordination overhead (agents talking to agents)
- ❌ Duplicate logic across agents
- ❌ Harder to maintain (which agent does what?)
- ❌ Context fragmentation (lost information between agents)
- ❌ Slower development (must update multiple agents)

### Proposed Agent Structure

#### Tier 1: Core Engine (No Agents)
**For**: Deterministic parsing, hash computation, timestamp correlation
```
sift_find_evil/parsers/
├── mft_parser.py        # File system metadata
├── pst_parser.py        # Email + attachments
├── pcap_parser.py       # Network traffic
├── prefetch_parser.py   # Execution traces
└── evtx_parser.py       # Event logs

sift_find_evil/detectors/
├── exfil_detector.py    # Save-then-email patterns
├── wipe_detector.py     # Partition anomalies
└── ... (future)
```

**When to use**: 
- Parsing structured artifacts (CSV, PCAP, PST, E01)
- Hash computation, timestamp math
- Pattern matching (temporal correlation, hash correlation)
- CLI-driven analysis

#### Tier 2: Specialized Investigator Agents (1-3 total)
**For**: Complex multi-step investigations requiring human-like reasoning

**Current**:
1. **network-investigator** - PCAP workflow, attribution, session analysis

**Candidates to Add** (only if needed):
2. **memory-investigator** - Volatility workflows, process correlation, malware hunting
3. **timeline-investigator** - Super-timeline generation, cross-artifact correlation

**When to use**:
- Multi-step workflows (parse → filter → correlate → attribute)
- Contextual decision-making (is this behavior suspicious?)
- Evidence chain building (IP → session → username → identity)
- Report generation for legal proceedings

#### Tier 3: Development Agents (Use System Agents)
**Use existing**:
- **planner** - Feature design, architecture decisions
- **code-reviewer** - Code quality checks
- **tdd-guide** - Test-first development
- **security-reviewer** - Vulnerability scanning

**Don't create custom development agents** - system ones are sufficient

## Specific Recommendations for Your Work

### For CIRCL Wiped Disk Case
**No new agent needed** ✅

The engine already handles this:
```bash
python -m sift_find_evil.cli analyze --image wiped_disk.E01
```

Output:
- Finding: Partition table wiped (CRITICAL, 0.95 confidence)
- Evidence: Primary GPT zeroed, secondary GPT intact
- 2 partitions recovered from secondary GPT

**Next steps** (no agents required):
1. Mount partitions from secondary GPT offsets
2. Run file carving (photorec, bulk_extractor) - SIFT tools
3. Parse carved files with existing parsers
4. Generate timeline from recovered artifacts

### For M57 Other Characters (Pat, Terry, Charlie, Jo)
**No new agent needed** ✅

Use existing engine:
```bash
python -m sift_find_evil.cli analyze \
  --mft <path> --prefetch <path> --evtx <path> \
  --pst <path> --image <path>
```

Same detectors work across all characters:
- Exfiltration detection (hash correlation)
- Temporal anomalies
- Missing artifacts
- Wipe detection

### When You WOULD Need a New Agent

**Only create new specialized agent if**:
1. The workflow requires 5+ sequential decision points
2. The reasoning cannot be encoded in detector logic
3. The investigation requires domain expertise (e.g., malware reverse engineering)
4. The output format is complex (legal briefs, incident response playbooks)

**Examples of workflows that DON'T need agents**:
- File carving → just run `photorec` or `bulk_extractor`
- Timeline generation → just run `log2timeline` + `psort`
- Registry analysis → just run `RegRipper`
- Memory analysis → write specific Volatility plugins, not a full agent

**Examples of workflows that DO need agents**:
- Network harassment investigation (what we built for Nitroba)
- APT campaign attribution (requires multi-artifact reasoning)
- Insider threat profiling (behavioral analysis across time)
- Legal evidence packaging (requires evidence chain construction)

## Concrete Plan for Next 3 Cases

### 1. CIRCL Wiped Disk
**Agent**: None
**Approach**: 
- Engine detects wipe (✓ done)
- Manual file carving with SIFT tools (photorec/bulk_extractor)
- Engine parses carved artifacts
- Generate report

### 2. M57 Other Characters
**Agent**: None
**Approach**:
- Same CLI command as Jean
- Same detectors (exfil, timestamps, artifacts)
- Compare findings across characters

### 3. Future: Memory Forensics (if needed)
**Agent**: memory-investigator (only if complexity warrants)
**Approach**:
- Agent orchestrates Volatility 3 workflows
- Correlates processes with disk/network artifacts
- Builds attack timeline

## Decision Framework

Before creating a new agent, ask:

1. **Can the engine handle it?** 
   - If yes → use engine (parser + detector)
   
2. **Can a SIFT tool handle it?**
   - If yes → call tool via subprocess, parse output
   
3. **Can existing agent handle it?**
   - If yes → use general-purpose or network-investigator
   
4. **Does it require 5+ decision steps with human-like reasoning?**
   - If no → add to engine
   - If yes → consider new specialized agent

## Summary

**Current agent count: JUST RIGHT (1 specialized + system agents)**

**Recommendation for CIRCL case: NO NEW AGENT NEEDED**
- Engine already detects the wipe
- Use SIFT tools directly for carving
- Engine parses carved artifacts

**Long-term agent target: 2-3 specialized agents maximum**
1. network-investigator (✓ exists)
2. memory-investigator (only if doing heavy Volatility work)
3. timeline-investigator (only if super-timeline correlation gets complex)

**Key principle**: Agents for reasoning, engine for parsing.

---

**Next action for CIRCL**: Test wipe detector (✓ done), then carve files and analyze.
