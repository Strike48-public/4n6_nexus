# Deploy sift_find_evil to the SIFT Workstation

Deployment steps for installing the detection engine on a SANS SIFT Workstation
(Protocol SIFT) and wiring it into Claude Code.

## Prerequisites

- A running SIFT Workstation (the forensic tool foundation: MFTECmd, PECmd,
  EvtxECmd, RECmd, Volatility 3, Sleuth Kit, tshark).
- SSH access to the host.
- Python 3.10+ (3.12 recommended — the version CI runs against).
- For the Claude Code path: the `claude` CLI installed and authenticated on the
  SIFT host (Protocol SIFT already ships this).

> **Why SIFT is required:** on real evidence, our MCP server shells out to the
> forensic binaries above. They live on the SIFT Workstation. The synthetic
> harness runs anywhere (pure Python), but real-evidence analysis needs SIFT.

## Deployment (git clone — reproducible)

### 1. Clone the repo on the SIFT host

```bash
ssh sansforensics@<sift-host>        # SIFT OVA default password: forensics

cd ~
git clone https://github.com/Strike48-public/sift_find_evil.git
cd sift_find_evil
```

### 2. Install (core, pure-Python)

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Verify it loads
python -m sift_find_evil.cli --help
```

For real disk/memory/PST evidence, also install the forensic extras (need a
compiler + system libs — see README step 3):

```bash
sudo apt-get install libtsk-dev libewf-dev libpff-dev libyara-dev
pip install -r requirements-forensic.txt
```

### 3. Validate deployment

```bash
cd ~/sift_find_evil && source venv/bin/activate

# Deterministic regression gate (no SIFT tools needed)
PYTHONPATH=. python3 tests/scenario_harness.py
# Expected: 14/14 scenarios @ F1=1.00

# Reproducible multi-agent run (standalone path)
PYTHONPATH=. python3 -m sift_find_evil.orchestration --output-dir analysis/demo_run
```

## Wire into Claude Code (the interactive / demo path)

The repo ships the dfir-* subagents (`.claude/agents/`) and a project-scope
`.mcp.json`. To register our Custom MCP server with case-specific evidence paths:

```bash
cd ~/sift_find_evil && source venv/bin/activate

./install-claude-agents.sh \
  --case-id INC-2026-001 \
  --evidence-root /cases/INC-2026-001/evidence \
  --audit-path    /cases/INC-2026-001/audit.jsonl \
  --examiner      "Jane Analyst"

claude mcp list          # confirm 'sift-find-evil' is registered
```

Then run an interactive investigation — the orchestrator subagent dispatches the
domain analysts, which reach the SIFT tools ONLY through our MCP boundary:

```bash
claude "Run a full forensic analysis on case INC-2026-001"
```

> The MCP server can also be launched directly for testing:
> `python -m sift_find_evil.mcp --evidence-root <dir> --audit-path <file>`

### Environment variables

The MCP server reads its case context from four `SFE_*` variables. CLI flags
take precedence over environment variables, which take precedence over the
built-in defaults.

| Variable | CLI flag | Default | Purpose |
|----------|----------|---------|---------|
| `SFE_CASE_ID` | `--case-id` | `INC-2026-001` | Case identifier stamped on every audit entry. |
| `SFE_EVIDENCE_ROOT` | `--evidence-root` | `.` | Directory all tool input paths must resolve inside (read-only containment). Set to the real case evidence directory. |
| `SFE_AUDIT_PATH` | `--audit-path` | `./audit.jsonl` | Append-only JSONL audit log. Set to a case-scoped path. |
| `SFE_EXAMINER` | `--examiner` | empty (no attribution) | Examiner identity recorded in the chain of custody. Empty is treated the same as unset. |

There are **two ways** these get set, for two different entry points:

1. **`install-claude-agents.sh` (recommended for real cases)** passes all four
   explicitly via `claude mcp add --env`, so it does **not** read `.mcp.json` and
   needs no shell exports. Just pass the flags shown above. Its `--examiner`
   defaults to `$USER`.

2. **The committed project-scope `.mcp.json` (zero-config dev path)** auto-loads
   when you open Claude Code in this checkout. It uses `${VAR:-default}` syntax,
   so it resolves cleanly even when nothing is exported. To point it at real
   evidence without editing the file, export the vars before launching:

   ```bash
   export SFE_EVIDENCE_ROOT=/cases/INC-2026-001/evidence
   export SFE_AUDIT_PATH=/cases/INC-2026-001/audit.jsonl
   export SFE_EXAMINER="Jane Analyst"
   ```

`.mcp.json` is committed intentionally and contains no secrets (only variable
references and a placeholder case ID). It is the zero-config integration point,
not a file to copy from an example.

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
