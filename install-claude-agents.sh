#!/usr/bin/env bash
# Install the SIFT Find Evil Claude Code integration on a SIFT Workstation.
#
# Registers our Custom MCP server with Claude Code and verifies the dfir-*
# subagents are discoverable, so a `claude` session in this repo can drive the
# forensic tools through our architectural boundary.
#
# Run from the repo root on the SIFT host (after git clone + pip install):
#     ./install-claude-agents.sh \
#         --evidence-root /cases/INC-2026-001/evidence \
#         --audit-path    /cases/INC-2026-001/audit.jsonl \
#         --case-id       INC-2026-001 \
#         --examiner      "Jane Analyst"
#
# Idempotent: re-running re-points the MCP server registration.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Defaults (overridable by flags). Evidence root must be a real directory the
# MCP guardrail will confine tool reads to.
CASE_ID="INC-2026-001"
EVIDENCE_ROOT=""
AUDIT_PATH=""
EXAMINER="${USER:-examiner}"
# Default to 'local' so the committed project-scope .mcp.json (the zero-config
# clone default) is not clobbered. This writes a case-specific registration
# (with the real evidence-root/audit-path env) for the current repo checkout.
SCOPE="local" # local (this checkout) | user (global) | project (overwrites .mcp.json)

usage() {
  cat <<'USAGE'
Usage: ./install-claude-agents.sh [options]

  --case-id ID          Case identifier (default: INC-2026-001)
  --evidence-root DIR   Directory tool reads are confined to (required)
  --audit-path FILE     Append-only JSONL audit log (default: <evidence-root>/../audit.jsonl)
  --examiner NAME       Examiner identity in the audit trail (default: $USER)
  --scope local|user|project  Where to register the MCP server. Default: local
                              (local=this checkout; user=global; project=overwrite .mcp.json)
  -h, --help            Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --case-id) CASE_ID="$2"; shift 2 ;;
    --evidence-root) EVIDENCE_ROOT="$2"; shift 2 ;;
    --audit-path) AUDIT_PATH="$2"; shift 2 ;;
    --examiner) EXAMINER="$2"; shift 2 ;;
    --scope) SCOPE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

echo "========================================="
echo "SIFT Find Evil - Claude Code integration"
echo "========================================="

# 1. Prerequisites.
if ! command -v claude >/dev/null 2>&1; then
  echo "ERROR: 'claude' (Claude Code CLI) not found on PATH." >&2
  echo "Install Claude Code on the SIFT host first, then re-run." >&2
  exit 1
fi

if ! python -c "import sift_find_evil" >/dev/null 2>&1; then
  echo "ERROR: the sift_find_evil package is not importable." >&2
  echo "Run from the repo root with deps installed: pip install -r requirements.txt" >&2
  exit 1
fi

if [[ -z "$EVIDENCE_ROOT" ]]; then
  echo "ERROR: --evidence-root is required (the dir tool reads are confined to)." >&2
  usage
  exit 1
fi
if [[ ! -d "$EVIDENCE_ROOT" ]]; then
  echo "ERROR: evidence root '$EVIDENCE_ROOT' is not a directory." >&2
  exit 1
fi
EVIDENCE_ROOT="$(cd "$EVIDENCE_ROOT" && pwd)" # canonicalize
if [[ -z "$AUDIT_PATH" ]]; then
  AUDIT_PATH="$(dirname "$EVIDENCE_ROOT")/audit.jsonl"
fi

echo "[1/3] Prerequisites OK (claude CLI + sift_find_evil importable)."
echo "      case-id:       $CASE_ID"
echo "      evidence-root: $EVIDENCE_ROOT"
echo "      audit-path:    $AUDIT_PATH"
echo "      examiner:      $EXAMINER"

# 2. Verify the dfir-* subagents are present (they ship in the repo, project-local).
AGENT_DIR="$REPO_ROOT/.claude/agents"
EXPECTED_AGENTS=(dfir-orchestrator dfir-triage dfir-disk-analyst dfir-memory-analyst dfir-network-analyst dfir-verifier)
missing=0
for a in "${EXPECTED_AGENTS[@]}"; do
  if [[ ! -f "$AGENT_DIR/$a.md" ]]; then
    echo "  WARNING: missing agent definition $a.md" >&2
    missing=1
  fi
done
if [[ "$missing" -eq 0 ]]; then
  echo "[2/3] All 6 dfir-* subagents present in .claude/agents/."
else
  echo "[2/3] Some agent definitions missing (see warnings above)." >&2
fi

# 3. Register the MCP server with Claude Code.
# `claude mcp add` writes the registration; we pass the case context via env so
# the same command works for any case by changing the flags.
echo "[3/3] Registering MCP server 'sift-find-evil' (scope: $SCOPE)..."
claude mcp remove sift-find-evil --scope "$SCOPE" >/dev/null 2>&1 || true
claude mcp add sift-find-evil \
  --scope "$SCOPE" \
  --env "SFE_CASE_ID=$CASE_ID" \
  --env "SFE_EVIDENCE_ROOT=$EVIDENCE_ROOT" \
  --env "SFE_AUDIT_PATH=$AUDIT_PATH" \
  --env "SFE_EXAMINER=$EXAMINER" \
  -- python -m sift_find_evil.mcp

echo ""
echo "Done. Verify with:  claude mcp list"
echo "Then, from this repo on the SIFT host:"
echo "    claude \"Run a full forensic analysis on case $CASE_ID\""
