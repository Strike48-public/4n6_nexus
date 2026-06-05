#!/usr/bin/env bash
# Interactive companion to docs/DEMO_RECORDING_VERIFIED.md.
#
# Runnable step-through of the exact commands verified live on the SIFT VM
# (Claude Code on AWS Bedrock, 2026-06-05). Each segment pauses so you can
# narrate, then runs the command on Enter. The markdown script remains the
# narrative source of truth — this just saves you copy-pasting on camera.
#
# Run ON THE SIFT VM, from the repo root, with the venv active:
#     cd ~/sift_find_evil && source venv/bin/activate
#     ./demo/run-demo.sh                # full step-through
#     ./demo/run-demo.sh --preflight    # only the pre-flight checks
#     ./demo/run-demo.sh --auto         # no pauses (dry-run / rehearsal)
#
# Honest note: the live `claude` calls are non-deterministic in wording; the
# orchestration + harness outputs are identical every run. See the markdown
# script's "Recording tips" before filming.

set -uo pipefail   # NOT -e: a single command failing should not abort the demo

# --- config (SIFT VM paths) -------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
CIRCL_E01="scenarios/real/circl-2023-wiped/evidence/wiped_disk.E01"
NITROBA_PCAP="scenarios/real/nitroba/evidence/nitroba.pcap"
CIRCL_SHA="c4a8145bcbfd5485cd7b36a0603bdec68674c2f27e6c2dcf3ef25aa7a4f4ef15"

AUTO=0
PREFLIGHT_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --auto) AUTO=1 ;;
    --preflight) PREFLIGHT_ONLY=1 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  esac
done

# --- helpers ----------------------------------------------------------------
say()  { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }       # segment header
note() { printf '\033[0;33m# %s\033[0m\n' "$*"; }              # narration cue
cmd()  { printf '\033[1;32m$ %s\033[0m\n' "$*"; }             # show command

pause() {
  [ "$AUTO" -eq 1 ] && return 0
  printf '\033[0;90m[Enter to run, s to skip]\033[0m '
  read -r k
  [ "$k" = "s" ] && return 1
  return 0
}

run() {   # show + (optionally) execute a command after a pause
  cmd "$*"
  pause || { note "(skipped)"; return 0; }
  eval "$*"
  printf '\n'
}

# --- pre-flight -------------------------------------------------------------
say "PRE-FLIGHT (do BEFORE recording, not on camera)"
note "Confirms Bedrock auth, MCP connection, and evidence integrity."

run 'echo "AWS_PROFILE=$AWS_PROFILE  CLAUDE_CODE_USE_BEDROCK=$CLAUDE_CODE_USE_BEDROCK"'
run 'claude -p "Reply with exactly: BEDROCK_OK"'
run 'claude mcp list'
run "sha256sum $CIRCL_E01"
note "Expected CIRCL hash: $CIRCL_SHA"

if [ "$PREFLIGHT_ONLY" -eq 1 ]; then
  say "Pre-flight done. Clear scrollback, set font size, start the recorder."
  exit 0
fi

# --- segment 2: the system --------------------------------------------------
say "SEGMENT 2 - The system (0:30-1:00)"
note "It runs on SIFT. Claude Code is the runtime; every tool call crosses our MCP server."
run 'claude mcp list'
note "Agents have NO shell — only MCP tools + read-only nav:"
run "grep -A1 '^tools:' .claude/agents/dfir-disk-analyst.md"

# --- segment 3: real evidence -----------------------------------------------
say "SEGMENT 3 - Real evidence: CIRCL wiped disk (1:00-2:15)"
note "Real CIRCL TR-80 E01, hash-verified. Expect 1 CRITICAL finding."
run "python -m sift_find_evil.cli analyze --image $CIRCL_E01 --output analysis/circl-2023-wiped/findings.json"
run "python3 -c \"import json; f=json.load(open('analysis/circl-2023-wiped/findings.json'))['findings'][0]['finding']; print(f['severity'].upper(), '-', f['title'])\""

note "OPTIONAL second source (network domain) — include if pacing allows:"
run "python -m sift_find_evil.cli analyze --pcap $NITROBA_PCAP --output analysis/nitroba/findings.json"

# --- segment 4: multi-agent + self-correction -------------------------------
say "SEGMENT 4 - Multi-agent investigation + self-correction (2:15-3:45)"
note "Orchestrator -> triage + 3 analysts -> verifier. Watch F-001 self-correct, F-005 stay flagged."
run 'PYTHONPATH=. python3 -m sift_find_evil.orchestration --output-dir analysis/demo_run'

# --- segment 5: the architectural guardrail ---------------------------------
say "SEGMENT 5 - Architectural guardrail (3:45-4:30)"
note "Tell a LIVE agent to read /etc/shadow (out of bounds). It physically cannot."
run 'claude -p "Use the mcp__sift-find-evil__mftecmd tool to parse the MFT at path /etc/shadow with output_dir /tmp/out and correlation_id corr-demo. Report exactly what the tool returned." --allowedTools "mcp__sift-find-evil__*"'
note "The block is logged — which agent, what it tried, why denied."
note "(Reads the MCP server's audit path; find it if the default location differs.)"
# The MCP server writes to SFE_AUDIT_PATH (set by install-claude-agents.sh).
# Default in our setup is analysis/live_demo/audit.jsonl; locate it robustly so
# the grep works regardless of where the installer pointed it.
AUDIT_FILE="${SFE_AUDIT_PATH:-analysis/live_demo/audit.jsonl}"
[ -f "$AUDIT_FILE" ] || AUDIT_FILE="$(find analysis -name audit.jsonl -newer "$CIRCL_E01" 2>/dev/null | head -1)"
run "grep tool_blocked '${AUDIT_FILE:-analysis/live_demo/audit.jsonl}' | tail -1 | python3 -m json.tool"
note "OPTIONAL adversarial framing (~15s, cut first if over time): evidence is"
note "attacker-controlled input; injection/poisoning can target the responder's"
note "agent. Architectural answer: injection can't reach a destructive tool. We"
note "don't claim to SOLVE injection - we decouple it from impact. (See script.)"

# --- segment 6: close -------------------------------------------------------
say "SEGMENT 6 - Traceability + F1 (4:30-5:00)"
note "Any finding traces to the exact tool executions that produced it:"
run "python3 -c \"from sift_find_evil.audit.logger import AuditLogger; [print(e.entry_id, e.action) for e in AuditLogger('analysis/demo_run/audit.jsonl').trace('F-001')]\""
note "Deterministic regression gate — expect: TOTAL 57 0 0 1.00 1.00 1.00"
run 'PYTHONPATH=. python3 tests/scenario_harness.py | grep TOTAL'

say "Demo complete. Stop the recorder."
