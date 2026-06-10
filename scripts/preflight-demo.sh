#!/usr/bin/env bash
# Pre-flight readiness gate for the FIND EVIL! demo recording.
#
# Run this ON THE SIFT VM, from the repo root, AFTER deploying current `main`
# and running `aws sso login --profile bedrock`. It verifies every claim the
# recording script (docs/DEMO_RECORDING_VERIFIED.md) makes, so you never get
# on camera with a stale tree or an expired SSO session.
#
# It is READ-ONLY: it runs analyses into /tmp and never modifies evidence.
#
# Usage:
#   export AWS_PROFILE=bedrock CLAUDE_CODE_USE_BEDROCK=1
#   export PATH="$HOME/.local/bin:$PATH"
#   ./scripts/preflight-demo.sh
#
# Exit code 0 = every check passed (GO). Non-zero = at least one FAIL (NO-GO).

set -uo pipefail   # NOT -e: we want to run every check and report them all.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Expected values — must match docs/DEMO_RECORDING_VERIFIED.md exactly.
readonly EXPECT_HARNESS_TOTAL="62"
readonly EXPECT_HARNESS_SCENARIOS="15"
readonly EXPECT_CIRCL_SHA="c4a8145bcbfd5485cd7b36a0603bdec68674c2f27e6c2dcf3ef25aa7a4f4ef15"
readonly EXPECT_NITROBA_SHA="2b77a9eaefc1d6af163d"   # prefix match (full hash in script table)
readonly CIRCL_E01="scenarios/real/circl-2023-wiped/evidence/wiped_disk.E01"
readonly NITROBA_PCAP="scenarios/real/nitroba/evidence/nitroba.pcap"

# Colors (plain if not a tty).
if [[ -t 1 ]]; then
  GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
else
  GREEN=''; RED=''; YELLOW=''; BOLD=''; NC=''
fi

PASS_COUNT=0
FAIL_COUNT=0

pass() { echo -e "  ${GREEN}PASS${NC}  $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo -e "  ${RED}FAIL${NC}  $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
info() { echo -e "  ${YELLOW}....${NC}  $1"; }

section() {
  echo ""
  echo -e "${BOLD}== $1 ==${NC}"
}

# Pick the venv interpreter if present.
PY="python3"
[[ -x "$REPO_ROOT/venv/bin/python" ]] && PY="$REPO_ROOT/venv/bin/python"

echo -e "${BOLD}FIND EVIL! demo pre-flight — $(date -u '+%Y-%m-%dT%H:%M:%SZ')${NC}"
echo "Repo: $REPO_ROOT   Interpreter: $PY"

# --- 1. Evidence present + hash-verified (Segment 3) ----------------------
section "Evidence integrity (Segment 3)"
if [[ -f "$CIRCL_E01" ]]; then
  got="$(sha256sum "$CIRCL_E01" | cut -d' ' -f1)"
  if [[ "$got" == "$EXPECT_CIRCL_SHA" ]]; then
    pass "CIRCL wiped_disk.E01 hash matches pinned value"
  else
    fail "CIRCL E01 hash mismatch (got ${got:0:20}..., want ${EXPECT_CIRCL_SHA:0:20}...)"
  fi
else
  fail "CIRCL E01 missing: $CIRCL_E01"
fi

if [[ -f "$NITROBA_PCAP" ]]; then
  got="$(sha256sum "$NITROBA_PCAP" | cut -c1-20)"
  if [[ "$got" == "$EXPECT_NITROBA_SHA" ]]; then
    pass "nitroba.pcap hash matches pinned value"
  else
    fail "nitroba PCAP hash mismatch (got $got, want $EXPECT_NITROBA_SHA)"
  fi
else
  fail "nitroba PCAP missing: $NITROBA_PCAP"
fi

# --- 2. Real-evidence analyses produce the narrated findings (Segment 3) --
section "Real-evidence analyses (Segment 3)"
if "$PY" -m sift_find_evil.cli analyze --image "$CIRCL_E01" \
     --output /tmp/preflight_circl.json >/dev/null 2>&1; then
  verdict="$("$PY" - <<'PYEOF'
import json
f = json.load(open("/tmp/preflight_circl.json"))["findings"][0]["finding"]
ok = f["severity"] == "critical" and abs(f.get("confidence", 0) - 0.95) < 1e-6 \
     and "wiped" in f["title"].lower()
print("OK" if ok else f"BAD sev={f['severity']} conf={f.get('confidence')} title={f['title']}")
PYEOF
)"
  [[ "$verdict" == "OK" ]] && pass "CIRCL -> CRITICAL wiped-GPT, confidence 0.95" \
                           || fail "CIRCL finding unexpected: $verdict"
else
  fail "CIRCL analyze exited non-zero"
fi

if "$PY" -m sift_find_evil.cli analyze --pcap "$NITROBA_PCAP" \
     --output /tmp/preflight_nitroba.json >/dev/null 2>&1; then
  verdict="$("$PY" - <<'PYEOF'
import json
f = json.load(open("/tmp/preflight_nitroba.json"))["findings"][0]["finding"]
e = f["evidence"]
ok = f["severity"] == "high" and abs(f.get("confidence", 0) - 0.7) < 1e-6 \
     and e.get("event_count") == 7 and e.get("coefficient_of_variation", 1) < 0.15
print("OK" if ok else f"BAD sev={f['severity']} conf={f.get('confidence')} "
      f"cov={e.get('coefficient_of_variation')} events={e.get('event_count')}")
PYEOF
)"
  [[ "$verdict" == "OK" ]] && pass "nitroba -> HIGH beaconing, confidence 0.7, CoV<0.15, 7 events" \
                           || fail "nitroba finding unexpected: $verdict"
else
  fail "nitroba analyze exited non-zero"
fi

# --- 3. Multi-agent self-correction is deterministic (Segment 4) ----------
section "Multi-agent self-correction (Segment 4)"
if PYTHONPATH=. "$PY" -m sift_find_evil.orchestration \
     --output-dir /tmp/preflight_orch >/tmp/preflight_orch.txt 2>&1; then
  if grep -q "6 findings" /tmp/preflight_orch.txt \
     && grep -q "F-005" /tmp/preflight_orch.txt \
     && grep "F-005" /tmp/preflight_orch.txt | grep -q "0.45"; then
    pass "orchestration -> 6 findings, F-005 held at 0.45 (self-correction proven)"
  else
    fail "orchestration output drifted (see /tmp/preflight_orch.txt)"
  fi
else
  fail "orchestration exited non-zero (see /tmp/preflight_orch.txt)"
fi

# --- 4. Scenario harness matches the script's numbers (Segment 6) ---------
section "Deterministic regression gate (Segment 6)"
harness_out="$(PYTHONPATH=. "$PY" tests/scenario_harness.py 2>/dev/null)"
total_line="$(echo "$harness_out" | grep TOTAL || true)"
scenario_rows="$(echo "$harness_out" | grep -cE '^[0-9]{2}_' || true)"
if echo "$total_line" | grep -qE "TOTAL +${EXPECT_HARNESS_TOTAL} +0 +0 +1\.00 +1\.00 +1\.00"; then
  pass "harness TOTAL = ${EXPECT_HARNESS_TOTAL}, F1=1.00, 0 FP / 0 FN"
else
  fail "harness TOTAL drifted from script (expected ${EXPECT_HARNESS_TOTAL}/F1=1.00): ${total_line:-<no TOTAL line>}"
fi
if [[ "$scenario_rows" == "$EXPECT_HARNESS_SCENARIOS" ]]; then
  pass "harness ran ${EXPECT_HARNESS_SCENARIOS} synthetic scenarios (matches script)"
else
  fail "harness scenario count drifted (expected ${EXPECT_HARNESS_SCENARIOS}, got ${scenario_rows})"
fi

# --- 5. Architectural constraint: agents have no shell (Segment 2/5) ------
section "Architectural constraint (Segment 2/5)"
disk_agent=".claude/agents/dfir-disk-analyst.md"
if [[ -f "$disk_agent" ]]; then
  tools_line="$(grep -m1 '^tools:' "$disk_agent" || true)"
  if echo "$tools_line" | grep -q 'mcp__sift-find-evil__' && ! echo "$tools_line" | grep -qi 'bash'; then
    pass "dfir-disk-analyst: MCP tools only, no Bash (architectural no-shell)"
  else
    fail "dfir-disk-analyst tools line unexpected: $tools_line"
  fi
else
  fail "agent definition missing: $disk_agent"
fi
agent_count="$(ls .claude/agents/dfir-*.md 2>/dev/null | wc -l | tr -d ' ')"
[[ "$agent_count" == "6" ]] && pass "all 6 dfir-* agents present" \
                            || fail "expected 6 dfir-* agents, found $agent_count"

# --- 6. Live Bedrock + MCP (VM-only beats: Segment 2/5) -------------------
section "Live agent runtime (Segment 2/5 — VM only)"
if command -v claude >/dev/null 2>&1; then
  bedrock="$(claude -p "Reply with exactly: BEDROCK_OK" 2>/dev/null | tr -d '[:space:]')"
  if [[ "$bedrock" == "BEDROCK_OK" ]]; then
    pass "claude reaches Bedrock (BEDROCK_OK)"
  else
    fail "claude did not return BEDROCK_OK — run: aws sso login --profile bedrock (got: '${bedrock:0:40}')"
  fi
  mcp_line="$(claude mcp list 2>/dev/null | grep -i 'sift-find-evil' || true)"
  if [[ -z "$mcp_line" ]]; then
    fail "MCP server sift-find-evil not registered — run install-claude-agents.sh with case flags"
  elif echo "$mcp_line" | grep -qi 'connected'; then
    pass "MCP server sift-find-evil: Connected"
  elif echo "$mcp_line" | grep -qi 'pending approval'; then
    # Project-scoped (.mcp.json) servers sit here until approved once in an
    # interactive `claude` session. The canonical SIFT path (install-claude-
    # agents.sh -> `claude mcp add`) registers user-scoped + pre-approved, so
    # on a correctly-set-up VM this is "Connected", not "Pending".
    fail "MCP server sift-find-evil is Pending approval — register via install-claude-agents.sh (or approve once in an interactive 'claude' session)"
  else
    fail "MCP server sift-find-evil registered but not connected: ${mcp_line#*: }"
  fi
else
  info "claude CLI not on PATH — VM-only beats (Segments 2 & 5) cannot be verified here"
  info "this is expected if you are NOT on the SIFT VM; those segments record on the VM only"
fi

# --- Verdict --------------------------------------------------------------
section "Verdict"
echo "  passed: $PASS_COUNT    failed: $FAIL_COUNT"
if [[ "$FAIL_COUNT" -eq 0 ]]; then
  echo -e "  ${GREEN}${BOLD}GO — every checked claim matches the recording script.${NC}"
  exit 0
else
  echo -e "  ${RED}${BOLD}NO-GO — fix the ${FAIL_COUNT} failure(s) above before recording.${NC}"
  exit 1
fi
