#!/usr/bin/env bash
# claude-code-baseline :: dispatcher/post-write.sh
#
# Single PostToolUse entry point (matcher: Write|Edit). settings.json points
# here; this script runs the baseline hooks in a fixed, safe order. Each hook
# self-gates on baseline.config.json, so enabling/disabling a hook is a config
# change only — no settings.json edits required.
#
# Order (and why):
#   1. auto-format      reshape the file before anything inspects it
#   2. security-defaults BLOCKING — never stage a security regression
#   3. fix-tags          BLOCKING — traceability gate
#   4. run-tests         BLOCKING (per posture) — correctness gate
#   5. auto-stage        LAST — only stage once every blocking gate passed
#
# A blocking hook's non-zero exit is propagated immediately and stops the chain,
# so auto-stage never runs after a failed gate.

set -uo pipefail

HOOKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/common.sh
source "$HOOKS_DIR/lib/common.sh"

PAYLOAD="$(cat 2>/dev/null || true)"

# Fail-closed visibility: without Python, every config-driven check is dark
# (module enable-state, posture, rules, and path extraction all need it). Never
# let that be silent. command-guard (PreToolUse) fails closed without Python; the
# secrets deny-list (a permission rule, enforced by Claude Code) is unaffected.
if [[ -z "$(bcl_python)" ]]; then
  {
    echo "[baseline] DEGRADED: Python unavailable — config-driven checks"
    echo "   (auto-format, securityDefaults, fix-tags, run-tests) did NOT run for this edit."
    echo "   The secrets deny-list (a permission rule) is unaffected; command-guard fails closed on Bash."
  } >&2
  bcl_failclosed_exit; exit $?
fi

# Config present but unparseable -> bcl_cfg silently returns defaults, which
# disables module gating. Surface it and fail closed rather than run dark.
if bcl_config_malformed; then
  {
    echo "[baseline] DEGRADED: .claude/baseline.config.json exists but is not valid JSON —"
    echo "   module gating could not be read, so config-driven checks may be silently disabled."
    echo "   Fix the JSON (or remove the file to restore defaults)."
  } >&2
  bcl_failclosed_exit; exit $?
fi

# Payload present but unparseable -> we cannot identify the changed files.
if bcl_payload_unparseable "$PAYLOAD"; then
  echo "[baseline] DEGRADED: tool payload was unparseable — PostToolUse checks could not run." >&2
  bcl_failclosed_exit; exit $?
fi

# First changed path -> CLAUDE_TOOL_FILE for hooks that key off a single file.
FIRST_FILE="$(bcl_extract_paths "$PAYLOAD" | head -1)"

run_hook() {
  local hook="$1"
  [[ -f "$hook" ]] || return 0
  CLAUDE_TOOL_FILE="$FIRST_FILE" bash "$hook" <<< "$PAYLOAD"
}

run_hook "$HOOKS_DIR/guardrails/auto-format.sh"        || true   # never blocks
run_hook "$HOOKS_DIR/modules/security-defaults.sh"     || exit $?
run_hook "$HOOKS_DIR/modules/fix-tags.sh"              || exit $?
run_hook "$HOOKS_DIR/modules/run-tests.sh"             || exit $?
run_hook "$HOOKS_DIR/modules/auto-stage.sh"            || true   # never blocks

exit 0
