#!/usr/bin/env bash
# claude-code-baseline :: modules/scope-guard.sh
#
# PreToolUse module (matcher: Write|Edit). Flags edits to files outside the
# declared scope of the active task. Scope is a newline-delimited list of file
# paths (substring match) in a scope file the agent maintains per task.
#
# Config (baseline.config.json):
#   "modules": { "scopeGuard": {
#       "enabled": true, "scopeFile": ".claude/active-issue-scope.txt" } }
#
# Posture: under "block", an out-of-scope edit exits 2 (blocks the tool);
# under "warn", it prints guidance and exits 0.

set -uo pipefail

# ${BASH_SOURCE[0]%/*} rather than $(dirname ...): dirname is an external binary
# under Git Bash and a fork measures ~21ms here — paid by every hook, on every tool call.
HERE="${BASH_SOURCE[0]%/*}"
[[ "$HERE" == "${BASH_SOURCE[0]}" ]] && HERE=.
HERE="$(cd "$HERE" && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"

# Read stdin BEFORE the enable-gate, then prime once: the gate needs the config and
# priming needs the payload, so doing them separately costs two interpreter starts.
# Acting on a read failure is deferred until after the gate, so a repo that disabled
# scopeGuard still exits 0 rather than having its edits blocked by our stdin.
read_rc=0
bcl_read_payload PAYLOAD || read_rc=1

# ONE interpreter for the config, the payload state and the extracted file_path.
bcl_prime "$PAYLOAD"

bcl_module_enabled scopeGuard || exit 0

# Could not read stdin: `cat` blocked until EOF, so a caller that left stdin open
# wedged this hook until Claude Code killed it — and a killed PreToolUse hook emits
# no exit 2, so the edit proceeded unchecked. Same fail-closed destination as an
# unparseable payload, with its own message so the two causes stay distinguishable.
if [[ $read_rc -ne 0 ]]; then
  echo "[scope-guard] CONTROL COULD NOT RUN — could not read the tool payload from stdin: $BCL_READ_ERROR; edit was NOT scope-checked." >&2
  bcl_failclosed_exit; exit $?
fi

# A PreToolUse control must not silently allow when it cannot read its input.
# (No-Python disables this opt-in module's gating, but that degradation is
# surfaced loudly by command-guard and the PostToolUse dispatcher on the same
# turn, so we don't block edits here on behalf of a possibly-off module. A
# present-yet-unparseable payload IS reachable while enabled and must fail closed
# rather than be mistaken for "no file_path to check".)
if bcl_payload_unparseable "$PAYLOAD"; then
  echo "[scope-guard] CONTROL COULD NOT RUN — tool payload unparseable; edit was NOT scope-checked." >&2
  bcl_failclosed_exit; exit $?
fi

ABOUT_TO_EDIT="$(bcl_extract_value "$PAYLOAD" file_path)"
[[ -z "$ABOUT_TO_EDIT" ]] && exit 0

SCOPE_FILE="$(bcl_cfg modules.scopeGuard.scopeFile .claude/active-issue-scope.txt)"
case "$SCOPE_FILE" in /*|?:*) : ;; *) SCOPE_FILE="$(bcl_repo_root)/$SCOPE_FILE" ;; esac

# No scope file => nothing declared => pass through silently.
[[ -f "$SCOPE_FILE" ]] || exit 0

# In scope => allow.
grep -qF -- "$ABOUT_TO_EDIT" "$SCOPE_FILE" && exit 0

ISSUE="$(head -1 "$SCOPE_FILE" 2>/dev/null || echo unknown)"
{
  echo ""
  echo "⚠️  [scope-guard] Edit to a file NOT in declared scope ($ISSUE):"
  echo "   File: $ABOUT_TO_EDIT"
  echo "   Declared scope file: $SCOPE_FILE"
  echo "   If this is a genuine scope expansion, stop and report it."
} >&2

if [[ "$(bcl_posture)" == "block" ]]; then
  exit 2
fi
exit 0
