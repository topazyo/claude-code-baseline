#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# claude-code-baseline :: dispatcher/post-write.sh
#
# Single PostToolUse entry point (matcher: Write|Edit). settings.json points
# here; this script runs the baseline hooks in a fixed, safe order. Each hook
# self-gates on baseline.config.json, so enabling/disabling a hook is a config
# change only — no settings.json edits required.
#
# Order (and why):
#   1. security-defaults BLOCKING — never let a security regression pass unreported
#   2. fix-tags          BLOCKING — traceability gate
#   3. run-tests         BLOCKING (per posture) — correctness gate
#   4. auto-format       non-blocking cosmetics — runs AFTER every gate has read the
#                        bytes Claude actually wrote
#   5. auto-stage        LAST — only stage once every blocking gate passed
#
# A blocking hook's non-zero exit is propagated immediately and stops the chain,
# so auto-format and auto-stage never run after a failed gate.
#
# Why auto-format moved from first to fourth: all five children share ONE
# PostToolUse timeout (settings.template.json wires 90s), and auto-format is the
# unbounded step — prettier, eslint, and `dotnet format` (which builds the project).
# Running it first meant a slow format could consume the whole budget, Claude Code
# would kill the hook, and the three blocking gates would never run. A killed hook
# emits no exit 2, so that was a silent fail-OPEN. Gates now run first, and every
# child is separately bounded by bcl_timeout so one slow child cannot starve the
# rest or the hook itself.

set -uo pipefail

# ${BASH_SOURCE[0]%/*} rather than $(dirname ...): dirname is an external binary
# under Git Bash and a fork measures ~21ms here — paid on every tool call.
HOOKS_DIR="${BASH_SOURCE[0]%/*}"
[[ "$HOOKS_DIR" == "${BASH_SOURCE[0]}" ]] && HOOKS_DIR=.
HOOKS_DIR="$(cd "$HOOKS_DIR/.." && pwd)"
# shellcheck source=../lib/common.sh
source "$HOOKS_DIR/lib/common.sh"
# Before any exit, so even the earliest degraded exit 0 is shown (see common.sh).
bcl_notice_event PostToolUse

# Bounded read. `cat` blocked until EOF and nothing guarantees EOF; a caller that
# leaves stdin open used to wedge this hook until Claude Code KILLED it, and a killed
# hook never reaches the fail-closed branches below. A read that fails is not an
# empty payload, so it lands here rather than in the "nothing to inspect" path.
if ! bcl_read_payload PAYLOAD; then
  bcl_say "[baseline] CONTROL COULD NOT RUN — could not read the tool payload from stdin: $BCL_READ_ERROR." \
    "   No PostToolUse check ran for this edit; the changed files were NOT inspected."
  bcl_failclosed_exit; exit $?
fi

# ONE interpreter for the whole hook: this parses baseline.config.json and the
# payload in a single process and publishes the results as shell variables, so the
# three checks below (config state, payload state, path extraction) cost no further
# spawns. They used to cost one interpreter start each.
bcl_prime "$PAYLOAD"

# Fail-closed visibility: without Python, every config-driven check is dark
# (module enable-state, posture, rules, and path extraction all need it). Never
# let that be silent. command-guard (PreToolUse) fails closed without Python; the
# secrets deny-list (a permission rule, enforced by Claude Code) is unaffected.
if [[ -z "$(bcl_python)" ]]; then
  bcl_say "[baseline] DEGRADED: Python unavailable — config-driven checks" \
    "   (auto-format, securityDefaults, fix-tags, run-tests) did NOT run for this edit." \
    "   The secrets deny-list (a permission rule) is unaffected; command-guard fails closed on Bash."
  bcl_failclosed_exit; exit $?
fi

# Config present but unparseable -> bcl_cfg silently returns defaults, which
# disables module gating. Surface it and fail closed rather than run dark.
if bcl_config_malformed; then
  bcl_say "$(bcl_config_malformed_text post-write)" \
    "   DEGRADED: module gating could not be read, so the PostToolUse checks did not run."
  bcl_failclosed_exit; exit $?
fi

# Payload present but unparseable -> we cannot identify the changed files.
if bcl_payload_unparseable "$PAYLOAD"; then
  bcl_say "[baseline] DEGRADED: tool payload was unparseable — PostToolUse checks could not run."
  bcl_failclosed_exit; exit $?
fi

# Where a child's stderr goes. Only when this config can let the edit through while a
# child reports something (warn, or failClosed false) do we keep it, so it can be shown
# (bcl_say -> one JSON object on exit 0). It goes to a FILE, never through `$( )`: a
# pipe makes us wait for EOF from every process holding it, so a grandchild a module
# left running (run-tests runs repo tooling) could hold us past our budget until
# Claude Code killed the hook, which produces no exit code at all. A file has no such
# wait, and costs no fork per child. Default posture: stderr streams as before, no file,
# so a child's exit-0 stderr (a skipped check, a rule-engine warning) stays in the debug
# log there, as it always did; only the dispatcher's own messages (bcl_say) are shown.
if bcl_allows_with_message; then
  _BCL_NOTICE_TMP="$(mktemp 2>/dev/null)" || _BCL_NOTICE_TMP=""
fi

# _child_ran <timeout-secs> <script>: runs a child with stdout discarded (on exit 0
# our stdout must be exactly one JSON object; a child's stdout used to reach only the
# debug log) and stderr streamed or kept, see above. Sets rc and err (err: at most 64
# KiB, for the notice). rc and err are the caller's locals; bash functions see them.
# Append mode (2>>): a grandchild an earlier child left running keeps writing at the
# end of the file rather than at its old offset past our truncation, which would
# leave NUL holes in the next child's text.
_child_ran() {
  local secs="$1" hook="$2"
  rc=0; err=""
  if [[ -n "$_BCL_NOTICE_TMP" ]]; then
    : > "$_BCL_NOTICE_TMP"
    bcl_timeout "$secs" bash -p "$hook" <<< "$PAYLOAD" 2>>"$_BCL_NOTICE_TMP" >/dev/null || rc=$?
    if [[ -s "$_BCL_NOTICE_TMP" ]]; then
      err="$(head -c 65536 "$_BCL_NOTICE_TMP")"
    fi
  else
    bcl_timeout "$secs" bash -p "$hook" <<< "$PAYLOAD" >/dev/null || rc=$?
  fi
}

# First changed path -> CLAUDE_TOOL_FILE for hooks that key off a single file.
FIRST_FILE="$(bcl_extract_paths "$PAYLOAD" | head -1)"
export CLAUDE_TOOL_FILE="$FIRST_FILE"

# Per-child time budgets, in seconds. Their sum (85) stays UNDER the PostToolUse
# timeout wired in settings.template.json (90) so the chain always ends on our
# terms: a child we kill ourselves becomes a fail-closed exit 2, whereas a hook
# Claude Code kills produces no exit code at all and the write stands unreviewed.
# If you raise one of these, raise the wired timeout by at least as much.
#
# Sizing note: the gates are generous because their FIXED cost is process startup,
# not the checking. Each child now pays one interpreter start (bcl_prime) plus a
# handful of forks; measured under Git Bash on Windows that is ~60ms for the
# interpreter and ~27ms per fork, against ~5ms and well under 1ms on Linux. The
# budgets are sized for the slow end of that range and for the real work on top.
# A gate that overruns is a loud fail-closed block, not a silent pass — if a slow
# host trips one, raise its constant AND the wired timeout together, or set
# failClosed:false to downgrade the overrun to a warning.
TO_SECURITY_DEFAULTS=25
TO_FIX_TAGS=18
TO_RUN_TESTS=27
TO_AUTO_FORMAT=10
TO_AUTO_STAGE=5

# run_gate <label> <timeout-secs> <script>
# Launches a BLOCKING child and translates its exit status:
#   0             -> gate passed; the chain continues
#   2             -> gate objected; propagate verbatim so Claude gets the full stderr
#   124           -> we killed it on timeout: its check did NOT complete -> fail closed
#   anything else -> missing / unreadable / truncated / erroring child: did NOT
#                    complete -> fail closed
# That last line is the point: `bash <missing-script>` exits 127, and Claude Code
# treats every non-zero-but-not-2 exit as a generic hook error and lets the action
# stand. Deleting or truncating a module file (neither is an Edit-tool call, so the
# deny-list does not see it) therefore used to disarm that module in total silence.
#
# A kept child stderr (see _child_ran) is re-printed on exit 2 exactly as the child
# wrote it, so Claude gets the same report; on any other status it joins the notice.
run_gate() {
  local label="$1" secs="$2" hook="$3" reason rc=0 err=""
  if reason="$(bcl_child_unusable "$hook")"; then
    bcl_say "[baseline] CONTROL COULD NOT RUN — $label hook $reason" \
      "   The $label gate did NOT run for this edit; the baseline hook tree is incomplete." \
      "   Re-run install.sh to restore it, or set failClosed:false to downgrade this to a warning."
    bcl_failclosed_exit; return $?
  fi
  # -p, as in the wired hook commands: a plain bash child would still run an
  # inherited BASH_ENV file and import exported functions (see common.sh).
  _child_ran "$secs" "$hook"
  case $rc in
    0)
      if [[ -n "$err" ]]; then bcl_say "$err"; fi
      return 0
      ;;
    2)
      # The file itself, byte for byte: $err is capped and loses trailing newlines.
      if [[ -n "$err" ]]; then cat -- "$_BCL_NOTICE_TMP" >&2; fi
      return 2
      ;;
    124)
      if [[ -n "$err" ]]; then bcl_say "$err"; fi
      bcl_say "[baseline] CONTROL COULD NOT RUN — $label exceeded its ${secs}s budget and was killed." \
        "   Its check did NOT complete for this edit."
      bcl_failclosed_exit; return $?
      ;;
    *)
      if [[ -n "$err" ]]; then bcl_say "$err"; fi
      bcl_say "[baseline] CONTROL COULD NOT RUN — $label exited $rc (a script error, not a policy verdict)." \
        "   Its check did NOT complete for this edit."
      bcl_failclosed_exit; return $?
      ;;
  esac
}

# run_helper <label> <timeout-secs> <script>
# Launches a NON-blocking convenience child (formatting, staging). Its exit status
# is deliberately ignored: neither child is a security control, so an absent one is
# not a fail-open and must never block a write. A timeout kill is still announced,
# because a half-run formatter leaves the file in a partial state.
run_helper() {
  local label="$1" secs="$2" hook="$3" rc=0 err=""
  bcl_child_unusable "$hook" >/dev/null && return 0
  _child_ran "$secs" "$hook"
  if [[ -n "$err" ]]; then bcl_say "$err"; fi
  if [[ $rc -eq 124 ]]; then
    bcl_say "[baseline] NOTE: $label exceeded its ${secs}s budget and was killed; it may have done only part of its work."
  fi
  return 0
}

run_gate   "security-defaults" "$TO_SECURITY_DEFAULTS" "$HOOKS_DIR/modules/security-defaults.sh" || exit $?
run_gate   "fix-tags"          "$TO_FIX_TAGS"          "$HOOKS_DIR/modules/fix-tags.sh"          || exit $?
run_gate   "run-tests"         "$TO_RUN_TESTS"         "$HOOKS_DIR/modules/run-tests.sh"         || exit $?
run_helper "auto-format"       "$TO_AUTO_FORMAT"       "$HOOKS_DIR/guardrails/auto-format.sh"
run_helper "auto-stage"        "$TO_AUTO_STAGE"        "$HOOKS_DIR/modules/auto-stage.sh"

exit 0
