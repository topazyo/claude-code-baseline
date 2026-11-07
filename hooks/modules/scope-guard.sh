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
# under "warn", it prints guidance and exits 0, and the guidance is also printed as
# one JSON object on stdout so Claude Code shows it (see bcl_say in common.sh).
#
# Whether or not scopeGuard is enabled, it also refuses a Write or Edit that puts the
# baseline hook directory's path into a subagent or skill definition (.claude/agents/,
# .claude/skills/); see below.

set -uo pipefail

# ${BASH_SOURCE[0]%/*} rather than $(dirname ...): dirname is an external binary
# under Git Bash and a fork measures ~21ms here — paid by every hook, on every tool call.
HERE="${BASH_SOURCE[0]%/*}"
[[ "$HERE" == "${BASH_SOURCE[0]}" ]] && HERE=.
HERE="$(cd "$HERE" && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"
# Before any exit, so even the earliest degraded exit 0 is shown (see common.sh).
bcl_notice_event PreToolUse

# Read stdin BEFORE the enable-gate, then prime once: the gate needs the config and
# priming needs the payload, so doing them separately costs two interpreter starts.
# Acting on a read failure is deferred until after the gate, so a repo that disabled
# scopeGuard still exits 0 rather than having its edits blocked by our stdin.
read_rc=0
bcl_read_payload PAYLOAD || read_rc=1

# ONE interpreter for the config, the payload state and the extracted file_path.
bcl_prime "$PAYLOAD"

# Self-protection, whatever scopeGuard.enabled says: like the deny-list it has no
# switch, and it follows the posture. A Write or Edit to a subagent or skill
# definition (under .claude/agents/ or .claude/skills/, read without case, with \ as
# /, and // and ./ collapsed; a ../ below .claude/ also counts) whose new text
# (content or new_string) names the baseline hook directory is refused. It judges the
# path as written and the edit's new text; baseline-status reads the files on disk.
# Only a payload whose raw text names that directory is examined, and if it cannot be
# parsed (no working Python, invalid JSON, or the payload prime failed) it fails
# closed. A payload that cannot be read at all is empty and goes to the handling
# below. Under warn, the scope check below still runs.
if [[ $read_rc -eq 0 && "$PAYLOAD" == *"/.claude/hooks/baseline/"* ]]; then
  if [[ "${_BCL_PRIME_STATE:-}" != ok ]] || bcl_payload_unparseable "$PAYLOAD"; then
    bcl_say "[scope-guard] CONTROL COULD NOT RUN — the edit names the baseline hook directory, but its payload could not be parsed (no working Python, invalid JSON, or the payload check failed); it was NOT checked."
    bcl_failclosed_exit; rc=$?; [[ $rc -ne 0 ]] && exit $rc
  else
    DEF_TARGET="$(bcl_extract_value "$PAYLOAD" file_path)"
    def_path="/${DEF_TARGET//\\//}"
    while [[ "$def_path" == *//* ]]; do def_path="${def_path//\/\///}"; done
    while [[ "$def_path" == */./* ]]; do def_path="${def_path//\/.\///}"; done
    def_hit=0
    shopt -s nocasematch   # bash 3.1+; ${x,,} needs bash 4
    case "$def_path" in */.claude/agents/*|*/.claude/skills/*|*/.claude/*/../*) def_hit=1 ;; esac
    shopt -u nocasematch
    if [[ $def_hit -eq 1 ]]; then
      DEF_TEXT="$(bcl_extract_value "$PAYLOAD" content)$(bcl_extract_value "$PAYLOAD" new_string)"
      if [[ "$DEF_TEXT" == *"/.claude/hooks/baseline/"* ]]; then
        bcl_say "[scope-guard] REFUSED — $DEF_TARGET is a subagent or skill definition, and the edit puts the baseline hook directory's path in it."
        bcl_violation_exit; rc=$?; [[ $rc -ne 0 ]] && exit $rc
      fi
    fi
  fi
fi

# A config that exists but cannot be read would read scopeGuard as off. Whether it is
# on is unknown, so fail closed before the enabled-gate (see _malformedConfigRationale).
if bcl_config_malformed; then
  bcl_say "$(bcl_config_malformed_text scope-guard)"
  bcl_failclosed_exit; exit $?
fi

bcl_module_enabled scopeGuard || exit 0

# Could not read stdin: `cat` blocked until EOF, so a caller that left stdin open
# wedged this hook until Claude Code killed it — and a killed PreToolUse hook emits
# no exit 2, so the edit proceeded unchecked. Same fail-closed destination as an
# unparseable payload, with its own message so the two causes stay distinguishable.
if [[ $read_rc -ne 0 ]]; then
  bcl_say "[scope-guard] CONTROL COULD NOT RUN — could not read the tool payload from stdin: $BCL_READ_ERROR; edit was NOT scope-checked."
  bcl_failclosed_exit; exit $?
fi

# A PreToolUse control must not silently allow when it cannot read its input.
# (No-Python disables this opt-in module's gating, but that degradation is
# surfaced loudly by command-guard and the PostToolUse dispatcher on the same
# turn, so we don't block edits here on behalf of a possibly-off module. A
# present-yet-unparseable payload IS reachable while enabled and must fail closed
# rather than be mistaken for "no file_path to check".)
if bcl_payload_unparseable "$PAYLOAD"; then
  bcl_say "[scope-guard] CONTROL COULD NOT RUN — tool payload unparseable; edit was NOT scope-checked."
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
bcl_say "" \
  "⚠️  [scope-guard] Edit to a file NOT in declared scope ($ISSUE):" \
  "   File: $ABOUT_TO_EDIT" \
  "   Declared scope file: $SCOPE_FILE" \
  "   If this is a genuine scope expansion, stop and report it."

if [[ "$(bcl_posture)" == "block" ]]; then
  exit 2
fi
exit 0
