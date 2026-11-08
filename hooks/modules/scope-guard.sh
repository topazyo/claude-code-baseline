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
# Whether or not scopeGuard is enabled, it also refuses every Write or Edit to a path
# only a human may write: subagent, skill and command definitions, plugins, user
# settings, .claude.json and .mcp.json; see below.

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

# ONE interpreter for the config, the payload state, the extracted file_path and the
# definition-path verdict below. Its own timeout, shorter than the shared one: when it
# fails, the standalone check below must still finish inside the hook's 10 s.
_BCL_PRIME_TIMEOUT=4
bcl_prime "$PAYLOAD" definition

# Self-protection, whatever scopeGuard.enabled says: like the deny-list it has no
# switch, and it follows the posture. A Write or Edit to a path only a human may write
# is refused: subagent, skill and command definitions and hook scripts
# (.claude/agents|skills|commands|hooks, at any depth and in the user's config home),
# plugins (a skill folder's .claude-plugin, the plugin cache), user settings,
# .claude.json, .mcp.json and .claude/security-defaults.json. Each of them can run
# commands command-guard never sees (hooks and MCP servers in frontmatter or JSON, a
# skill's allowed-tools and `!` lines, the scripts a definition runs) or relax a check,
# so no content is judged: the path decides. _BCL_DEFPATH_SRC (common.sh) reads it as
# written, in its canonical Windows form (device prefixes, trailing dots), as it
# resolves (8.3 names, links, junctions), under the real protected directories, and
# through hard links; see README for what this leaves to humans. A slow interpreter
# start can cost the prime's 4 s and then the standalone run's 4 s before it fails
# closed.
#
# Only the exact verdict "no" (or "nopath": no file_path in the payload) lets the edit
# through. Without a parsed payload (no working Python, or a payload that is not JSON),
# the raw payload text is searched for those paths instead, and a hit fails closed.
# Anything else -- an empty or unknown verdict, a timeout -- fails closed too.
# MultiEdit never reaches this hook (it is wired for Write and Edit only).
#
# Could not read stdin: `cat` blocked until EOF, so a caller that left stdin open
# wedged this hook until Claude Code killed it — and a killed PreToolUse hook emits
# no exit 2, so the edit proceeded unchecked. The target is unknown, so this fails
# closed before the enabled-gate, with its own message.
if [[ $read_rc -ne 0 ]]; then
  bcl_say "[scope-guard] CONTROL COULD NOT RUN — could not read the tool payload from stdin: $BCL_READ_ERROR; the edit's target is unknown and was NOT checked."
  bcl_failclosed_exit; exit $?
fi
if [[ "${_BCL_PRIME_STATE:-}" == ok ]]; then
  def_verdict="${_BCL_PL_DEFINITION:-}"
  def_real="${_BCL_PL_DEFREAL:-}"
elif [[ -n "${_BCL_PY:-}" ]]; then
  def_root="${CLAUDE_PROJECT_DIR:-}"
  [[ -z "$def_root" ]] && def_root="$(bcl_repo_root)"
  def_out="$(bcl_timeout 4 "$_BCL_PY" -I -S -X utf8 -c "$_BCL_DEFPATH_SRC$_BCL_DEFPATH_MAIN_TAIL" \
    "$def_root" <<< "$PAYLOAD")" || def_out=""
  def_verdict="${def_out%%$'\n'*}"
  def_real=""
  if [[ "$def_out" == *$'\n'* ]]; then
    def_real="${def_out#*$'\n'}"
    def_real="${def_real%%$'\n'*}"
  fi
else
  def_verdict=unparsed
  def_real=""
fi
case "$def_verdict" in
  no|nopath) ;;
  yes)
    bcl_say "[scope-guard] REFUSED — ${def_real:-the target} is a path only a human may write (a subagent, skill or command definition, a hook script, a plugin, user settings, .claude.json, .mcp.json or the security-defaults rules). These can register hooks, MCP servers or pre-approved commands that no guard sees, so Claude may not write them: edit it yourself."
    bcl_violation_exit; rc=$?; [[ $rc -ne 0 ]] && exit $rc ;;
  unparsed)
    # No parser: the raw text, without case, with /, \ or \\ (JSON) as separators, a
    # `./` or a stream suffix (`.claude::$INDEX_ALLOCATION\agents`) allowed in between.
    def_re='\.claude(:[^/\\"]*)?([/\\]+\.)*[/\\]+(agents|skills|commands|plugins|hooks'
    def_re+='|settings\.json|settings\.local\.json|security-defaults\.json)'
    def_re+='|\.claude[/\\]+[^/\\"]+[/\\]+\.\.[/\\]|\.claude\.json|\.mcp\.json'
    def_re+='|(^|[/\\"])(cl[0-9a-z]{0,4}|mcp[0-9a-z]{0,3})~[0-9]+(\.[0-9a-z]{1,3})?([/\\"]|$)'
    shopt -s nocasematch   # bash 3.1+; ${x,,} needs bash 4
    if [[ "$PAYLOAD" =~ $def_re ]]; then def_hit=1; else def_hit=0; fi
    shopt -u nocasematch
    if [[ $def_hit -eq 1 ]]; then
      bcl_say "[scope-guard] CONTROL COULD NOT RUN — the edit may target a path only a human may write, but its payload could not be parsed (no working Python, or not JSON); it was NOT checked."
      bcl_failclosed_exit; rc=$?; [[ $rc -ne 0 ]] && exit $rc
    fi ;;
  *)
    bcl_say "[scope-guard] CONTROL COULD NOT RUN — whether the edit targets a path only a human may write could not be decided (a link, UNC or device path it may not resolve, or the check failed); it was NOT checked."
    bcl_failclosed_exit; rc=$?; [[ $rc -ne 0 ]] && exit $rc ;;
esac

# A config that exists but cannot be read would read scopeGuard as off. Whether it is
# on is unknown, so fail closed before the enabled-gate (see _malformedConfigRationale).
if bcl_config_malformed; then
  bcl_say "$(bcl_config_malformed_text scope-guard)"
  bcl_failclosed_exit; exit $?
fi

bcl_module_enabled scopeGuard || exit 0

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
