#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# claude-code-baseline :: hooks/lib/common.sh
#
# Shared helpers for every baseline hook. SOURCE this file; do not execute it.
#   source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
#
# All functions are prefixed bcl_ (baseline common lib) to avoid clobbering
# anything in a repo's own hooks. Requires: bash, python3 (or python).
#
# Windows note: Claude Code on Windows passes Windows-style paths and Python's
# print() emits CRLF, so every path extracted here is stripped of trailing CR.

# Guard against double-sourcing (dispatcher + module may both source us).
[[ -n "${_BCL_SOURCED:-}" ]] && return 0
_BCL_SOURCED=1

# Drop any INHERITED memo slots before the memoized helpers below can read them.
# _BCL_PY / _BCL_CFG_* are process-local caches, never exported — but bash imports
# same-named environment variables as shell variables, so an inherited value would
# let anything able to set this hook's environment (a settings.json `env` block, a
# parent shell) pre-seed e.g. a "warn" posture without touching baseline.config.json.
# Posture and gating must come from the config file only.
for _bcl_v in $(compgen -v _BCL_CFG_ 2>/dev/null); do unset "$_bcl_v"; done
unset _BCL_PY _bcl_v

# --- python resolver --------------------------------------------------------
# Git Bash on Windows often ships `python` but not `python3`; WSL ships both.
# Memoized: almost every helper below resolves the interpreter, and a hook process
# cannot grow a Python installation mid-run, so resolving once per process is safe
# (and keeps the PostToolUse chain inside its hook budget — see bcl_cfg).
bcl_python() {
  if [[ -n "${_BCL_PY+x}" ]]; then printf '%s' "$_BCL_PY"; return 0; fi
  if command -v python3 >/dev/null 2>&1; then _BCL_PY=python3
  elif command -v python >/dev/null 2>&1; then _BCL_PY=python
  else _BCL_PY=""; fi
  printf '%s' "$_BCL_PY"
}

# --- repo + config location -------------------------------------------------
bcl_repo_root() {
  if [[ -n "${CLAUDE_PROJECT_DIR:-}" ]]; then
    printf '%s' "$CLAUDE_PROJECT_DIR"
  else
    git rev-parse --show-toplevel 2>/dev/null || pwd
  fi
}

bcl_config_path() {
  printf '%s/.claude/baseline.config.json' "$(bcl_repo_root)"
}

# bcl_cfg <dotted.key> [default]
# Echoes the config value at dotted.key, or [default] if absent/unreadable.
# Booleans render as the literal strings "true"/"false".
bcl_cfg() {
  local key="$1" default="${2:-}" py cfg cvar val
  # Memoized per (key, default) for the life of this process. One key costs a whole
  # Python startup (~1 s on Windows) and a single hook asks for the same keys over
  # and over (every bcl_*_exit re-reads the posture) — one PostToolUse write measured
  # 17 interpreter spawns. baseline.config.json cannot change mid-hook, so the cache
  # cannot hide a config edit from the next hook run.
  cvar="_BCL_CFG_${key//[^A-Za-z0-9]/_}__${default//[^A-Za-z0-9]/_}"
  if [[ -n "${!cvar+x}" ]]; then printf '%s' "${!cvar}"; return 0; fi
  py="$(bcl_python)"; cfg="$(bcl_config_path)"
  if [[ -z "$py" || ! -f "$cfg" ]]; then
    printf -v "$cvar" '%s' "$default"; printf '%s' "$default"; return 0
  fi
  val="$("$py" - "$cfg" "$key" "$default" <<'PY'
import json, sys
cfg, key, default = sys.argv[1], sys.argv[2], (sys.argv[3] if len(sys.argv) > 3 else "")
try:
    with open(cfg, encoding="utf-8") as fh:
        data = json.load(fh)
except Exception:
    print(default); raise SystemExit(0)
cur = data
for part in key.split("."):
    if isinstance(cur, dict) and part in cur:
        cur = cur[part]
    else:
        print(default); raise SystemExit(0)
if isinstance(cur, bool):
    print("true" if cur else "false")
elif cur is None:
    print(default)
else:
    print(cur)
PY
)"
  printf -v "$cvar" '%s' "$val"
  printf '%s' "$val"
}

# Global enforcement posture: "block" or "warn". Defaults to block.
bcl_posture() {
  local p; p="$(bcl_cfg enforcement block)"
  [[ "$p" == "warn" ]] && { echo warn; return 0; }
  echo block
}

# bcl_module_enabled <name>    -> 0 if modules.<name>.enabled == true
bcl_module_enabled() { [[ "$(bcl_cfg "modules.$1.enabled" false)" == "true" ]]; }
# bcl_guardrail_enabled <name> -> 0 if guardrails.<name>.enabled == true (default true)
bcl_guardrail_enabled() { [[ "$(bcl_cfg "guardrails.$1.enabled" true)" == "true" ]]; }
# bcl_guardrail_opted_in <name> -> 0 ONLY if guardrails.<name>.enabled is LITERALLY
# true in a readable baseline.config.json. Unlike bcl_guardrail_enabled it defaults
# to FALSE, so a missing key, a missing config or an unreadable config keeps the
# guardrail off. Use this — never bcl_guardrail_enabled — for a guardrail that
# EXECUTES code (auto-format), where "default on" means "silently execute whatever
# the cloned repo supplied". Security controls that only inspect keep the
# default-on gate: for them, absent config must not mean absent enforcement.
bcl_guardrail_opted_in() { [[ "$(bcl_cfg "guardrails.$1.enabled" false)" == "true" ]]; }

# bcl_violation_exit
# Call after printing a violation to stderr. Returns the exit code that matches
# the configured posture: 2 (block) or 0 (warn). Use: `bcl_violation_exit; exit $?`
#
# Why 2 (not 1): Claude Code treats hook exit code 2 as the canonical "stop / I
# object" signal and feeds the hook's FULL stderr back to the model as actionable
# feedback. For a PreToolUse hook, exit 2 blocks the call; for a PostToolUse hook
# (the tool already ran) it surfaces the complete violation report to Claude so it
# self-corrects. Any OTHER non-zero code is treated as a generic "hook error" and
# only the first stderr line is shown — which would truncate our multi-line reports.
bcl_violation_exit() { [[ "$(bcl_posture)" == "block" ]] && return 2 || return 0; }

# bcl_failclosed
# True (0) when fail-closed handling is active — the global `failClosed` config
# key (default true). When config can't be read (e.g. Python unavailable),
# bcl_cfg returns the default "true", so we fail closed by default.
bcl_failclosed() { [[ "$(bcl_cfg failClosed true)" != "false" ]]; }

# bcl_failclosed_exit
# Call after printing a "control could not run" message to stderr. Returns the
# exit code for a DEGRADED control (a security check that could not run, as
# opposed to a detected violation): 2 when fail-closed is active AND posture is
# block, else 0 (announce only). Use: `bcl_failclosed_exit; exit $?`
bcl_failclosed_exit() {
  if bcl_failclosed && [[ "$(bcl_posture)" == "block" ]]; then return 2; fi
  return 0
}

# bcl_payload_unparseable <payload>
# Returns 0 (true) ONLY when the payload is NON-EMPTY but cannot be parsed as
# JSON — a "control could not read its input" condition that must not be mistaken
# for "nothing to check". Returns 1 when the payload is empty/whitespace (nothing
# to check), parses fine, or Python is unavailable (callers handle no-Python with
# their own message before calling this).
bcl_payload_unparseable() {
  local payload="$1" py; py="$(bcl_python)"
  [[ -z "$py" ]] && return 1
  [[ -z "${payload//[[:space:]]/}" ]] && return 1
  printf '%s' "$payload" | "$py" -c 'import json,sys
try:
    json.load(sys.stdin)
except Exception:
    raise SystemExit(0)
raise SystemExit(1)' && return 0 || return 1
}

# bcl_config_malformed
# Returns 0 (true) when baseline.config.json EXISTS but is not valid JSON — a
# degraded state that silently disables module gating (bcl_cfg would return
# defaults for every key). Returns 1 when there is no config (defaults apply),
# it parses fine, or Python is unavailable (no-Python handled separately).
bcl_config_malformed() {
  local py cfg; py="$(bcl_python)"; cfg="$(bcl_config_path)"
  [[ -z "$py" || ! -f "$cfg" ]] && return 1
  "$py" -c 'import json,sys
try:
    json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    raise SystemExit(0)
raise SystemExit(1)' "$cfg" && return 0 || return 1
}

# --- payload parsing --------------------------------------------------------
# bcl_extract_paths <payload-json>
# Prints every file_path/filePath/path string found anywhere in the payload,
# one per line, sorted, with trailing CR stripped.
bcl_extract_paths() {
  local payload="$1" py; py="$(bcl_python)"
  [[ -z "$py" ]] && return 0
  printf '%s' "$payload" | "$py" -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    raise SystemExit(0)
paths = set()
def walk(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in {"file_path", "filepath", "path"} and isinstance(v, str):
                paths.add(v)
            else:
                walk(v)
    elif isinstance(obj, list):
        for item in obj:
            walk(item)
walk(data)
for p in sorted(paths):
    print(p)
' | tr -d '\r'
}

# bcl_extract_value <payload-json> <key>
# Prints the first string value found for <key> anywhere in the payload.
bcl_extract_value() {
  local payload="$1" key="$2" py; py="$(bcl_python)"
  [[ -z "$py" ]] && return 0
  printf '%s' "$payload" | "$py" -c '
import json, sys
key = sys.argv[1]
try:
    data = json.load(sys.stdin)
except Exception:
    print(""); raise SystemExit(0)
def find(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key and isinstance(v, str):
                return v
            r = find(v)
            if r:
                return r
    if isinstance(obj, list):
        for item in obj:
            r = find(item)
            if r:
                return r
    return ""
print(find(data))
' "$key" | tr -d '\r'
}

# --- path normalization -----------------------------------------------------
# Claude Code hands hooks an ABSOLUTE file_path (Windows-style on Windows), while
# the files humans write for these hooks — scope lists, rule paths — are
# repo-relative with forward slashes. Comparing the two forms directly is how a
# guard ends up matching nothing (or matching everything by substring), so every
# path comparison in the baseline goes through these two helpers first.

# bcl_norm_path <path>
# Backslashes -> forward slashes, collapse repeated slashes, drop a leading './'
# and a trailing '/'. Purely textual: it never touches the filesystem, so it works
# for paths that do not exist yet (a Write to a new file).
bcl_norm_path() {
  # ${1//\\//} = replace every literal backslash with a forward slash.
  local p="${1//\\//}"
  while [[ "$p" == *//* ]]; do p="${p//\/\//\/}"; done
  p="${p#./}"
  [[ ${#p} -gt 1 ]] && p="${p%/}"
  printf '%s' "$p"
}

# bcl_repo_relative <path>
# Prints <path> normalized and made repo-relative when it lives under the repo
# root; a path outside the repo is returned normalized but still absolute, so a
# comparison against repo-relative entries cannot accidentally match it.
bcl_repo_relative() {
  local p root lp lroot
  p="$(bcl_norm_path "$1")"
  root="$(bcl_norm_path "$(bcl_repo_root)")"
  [[ -z "$root" ]] && { printf '%s' "$p"; return 0; }
  case "$p" in
    "$root") printf '.'; return 0 ;;
    "$root"/*) printf '%s' "${p#"$root"/}"; return 0 ;;
  esac
  # Windows hands out the same path with different casing (C:/Users vs c:/users),
  # so retry the prefix test case-insensitively. Only the PREFIX is compared that
  # way; the returned remainder keeps the real casing of the incoming path.
  # (tr, not ${var,,}: bash 3.2 — still /bin/bash on macOS — cannot PARSE ${var,,},
  # and a parse error here would take down every hook that sources this file.)
  lp="$(printf '%s' "$p" | tr 'A-Z' 'a-z')"; lroot="$(printf '%s' "$root" | tr 'A-Z' 'a-z')"
  if [[ "$lp" == "$lroot"/* ]]; then
    printf '%s' "${p:${#root}+1}"
    return 0
  fi
  printf '%s' "$p"
}

# --- bounded child execution ------------------------------------------------
# bcl_timeout <seconds> <command...>
# Runs <command> under coreutils `timeout` when it is available. Rationale: Claude
# Code enforces its own per-hook timeout by KILLING the hook, and a killed hook
# produces no exit 2 — so every fail-closed path in this library is skipped and the
# tool call proceeds. Bounding each child ourselves converts "hook was killed"
# (fail-open) into "child was killed, rc=124" (which callers route through
# bcl_failclosed_exit). Where `timeout` is absent (stock macOS, minimal images) the
# command still runs, just unbounded — bcl_timeout_available says so honestly.
bcl_timeout_available() { command -v timeout >/dev/null 2>&1; }
bcl_timeout() {
  local secs="$1"; shift
  if bcl_timeout_available; then
    # -k: if the child ignores TERM, KILL it 2s later. 124 = killed by timeout.
    timeout -k 2 "$secs" "$@"
  else
    "$@"
  fi
}

# bcl_child_unusable <script-path>
# Prints a one-line reason and returns 0 (true) when <script-path> cannot be run as
# a hook child; prints nothing and returns 1 (false) when it can.
#
# Why this exists: `bash /missing/hook.sh` exits 127, and Claude Code treats any
# non-zero-but-not-2 exit as a generic hook error — the action proceeds. So a
# DELETED or TRUNCATED hook script is a fail-open that no amount of fail-closed
# logic *inside* the script can cover. Every launcher in the baseline therefore
# checks its children itself and routes a failure through bcl_failclosed_exit.
#
# We test readability, not the execute bit: children are launched as `bash <path>`,
# so `chmod -x` cannot disarm them — but truncation (`printf '' > hook.sh`) can,
# which is why a zero-byte file counts as unusable.
bcl_child_unusable() {
  local p="$1"
  if [[ ! -e "$p" ]]; then printf 'not found: %s' "$p"; return 0; fi
  if [[ ! -f "$p" ]]; then printf 'not a regular file: %s' "$p"; return 0; fi
  if [[ ! -r "$p" ]]; then printf 'not readable: %s' "$p"; return 0; fi
  if [[ ! -s "$p" ]]; then printf 'empty — truncated?: %s' "$p"; return 0; fi
  return 1
}
