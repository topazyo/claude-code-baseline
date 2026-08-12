#!/usr/bin/env bash
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

# --- python resolver --------------------------------------------------------
# Git Bash on Windows often ships `python` but not `python3`; WSL ships both.
bcl_python() {
  if command -v python3 >/dev/null 2>&1; then echo python3
  elif command -v python >/dev/null 2>&1; then echo python
  else echo ""; fi
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
  local key="$1" default="${2:-}" py cfg
  py="$(bcl_python)"; cfg="$(bcl_config_path)"
  if [[ -z "$py" || ! -f "$cfg" ]]; then printf '%s' "$default"; return 0; fi
  "$py" - "$cfg" "$key" "$default" <<'PY'
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
