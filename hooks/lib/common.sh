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

# Drop any INHERITED cache slots before the helpers below can read them.
# _BCL_PY / _BCL_CFG_* / _BCL_PL_* / _BCL_PRIME_* are process-local caches, never
# exported — but bash imports same-named environment variables as shell variables, so
# an inherited value would let anything able to set this hook's environment (a
# settings.json `env` block, a parent shell) pre-seed e.g. a "warn" posture without
# touching baseline.config.json. Posture and gating must come from the config file only.
#
# This is also why the dispatcher does NOT export its primed values to its children
# even though that would save five interpreter starts: an exported cache is an
# environment-injectable cache, and the saving is not worth reopening this hole.
# Each child pays its own single bcl_prime instead.
# ${!prefix@} is bash's own name-prefix expansion, not `$(compgen -v prefix)`. Same
# list of names, but compgen has to run inside a command substitution, and a fork
# costs ~20ms under Git Bash on Windows — per prefix, on every one of the six
# processes in a PostToolUse chain. This expansion forks nothing.
for _bcl_v in ${!_BCL_CFG_@} ${!_BCL_PL_@} ${!_BCL_PRIME_@}; do unset "$_bcl_v"; done
unset _BCL_PY _BCL_READ_ERROR _bcl_v

# Primed state. Declared unconditionally so `set -u` is safe and so an inherited
# scalar of the same name cannot masquerade as one of these arrays.
_BCL_PRIME_STATE=""     # "" | ok | failed | nopy   (only "ok" is authoritative)
_BCL_PRIME_DIR=""       # CLAUDE_PROJECT_DIR as it stood when we primed
_BCL_PRIME_KEY=""       # resolved baseline.config.json path we primed from
_BCL_CFG_STATE=""       # ok | absent | malformed
_BCL_CFG_KEYS=(); _BCL_CFG_VALS=()
_BCL_PL_STATE=""        # none | empty | ok | bad
_BCL_PL_LEN=-1          # length of the payload bcl_prime was given
_BCL_PL_KEYS=(); _BCL_PL_VALS=(); _BCL_PL_PATHS=()
_BCL_LOOKUP=""          # out-parameter of the two map lookups below
BCL_READ_ERROR=""       # set by bcl_read_payload on failure

# --- python resolver --------------------------------------------------------
# Git Bash on Windows often ships `python` but not `python3`; WSL ships both.
# Memoized: almost every helper below resolves the interpreter, and a hook process
# cannot grow a Python installation mid-run, so resolving once per process is safe.
#
# The memo only ever HITS when _BCL_PY was set in this shell or an ancestor of it —
# a subshell inherits shell variables but cannot export them back, and every call
# site spells this `PY="$(bcl_python)"`. bcl_prime is what actually populates the
# hook's own shell (see its `eval` contract); without a prime this memo is a no-op
# and each call redoes the `command -v` probes. Those are builtins, so the cost is
# microseconds — unlike bcl_cfg, whose misses used to cost a whole interpreter start.
bcl_python() {
  if [[ -n "${_BCL_PY+x}" ]]; then printf '%s' "$_BCL_PY"; return 0; fi
  local cand path
  _BCL_PY=""
  for cand in python3 python; do
    path="$(command -v "$cand" 2>/dev/null)" || continue
    [[ -z "$path" ]] && continue
    # Skip the Windows Store "app execution alias". On a default Windows install
    # `python3` resolves to %LOCALAPPDATA%\Microsoft\WindowsApps\python3, a stub that
    # routes every launch through the Store app layer: measured ~2000ms per start
    # versus ~220ms for the same CPython invoked directly, and `-S -E` does not help
    # because the cost is the alias, not site-packages. Hooks run per tool call and
    # spawn an interpreter per helper, so that difference is the whole latency budget.
    case "$path" in
      *[Ww]indows[Aa]pps*) continue ;;
    esac
    _BCL_PY="$cand"; break
  done
  # If the alias is the ONLY interpreter, use it anyway — slow beats inert, since an
  # unresolvable interpreter silently disables every opt-in module.
  if [[ -z "$_BCL_PY" ]]; then
    if command -v python3 >/dev/null 2>&1; then _BCL_PY=python3
    elif command -v python >/dev/null 2>&1; then _BCL_PY=python
    fi
  fi
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

# --- prime: ONE interpreter per hook process --------------------------------
# Why this exists. Every helper here used to launch its own Python: bcl_cfg (per
# key), bcl_module_enabled, bcl_payload_unparseable, bcl_config_malformed,
# bcl_extract_value (per key), bcl_extract_paths. Measured on a Windows host after
# the interpreter-resolution fix: config-guard 5 spawns / 636 ms, the PostToolUse
# dispatcher 3 spawns / 1561 ms, command-guard 2 spawns / 509 ms on EVERY Bash call.
# Interpreter startup, not work, was almost all of it.
#
# The obvious fix — memoize inside the helpers — cannot work, and the comment that
# used to claim it did was wrong. Every call site is `x="$(bcl_cfg ...)"`, i.e. a
# COMMAND SUBSTITUTION, which runs the function in a subshell: the memo variable is
# written in that subshell and dies with it, so the next call re-spawned. (Reads go
# the other way — a subshell inherits its parent's variables — which is exactly the
# asymmetry bcl_prime exploits.)
#
# So the hook primes ONCE, in its own shell:
#     bcl_prime "$PAYLOAD"
# That is a single Python call that parses baseline.config.json AND the tool payload
# and emits shell assignments, which bcl_prime evals into the hook's own shell. Every
# helper below then answers from those variables — including when it is called from a
# subshell, because a subshell inherits them. An unprimed consumer
# (tools/baseline-status.sh, or a module that never calls bcl_prime) keeps the
# original per-call behaviour verbatim, so this is additive, not a rewrite of policy.
#
# SAFETY, in order of how badly each would bite:
#  * The emitted VALUES are untrusted — a payload carries attacker-influenced file
#    paths and command strings, and baseline.config.json comes from the repo. Python
#    shlex.quote()s every one, so eval sees POSIX single-quoted text it cannot
#    execute. The emitted NAMES are a fixed allowlist of literals in the script
#    below; no name is ever derived from input. Config keys and payload keys are
#    carried as ARRAY ELEMENTS, never as variable names.
#  * `_BCL_PRIME_STATE=ok` is assigned by BASH, after the eval. eval parses its whole
#    argument before running any of it, so a truncated or malformed Python block sets
#    nothing and the state stays unset — which routes every helper back to its own
#    per-call check. A prime failure can only read as "unknown", never as
#    "config fine".
_BCL_PRIME_TIMEOUT=10

IFS='' read -r -d '' _BCL_PRIME_SRC <<'PRIMEPY' || true
import json, os, shlex, sys

CFG_PATH = sys.argv[1]
WANT_PAYLOAD = len(sys.argv) > 2 and sys.argv[2] == "1"

# Bounds. A repo-supplied config or a hostile payload must not be able to make this
# emit a multi-megabyte eval string or spend the hook's budget walking itself. Going
# over is reported as a prime FAILURE (exit 3 -> _BCL_PRIME_STATE stays unset), which
# degrades to the original per-call helpers rather than to a truncated view of policy.
MAX_CFG_ENTRIES = 4096
MAX_PL_KEYS = 512
MAX_DEPTH = 64


class Overflow(Exception):
    pass


def q(s):
    # NUL cannot survive a bash variable anyway; strip it so the emitted script is
    # always well-formed rather than silently cut short at the first NUL.
    return shlex.quote(s.replace("\x00", ""))


lines = []


def emit(name, value):
    lines.append(name + "=" + q(value))


def emit_arr(name, values):
    lines.append(name + "=(" + " ".join(q(v) for v in values) + ")")


def render(v):
    # Mirrors the old bcl_cfg reader exactly: booleans render as the literal strings
    # "true"/"false"; everything else is str()'d the way print() rendered it.
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


cfg_state = "absent"
cfg_data = None
if os.path.isfile(CFG_PATH):
    try:
        with open(CFG_PATH, encoding="utf-8") as fh:
            cfg_data = json.load(fh)
        cfg_state = "ok"
    except Exception:
        cfg_state = "malformed"

cfg_keys = []
cfg_vals = []


def flatten(node, prefix, depth):
    if depth > MAX_DEPTH:
        raise Overflow()
    for k, v in node.items():
        # The old reader split the lookup key on "." and walked dicts, so a config key
        # that CONTAINS a dot was unreachable. Skipping it here keeps that: emitting
        # it would answer a lookup the old reader answered with the caller's default.
        if not isinstance(k, str) or "." in k:
            continue
        path = k if not prefix else prefix + "." + k
        # JSON null -> the old reader printed the CALLER's default, which differs per
        # call site. Not emitting the key makes the lookup miss, which does the same.
        if v is None:
            continue
        if len(cfg_keys) >= MAX_CFG_ENTRIES:
            raise Overflow()
        cfg_keys.append(path)
        cfg_vals.append(render(v))
        if isinstance(v, dict):
            flatten(v, path, depth + 1)


pl_state = "none"
pl_keys = []
pl_vals = []
pl_paths = []


def find(obj, key):
    # Ported verbatim from the old bcl_extract_value so its quirks are preserved
    # (notably: an empty-string hit is falsy, so the DFS keeps looking past it).
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key and isinstance(v, str):
                return v
            r = find(v, key)
            if r:
                return r
    if isinstance(obj, list):
        for item in obj:
            r = find(item, key)
            if r:
                return r
    return ""


def walk_paths(obj, acc, depth):
    if depth > MAX_DEPTH:
        raise Overflow()
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in ("file_path", "filepath", "path") and isinstance(v, str):
                acc.add(v)
            else:
                walk_paths(v, acc, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            walk_paths(item, acc, depth + 1)


def collect_keys(obj, acc, depth):
    if depth > MAX_DEPTH:
        raise Overflow()
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                acc.add(k)
            if len(acc) > MAX_PL_KEYS:
                raise Overflow()
            collect_keys(v, acc, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            collect_keys(item, acc, depth + 1)


try:
    if isinstance(cfg_data, dict):
        flatten(cfg_data, "", 0)
    if WANT_PAYLOAD:
        # Read BYTES and decode strictly: Windows Python would otherwise decode stdin
        # with the legacy code page and mangle a UTF-8 payload. Undecodable input is
        # not JSON, so it lands in the same "unparseable" state it does today.
        raw = sys.stdin.buffer.read()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        if text is None:
            pl_state = "bad"
        elif text.strip() == "":
            pl_state = "empty"
        else:
            try:
                pdata = json.loads(text)
            except Exception:
                pl_state = "bad"
            else:
                pl_state = "ok"
                acc = set()
                collect_keys(pdata, acc, 0)
                for k in sorted(acc):
                    pl_keys.append(k)
                    # `| tr -d '\r'` then $(...) newline-stripping, done here instead.
                    pl_vals.append(find(pdata, k).replace("\r", "").rstrip("\n"))
                pacc = set()
                walk_paths(pdata, pacc, 0)
                pl_paths = [p.replace("\r", "") for p in sorted(pacc)]
except Overflow:
    raise SystemExit(3)
except RecursionError:
    raise SystemExit(3)

emit("_BCL_PRIME_KEY", CFG_PATH)
emit("_BCL_CFG_STATE", cfg_state)
emit_arr("_BCL_CFG_KEYS", cfg_keys)
emit_arr("_BCL_CFG_VALS", cfg_vals)
emit("_BCL_PL_STATE", pl_state)
emit_arr("_BCL_PL_KEYS", pl_keys)
emit_arr("_BCL_PL_VALS", pl_vals)
emit_arr("_BCL_PL_PATHS", pl_paths)

# Bytes, with explicit "\n": sys.stdout would apply Windows newline translation and
# hand bash CRLF, which it would eval as trailing carriage returns in every value.
sys.stdout.buffer.write(("\n".join(lines) + "\n").encode("utf-8"))
PRIMEPY

# bcl_prime [payload]
# Call it plainly — `bcl_prime "$PAYLOAD"`, NOT `eval "$(bcl_prime ...)"`. A shell
# function body runs in the caller's shell, so it can set these globals directly;
# wrapping it in a command substitution would put the whole thing back in a subshell
# and cost an extra fork for nothing. With an argument it primes the payload-derived
# values too; with none it primes config only (for hooks that read no stdin) and
# leaves the payload helpers on their per-call path.
#
# Fork budget matters more than it looks: on this Windows host one fork/exec measures
# ~27ms, and a PostToolUse chain is six processes deep, so every avoidable
# subshell inside here is ~160ms across the chain. An earlier draft of this function
# spent nine forks (bcl_python, bcl_config_path, bcl_repo_root, two quoting helpers,
# the pipeline, the capture, timeout, python) and measured 235ms; it is now four.
bcl_prime() {
  local out rc=0 want=0 root
  [[ $# -gt 0 ]] && want=1
  _BCL_PRIME_STATE=""

  # Called, not substituted, so _BCL_PY lands in the caller's shell: every later
  # `$(bcl_python)` then answers from the memo instead of re-probing.
  bcl_python >/dev/null

  # bcl_repo_root/bcl_config_path inlined: calling them would be two more command
  # substitutions, and with CLAUDE_PROJECT_DIR set (Claude Code always sets it) the
  # answer needs no process at all.
  if [[ -n "${CLAUDE_PROJECT_DIR:-}" ]]; then
    root="$CLAUDE_PROJECT_DIR"
  else
    root="$(git rev-parse --show-toplevel 2>/dev/null)"
    [[ -z "$root" ]] && root="$PWD"
  fi
  _BCL_PRIME_KEY="$root/.claude/baseline.config.json"

  if [[ -z "${_BCL_PY:-}" ]]; then
    # No interpreter. Every helper's no-Python branch already yields the safe
    # defaults (config unreadable, nothing extractable), so leave them to it.
    _BCL_PRIME_STATE=nopy
    return 0
  fi

  # Here-string rather than `printf ... | python`: a pipeline would fork a subshell
  # for the left-hand side. It appends a newline, which JSON parsing and the
  # empty-payload test both ignore.
  if [[ $want -eq 1 ]]; then
    out="$(bcl_timeout "$_BCL_PRIME_TIMEOUT" "$_BCL_PY" -c "$_BCL_PRIME_SRC" "$_BCL_PRIME_KEY" 1 <<< "$1")" || rc=$?
  else
    out="$(bcl_timeout "$_BCL_PRIME_TIMEOUT" "$_BCL_PY" -c "$_BCL_PRIME_SRC" "$_BCL_PRIME_KEY" 0 </dev/null)" || rc=$?
  fi
  if [[ $rc -ne 0 || -z "$out" ]]; then
    # Bounds exceeded, interpreter error, or we killed it. Leave every primed value
    # unset so the helpers fall back to their own per-call checks: a broken prime
    # must read as "unknown", never as "config fine" / "payload clean".
    _BCL_PRIME_STATE=failed
    return 0
  fi
  # eval parses its whole argument before executing any of it, so truncated or
  # malformed output sets NOTHING and returns non-zero — the state below stays
  # unset and every helper reverts to checking for itself.
  eval "$out" || { _BCL_PRIME_STATE=failed; return 0; }
  _BCL_PRIME_DIR="${CLAUDE_PROJECT_DIR:-}"
  [[ $want -eq 1 ]] && _BCL_PL_LEN=${#1}
  # LAST: nothing above may be trusted until this line is reached.
  _BCL_PRIME_STATE=ok
  return 0
}

# _bcl_primed -> 0 when the primed values apply to the config we would read now.
# The CLAUDE_PROJECT_DIR check is not decoration: tools/baseline-status.sh reassigns
# it in a loop to report on many repos from one process. It never calls bcl_prime, so
# it can never hit this cache — but if it ever does, a stale hit would report repo A's
# posture for repo B. When CLAUDE_PROJECT_DIR is unset both then and now, the primed
# values stay tied to the root git resolved at prime time; the hooks that `cd` do so
# to that same root, so the answer does not move.
_bcl_primed() {
  [[ "${_BCL_PRIME_STATE:-}" == "ok" ]] || return 1
  [[ "${CLAUDE_PROJECT_DIR:-}" == "${_BCL_PRIME_DIR:-}" ]] || return 1
  return 0
}

# _bcl_payload_primed <payload> -> 0 when the primed payload values describe THIS
# string. Guards against a hook priming with one payload and then querying another;
# a mismatch just costs the old per-call spawn, it never returns a wrong answer.
_bcl_payload_primed() {
  _bcl_primed || return 1
  [[ "${_BCL_PL_STATE:-}" != "none" && "${_BCL_PL_STATE:-}" != "" ]] || return 1
  [[ ${#1} -eq ${_BCL_PL_LEN:--1} ]] || return 1
  return 0
}

# Primed-map lookups. Sets _BCL_LOOKUP and returns 0 on a hit, else returns 1.
# Deliberately two parallel indexed arrays and a linear scan, not one associative
# array: bash 3.2 (still /bin/bash on macOS) cannot PARSE `declare -A`, and a parse
# error in this file would take down every hook that sources it. The maps hold a few
# dozen entries, so the scan does not show up in a measurement.
_bcl_cfg_lookup() {
  local i n=${#_BCL_CFG_KEYS[@]}
  for (( i = 0; i < n; i++ )); do
    if [[ "${_BCL_CFG_KEYS[$i]}" == "$1" ]]; then _BCL_LOOKUP="${_BCL_CFG_VALS[$i]}"; return 0; fi
  done
  return 1
}
_bcl_pl_lookup() {
  local i n=${#_BCL_PL_KEYS[@]}
  for (( i = 0; i < n; i++ )); do
    if [[ "${_BCL_PL_KEYS[$i]}" == "$1" ]]; then _BCL_LOOKUP="${_BCL_PL_VALS[$i]}"; return 0; fi
  done
  return 1
}

# bcl_cfg <dotted.key> [default]
# Echoes the config value at dotted.key, or [default] if absent/unreadable.
# Booleans render as the literal strings "true"/"false".
bcl_cfg() {
  local key="$1" default="${2:-}" py cfg val
  # Primed path: answered from the map bcl_prime put in the hook's own shell, with no
  # process at all. A key that is absent, JSON-null, or in an unreadable/malformed
  # config is simply not in the map, so it falls through to the caller's default —
  # the same answer the interpreter used to print.
  #
  # There is deliberately NO per-(key,default) memo here any more. One used to exist,
  # with a comment claiming it kept the PostToolUse chain inside its hook budget. It
  # never did: every call site is `$(bcl_cfg ...)`, so the function ran in a subshell
  # and the memo it wrote died with that subshell before the next call could read it.
  # The cache had to move to the CALLER's shell to work, which is what bcl_prime is.
  if _bcl_primed; then
    if _bcl_cfg_lookup "$key"; then printf '%s' "$_BCL_LOOKUP"; return 0; fi
    printf '%s' "$default"; return 0
  fi
  py="$(bcl_python)"; cfg="$(bcl_config_path)"
  if [[ -z "$py" || ! -f "$cfg" ]]; then
    printf '%s' "$default"; return 0
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
  local payload="$1" py
  if _bcl_payload_primed "$payload"; then
    [[ "$_BCL_PL_STATE" == "bad" ]] && return 0
    return 1
  fi
  py="$(bcl_python)"
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
  local py cfg
  # A prime that FAILED must not answer here: "we could not tell" is not "fine".
  # _bcl_primed is false in that case, so we drop through and re-check for real.
  if _bcl_primed; then
    [[ "$_BCL_CFG_STATE" == "malformed" ]] && return 0
    return 1
  fi
  py="$(bcl_python)"; cfg="$(bcl_config_path)"
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
  local payload="$1" py i n
  # Primed path keeps the one-per-line stdout contract: callers outside this file
  # consume it with `mapfile`/`while read`, so the shape must not change.
  if _bcl_payload_primed "$payload"; then
    [[ "$_BCL_PL_STATE" == "ok" ]] || return 0
    n=${#_BCL_PL_PATHS[@]}
    for (( i = 0; i < n; i++ )); do printf '%s\n' "${_BCL_PL_PATHS[$i]}"; done
    return 0
  fi
  py="$(bcl_python)"
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
  local payload="$1" key="$2" py
  # A key the prime did not see cannot exist anywhere in the payload, so the honest
  # answer is the empty string the old reader printed — not a re-spawn.
  if _bcl_payload_primed "$payload"; then
    [[ "$_BCL_PL_STATE" == "ok" ]] || return 0
    _bcl_pl_lookup "$key" && printf '%s' "$_BCL_LOOKUP"
    return 0
  fi
  py="$(bcl_python)"
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

# --- bounded payload read ---------------------------------------------------
# bcl_read_payload <varname>
# Reads the tool payload from stdin into the named variable. Returns 0 on success;
# on failure returns non-zero and sets BCL_READ_ERROR to a one-line reason.
#
# Why this replaced `PAYLOAD="$(cat 2>/dev/null || true)"` everywhere: `cat` blocks
# until EOF, and nothing guarantees EOF. Confirmed on this host — every hook invoked
# with `< /dev/zero` ran until an external bound killed it at 10s. Claude Code does
# close the pipe, but any other caller that does not wedges the hook until Claude
# Code's own timeout KILLS it, and a killed hook never reaches its fail-closed
# branch: the guard silently does not run. Bounding the read converts that into an
# exit code the caller can act on. A failed read is NOT an empty payload — empty
# means "nothing to inspect, exit 0", so callers must route this to the same
# fail-closed path they already use for an unparseable payload.
#
# Both bounds matter, and for different reasons:
#   * time  — stdin that never EOFs (a caller that forgot to close it).
#   * size  — stdin that never EOFs and is FAST. `timeout 5 cat < /dev/zero` returns,
#             but only after piling gigabytes into a shell variable.
_BCL_STDIN_TIMEOUT=5
_BCL_STDIN_MAX=16777216          # 16 MiB; far above any real tool payload
bcl_read_payload() {
  local __var="$1" __data="" __rc=0 __extra
  BCL_READ_ERROR=""
  case "$__var" in
    [A-Za-z_]*) : ;;
    *) BCL_READ_ERROR="internal: invalid destination variable"; return 1 ;;
  esac
  # 2>/dev/null on the whole assignment, not on the command: the message we are
  # suppressing ("ignored null byte in input") is emitted by BASH itself while
  # capturing binary stdin, so redirecting head's stderr would not catch it. Nothing
  # is lost — the exit status is still checked, and the NUL case is detected below.
  { __data="$(bcl_timeout "$_BCL_STDIN_TIMEOUT" head -c "$_BCL_STDIN_MAX")" || __rc=$?; } 2>/dev/null
  if [[ $__rc -ne 0 ]]; then
    printf -v "$__var" '%s' ''
    if bcl_timeout_available; then
      BCL_READ_ERROR="stdin did not reach EOF within ${_BCL_STDIN_TIMEOUT}s"
    else
      BCL_READ_ERROR="stdin could not be read (rc=$__rc)"
    fi
    return 1
  fi
  # Two cases where `head` may have stopped short of the real end of input, and
  # neither is distinguishable from a clean read by looking at $__data alone:
  #   * we hit the byte cap;
  #   * the input was binary. Command substitution DROPS NUL bytes, so /dev/zero
  #     arrives as the empty string — which would otherwise read as "empty payload,
  #     nothing to inspect, exit 0", i.e. the exact fail-open this function exists
  #     to close.
  # Probe for a further byte only in those two cases, so the ordinary path spends no
  # extra processes. ${#} counts CHARACTERS, and UTF-8 uses up to 4 bytes per
  # character, so compare against a quarter of the cap to stay conservative.
  if [[ -z "$__data" || ${#__data} -ge $((_BCL_STDIN_MAX / 4)) ]]; then
    __extra="$( { bcl_timeout "$_BCL_STDIN_TIMEOUT" head -c 1 || true; } 2>/dev/null | wc -c )" || __extra=""
    __extra="${__extra//[^0-9]/}"
    if [[ -z "$__extra" ]]; then
      printf -v "$__var" '%s' ''
      BCL_READ_ERROR="could not determine whether the payload was complete"
      return 1
    fi
    if [[ "$__extra" != "0" ]]; then
      printf -v "$__var" '%s' ''
      BCL_READ_ERROR="payload exceeded ${_BCL_STDIN_MAX} bytes, or contains binary data"
      return 1
    fi
  fi
  printf -v "$__var" '%s' "$__data"
  return 0
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
