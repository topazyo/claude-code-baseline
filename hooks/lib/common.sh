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

# Guard against double-sourcing (dispatcher + module may both source us). Re-running
# this file in a shell that already sourced it would wipe its primed state below.
#
# The guard is an ARRAY ELEMENT, index 1, never a plain variable. bash imports every
# environment variable as a scalar, and a scalar's value sits at index 0; it cannot
# import an array at all. So no environment variable can pre-set index 1, which matters
# because this check runs before the scrub of inherited cache slots further down. As a
# scalar it could: an inherited _BCL_SOURCED (a parent shell, a settings.json `env`
# block) made every hook return from this file with no bcl_ helper defined, so each
# guard failed instead of checking. The unset drops such an inherited value, export
# included, before the array takes its name.
# This covers environment VARIABLES only. Code that runs before this file is stopped
# by the launch instead: every baseline hook, and every child the dispatcher starts,
# runs as `bash -p`, which does not read a BASH_ENV startup file, import exported
# functions (BASH_FUNC_*), or apply SHELLOPTS/BASHOPTS. A -p shell still EXPORTS
# BASH_ENV and passes exported functions on, so a bash started without -p from a hook
# would act on them (see the unset below). The shell Claude Code itself uses to run the
# hook command string is outside any hook's reach; config-guard, install.sh and
# tools/baseline-status.sh report such values in the settings files.
# Subshells inherit the array, so they still skip a second source; child processes
# (the dispatcher runs each module with `bash -p`) inherit nothing and load fresh.
[[ -n "${_BCL_SOURCED[1]:-}" ]] && return 0
unset -v _BCL_SOURCED
_BCL_SOURCED=([1]=1)

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
for _bcl_v in ${!_BCL_CFG_@} ${!_BCL_PL_@} ${!_BCL_PRIME_@} ${!_BCL_NOTICE@}; do unset -v "$_bcl_v"; done
# BCL_READ_ERROR, _BCL_LOOKUP, _BCL_STDIN_TIMEOUT and _BCL_STDIN_MAX are reassigned
# below; unsetting them first also drops the export an inherited copy carries, so it
# is not handed on to every child process. A new global needs adding here too — but
# never widen this to ${!_BCL_@}, which would also unset the source guard above.
# _BCL_PY must stay UNSET, not empty: bcl_python tests ${_BCL_PY+x}, and an empty
# value would be cached as "no interpreter".
unset -v _BCL_PY BCL_READ_ERROR _BCL_LOOKUP _BCL_STDIN_TIMEOUT _BCL_STDIN_MAX _bcl_v

# The hook tree this library belongs to: the parent of lib/, as this file was sourced.
# Every hook sources "$HERE/../lib/common.sh" with HERE made absolute, so this is an
# absolute path taken from the hook's own command line, never from anything in the
# project. A relative or unknown path is left empty, which reads as managed (the safe
# side; see _bcl_cfg_scope). Recorded now, because a hook may cd before a later lookup.
case "${BASH_SOURCE[0]}" in
  /*/*|[A-Za-z]:*/*) _BCL_CFG_ROOT="${BASH_SOURCE[0]%/*}/.." ;;
  *)                 _BCL_CFG_ROOT="" ;;
esac

# Inherited values that `bash -p` does not neutralise for us. FUNCNEST still applies
# under -p and caps function nesting, so a hook could not complete its checks.
# POSIXLY_CORRECT (unsetting it leaves posix mode), BASH_COMPAT, EXECIGNORE, CDPATH
# and GLOBIGNORE change how bash parses, resolves commands, paths and globs (bash
# 3.2's -p keeps the last two). BASH_ENV a -p shell ignores but
# still exports, so a plain-bash program a hook starts (bats, the sh git or npm spawn)
# would run the file it names. Every hook sources this file at top level before its
# first function call, so this lands in time. Exported functions cannot be dropped this
# way (their names are not identifiers); only a -p child ignores them, which is why the
# dispatcher starts its children with -p.
unset -v FUNCNEST POSIXLY_CORRECT BASH_COMPAT EXECIGNORE CDPATH GLOBIGNORE BASH_ENV

# Primed state. Declared unconditionally so `set -u` is safe and so an inherited
# scalar of the same name cannot masquerade as one of these arrays.
_BCL_PRIME_STATE=""     # "" | ok | failed | nopy   (only "ok" is authoritative)
_BCL_PRIME_DIR=""       # CLAUDE_PROJECT_DIR as it stood when we primed
_BCL_PRIME_KEY=""       # resolved baseline.config.json path we primed from
_BCL_CFG_STATE=""       # ok | absent | malformed
_BCL_CFG_ERROR=""       # why a malformed config could not be read (bcl_config_malformed)
_BCL_CFG_BAD_FILE=""    # which one: repo | managed
_BCL_CFG_MANAGED=""     # managed config path, set by _bcl_cfg_scope ("" = per-repo)
_BCL_CFG_IS_MANAGED=1   # 1 when this hook tree is a managed deployment (safe default until _bcl_cfg_scope)
_BCL_CFG_KEYS=(); _BCL_CFG_VALS=()
_BCL_PL_STATE=""        # none | empty | ok | bad
_BCL_PL_LEN=-1          # length of the payload bcl_prime was given
_BCL_PL_KEYS=(); _BCL_PL_VALS=(); _BCL_PL_PATHS=()
_BCL_LOOKUP=""          # out-parameter of the two map lookups below
BCL_READ_ERROR=""       # set by bcl_read_payload on failure
_BCL_NOTICE=""          # lines bcl_say printed; surfaced on exit 0 (see bcl_notice_event)
_BCL_NOTICE_EVENT=""    # hook event a wired script declared; "" = never emit
_BCL_NOTICE_TMP=""      # dispatcher's child-stderr file; removed by the EXIT trap

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
#
# Every launch of this interpreter by the baseline's own helpers passes `-I -S -X utf8`,
# right after the interpreter (auto-format's black and run-tests' pytest run the repo's
# own code by design and are not isolated). Without it, `python -c` and `python -` put the working directory —
# normally the project the agent is editing — first on sys.path, every launch honours
# PYTHONPATH and the user site, and the interpreter's site-packages runs its .pth files
# (an activated in-project .venv puts that directory inside the project). Any of these
# lets a file written into the project be imported by the hooks' own helpers and decide
# what they report.
#   -I       drops the working and script directories from sys.path, and ignores
#            PYTHON* variables and the user site.
#   -S       skips site-packages entirely (.pth files, sitecustomize). The helpers
#            import only the standard library, so they need nothing from it.
#   -X utf8  decodes stdin and encodes stdout as UTF-8 on every platform. -I ignores
#            PYTHONUTF8/PYTHONIOENCODING, and without UTF-8 mode Windows reads
#            a non-ASCII command, or prints a non-ASCII rule message, in its
#            ANSI code page.
# tests/test_hooks.sh checks that every launch keeps all three.
#
# What this does not cover: the interpreter itself is the first python3/python on
# PATH. One that lives inside the project (an in-project virtualenv), or that a
# version-manager shim picks from a project file such as .python-version, is only
# as trustworthy as that directory. One that is found but cannot run is caught by
# bcl_prime, which then reports no interpreter.
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

# --- the hooks' own git -------------------------------------------------------
# Every git the hooks run goes through this. A repository's config can make git start a
# program, and the hooks run outside Claude Code's sandbox. Switched off for these calls
# only (a command-line -c outranks every config file):
#   core.fsmonitor=        runs on any index read. Empty, not false: git 2.16-2.35 read
#                          the value as a program path, where only empty means none; 2.36+
#                          read empty as false.
#   core.hooksPath=/dev/null, hook.post-index-change.enabled=false, hook.<name>.enabled=false
#                          git add, and a diff's index refresh, write the index and run
#                          post-index-change: from a hooks directory, or a hook.<name>
#                          config entry (git 2.54+), which core.hooksPath does not reach.
#                          The event switch is git 2.55+, so each configured hook is
#                          also switched off by name (see bcl_git_init), through
#                          GIT_CONFIG_KEY_<n>: -c splits at the first `=`, and a hook
#                          name may hold one. That replaces any GIT_CONFIG_COUNT the
#                          session started with (config-guard reports GIT_CONFIG_* in a
#                          settings env block).
#   GIT_NO_LAZY_FETCH=1, protocol.allow=never, protocol.<name>.allow=never
#                          a repository set up as a partial clone fetches a missing
#                          object on demand, through a transport its config chooses
#                          (remote.<name>.uploadpack, core.sshCommand, an ext:: URL). The
#                          variable is git 2.44+. On older git the protocol keys refuse
#                          the transports; each per-protocol key is given too, because a
#                          repository's own protocol.<name>.allow outranks protocol.allow.
#   --literal-pathspecs    a path is a name, never a pattern (`git add -- '*'`). The
#                          GIT_*_PATHSPECS variables are pinned off: git refuses to run
#                          when one is set beside the literal mode.
# Not covered: a repository's filter driver (filter.<name>.clean/.process with a
# .gitattributes entry) still runs inside git add and a diff of a working-tree file, as it
# does for the user's own git add; its name is not known in advance, and dropping filters
# would change what git add stages (git-lfs pointers, line endings).
_BCL_GIT_ENV=()      # GIT_CONFIG_COUNT/KEY_<n>/VALUE_<n> words; filled by bcl_git_init
# bcl_git_init: list the repository's configured hooks once, from the directory the
# hook's git calls run in. Call it there, in the hook's own shell: a $(...) or <(...) is
# a subshell, so a list made inside one would be made again on every call.
bcl_git_init() {
  local name i=0
  _BCL_GIT_ENV=()
  # Reading config runs nothing: no index, no hook, no fetch.
  while IFS= read -r -d '' name; do
    name="${name#hook.}"
    _BCL_GIT_ENV+=("GIT_CONFIG_KEY_$i=hook.${name%.command}.enabled" "GIT_CONFIG_VALUE_$i=false")
    i=$((i + 1))
  done < <(command git config -z --name-only --get-regexp '^hook\..*\.command$' 2>/dev/null)
  _BCL_GIT_ENV+=("GIT_CONFIG_COUNT=$i")
}
bcl_git() {
  (( ${#_BCL_GIT_ENV[@]} )) || bcl_git_init
  (
    for kv in "${_BCL_GIT_ENV[@]}"; do export "$kv"; done
    export GIT_NO_LAZY_FETCH=1 GIT_GLOB_PATHSPECS=0 GIT_NOGLOB_PATHSPECS=0 GIT_ICASE_PATHSPECS=0
    exec git -c core.fsmonitor= -c core.hooksPath=/dev/null \
      -c hook.post-index-change.enabled=false -c protocol.allow=never \
      -c protocol.file.allow=never -c protocol.ssh.allow=never -c protocol.ext.allow=never \
      -c protocol.git.allow=never -c protocol.http.allow=never -c protocol.https.allow=never \
      -c protocol.ftp.allow=never -c protocol.ftps.allow=never --literal-pathspecs "$@"
  )
}

# --- repo + config location -------------------------------------------------
bcl_repo_root() {
  if [[ -n "${CLAUDE_PROJECT_DIR:-}" ]]; then
    printf '%s' "$CLAUDE_PROJECT_DIR"
  else
    bcl_git rev-parse --show-toplevel 2>/dev/null || pwd
  fi
}

bcl_config_path() {
  printf '%s/.claude/baseline.config.json' "$(bcl_repo_root)"
}

# _bcl_cfg_scope -> sets _BCL_CFG_IS_MANAGED and _BCL_CFG_MANAGED in THIS shell (call it
# plainly, not in $( )). A hook tree that install.sh put into a repo carries the marker
# INSTALL_SCOPE; one without it is a managed deployment of the source hooks/ under
# <BASELINE_PREFIX>, run by managed settings for every repo. There, the managed keys
# (enforcement, failClosed, guardrails.<name>.enabled, modules.runTests.enabled — the
# posture and every switch that can disarm the floor or run repo code) come ONLY from
# <BASELINE_PREFIX>/managed.config.json, and the repo's values are ignored; with no
# managed config each falls to its caller's default (block, fail closed, commandGuard
# on, autoFormat and runTests off). Every other key still comes from the repo. The
# decision reads only the hook's own tree, never a path inside the project, so a link
# the repo plants cannot change it. tools/baseline-status.sh, which reports per-repo
# installs from the source tree, sets _BCL_CFG_PER_REPO=1 after sourcing this file; the
# environment cannot, because every _BCL_CFG_ name is unset when this file loads.
_bcl_cfg_scope() {
  if [[ "${_BCL_CFG_PER_REPO:-}" == 1 ]] \
     || [[ -n "$_BCL_CFG_ROOT" && -f "$_BCL_CFG_ROOT/INSTALL_SCOPE" ]]; then
    _BCL_CFG_IS_MANAGED=0; _BCL_CFG_MANAGED=""
  else
    _BCL_CFG_IS_MANAGED=1
    _BCL_CFG_MANAGED="${_BCL_CFG_ROOT:+$_BCL_CFG_ROOT/managed.config.json}"
  fi
}

# Python shared by every config reader (the prime, bcl_cfg, bcl_config_malformed), so
# the managed-key rule and the file reading cannot drift apart between them.
_BCL_CFG_RULE_SRC='
import json, os


def bcl_managed_key(path):
    # Judged on the key as bash will see it: q() strips NUL, so a repo key spelled with
    # one must not slip past as a different string and then shadow a managed key.
    p = path.replace("\x00", "")
    if p in ("enforcement", "failClosed", "modules.runTests.enabled"):
        return True
    parts = p.split(".")
    return len(parts) == 3 and parts[0] == "guardrails" and parts[2] == "enabled"


def bcl_read_cfg(path):
    """(data, error): data None when absent or unreadable; error "" unless unreadable.
    Bytes in, so UTF-8 with or without a BOM and UTF-16/32 all read."""
    if not path or not os.path.isfile(path):
        return None, ""
    try:
        with open(path, "rb") as fh:
            data = json.loads(fh.read())
    except json.JSONDecodeError as exc:
        return None, "line %d column %d: %s" % (exc.lineno, exc.colno, exc.msg)
    except Exception as exc:
        return None, type(exc).__name__
    if not isinstance(data, dict):
        return None, "the top level is not a JSON object"
    return data, ""
'

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
# Managed deployment (see _bcl_cfg_scope): "1" plus the managed config path ("" if the
# hook tree's own path is unknown, which leaves only the callers' defaults).
IS_MANAGED = len(sys.argv) > 3 and sys.argv[3] == "1"
MANAGED_PATH = sys.argv[4] if len(sys.argv) > 4 else ""

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


# bcl_read_cfg (from _BCL_CFG_RULE_SRC, prepended to this script) reads bytes, the
# same reading as bcl_cfg, bcl_config_malformed and the command-guard matcher. A
# managed config that cannot be read is malformed too: the managed floor fails closed.
cfg_data, cfg_error = bcl_read_cfg(CFG_PATH)
managed_data, managed_error = bcl_read_cfg(MANAGED_PATH) if IS_MANAGED else (None, "")
cfg_bad_file = ""
if managed_error:
    cfg_state, cfg_error, cfg_bad_file = "malformed", managed_error, "managed"
elif cfg_error:
    cfg_state, cfg_bad_file = "malformed", "repo"
else:
    cfg_state = "ok" if cfg_data is not None else "absent"

cfg_keys = []
cfg_vals = []


def flatten(node, prefix, depth, keep=lambda path: True):
    # keep(path) decides which entries are emitted; the walk itself always descends.
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
        if keep(path):
            if len(cfg_keys) >= MAX_CFG_ENTRIES:
                raise Overflow()
            cfg_keys.append(path)
            cfg_vals.append(render(v))
        if isinstance(v, dict):
            flatten(v, path, depth + 1, keep)


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
    if IS_MANAGED:
        # Managed entries FIRST (a lookup answers with the first match), and only the
        # managed keys; then the repo's entries without any managed key.
        if managed_data is not None:
            flatten(managed_data, "", 0, bcl_managed_key)
        if cfg_data is not None:
            flatten(cfg_data, "", 0, lambda path: not bcl_managed_key(path))
    elif cfg_data is not None:
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
emit("_BCL_CFG_ERROR", cfg_error)
emit("_BCL_CFG_BAD_FILE", cfg_bad_file)
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

# >>> definition paths (scope-guard) >>>
# _BCL_DEFPATH_SRC decides whether a Write/Edit target is a path only a human may write:
# subagent, skill and command definitions, plugins, user settings, .claude.json and
# .mcp.json (see scope-guard.sh for why). It is source text, never an imported module:
# an import would read and write __pycache__ inside the installed hook tree, which the
# drift check skips, so a planted .pyc could run in place of this reviewed code.
# Two tails run it: _BCL_DEFPATH_PRIME_TAIL is appended to the payload prime only when
# a hook asks (bcl_prime "$PAYLOAD" definition) and reuses the parsed payload;
# _BCL_DEFPATH_MAIN_TAIL runs it standalone, payload on stdin and the project root as
# argv[1], when the prime failed. Each prints a verdict and the resolved path.
IFS='' read -r -d '' _BCL_DEFPATH_SRC <<'DEFPATHPY' || true
# --- _BCL_DEFPATH_SRC: is a Write/Edit target a path only a human may write? ---
# Human-only targets (see scope-guard.sh): subagent/skill/command definitions, hook
# scripts, plugins, user settings, .claude.json, .mcp.json and the default
# securityDefaults rules file. Path-only: no file content is read.
# Verdicts: "yes" protected, "no" not, "nopath" the payload names no file_path,
# "unparsed" the payload is not a JSON object, "cannot" could not judge (fail closed).
import os as _d_os
import re as _d_re

_D_NT = _d_os.name == "nt"
# Under <project>/.claude and the user's config home.
_D_DIRS = ("agents", "skills", "commands", "hooks")
# main's rule: a ../ below .claude/ may step back into a protected directory.
_D_RAW_RE = _d_re.compile(
    r"/\.claude/(?:agents|skills|commands|plugins|hooks)/|/\.claude/[^/]+/\.\./"
    r"|/\.mcp\.json$|/\.claude\.json$|/\.claude/security-defaults\.json$")
# Generated 8.3 names for .claude, .claude.json and .mcp.json (CLAUDE~1, CL3F2A~1, MCP~1.JSO).
_D_SHORT_RE = _d_re.compile(r"(?:cl[0-9a-z]{0,4}|mcp[0-9a-z]{0,3})~[0-9]+(?:\.[0-9a-z]{1,3})?")
_D_DRIVE_RE = _d_re.compile(r"[A-Za-z]:")
_D_HDV_RE = _d_re.compile(r"globalroot\\device\\harddiskvolume[0-9]+(?:\\|$)")
# A host Windows may read as an address: dotted or bare numbers, hex, IPv6 (a `:` is
# refused before this), or the IPv6 literal form. Any of them may be this machine.
_D_ADDR_RE = _d_re.compile(r"[0-9.]+|0x[0-9a-f.x]*|.*\.ipv6-literal\.net")
_D_WALK_BOUND = 20000
_D_MAX_DEPTH = 64


class _DCannot(Exception):
    pass


def _d_norm(path):
    """`\\` as `/`, `//` and `/./` collapsed, casefolded, with a leading `/`."""
    p = "/" + path.replace("\\", "/")
    while "//" in p:
        p = p.replace("//", "/")
    while "/./" in p:
        p = p.replace("/./", "/")
    return p.casefold()


def _d_raw_hit(path):
    return bool(_D_RAW_RE.search(_d_norm(path)))


def _d_short_hit(path):
    return any(_D_SHORT_RE.fullmatch(c) for c in _d_norm(path).split("/"))


def _d_trim(p):
    """Win32 drops trailing dots and spaces from each path component (`x.json.`)."""
    return "\\".join(c if c in (".", "..") else c.rstrip(". ") for c in p.split("\\"))


def _d_win(path, trim=True):
    """The canonical Windows reading of a path: (kind, path).
    "local": a drive path (X:\\...) or a relative one; "unc": \\\\host\\share...;
    "volume": a volume with no drive letter (\\\\?\\Volume{...}, GLOBALROOT\\Device\\
    HarddiskVolumeN), resolvable but never equal to a drive path; "cannot": any other
    device namespace (pipes, \\Device\\Mup, ...), an NTFS stream (`x::$DATA`), a
    drive-relative path (`C:x`). Every prefix Windows accepts is peeled first:
    \\\\?\\, \\\\.\\, \\??\\, \\\\?\\UNC\\, GLOBALROOT\\??\\; any two leading
    separators are a UNC or device prefix (`\\/h` and `/\\h` too)."""
    p = path.replace("/", "\\")
    kind = None
    for _ in range(8):
        if p[:4] not in ("\\\\?\\", "\\\\.\\", "\\??\\"):
            break
        ns = p[4:]
        low = ns.casefold()
        if _D_DRIVE_RE.match(ns) and ns[2:3] in ("", "\\"):
            p = ns
        elif low.startswith("unc\\"):
            p = "\\\\" + ns[4:]
        elif low.startswith("globalroot\\??\\"):
            p = "\\??\\" + ns[14:]
        elif low.startswith("volume{") or _D_HDV_RE.match(low):
            kind = "volume"
            break
        else:
            return "cannot", None
    else:
        return "cannot", None
    if kind == "volume":
        body = p[4:]
    elif p[:2] == "\\\\":
        kind, body = "unc", p[2:]
    elif _D_DRIVE_RE.match(p):
        if p[2:3] not in ("", "\\"):
            return "cannot", None
        kind, body = "local", p[2:]
    else:
        kind, body = "local", p
    if ":" in body:
        return "cannot", None
    return kind, (_d_trim(p) if trim else p)


def _d_loopback(host):
    h = host.strip("[]")
    if h in ("", "localhost", "localhost.", ".", "?") or _D_ADDR_RE.fullmatch(h):
        return True
    try:
        import socket
        name = socket.gethostname().casefold()
    except Exception:
        return True
    return h == name or h.split(".")[0] == name.split(".")[0]


def _d_classify(path, nt, trim=True):
    """("local" | "volume", path to resolve) | ("remote", path) | ("cannot", None).
    A remote UNC path is never touched: resolving it opens an SMB connection before
    the permission prompt. A loopback or address-literal host could alias any local
    file, so it is not judged. WSL's \\\\wsl$ and \\\\wsl.localhost are local."""
    if not nt:
        return "local", path
    kind, p = _d_win(path, trim)
    if kind != "unc":
        return kind, p
    host = p[2:].split("\\", 1)[0].casefold()
    if host in ("wsl$", "wsl.localhost"):
        return "local", p
    if _d_loopback(host):
        return "cannot", None
    return "remote", p


def _d_real(path):
    try:
        return _d_os.path.realpath(path)
    except (OSError, ValueError):
        raise _DCannot()


def _d_key(path, nt=_D_NT):
    """A comparison key: the canonical Windows reading on nt, `/`, casefolded."""
    if nt:
        kind, p = _d_win(path)
        if p is not None:
            path = p
    return path.replace("\\", "/").casefold().rstrip("/")


def _d_protected(project, env, nt=_D_NT):
    """Keys of the protected directories and files, for comparing, and their real
    paths, for the POSIX hard-link checks (a key need not exist on disk)."""
    home = _d_os.path.expanduser("~")
    cfg = env.get("CLAUDE_CONFIG_DIR") or _d_os.path.join(home, ".claude")
    plugins = env.get("CLAUDE_CODE_PLUGIN_CACHE_DIR") or _d_os.path.join(cfg, "plugins")
    dirs = [_d_os.path.join(project, ".claude", d) for d in _D_DIRS]
    dirs += [_d_os.path.join(cfg, d) for d in _D_DIRS] + [plugins]
    files = [_d_os.path.join(cfg, "settings.json"), _d_os.path.join(cfg, "settings.local.json"),
             _d_os.path.join(home, ".claude.json"), _d_os.path.join(project, ".mcp.json"),
             _d_os.path.join(project, ".claude", "security-defaults.json")]
    if env.get("CLAUDE_CONFIG_DIR"):
        files.append(_d_os.path.join(cfg, ".claude.json"))
    dreals = [_d_real(d) for d in dirs]
    freals = [_d_real(f) for f in files]
    return ([_d_key(d, nt) for d in dreals], [_d_key(f, nt) for f in freals], dreals, freals)


def _d_contained(real, dirs, files, nt=_D_NT):
    k = _d_key(real, nt)
    return k in files or any(k == d or k.startswith(d + "/") for d in dirs)


def _d_link_names(real):
    """Every name of a Windows file (its hard links), as full paths."""
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.FindFirstFileNameW.restype = wintypes.HANDLE
    k32.FindFirstFileNameW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                       ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR]
    k32.FindNextFileNameW.restype = wintypes.BOOL
    k32.FindNextFileNameW.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
                                      wintypes.LPWSTR]
    k32.FindClose.argtypes = [wintypes.HANDLE]
    size = 32768
    buf = ctypes.create_unicode_buffer(size)
    n = wintypes.DWORD(size)
    h = k32.FindFirstFileNameW(real, 0, ctypes.byref(n), buf)
    if h in (None, wintypes.HANDLE(-1).value, -1):
        raise _DCannot()
    drive = _d_os.path.splitdrive(real)[0]
    names = []
    try:
        while True:
            names.append(drive + buf.value)          # names are volume-relative
            if len(names) > 1024:
                raise _DCannot()
            n = wintypes.DWORD(size)
            if not k32.FindNextFileNameW(h, ctypes.byref(n), buf):
                if ctypes.get_last_error() != 38:     # ERROR_HANDLE_EOF
                    raise _DCannot()
                break
    finally:
        k32.FindClose(h)
    return names


def _d_hardlinked(real, prot, nt, link_names):
    """Is the existing file at real also reachable under a protected name? Only a file
    with more than one link is looked at, so ordinary edits pay nothing."""
    import stat as _d_stat
    dirs, files, dreals, freals = prot
    try:
        st = _d_os.stat(real)
    except FileNotFoundError:
        return False
    except (OSError, ValueError):
        raise _DCannot()
    if not _d_stat.S_ISREG(st.st_mode) or st.st_nlink <= 1:
        return False
    if nt:
        try:
            names = link_names(real)
        except _DCannot:
            raise
        except Exception:
            raise _DCannot()
        return any(_d_raw_hit(n) or _d_contained(n, dirs, files, nt) for n in names if n)
    for f in freals:
        try:
            fs = _d_os.stat(f)
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            raise _DCannot()
        if (fs.st_dev, fs.st_ino) == (st.st_dev, st.st_ino):
            return True
    seen = 0
    stack = [(d, 0) for d in dreals]
    while stack:
        top, depth = stack.pop(0)
        try:
            it = _d_os.scandir(top)
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            raise _DCannot()
        with it:
            for e in it:
                seen += 1
                if seen > _D_WALK_BOUND:
                    raise _DCannot()
                try:
                    if e.is_dir(follow_symlinks=False):
                        if depth < _D_MAX_DEPTH:
                            stack.append((e.path, depth + 1))
                    elif e.inode() == st.st_ino and e.stat(follow_symlinks=False).st_dev == st.st_dev:
                        return True
                except OSError:
                    raise _DCannot()
    return False


def _d_literal(p):
    """The \\\\?\\ spelling of a canonical Windows path, which Win32 does not trim: a drive
    path gets the prefix, a UNC one (WSL) becomes \\\\?\\UNC\\..., a volume path already
    has it. None for a relative path."""
    if p.startswith("\\\\?\\"):
        return p
    if p.startswith("\\\\"):
        return "\\\\?\\UNC\\" + p[2:]
    if _D_DRIVE_RE.match(p):
        return "\\\\?\\" + p
    return None


def _d_resolved(local, project, env, nt, link_names, literal=False):
    """(verdict, real path) for an absolute local path. literal: judge the spelling as
    written (a \\\\?\\ path), not Win32's trimmed one -- see _d_judge."""
    real = _d_real(local)
    probe = real
    if nt:
        # What it resolved to is classified again: a link may lead to a network or
        # loopback path, and a volume with no drive letter (mounted as a folder)
        # matches no key, so it is not judged (fails closed).
        rkind, rp = _d_classify(real, True, trim=not literal)
        if rkind in ("cannot", "volume"):
            return "cannot", ""
        if rkind == "remote":
            return ("yes" if _d_raw_hit(rp) or _d_short_hit(rp) else "no"), rp
        real = rp
        probe = _d_literal(rp) if literal else real
        if probe is None:
            probe = real
    if _d_raw_hit(real):
        return "yes", real
    prot = _d_protected(project, env, nt)
    if _d_contained(real, prot[0], prot[1], nt):
        return "yes", real
    if _d_hardlinked(probe, prot, nt, link_names or _d_link_names):
        return "yes", real
    return "no", real


def _d_judge(path, project, env, nt=_D_NT, link_names=None):
    """(verdict, real path or "") for one file_path."""
    if not path:
        return "no", ""
    if "\x00" in path:
        return "cannot", ""
    if _d_raw_hit(path):
        return "yes", ""
    kind, local = _d_classify(path, nt)
    if kind == "cannot":
        return "cannot", ""
    if _d_raw_hit(local):
        return "yes", ""
    if kind == "remote":
        return ("yes" if _d_short_hit(local) else "no"), ""
    try:
        if not _d_os.path.isabs(local):
            local = _d_os.path.join(project, local)
        v, real = _d_resolved(local, project, env, nt, link_names)
        if nt and kind in ("local", "volume") and v == "no":
            # Win32 drops trailing dots and spaces, but a runtime that writes through
            # \\?\ (Node, Bun) keeps them: an existing link named `ag.` or `h.md.` is
            # another file. When trimming changed the path -- a drive, volume or WSL
            # path alike -- judge the literal \\?\ spelling too; yes or cannot wins.
            lkind, lit = _d_classify(path, nt, trim=False)
            if lkind == kind and lit is not None:
                if not _d_os.path.isabs(lit):
                    lit = _d_os.path.join(project, lit)
                lit_ns = _d_literal(lit)
                if lit != local and lit_ns is not None:
                    v2, r2 = _d_resolved(lit_ns, project, env, nt, link_names, True)
                    if v2 != "no":
                        return v2, r2
    except _DCannot:
        return "cannot", ""
    return v, real


def _d_paths(obj, acc, depth):
    if depth > _D_MAX_DEPTH:
        raise _DCannot()
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "file_path":
                acc.append(v)
            _d_paths(v, acc, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            _d_paths(v, acc, depth + 1)


def bcl_definition_verdict(obj, project, env=None, nt=_D_NT, link_names=None):
    """The verdict for a parsed payload (None when it did not parse)."""
    env = _d_os.environ if env is None else env
    if not isinstance(obj, dict):
        return "unparsed", ""
    try:
        acc = []
        _d_paths(obj, acc, 0)
    except (_DCannot, RecursionError):
        return "cannot", ""
    if any(not isinstance(p, str) for p in acc):
        return "cannot", ""
    acc = [p for p in acc if p]
    if not acc:
        return "nopath", ""
    out, shown = "no", ""
    for p in acc:
        try:
            v, real = _d_judge(p, project, env, nt, link_names)
        except Exception:
            v, real = "cannot", ""
        if v == "yes":
            return "yes", real or p
        if v != "no":
            out = "cannot"
        shown = shown or real
    return out, shown
DEFPATHPY

IFS='' read -r -d '' _BCL_DEFPATH_PRIME_TAIL <<'DEFPATHPY' || true
try:
    _d_obj = pdata if globals().get("pl_state") == "ok" else None
    _d_v, _d_r = bcl_definition_verdict(_d_obj, os.path.dirname(os.path.dirname(CFG_PATH)))
except Exception:
    _d_v, _d_r = "cannot", ""
sys.stdout.buffer.write(("_BCL_PL_DEFINITION=" + q(_d_v) + "\n_BCL_PL_DEFREAL=" + q(_d_r) + "\n")
                        .encode("utf-8", "backslashreplace"))
DEFPATHPY

IFS='' read -r -d '' _BCL_DEFPATH_MAIN_TAIL <<'DEFPATHPY' || true
import json as _d_json
import sys as _d_sys
try:
    _d_obj = _d_json.loads(_d_sys.stdin.buffer.read().decode("utf-8"))
except Exception:
    _d_obj = None
try:
    _d_v, _d_r = bcl_definition_verdict(_d_obj, _d_sys.argv[1])
except Exception:
    _d_v, _d_r = "cannot", ""
_d_sys.stdout.buffer.write((_d_v + "\n" + _d_r.replace("\n", " ") + "\n")
                           .encode("utf-8", "backslashreplace"))
DEFPATHPY
# <<< definition paths (scope-guard) <<<

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
  local out rc=0 want=0 root src="$_BCL_CFG_RULE_SRC$_BCL_PRIME_SRC"
  [[ $# -gt 0 ]] && want=1
  _BCL_PRIME_STATE=""
  # bcl_prime "$PAYLOAD" definition: also judge the payload's file_path (see
  # _BCL_DEFPATH_SRC). Opt-in, so every other hook's prime runs exactly the script
  # it ran before, and a fault in that code can fail only the hook that asked.
  if [[ "${2:-}" == definition ]]; then
    src+="$_BCL_DEFPATH_SRC$_BCL_DEFPATH_PRIME_TAIL"
    unset -v _BCL_PL_DEFINITION _BCL_PL_DEFREAL
  fi

  # Called, not substituted, so _BCL_PY lands in the caller's shell: every later
  # `$(bcl_python)` then answers from the memo instead of re-probing.
  bcl_python >/dev/null

  # bcl_repo_root/bcl_config_path inlined: calling them would be two more command
  # substitutions, and with CLAUDE_PROJECT_DIR set (Claude Code always sets it) the
  # answer needs no process at all.
  if [[ -n "${CLAUDE_PROJECT_DIR:-}" ]]; then
    root="$CLAUDE_PROJECT_DIR"
  else
    root="$(bcl_git rev-parse --show-toplevel 2>/dev/null)"
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
  _bcl_cfg_scope
  if [[ $want -eq 1 ]]; then
    out="$(bcl_timeout "$_BCL_PRIME_TIMEOUT" "$_BCL_PY" -I -S -X utf8 -c "$src" \
      "$_BCL_PRIME_KEY" 1 "$_BCL_CFG_IS_MANAGED" "$_BCL_CFG_MANAGED" <<< "$1")" || rc=$?
  else
    out="$(bcl_timeout "$_BCL_PRIME_TIMEOUT" "$_BCL_PY" -I -S -X utf8 -c "$src" \
      "$_BCL_PRIME_KEY" 0 "$_BCL_CFG_IS_MANAGED" "$_BCL_CFG_MANAGED" </dev/null)" || rc=$?
  fi
  # No output at all, other than the script's own bounds exit (3) or a timeout
  # (124/137), and the interpreter cannot even import the modules the helpers use: it
  # can run none of them — a stub, a broken shim, one that rejects -I/-S, a legacy
  # virtualenv whose stdlib only its own site.py adds, one that needs PYTHONHOME.
  # Treat it as no interpreter, so every hook takes its "Python unavailable" branch
  # and fails closed. Left to the per-call helpers, the same broken interpreter made
  # bcl_cfg return "" for every key, so command-guard read itself as disabled and
  # allowed the call. The import probe runs only on this failure path; when it
  # succeeds, the prime script itself failed (e.g. on an unencodable value) and the
  # per-call helpers below take over as before.
  if [[ -z "$out" && $rc -ne 3 && $rc -ne 124 && $rc -ne 137 ]] \
     && ! bcl_timeout "$_BCL_PRIME_TIMEOUT" "$_BCL_PY" -I -S -X utf8 -c 'import json, os, re, shlex, sys' >/dev/null 2>&1 </dev/null; then
    _BCL_PY=""
    _BCL_PRIME_STATE=nopy
    return 0
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

# The per-call lookup script (bcl_cfg), run after _BCL_CFG_RULE_SRC.
_BCL_CFG_GET_SRC='
import sys
cfg, key = sys.argv[1], sys.argv[2]
default = sys.argv[3] if len(sys.argv) > 3 else ""
is_managed = len(sys.argv) > 4 and sys.argv[4] == "1"
managed_path = sys.argv[5] if len(sys.argv) > 5 else ""
if is_managed and bcl_managed_key(key):
    data, _err = bcl_read_cfg(managed_path)
else:
    data, _err = bcl_read_cfg(cfg)
if data is None:
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
'

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
  # Per-call path: no prime, or a prime that failed. A repo can force the latter (a config
  # past the prime's bounds), so it applies the same managed-key rule as the prime, from
  # the same _BCL_CFG_RULE_SRC: a managed key is read only from the managed config.
  py="$(bcl_python)"; cfg="$(bcl_config_path)"
  _bcl_cfg_scope
  if [[ -z "$py" ]] || [[ $_BCL_CFG_IS_MANAGED -eq 0 && ! -f "$cfg" ]]; then
    printf '%s' "$default"; return 0
  fi
  val="$("$py" -I -S -X utf8 -c "$_BCL_CFG_RULE_SRC$_BCL_CFG_GET_SRC" \
    "$cfg" "$key" "$default" "$_BCL_CFG_IS_MANAGED" "$_BCL_CFG_MANAGED")" \
    || val="$default"   # the script itself always exits 0; non-zero = the interpreter failed
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
# bcl_guardrail_enabled <name> -> 0 unless guardrails.<name>.enabled is false (default
# true). Only JSON false (or the string "false", which renders the same) turns a
# default-on guardrail off: any other value ("TRUE", "False", 1, 0, "", null) leaves it
# on, as bcl_failclosed reads failClosed.
bcl_guardrail_enabled() { [[ "$(bcl_cfg "guardrails.$1.enabled" true)" != "false" ]]; }
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

# --- notices: show an ALLOWED action's hook messages ------------------------
# Claude Code shows the stderr of a hook that exits 0 to no one: it goes to the debug
# log. So under `enforcement: "warn"`, or `failClosed: false`, a violation or a
# control that could not run used to be reported to nobody. On exit 0 the only
# channel is ONE JSON object on stdout (hooks reference): `systemMessage` is shown to
# the user, `hookSpecificOutput.additionalContext` is added to Claude's context
# (PreToolUse and PostToolUse). ConfigChange discards both, so config-guard does not
# opt in; its warn-mode report stays in the debug log (documented in README).
#
# bcl_say <line>...
# Prints each argument as one line to stderr — byte-for-byte what `echo "$line" >&2`
# printed, so every exit-2 path is unchanged — and remembers it. Use it for any
# message a wired hook may print before exiting 0.
bcl_say() {
  local line
  for line in "$@"; do
    printf '%s\n' "$line" >&2
    _BCL_NOTICE+="$line"$'\n'
  done
}

# bcl_allows_with_message -> 0 when this config can let an action through while a hook
# reports something: enforcement "warn", or failClosed false. Same readings as
# bcl_posture / bcl_failclosed, but answered in this shell, with no fork, once primed:
# the dispatcher asks on every edit, and the default posture must not pay for it.
bcl_allows_with_message() {
  local p=block fc=true
  if _bcl_primed; then
    if _bcl_cfg_lookup enforcement; then p="$_BCL_LOOKUP"; fi
    if _bcl_cfg_lookup failClosed; then fc="$_BCL_LOOKUP"; fi
  else
    p="$(bcl_cfg enforcement block)"; fc="$(bcl_cfg failClosed true)"
  fi
  [[ "$p" == "warn" || "$fc" == "false" ]]
}

# bcl_notice_event <PreToolUse|PostToolUse>
# Opt-in, once, by a WIRED script, straight after sourcing this file so that the
# earliest degraded exits are covered too. Installs the EXIT trap that emits the
# remembered lines. Dispatcher children and config-guard never call it, so they can
# never put anything on stdout through this path.
bcl_notice_event() {
  _BCL_NOTICE_EVENT="$1"
  trap _bcl_emit_notice EXIT
}

# _bcl_json_escape <text> -> _BCL_LOOKUP = <text> as JSON string contents (no quotes).
# Pure bash: the "Python unavailable" path must be able to surface too. Replacement
# strings are held in quoted variables so bash 5.2's patsub_replacement (`&` and `\`
# in a replacement) cannot alter them. Bytes are passed through; invalid UTF-8 in a
# repo-supplied message is the reader's to handle (likely replaced, possibly a parse
# failure, which only means the debug log as before), never a different exit code.
_bcl_json_escape() {
  local s="$1" r ch hex
  r='\\';  s=${s//\\/"$r"}
  r='\"';  s=${s//\"/"$r"}
  r='\n';  s=${s//$'\n'/"$r"}
  r='\r';  s=${s//$'\r'/"$r"}
  r='\t';  s=${s//$'\t'/"$r"}
  for hex in 01 02 03 04 05 06 07 08 0b 0c 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f; do
    printf -v ch "\\x$hex"
    if [[ "$s" == *"$ch"* ]]; then r="\\u00$hex"; s=${s//"$ch"/"$r"}; fi
  done
  _BCL_LOOKUP="$s"
}

# _bcl_notice_cut <text> -> stdout: at most 8000 BYTES of <text>, never ending inside
# a UTF-8 sequence. Claude Code caps systemMessage / additionalContext at 10,000
# characters (longer text is moved to a file), so the cut keeps the notice inline.
# Runs in a subshell (only for an oversized notice) so LC_ALL=C cannot leak.
_bcl_notice_cut() {
  local LC_ALL=C s="$1" n=0
  s="${s:0:8000}"
  while (( n < 3 )) && [[ "${s: -1}" == [$'\x80'-$'\xbf'] ]]; do s="${s%?}"; n=$((n + 1)); done
  [[ "${s: -1}" == [$'\xc0'-$'\xff'] ]] && s="${s%?}"
  printf '%s\n… (truncated; the full text is in the hook stderr, see claude --debug)' "$s"
}

# EXIT trap. Never changes the exit status: it does not call `exit`, and bash keeps the
# status the script exited with when the trap returns. Emits only on exit 0 — on exit 2
# Claude Code already shows the stderr, and stdout is ignored.
_bcl_emit_notice() {
  local rc=$?
  set +eu
  # The dispatcher's child-stderr file (bcl_notice_tmp); removed on every exit code.
  if [[ -n "${_BCL_NOTICE_TMP:-}" ]]; then rm -f -- "$_BCL_NOTICE_TMP"; fi
  (( rc == 0 )) || return 0
  [[ -n "${_BCL_NOTICE:-}" && -n "${_BCL_NOTICE_EVENT:-}" ]] || return 0
  local fc=true msg
  bcl_failclosed || fc=false
  msg="[baseline] This action was allowed (enforcement: $(bcl_posture), failClosed: $fc). Hook messages:"$'\n'"${_BCL_NOTICE%$'\n'}"
  if (( ${#msg} > 8000 )); then msg="$(_bcl_notice_cut "$msg")"; fi
  _bcl_json_escape "$msg"
  printf '{"systemMessage":"%s","hookSpecificOutput":{"hookEventName":"%s","additionalContext":"%s"}}\n' \
    "$_BCL_LOOKUP" "$_BCL_NOTICE_EVENT" "$_BCL_LOOKUP"
}

# bcl_system_message <text>
# Shows <text> to the USER only: prints ONE JSON object, {"systemMessage": <text>}, on
# stdout (and <text> on stderr, for the debug log). For a Stop hook this is the only
# exit-0 channel that does not send Claude back to work: Stop's
# hookSpecificOutput.additionalContext and decision:"block" both continue the turn.
# Same 8000-byte cut and escaping as the notices. Call it at most once, as the script's
# only stdout, and never in a script that calls bcl_notice_event (two objects would
# make Claude Code reject both). Empty text prints nothing.
bcl_system_message() {
  local msg="${1-}"
  [[ -n "$msg" ]] || return 0
  printf '%s\n' "$msg" >&2
  if (( ${#msg} > 8000 )); then msg="$(_bcl_notice_cut "$msg")"; fi
  _bcl_json_escape "$msg"
  printf '{"systemMessage":"%s"}\n' "$_BCL_LOOKUP"
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
  printf '%s' "$payload" | "$py" -I -S -X utf8 -c 'import json,sys
try:
    json.load(sys.stdin)
except Exception:
    raise SystemExit(0)
raise SystemExit(1)' && return 0 || return 1
}

# bcl_config_malformed
# Returns 0 (true) when baseline.config.json EXISTS but cannot be read as a JSON
# object — not JSON, not text in UTF-8/16/32, or a top level that is not an object.
# That state would make every lookup return its default (module gating off,
# commandGuard.extraPatterns gone), so every wired hook tests this BEFORE its
# enabled-gate and fails closed. Sets _BCL_CFG_ERROR to the reason. Returns 1 when
# there is no config (defaults apply), it reads fine, or Python is unavailable
# (no-Python handled separately). Call it as `if bcl_config_malformed`, never inside
# $( ): the reason is set in the caller's shell.
bcl_config_malformed() {
  local py cfg out
  # A prime that FAILED must not answer here: "we could not tell" is not "fine".
  # _bcl_primed is false in that case, so we drop through and re-check for real.
  if _bcl_primed; then
    [[ "$_BCL_CFG_STATE" == "malformed" ]] && return 0
    return 1
  fi
  _BCL_CFG_ERROR=""; _BCL_CFG_BAD_FILE=""
  py="$(bcl_python)"; cfg="$(bcl_config_path)"
  _bcl_cfg_scope
  [[ -z "$py" ]] && return 1
  [[ ! -f "$cfg" && ( $_BCL_CFG_IS_MANAGED -eq 0 || ! -f "$_BCL_CFG_MANAGED" ) ]] && return 1
  # "fine" only on an explicit OK line: an interpreter that crashes is not a clean read.
  # The managed config is checked first: on a managed deployment it governs.
  out="$("$py" -I -S -X utf8 -c "$_BCL_CFG_RULE_SRC"'
import sys
if len(sys.argv) > 2 and sys.argv[2] == "1":
    _d, err = bcl_read_cfg(sys.argv[3] if len(sys.argv) > 3 else "")
    if err:
        print("managed\t" + err); raise SystemExit(0)
_d, err = bcl_read_cfg(sys.argv[1])
print("repo\t" + err if err else "OK")' "$cfg" "$_BCL_CFG_IS_MANAGED" "$_BCL_CFG_MANAGED" 2>/dev/null)"
  out="${out%$'\r'}"
  [[ "$out" == "OK" ]] && return 1
  if [[ "$out" == managed$'\t'* || "$out" == repo$'\t'* ]]; then
    _BCL_CFG_BAD_FILE="${out%%$'\t'*}"; _BCL_CFG_ERROR="${out#*$'\t'}"
  else
    _BCL_CFG_BAD_FILE="repo"; _BCL_CFG_ERROR="the check could not run"
  fi
  return 0
}

# bcl_config_malformed_text <hook label>
# The message every hook gives for a config bcl_config_malformed refused (it must have
# just returned 0, so _BCL_CFG_ERROR and _BCL_CFG_BAD_FILE hold the reason).
bcl_config_malformed_text() {
  local why="${_BCL_CFG_ERROR:-unreadable}"
  if [[ "$_BCL_CFG_BAD_FILE" == managed ]]; then
    printf '%s' "[$1] CONTROL COULD NOT RUN — the managed config managed.config.json beside the managed baseline hooks exists but cannot be read ($why), so this hook's settings are unknown and it fails closed. An administrator must fix or delete that file."
  else
    printf '%s' "[$1] CONTROL COULD NOT RUN — .claude/baseline.config.json exists but cannot be read ($why), so this hook's settings are unknown and it fails closed. A human must fix or delete that file; Claude's edit tools are denied it."
  fi
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
  printf '%s' "$payload" | "$py" -I -S -X utf8 -c '
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
  printf '%s' "$payload" | "$py" -I -S -X utf8 -c '
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
# tool call proceeds. (Claude Code 2.1.295+ blocks a timed-out hook wired with
# onFailure:block — the two PreToolUse guards — but that ignores enforcement and
# failClosed; every other hook still fails open, as do older releases most likely
# (unverified).) Bounding
# each child ourselves converts "hook was killed" (fail-open) into "child was
# killed, rc=124" (which callers route through bcl_failclosed_exit). Where `timeout` is absent (stock macOS, minimal images) the
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
# logic *inside* the script can cover. (Since Claude Code 2.1.295 a hook wired with
# onFailure:block — the two PreToolUse guards — blocks on that exit instead; every
# other hook still lets the action proceed, as older releases most likely do
# (unverified).) Every
# launcher in the baseline therefore checks its children itself and routes a
# failure through bcl_failclosed_exit.
#
# We test readability, not the execute bit: children are launched as `bash -p <path>`,
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
