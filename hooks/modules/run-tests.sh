#!/usr/bin/env bash
# claude-code-baseline :: modules/run-tests.sh
#
# PostToolUse module (matcher: Write|Edit). Runs the test/lint tool appropriate
# to each changed file type: pytest for .py, shellcheck + bats for shell,
# yamllint + actionlint for YAML. Missing tools are skipped, not failed.
#
# Config (baseline.config.json):
#   "modules": { "runTests": { "enabled": true } }
#
# Posture: under "block", a test/lint failure exits 2 (full feedback to Claude,
# which must fix it); under "warn", failures are reported but the hook exits 0.
#
# Output: a failing check's output goes to STDERR, the only stream that reaches anyone.
# The dispatcher discards its children's stdout (its own stdout must stay one JSON
# object), passes stderr to Claude on exit 2, and folds it into the shown notice under
# warn. A passing check prints nothing there, so warn mode does not add a notice to
# every edit. The details are the tool's own output, verbatim: repo-controlled text.

set -uo pipefail

# ${BASH_SOURCE[0]%/*} rather than $(dirname ...): dirname is an external binary
# under Git Bash and a fork measures ~21ms here — paid by every hook, on every tool call.
HERE="${BASH_SOURCE[0]%/*}"
[[ "$HERE" == "${BASH_SOURCE[0]}" ]] && HERE=.
HERE="$(cd "$HERE" && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"

# Bounded read before the gate, so one prime can cover both the config and the
# payload. `cat` blocked until EOF and nothing guarantees EOF; a wedged hook is
# killed by Claude Code without ever running its checks.
read_rc=0
bcl_read_payload PAYLOAD || read_rc=1
bcl_prime "$PAYLOAD"

bcl_module_enabled runTests || exit 0

# An unread payload is not fatal HERE, unlike in the guards: the dispatcher passes
# the changed file separately in CLAUDE_TOOL_FILE, and the last-resort target is
# "." — the whole suite, i.e. more checking rather than less. Say so anyway; a
# silent switch to a different target is how a "passed" line stops meaning anything.
if [[ $read_rc -ne 0 ]]; then
  echo "[run-tests] NOTE: could not read the tool payload from stdin ($BCL_READ_ERROR); falling back to CLAUDE_TOOL_FILE${CLAUDE_TOOL_FILE:+ ($CLAUDE_TOOL_FILE)}." >&2
fi

cd "$(bcl_repo_root)" || { echo "[run-tests] could not enter repo root — checks skipped." >&2; exit 0; }

# Prefer the explicit changed file passed by the dispatcher; fall back to payload.
CHANGED_FILE="${CLAUDE_TOOL_FILE:-}"
if [[ -z "$CHANGED_FILE" ]]; then
  CHANGED_FILE="$(bcl_extract_paths "$PAYLOAD" | head -1)"
fi
[[ -z "$CHANGED_FILE" ]] && CHANGED_FILE="."

FAILED=0
# Never an inherited value: bash imports the environment, and an OUT_TMP from it would
# choose the file every check empties and writes (or, empty, force the streaming path).
unset -v OUT_TMP
run_if_available() { command -v "$1" >/dev/null 2>&1; }

# run_check <head|tail> <max-lines> <label> <cmd> [args...]
# Runs one check with its stdout and stderr in a file — not a pipe and not $( ): a
# grandchild the tool leaves running would hold a pipe open and keep this module waiting
# until the dispatcher kills it. On failure, at most <max-lines> of that output go to
# stderr: the first for a linter (issues in file order), the last for a test runner (its
# summary comes last). On success nothing goes to stderr.
# One file, created on first use so an edit no check matches pays no fork, emptied and
# then APPENDED to, as in the dispatcher (post-write.sh, _child_ran): a grandchild an
# earlier check left running keeps writing at its old offset after a plain truncation,
# which leaves NUL holes in the next check's text.
run_check() {
  local end="$1" max="$2" label="$3" rc=0 total; shift 3
  if [[ -z "${OUT_TMP+x}" ]]; then
    OUT_TMP="$(mktemp 2>/dev/null)" || OUT_TMP=""
    # The only EXIT trap in this process (chain it with _bcl_emit_notice if this script
    # ever calls bcl_notice_event). rm's own errors stay out of the notice. A SIGKILL
    # (timeout -k, for a tool that ignores TERM) skips it and leaves the file in TMPDIR.
    if [[ -n "$OUT_TMP" ]]; then trap 'rm -f -- "$OUT_TMP" 2>/dev/null' EXIT; fi
  fi
  if [[ -n "$OUT_TMP" ]]; then
    : > "$OUT_TMP"
    "$@" >>"$OUT_TMP" 2>&1 || rc=$?
  else
    # No temp file: stream to stderr, so a failure's details are never lost (the cost:
    # a passing check's output joins a warn-mode notice too, on this rare path only).
    "$@" >&2 || rc=$?
  fi
  if (( rc == 0 )); then echo "✅ $label passed"; return 0; fi
  FAILED=1
  echo "⚠️  $label failed (exit $rc):" >&2
  [[ -n "$OUT_TMP" ]] || return 1
  total=$(( $(wc -l < "$OUT_TMP") ))
  # wc -l counts newlines: an unterminated last line is a line too, and gets its newline
  # below so it is not glued to the next line of the report.
  local open=0
  if [[ -s "$OUT_TMP" && -n "$(tail -c 1 -- "$OUT_TMP")" ]]; then open=1; total=$((total + 1)); fi
  if (( total <= max )); then
    cat -- "$OUT_TMP" >&2
    if (( open )); then echo >&2; fi
  elif [[ "$end" == head ]]; then
    head -n "$max" -- "$OUT_TMP" >&2
    echo "… ($((total - max)) more lines omitted)" >&2
  else
    echo "… ($((total - max)) earlier lines omitted)" >&2
    tail -n "$max" -- "$OUT_TMP" >&2
    if (( open )); then echo >&2; fi
  fi
  return 1
}

echo "[run-tests] target: $CHANGED_FILE"

# --- Python ---------------------------------------------------------------
if [[ "$CHANGED_FILE" == *.py || "$CHANGED_FILE" == "." ]]; then
  PYBIN="$(bcl_python)"
  if [[ -n "$PYBIN" ]] && "$PYBIN" -c 'import pytest' >/dev/null 2>&1 && [[ -d tests ]]; then
    BASENAME="$(basename "$CHANGED_FILE" .py)"
    if [[ -f "tests/test_${BASENAME}.py" ]]; then
      run_check tail 30 pytest "$PYBIN" -m pytest "tests/test_${BASENAME}.py" -x -q --tb=short
    else
      run_check tail 30 pytest "$PYBIN" -m pytest tests/ -x -q --tb=short
    fi
  else
    echo "[run-tests] pytest unavailable or no tests/ — skipping Python tests"
  fi
fi

# --- Shell ----------------------------------------------------------------
if [[ "$CHANGED_FILE" == *.sh || "$CHANGED_FILE" == *.bash ]]; then
  if run_if_available shellcheck; then
    run_check head 60 shellcheck shellcheck --severity=error "$CHANGED_FILE"
  fi
  BASENAME="$(basename "$CHANGED_FILE" .sh)"
  if run_if_available bats && [[ -f "tests/${BASENAME}.bats" ]]; then
    run_check tail 20 bats bats "tests/${BASENAME}.bats"
  fi
fi

# --- YAML -----------------------------------------------------------------
if [[ "$CHANGED_FILE" == *.yml || "$CHANGED_FILE" == *.yaml ]]; then
  if run_if_available yamllint; then
    run_check head 60 yamllint yamllint -d relaxed "$CHANGED_FILE"
  fi
  if [[ "$CHANGED_FILE" == *.github/workflows/* ]] && run_if_available actionlint; then
    run_check head 60 actionlint actionlint "$CHANGED_FILE"
  fi
fi

if [[ $FAILED -ne 0 ]]; then
  echo "❌ [run-tests] checks failed for $CHANGED_FILE" >&2
  bcl_violation_exit; exit $?
fi
exit 0
