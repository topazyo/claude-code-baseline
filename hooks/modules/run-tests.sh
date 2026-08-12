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

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"

bcl_module_enabled runTests || exit 0

PAYLOAD="$(cat 2>/dev/null || true)"
cd "$(bcl_repo_root)" || { echo "[run-tests] could not enter repo root — checks skipped." >&2; exit 0; }

# Prefer the explicit changed file passed by the dispatcher; fall back to payload.
CHANGED_FILE="${CLAUDE_TOOL_FILE:-}"
if [[ -z "$CHANGED_FILE" ]]; then
  CHANGED_FILE="$(bcl_extract_paths "$PAYLOAD" | head -1)"
fi
[[ -z "$CHANGED_FILE" ]] && CHANGED_FILE="."

FAILED=0
run_if_available() { command -v "$1" >/dev/null 2>&1; }

echo "[run-tests] target: $CHANGED_FILE"

# --- Python ---------------------------------------------------------------
if [[ "$CHANGED_FILE" == *.py || "$CHANGED_FILE" == "." ]]; then
  PYBIN="$(bcl_python)"
  if [[ -n "$PYBIN" ]] && "$PYBIN" -c 'import pytest' >/dev/null 2>&1 && [[ -d tests ]]; then
    BASENAME="$(basename "$CHANGED_FILE" .py)"
    if [[ -f "tests/test_${BASENAME}.py" ]]; then
      "$PYBIN" -m pytest "tests/test_${BASENAME}.py" -x -q --tb=short 2>&1 | tail -30 || FAILED=1
    else
      "$PYBIN" -m pytest tests/ -x -q --tb=short 2>&1 | tail -30 || FAILED=1
    fi
  else
    echo "[run-tests] pytest unavailable or no tests/ — skipping Python tests"
  fi
fi

# --- Shell ----------------------------------------------------------------
if [[ "$CHANGED_FILE" == *.sh || "$CHANGED_FILE" == *.bash ]]; then
  if run_if_available shellcheck; then
    shellcheck --severity=error "$CHANGED_FILE" && echo "✅ shellcheck passed" || { echo "⚠️  shellcheck found issues"; FAILED=1; }
  fi
  BASENAME="$(basename "$CHANGED_FILE" .sh)"
  if run_if_available bats && [[ -f "tests/${BASENAME}.bats" ]]; then
    bats "tests/${BASENAME}.bats" 2>&1 | tail -20 || FAILED=1
  fi
fi

# --- YAML -----------------------------------------------------------------
if [[ "$CHANGED_FILE" == *.yml || "$CHANGED_FILE" == *.yaml ]]; then
  if run_if_available yamllint; then
    yamllint -d relaxed "$CHANGED_FILE" && echo "✅ yamllint passed" || { echo "⚠️  yamllint found issues"; FAILED=1; }
  fi
  if [[ "$CHANGED_FILE" == *.github/workflows/* ]] && run_if_available actionlint; then
    actionlint "$CHANGED_FILE" && echo "✅ actionlint passed" || { echo "⚠️  actionlint found issues"; FAILED=1; }
  fi
fi

if [[ $FAILED -ne 0 ]]; then
  echo "❌ [run-tests] checks failed for $CHANGED_FILE" >&2
  bcl_violation_exit; exit $?
fi
exit 0
