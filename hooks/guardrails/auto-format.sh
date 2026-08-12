#!/usr/bin/env bash
# claude-code-baseline :: guardrails/auto-format.sh
#
# PostToolUse helper (matcher: Write|Edit). Auto-formats changed files using
# whatever formatter is available for each file type. Never blocks — formatting
# is a best-effort side effect, so this always exits 0.
#
# Reads the tool payload on stdin and formats every changed path it finds.
# Honours node_modules/.bin first, then global tools on PATH.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"

bcl_guardrail_enabled autoFormat || exit 0

# Run from the repo root so repo-relative paths and project-local tool binaries
# (./node_modules/.bin/...) resolve regardless of the hook's working directory.
cd "$(bcl_repo_root)" 2>/dev/null || true

PAYLOAD="$(cat 2>/dev/null || true)"

run_if_available() { command -v "$1" >/dev/null 2>&1; }

format_file() {
  local file="$1"
  [[ -f "$file" ]] || return 0

  case "$file" in
    *.js|*.jsx|*.ts|*.tsx|*.json|*.css|*.scss|*.md|*.yaml|*.yml)
      if [[ -x ./node_modules/.bin/prettier ]]; then
        ./node_modules/.bin/prettier --write "$file" >/dev/null 2>&1 || true
      elif run_if_available prettier; then
        prettier --write "$file" >/dev/null 2>&1 || true
      fi
      case "$file" in
        *.js|*.jsx|*.ts|*.tsx)
          if [[ -x ./node_modules/.bin/eslint ]]; then
            ./node_modules/.bin/eslint --fix "$file" >/dev/null 2>&1 || true
          elif run_if_available eslint; then
            eslint --fix "$file" >/dev/null 2>&1 || true
          fi
          ;;
      esac
      ;;
    *.py)
      if run_if_available black; then
        black "$file" >/dev/null 2>&1 || true
      elif run_if_available python3; then
        python3 -m black "$file" >/dev/null 2>&1 || true
      elif run_if_available python; then
        python -m black "$file" >/dev/null 2>&1 || true
      fi
      ;;
    *.cs)
      run_if_available dotnet && dotnet format --include "$file" >/dev/null 2>&1 || true
      ;;
  esac
}

while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  format_file "$f"
done < <(bcl_extract_paths "$PAYLOAD")

exit 0
