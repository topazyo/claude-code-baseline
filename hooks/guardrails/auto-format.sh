#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# claude-code-baseline :: guardrails/auto-format.sh
#
# PostToolUse helper (matcher: Write|Edit). Auto-formats changed files using
# whatever formatter is available for each file type. Never blocks — formatting
# is a best-effort side effect, so this always exits 0.
#
# ---------------------------------------------------------------------------
# READ THIS BEFORE ENABLING — this module EXECUTES CODE FROM THE REPOSITORY.
# ---------------------------------------------------------------------------
# It is DEFAULT OFF and must be opted into explicitly (guardrails.autoFormat.enabled
# = true in baseline.config.json). It is not a security control; it is a convenience
# that costs you an execution surface. What "enabled" grants, concretely:
#
#   * `prettier` / `eslint` / `black` / `dotnet format` run automatically on every
#     Write or Edit, with no per-command approval prompt.
#   * Those tools load REPO-CONTROLLED configuration — prettier.config.js,
#     eslint.config.js, and the plugins they import are JavaScript executed by the
#     formatter — and `dotnet format` BUILDS the project, running its MSBuild
#     targets. So even a formatter resolved from PATH runs code the cloned repo
#     supplied.
#   * With BCL_AUTOFORMAT_ALLOW_REPO_BINARIES=1 (see below) it will additionally
#     execute ./node_modules/.bin/prettier and ./node_modules/.bin/eslint — files
#     that ship inside the checkout, so cloning a hostile repo and letting the agent
#     touch one file is enough to run whatever was planted there.
#
# That is the same primitive as CVE-2025-59536 (repo-defined hooks auto-executing
# with no per-command approval), which is part of why this baseline exists. Enable
# auto-format only for repositories whose contents you already trust to execute.
#
# Two independent gates, both default-closed:
#   1. guardrails.autoFormat.enabled must be LITERALLY true (bcl_guardrail_opted_in —
#      a missing key, missing config, or unreadable config leaves it OFF; contrast
#      command-guard, which defaults ON because absent config must not mean absent
#      enforcement for an inspection-only control).
#   2. Repo-local binaries under ./node_modules/.bin are additionally gated on the
#      environment variable BCL_AUTOFORMAT_ALLOW_REPO_BINARIES=1. Without it, only
#      formatters found on PATH are run. Set it per-invocation in an environment you
#      control; do not bake it into a repo-committed settings file.
#
# Reads the tool payload on stdin and formats every changed path it finds.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"

# Deliberately bcl_guardrail_opted_in (default FALSE), not bcl_guardrail_enabled
# (default true): a guardrail that executes code must never run because a config
# file was missing or unreadable.
bcl_guardrail_opted_in autoFormat || exit 0

# Second gate for repo-supplied executables. Computed once, checked at each call
# site, so no future edit can reach a ./node_modules/.bin exec without it.
REPO_BINARIES_OK=0
[[ "${BCL_AUTOFORMAT_ALLOW_REPO_BINARIES:-0}" == "1" ]] && REPO_BINARIES_OK=1

# Run from the repo root so repo-relative paths (and, when explicitly allowed,
# project-local tool binaries) resolve regardless of the hook's working directory.
cd "$(bcl_repo_root)" 2>/dev/null || true

PAYLOAD="$(cat 2>/dev/null || true)"

run_if_available() { command -v "$1" >/dev/null 2>&1; }

format_file() {
  local file="$1"
  [[ -f "$file" ]] || return 0

  case "$file" in
    *.js|*.jsx|*.ts|*.tsx|*.json|*.css|*.scss|*.md|*.yaml|*.yml)
      # Repo-supplied binary: only with the explicit second opt-in (see header).
      if [[ $REPO_BINARIES_OK -eq 1 && -x ./node_modules/.bin/prettier ]]; then
        ./node_modules/.bin/prettier --write "$file" >/dev/null 2>&1 || true
      elif run_if_available prettier; then
        prettier --write "$file" >/dev/null 2>&1 || true
      fi
      case "$file" in
        *.js|*.jsx|*.ts|*.tsx)
          # Repo-supplied binary: only with the explicit second opt-in (see header).
          if [[ $REPO_BINARIES_OK -eq 1 && -x ./node_modules/.bin/eslint ]]; then
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
