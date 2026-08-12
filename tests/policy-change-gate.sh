#!/usr/bin/env bash
# claude-code-baseline :: tests/policy-change-gate.sh
#
# Release gate (OWASP CI/CD): if a change touches a high-risk POLICY file (the
# command-guard, the matcher, common.sh, the config-guard tamper hook, or the
# merged deny-list) WITHOUT also touching tests/, fail — so the deny-list / matcher
# / tamper-detection logic cannot move without updated, reviewed fixtures.
#
# Usage: tests/policy-change-gate.sh [BASE_REF]   (BASE_REF default: origin/main)
set -uo pipefail

BASE="${1:-origin/main}"

if git rev-parse --verify "$BASE" >/dev/null 2>&1; then
  changed="$(git diff --name-only "$BASE"...HEAD 2>/dev/null || true)"
else
  # Fallback for shallow/local checkouts with no base ref available.
  changed="$(git diff --name-only HEAD~1 2>/dev/null || true)"
fi

if [ -z "$changed" ]; then
  echo "policy-change-gate: no changed files detected (base=$BASE) — nothing to gate."
  exit 0
fi

# Paths are relative to the baseline repo root.
policy_re='(^|/)hooks/guardrails/command-guard\.sh$|(^|/)hooks/lib/command_guard_match\.py$|(^|/)hooks/lib/common\.sh$|(^|/)hooks/modules/config-guard\.sh$|(^|/)settings\.template\.json$|(^|/)managed/managed-settings(\.strict)?\.json$|(^|/)managed/allowlist\.example\.json$'

policy_changed="$(printf '%s\n' "$changed" | grep -E "$policy_re" || true)"
tests_changed="$(printf '%s\n' "$changed" | grep -E '(^|/)tests/' || true)"

if [ -n "$policy_changed" ] && [ -z "$tests_changed" ]; then
  {
    echo "RELEASE GATE FAILED: high-risk policy files changed without updated tests/:"
    printf '%s\n' "$policy_changed" | sed 's/^/   /'
    echo ""
    echo "Add or adjust fixtures in tests/ (e.g. tests/test_command_guard.py / tests/test_hooks.sh)"
    echo "covering the new behaviour, then re-run. This gate enforces that deny-list / matcher"
    echo "logic cannot change without reviewed adversarial coverage."
  } >&2
  exit 1
fi

if [ -n "$policy_changed" ]; then
  echo "policy-change-gate: policy change accompanied by test changes — OK."
else
  echo "policy-change-gate: no high-risk policy files changed — gate not applicable."
fi
exit 0
