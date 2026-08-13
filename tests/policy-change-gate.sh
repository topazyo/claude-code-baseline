#!/usr/bin/env bash
# claude-code-baseline :: tests/policy-change-gate.sh
#
# Release gate (OWASP CI/CD): if a change touches a high-risk POLICY file (the
# command-guard, the matcher, common.sh, the config-guard tamper hook, or the
# merged deny-list) WITHOUT also touching tests/, fail — so the deny-list / matcher
# / tamper-detection logic cannot move without updated, reviewed fixtures.
#
# THIS GATE FAILS CLOSED. Every way of NOT knowing what changed is an error, not a
# pass. It previously did the opposite in four places, and each one silently
# admitted a weakened matcher:
#   * an unresolvable base ref fell back to `HEAD~1`, which on a multi-commit PR
#     diffs only the tip — a matcher edit in an earlier commit was invisible;
#   * `git diff ... || true` turned any git failure into an empty change set;
#   * an empty change set printed "nothing to gate" and exited 0, so a failed diff
#     and a genuinely empty PR were indistinguishable;
#   * `grep -E ... || true` conflated grep's exit 1 ("no match") with exit 2+
#     ("bad regex", "read error"), so a broken pattern read as "no policy files
#     changed".
# A gate that cannot determine the change set must fail the build and say why.
#
# Usage: tests/policy-change-gate.sh [BASE_REF]   (BASE_REF default: origin/main)
#
# Local runs: pass an explicit base, e.g. `tests/policy-change-gate.sh HEAD~1`.
# Without a remote there is no origin/main, and the gate will refuse rather than
# guess. tests/run.sh does not invoke this gate, so strictness here does not
# affect the ordinary local test run.
set -uo pipefail

die() { printf 'RELEASE GATE FAILED: %s\n' "$1" >&2; shift; for l in "$@"; do printf '   %s\n' "$l" >&2; done; exit 1; }

BASE="${1:-origin/main}"

git rev-parse --git-dir >/dev/null 2>&1 \
  || die "not a git repository — the gate cannot determine what changed." \
         "Run it from inside the checkout."

if ! git rev-parse --verify --quiet "$BASE^{commit}" >/dev/null; then
  die "base ref '$BASE' cannot be resolved — refusing to guess what changed." \
      "In CI, fetch the base branch first:" \
      "   git fetch --no-tags origin \"\$GITHUB_BASE_REF\"" \
      "Locally, pass an explicit base, e.g.:" \
      "   tests/policy-change-gate.sh HEAD~1" \
      "" \
      "This used to fall back to HEAD~1, which diffs only the tip commit and" \
      "misses a policy change made earlier in a multi-commit branch."
fi

# Triple-dot: diff against the MERGE BASE, so commits landing on the base branch
# after this branch forked are not misread as this branch's changes.
MERGE_BASE="$(git merge-base "$BASE" HEAD 2>/dev/null)" || MERGE_BASE=""
[ -n "$MERGE_BASE" ] \
  || die "no merge base between '$BASE' and HEAD — histories are unrelated or the clone is shallow." \
         "CI must check out with fetch-depth: 0 for this gate to work."

# Capture status separately: `changed="$(git diff ...)"` alone would report the
# assignment's status, and a `|| true` would discard the failure entirely.
changed="$(git diff --name-only "$MERGE_BASE" HEAD 2>&1)"; rc=$?
[ "$rc" -eq 0 ] \
  || die "git diff against the merge base failed (exit $rc) — cannot determine the change set." \
         "$changed"

if [ -z "$changed" ]; then
  # Reachable only with a successful diff, so this really is an empty change set.
  echo "policy-change-gate: base=$BASE merge-base=${MERGE_BASE:0:12} — no files changed; gate not applicable."
  exit 0
fi

# Paths are relative to the baseline repo root.
policy_re='(^|/)hooks/guardrails/command-guard\.sh$|(^|/)hooks/lib/command_guard_match\.py$|(^|/)hooks/lib/common\.sh$|(^|/)hooks/modules/config-guard\.sh$|(^|/)settings\.template\.json$|(^|/)managed/managed-settings(\.strict)?\.json$|(^|/)managed/allowlist\.example\.json$'

# grep exits 0 on match, 1 on no match, >=2 on a real error. Only 0 and 1 are
# answers; anything else means the classification did not happen.
policy_changed="$(printf '%s\n' "$changed" | grep -E "$policy_re")"; prc=$?
[ "$prc" -le 1 ] || die "grep failed (exit $prc) while classifying policy files — cannot evaluate the gate."

tests_changed="$(printf '%s\n' "$changed" | grep -E '(^|/)tests/')"; trc=$?
[ "$trc" -le 1 ] || die "grep failed (exit $trc) while classifying test files — cannot evaluate the gate."

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
  echo "policy-change-gate: base=$BASE merge-base=${MERGE_BASE:0:12} — policy change accompanied by test changes; OK."
else
  echo "policy-change-gate: base=$BASE merge-base=${MERGE_BASE:0:12} — no high-risk policy files changed; gate not applicable."
fi
exit 0
