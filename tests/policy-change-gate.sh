#!/usr/bin/env bash
# claude-code-baseline :: tests/policy-change-gate.sh
#
# Release gate (OWASP CI/CD): if a change touches anything that decides what the
# baseline enforces WITHOUT also adding or modifying an enforcement fixture file,
# fail — so the deny-list / matcher / guard / installer logic cannot move without
# updated, reviewed fixtures.
#
# What counts as POLICY (any path segment, so a vendored copy works too; any case):
#   hooks/  lib/  tools/  managed/  examples/  tests/  .github/
#   install.sh  settings.template.json  baseline.config.schema.json
#   baseline.config.json  .gitattributes  .gitmodules
# EXCEPT: root-level *.md, any README*.md, hooks/VERSION, .github/CODEOWNERS, and a
# baseline.config.json whose only change is its "baselineVersion" line — so a
# version-bump PR and a docs-only PR stay "not applicable". The gate and run.sh are
# policy themselves: neutering either needs a fixture change too (and CI runs the
# BASE branch's copy).
# examples/ is policy because install.sh ships a file from it as live config;
# .gitattributes because it decides the line endings of the shipped scripts;
# .github/ because the workflows decide what CI checks — which also means a
# dependabot or issue-template change needs a fixture touch. Accepted.
#
# What SATISFIES the gate: an ADDED or MODIFIED enforcement fixture file in the
# repository root's tests/ (a vendored or planted copy elsewhere does not count) —
#   tests/test_command_guard.py  test_hooks.sh  test_managed.sh
#   tests/test_merge_settings.py test_status.sh test_policy_gate.sh
#   tests/test_definition_path.py test_old_windows_python.sh test_msys_python.sh
# Not tests/README.md, not the translation checker, not a deleted fixture file.
# Each is also a policy file (all of tests/ is), so a change to one alone passes:
# a fixture can be thinned without another touch. Accepted, as for the first six.
# The backstops are partial: the command-guard corpus has its own floor, and CI pins
# the pass counts of test_hooks.sh, test_status.sh and test_policy_gate.sh; the
# others rely on review.
# A one-line edit to one of these still satisfies it: this is a tripwire that
# makes a reviewer look at fixtures, not proof the fixtures cover the change. The
# block-corpus floor in test_command_guard.py (BLOCK_FLOOR, MUST_BLOCK, reason
# coverage) is what stops the command-guard fixtures from quietly shrinking.
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
# guess. tests/run.sh runs this gate only against scratch repositories (through
# tests/test_policy_gate.sh), never against the real checkout.
set -uo pipefail
# Byte semantics for every grep below. Under a UTF-8 locale GNU grep treats a path with
# an invalid byte (hooks/modules/<0xff>.sh) as binary input, drops the matching line
# from its output and still exits 0 — the path would vanish from the classification.
export LC_ALL=C

die() { printf 'RELEASE GATE FAILED: %s\n' "$1" >&2; shift; for l in "$@"; do printf '   %s\n' "$l" >&2; done; exit 1; }

BASE="${1:-origin/main}"

# Every diff the gate reads. --no-renames: a rename is otherwise reported under its
# NEW path only, so `git mv hooks/x.sh hooks/x.md` read as a docs change. The rest
# keep repository or user config (external diff drivers, textconv, colour, a
# diff.relative subdirectory) from changing what the gate sees.
# --ignore-submodules=none: a PR's .gitmodules could otherwise set ignore=all and hide a
# gitlink under hooks/ from the diff.
DIFF_OPTS=(--no-renames --no-ext-diff --no-textconv --no-color --no-relative --ignore-submodules=none)

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

# list_changed [diff options...] — changed paths, one per line.
# -z prints every path verbatim: without it git quotes an unusual path ("hooks/\303\251.sh"),
# and the leading quote kept it from matching (^|/)hooks/. The tr turns a newline INSIDE a
# path into \001 and only then each NUL terminator into a newline, so one path is always one
# line ("hooks/x.md<LF>y" must not split into a ".md" line and an unclassified one). The
# status is the pipeline's (pipefail), so a git failure is not lost behind tr; stderr goes
# to the log, not into the path list.
list_changed() {
  git diff --name-only -z "${DIFF_OPTS[@]}" "$@" "$MERGE_BASE" HEAD | tr '\n\0' '\001\n'
}

# Capture status separately: `changed="$(git diff ...)"` alone would report the
# assignment's status, and a `|| true` would discard the failure entirely.
changed="$(list_changed)"; rc=$?
[ "$rc" -eq 0 ] \
  || die "git diff against the merge base failed (exit $rc) — cannot determine the change set."

if [ -z "$changed" ]; then
  # Reachable only with a successful diff, so this really is an empty change set.
  echo "policy-change-gate: base=$BASE merge-base=${MERGE_BASE:0:12} — no files changed; gate not applicable."
  exit 0
fi

# Paths are relative to the repository root (--no-relative).
# POLICY is matched case-INsensitively (`Hooks/x.sh` and `INSTALL.sh` land in hooks/ and
# on install.sh on a case-insensitive checkout); the exemptions and the fixture list are
# case-sensitive, so a case variant can only make a path MORE policy, never less.
# All of tests/ is policy (its *.md aside): run.sh can neuter the suite, and a new
# tests/re.py would shadow the standard library for the fixture suites, which run with
# tests/ first on sys.path. A change to only the translation checker therefore needs a
# fixture touch too; accepted.
policy_re='(^|/)(hooks|lib|tools|managed|examples|tests|\.github)/|(^|/)(install\.sh|settings\.template\.json|baseline\.config\.schema\.json|baseline\.config\.json|\.gitattributes|\.gitmodules)$'
# Exempt: root-level docs and any README*.md — not every *.md, so a future .md shipped
# from hooks/ or managed/ (an instruction file, say) stays policy.
exempt_re='^[^/]*\.md$|(^|/)README[^/]*\.md$|^hooks/VERSION$|^\.github/CODEOWNERS$'
# Fixture files count only at the repository root: a vendored or planted
# junk/tests/test_hooks.sh is not this repository's fixture.
fixture_re='^tests/(test_command_guard\.py|test_hooks\.sh|test_managed\.sh|test_merge_settings\.py|test_status\.sh|test_policy_gate\.sh|test_definition_path\.py|test_old_windows_python\.sh|test_msys_python\.sh)$'
# One "baselineVersion" member line, nothing else on it ([^"\\]* stops a second key, or
# an escaped quote, riding along).
version_line_re='^[+-][[:space:]]*"baselineVersion"[[:space:]]*:[[:space:]]*"[^"\\]*",?[[:space:]]*$'

# grep exits 0 on match, 1 on no match, >=2 on a real error. Only 0 and 1 are
# answers; anything else means the classification did not happen. -a: every input
# line is text, whatever bytes it holds.
# classify LABEL PATTERN [grep flags] — reads paths on stdin, prints the matches.
classify() {
  local label="$1" re="$2" out grc; shift 2
  out="$(grep -a "$@" -E -- "$re")"; grc=$?
  [ "$grc" -le 1 ] || die "grep failed (exit $grc) while classifying $label — cannot evaluate the gate."
  [ -n "$out" ] && printf '%s\n' "$out"
  return 0
}

# version_only PATH — true when PATH exists on both sides and every changed line of
# its diff is a "baselineVersion" line, with at least one such line. Anything the
# gate cannot read that way (added or deleted file, binary diff, a diff failure, an
# unexpected line) is NOT version-only, so it stays policy.
version_only() {
  local path="$1" diff drc lines n bad
  git cat-file -e "$MERGE_BASE:$path" 2>/dev/null || return 1
  git cat-file -e "HEAD:$path" 2>/dev/null || return 1
  diff="$(git diff -U0 "${DIFF_OPTS[@]}" "$MERGE_BASE" HEAD -- ":(literal)$path")"; drc=$?
  [ "$drc" -eq 0 ] || die "git diff of '$path' failed (exit $drc) — cannot tell whether it is a version bump."
  # The changed lines are the +/- lines AFTER the first hunk header; everything before
  # it is the header block (diff --git, index, ---, +++), whatever prefix it uses.
  # "\ No newline at end of file" is a marker, not content.
  lines="$(printf '%s\n' "$diff" | awk 'h && /^[+-]/ {print; next} /^@@/ {h=1}')"
  [ -n "$lines" ] || return 1
  # A die inside $(...) ends only the subshell: test each status here, or a failed count
  # would read as 0 — and 0 bad lines reads as a version bump.
  n="$(printf '%s\n' "$lines" | classify "the version bump" "$version_line_re" -c)" || exit 1
  bad="$(printf '%s\n' "$lines" | classify "the version bump" "$version_line_re" -vc)" || exit 1
  [ "${n:-0}" -ge 1 ] && [ "${bad:-0}" -eq 0 ]
}

candidates="$(printf '%s\n' "$changed" | classify "policy files" "$policy_re" -i)" || exit 1
candidates="$(printf '%s\n' "$candidates" | classify "exempt files" "$exempt_re" -v)" || exit 1

policy_changed=""
while IFS= read -r path; do
  [ -n "$path" ] || continue
  case "$path" in
    baseline.config.json|*/baseline.config.json)
      version_only "$path" && continue ;;
  esac
  policy_changed="${policy_changed}${path}"$'\n'
done <<< "$candidates"
policy_changed="${policy_changed%$'\n'}"

if [ -z "$policy_changed" ]; then
  echo "policy-change-gate: base=$BASE merge-base=${MERGE_BASE:0:12} — no high-risk policy files changed; gate not applicable."
  exit 0
fi

fixtures="$(list_changed --diff-filter=AM)"; rc=$?
[ "$rc" -eq 0 ] \
  || die "git diff of added/modified files failed (exit $rc) — cannot tell whether fixtures changed."
fixtures_changed="$(printf '%s\n' "$fixtures" | classify "fixture files" "$fixture_re")" || exit 1

if [ -z "$fixtures_changed" ]; then
  {
    echo "RELEASE GATE FAILED: high-risk policy files changed without an added or modified fixture file:"
    printf '%s\n' "$policy_changed" | sed 's/^/   /'
    echo ""
    echo "Add or adjust fixtures covering the new behaviour in one of:"
    echo "   tests/test_command_guard.py  tests/test_hooks.sh  tests/test_managed.sh"
    echo "   tests/test_merge_settings.py tests/test_status.sh tests/test_policy_gate.sh"
    echo "   tests/test_definition_path.py tests/test_old_windows_python.sh tests/test_msys_python.sh"
    echo "then re-run. tests/README.md and other files under tests/ do not count, and"
    echo "deleting a fixture file does not count."
  } >&2
  exit 1
fi

echo "policy-change-gate: base=$BASE merge-base=${MERGE_BASE:0:12} — policy change accompanied by test changes; OK."
exit 0
