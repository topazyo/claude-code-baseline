#!/usr/bin/env bash
# claude-code-baseline :: tests/test_policy_gate.sh
#
# Regression tests for the policy-change release gate (tests/policy-change-gate.sh).
# Builds a scratch repository laid out like this one, makes one kind of change per
# case on a fresh branch, runs the WORKING-TREE gate against `main`, and asserts the
# exit code and the verdict line. Covers: what counts as policy (and what is exempt —
# a version bump, docs), what satisfies the gate (an added or modified enforcement
# fixture file only), renames, deletions, unusual path names, and every way the gate
# can fail to determine the change set (it must fail closed, never pass).
#
# Git runs hermetically: no global or system config (a host's diff.renames,
# core.autocrlf, commit.gpgsign or init.defaultBranch would otherwise leak in) and
# an inline identity (CI runners have none).
#
# POLICY_GATE_UNDER_TEST overrides which gate script is exercised — for mutation
# runs only; the suite tests tests/policy-change-gate.sh by default.
# Requires bash + git. Exits non-zero on any failure.
set -uo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v git >/dev/null 2>&1 || { echo "git is required" >&2; exit 1; }
GATE="${POLICY_GATE_UNDER_TEST:-$SRC/tests/policy-change-gate.sh}"
[ -s "$GATE" ] || { echo "gate script not found: $GATE" >&2; exit 1; }
winpath() { cygpath -m "$1" 2>/dev/null || printf '%s' "$1"; }

TMP="$(mktemp -d)"
cleanup() { cd / 2>/dev/null; rm -rf "$TMP"; }
# The signal handlers exit explicitly: a bash trap on INT/TERM does not end the
# script by itself, and the cases would carry on against a deleted directory.
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

: > "$TMP/empty.gitconfig"
GIT_CONFIG_GLOBAL="$(winpath "$TMP/empty.gitconfig")"
GIT_CONFIG_NOSYSTEM=1
GIT_AUTHOR_NAME=gate-test GIT_AUTHOR_EMAIL=gate-test@example.invalid
GIT_COMMITTER_NAME=gate-test GIT_COMMITTER_EMAIL=gate-test@example.invalid
export GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL

# A `git` that refuses any invocation carrying the argument named in $SHIM_REFUSE and
# passes everything else to the real git (absolute path, captured now, so the shim
# never finds itself on PATH).
REAL_GIT="$(command -v git)"
SHIM="$TMP/shim"; mkdir -p "$SHIM"
cat > "$SHIM/git" <<EOF
#!/usr/bin/env bash
for a in "\$@"; do
  if [ "\$a" = "\$SHIM_REFUSE" ]; then echo "git shim: refusing \$SHIM_REFUSE" >&2; exit 128; fi
done
exec "$REAL_GIT" "\$@"
EOF
chmod +x "$SHIM/git"

pass=0; fail=0
ok() { pass=$((pass + 1)); }
no() { fail=$((fail + 1)); echo "  FAIL [$1]"; }

R="$TMP/repo"
mkdir -p "$R"
cd "$R" || exit 1
git init -q -b main . || { echo "git init failed" >&2; exit 1; }

# --- seed: the real layout, stub contents (baseline.config.json is the real file,
# so the version-bump case exercises the real line format) ---
seed() { mkdir -p "$(dirname "$1")"; printf '%s\n' "${2:-seed $1}" > "$1"; }
for f in hooks/lib/common.sh hooks/modules/scope-guard.sh hooks/guardrails/command-guard.sh \
         hooks/lib/command_guard_match.py hooks/x.md install.sh lib/merge_settings.py \
         tools/baseline-status.sh tools/README.md settings.template.json \
         baseline.config.schema.json managed/managed-settings.json managed/README.md \
         examples/security-defaults.openclaw.json .gitattributes .github/CODEOWNERS \
         .github/workflows/baseline-ci.yml README.md RELEASING.md tests/README.md \
         tests/run.sh tests/policy-change-gate.sh tests/test_hooks.sh \
         tests/test_command_guard.py tests/test_translation_sync.py tests/translation_sync.py \
         tests/test_latency.sh; do
  seed "$f"
done
seed hooks/VERSION "2026-01-01"
cp "$SRC/baseline.config.json" baseline.config.json
# A config whose whole body is one version line: deleting it, or adding another like it,
# changes only "baselineVersion" lines — and is still not a version bump.
seed vendor/baseline.config.json '  "baselineVersion": "2026-01-01",'
git add -A && git commit -q -m seed || { echo "seed commit failed" >&2; exit 1; }

# --- helpers ---
n=0
# begin LABEL — a fresh branch off main for one case.
begin() { n=$((n + 1)); git checkout -q -f -B "case$n" main; }
touchf() { local f; for f in "$@"; do mkdir -p "$(dirname "$f")"; printf 'change %s\n' "$n" >> "$f"; done; }
commit() { git add -A && git commit -q -m "case $n" || { echo "commit failed in case $n" >&2; exit 1; }; }
# subst FILE SED-EXPR — portable in-place edit (no sed -i: BSD and GNU differ).
subst() { sed "$2" "$1" > "$1.new" && mv "$1.new" "$1"; }
bump_version() { subst baseline.config.json 's/"baselineVersion": "[^"]*"/"baselineVersion": "2099-01-01.1"/'; printf '2099-01-01.1\n' > hooks/VERSION; }

# expect WANT_RC NEEDLE LABEL [BASE] — run the gate (env SHIM_REFUSE set => via the shim)
# and check its exit code and that NEEDLE appears in its output.
expect() {
  local want="$1" needle="$2" label="$3" base="${4:-main}" out rc
  if [ -n "${SHIM_REFUSE:-}" ]; then
    out="$(PATH="$SHIM:$PATH" bash "$GATE" "$base" 2>&1)"; rc=$?
  else
    out="$(bash "$GATE" "$base" 2>&1)"; rc=$?
  fi
  if [ "$rc" -eq "$want" ] && [[ "$out" == *"$needle"* ]]; then
    ok
  else
    no "$label: want rc=$want and '$needle', got rc=$rc"
    printf '%s\n' "$out" | sed 's/^/      /'
  fi
}
export SHIM_REFUSE=""

NOFIX="without an added or modified fixture file"
NA="gate not applicable"
OKMSG="accompanied by test changes; OK"

echo "== policy-change gate: cannot determine the change set => fail closed =="
begin; touchf hooks/lib/common.sh; commit
expect 1 "cannot be resolved" "unresolvable base" "no-such-ref"
git checkout -q --orphan orphan && git rm -q -rf --cached . >/dev/null && touchf hooks/lib/common.sh && git add hooks/lib/common.sh && git commit -q -m orphan
expect 1 "no merge base" "unrelated histories"
git checkout -q -f main && git clean -q -fdx
begin; touchf hooks/lib/common.sh tests/test_hooks.sh; commit
SHIM_REFUSE="--name-only" expect 1 "git diff against the merge base failed" "a git diff failure is not an empty change set"
begin; bump_version; commit
SHIM_REFUSE="-U0" expect 1 "git diff of 'baseline.config.json' failed" "a failed version-bump diff is not admitted"
begin; touchf hooks/lib/common.sh tests/test_hooks.sh; commit
SHIM_REFUSE="--diff-filter=AM" expect 1 "git diff of added/modified files failed" "a failed fixture diff is not admitted"

echo "== policy-change gate: not applicable =="
begin
expect 0 "no files changed" "empty change set"
begin; bump_version; commit
expect 0 "$NA" "version bump (hooks/VERSION + the baselineVersion line)"
begin; touchf README.md managed/README.md tools/README.md .github/CODEOWNERS RELEASING.md tests/README.md; commit
expect 0 "$NA" "docs only"

echo "== policy-change gate: policy without a fixture => fail =="
for f in hooks/lib/common.sh hooks/modules/scope-guard.sh hooks/guardrails/command-guard.sh \
         hooks/lib/command_guard_match.py install.sh lib/merge_settings.py \
         tools/baseline-status.sh settings.template.json baseline.config.schema.json \
         managed/managed-settings.json examples/security-defaults.openclaw.json .gitattributes \
         .github/workflows/baseline-ci.yml tests/run.sh tests/policy-change-gate.sh; do
  begin; touchf "$f"; commit
  expect 1 "$NOFIX" "$f alone"
done
begin; touchf hooks/modules/new-guard.sh; commit
expect 1 "$NOFIX" "a new file under hooks/"
begin; git rm -q hooks/modules/scope-guard.sh; commit
expect 1 "$NOFIX" "a deleted policy file"
begin; subst baseline.config.json 's/"enforcement": "block"/"enforcement": "warn"/'; commit
expect 1 "$NOFIX" "baseline.config.json enforcement changed"
begin; bump_version; subst baseline.config.json 's/"enforcement": "block"/"enforcement": "warn"/'; commit
expect 1 "$NOFIX" "version line plus another config line"
begin; subst baseline.config.json 's/"baselineVersion": "[^"]*",/"baselineVersion": "2099-01-01.1", "enforcement": "off",/'; commit
expect 1 "$NOFIX" "a second key riding on the version line"
begin; mkdir -p other && printf '  "baselineVersion": "2099-01-01.1",\n' > other/baseline.config.json; commit
expect 1 "$NOFIX" "an added baseline.config.json is not a version bump, even one holding only that line"
begin; git rm -q vendor/baseline.config.json; commit
expect 1 "$NOFIX" "a deleted baseline.config.json is not a version bump, even one holding only that line"
begin; git rm -q baseline.config.json; commit
expect 1 "$NOFIX" "a deleted baseline.config.json is not a version bump"
begin; subst baseline.config.json 's/"baselineVersion": "[^"]*",/"baselineVersion": "2099\\",/'; commit
expect 1 "$NOFIX" "an escaped quote in the version value is not a version bump"
begin; touchf "hooks/modules/caf$(printf '\303\251').sh"; commit
expect 1 "$NOFIX" "a non-ASCII path under hooks/ (git would quote it without -z)"
begin; git update-index --chmod=+x hooks/lib/common.sh; git commit -q -m "case $n"
expect 1 "$NOFIX" "a mode-only change to a policy file"
begin; touchf hooks/x.md; commit
expect 1 "$NOFIX" "a *.md under hooks/ is not a docs file (it ships)"
begin; touchf managed/CLAUDE.md; commit
expect 1 "$NOFIX" "a non-README *.md under managed/"
begin; touchf .gitmodules; commit
expect 1 "$NOFIX" ".gitmodules alone"
begin; touchf vendor/Hooks/x.sh vendor/INSTALL.sh; commit
expect 1 "$NOFIX" "case variants of policy paths"
begin; touchf tests/translation_sync.py; commit
expect 1 "$NOFIX" "a non-fixture file under tests/"
begin; touchf tests/re.py; commit
expect 1 "$NOFIX" "a new module under tests/ (it would shadow the stdlib for the suites)"
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    echo "   SKIP: newline in a file name (not creatable on Windows)" ;;
  *)
    begin; touchf "hooks/README.md
x"; commit
    expect 1 "$NOFIX" "a newline in a path does not split it into an exempt line" ;;
esac
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*|Darwin*)
    echo "   SKIP: invalid-UTF-8 file name (refused by NTFS and APFS)" ;;
  *)
    begin; touchf "hooks/modules/$(printf '\377').sh"; commit
    expect 1 "$NOFIX" "an invalid-UTF-8 path under hooks/ is still classified" ;;
esac

echo "== policy-change gate: renames report both sides =="
begin; git config diff.renames true; git mv hooks/modules/scope-guard.sh hooks/modules/scope-guard.md; commit
expect 1 "$NOFIX" "rename of a policy file to *.md"
begin; mkdir -p docs && git mv hooks/lib/common.sh docs/common.sh; commit
expect 1 "$NOFIX" "rename of a policy file out of hooks/"
git config --unset diff.renames

echo "== policy-change gate: what satisfies it =="
begin; touchf hooks/lib/common.sh tests/test_hooks.sh; commit
expect 0 "$OKMSG" "policy + a modified fixture file"
begin; touchf hooks/lib/common.sh tests/README.md; commit
expect 1 "$NOFIX" "tests/README.md is not a fixture"
begin; touchf hooks/lib/common.sh tests/test_translation_sync.py tests/test_latency.sh; commit
expect 1 "$NOFIX" "a non-enforcement test file is not a fixture"
begin; touchf hooks/lib/common.sh; git rm -q tests/test_hooks.sh; commit
expect 1 "$NOFIX" "deleting a fixture file is not a fixture change"
begin; touchf hooks/lib/common.sh junk/tests/test_hooks.sh; commit
expect 1 "$NOFIX" "a fixture-named file outside the root tests/ is not a fixture"
begin; touchf tests/test_hooks.sh; commit
expect 0 "$OKMSG" "a fixture-only change"
begin; touchf tests/policy-change-gate.sh tests/test_policy_gate.sh; commit
expect 0 "$OKMSG" "the gate + an added fixture file"
begin; touchf hooks/lib/common.sh; commit; touchf README.md; commit
expect 1 "$NOFIX" "a policy change in an earlier commit of the branch"

# Last, because it moves main: a policy commit landing on the base AFTER the branch
# forked is the base's change, not this branch's (the gate diffs from the merge base).
echo "== policy-change gate: the base moved after the fork =="
begin; touchf README.md; commit
git checkout -q main; touchf hooks/lib/common.sh; commit; git checkout -q "case$n"
expect 0 "$NA" "policy commits on the base after the fork are not this branch's"

echo ""
echo "test_policy_gate: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
