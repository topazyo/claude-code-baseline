#!/usr/bin/env bash
# claude-code-baseline :: tests/run.sh
#
# Aggregate test runner — local and CI. Runs every check and exits non-zero if any
# fails. Requires bash + python3 (git for the integration suite). Usage:
#   bash tests/run.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$(command -v python3 || command -v python || true)"
[ -z "$PY" ] && { echo "python3 (or python) is required" >&2; exit 1; }
fail=0
# The fixture suites check with bare `assert` in places, which PYTHONOPTIMIZE strips:
# every such check would pass without looking. The suites guard themselves too.
unset PYTHONOPTIMIZE
# A suite that cannot run is a skip locally but a failure on CI, where git is always
# installed and a missing one means the job lost a whole suite without a word.
no_git() {
  if [ -n "${BCL_CI_LEG:-}" ] || [ "${GITHUB_ACTIONS:-}" = true ]; then
    echo "  FAIL: git not available on a CI leg; $1 did not run"; fail=1
  else
    echo "   SKIP (git not available)"
  fi
}

echo "== 1. shell syntax (bash -n) =="
while IFS= read -r f; do
  bash -n "$f" || { echo "  FAIL: bash -n $f"; fail=1; }
done < <(find "$ROOT/hooks" "$ROOT/tools" -name '*.sh' 2>/dev/null)
echo "   ok"

echo "== 2. python sources compile =="
for p in "$ROOT/hooks/lib/command_guard_match.py" "$ROOT/lib/merge_settings.py"; do
  "$PY" -m py_compile "$p" && echo "   ok $(basename "$p")" || { echo "  FAIL: py_compile $p"; fail=1; }
done
# The Python the hooks and the status tool carry as quoted heredocs (<<'...PY...') is
# compiled too, each body on its own: a test only compiles the code it reaches, so on
# the python-floor legs this proves those bodies parse on the oldest supported Python
# even where no case runs them. Python passed as `-c '...'` strings or held in quoted
# variables (common.sh's _BCL_CFG_*_SRC) is not extracted here; the suites run it.
# The minimum count stops a broken extraction from passing by compiling nothing.
"$PY" - "$ROOT" <<'PY' || fail=1
import re, sys
from pathlib import Path
root = Path(sys.argv[1])
start = re.compile(r"<<'([A-Za-z_]*PY[A-Za-z_]*)'")
files = sorted(root.glob("hooks/**/*.sh")) + sorted(root.glob("tools/*.sh")) + [root / "install.sh"]
n, bad = 0, 0
for f in files:
    # chr() rather than escapes: CRLF and LF only, as bash reads the file.
    lines = f.read_bytes().decode("utf-8").replace(chr(13) + chr(10), chr(10)).split(chr(10))
    i = 0
    while i < len(lines):
        m = start.search(lines[i])
        if not m:
            i += 1
            continue
        end = next((j for j in range(i + 1, len(lines)) if lines[j] == m.group(1)), None)
        where = "%s:%d" % (f.relative_to(root).as_posix(), i + 1)
        if end is None:
            print("  FAIL: heredoc %s has no closing %s line" % (where, m.group(1)))
            bad += 1
            break
        try:
            compile(chr(10).join(lines[i + 1:end]), where, "exec")
        except SyntaxError as exc:
            print("  FAIL: embedded Python at %s does not compile: %s" % (where, exc))
            bad += 1
        n += 1
        i = end + 1
if n < 8:
    print("  FAIL: found %d embedded Python heredocs, expected at least 8" % n)
    bad += 1
if not bad:
    print("   ok %d embedded Python heredocs compile" % n)
sys.exit(1 if bad else 0)
PY

echo "== 3. command-guard matcher + settings merge fixtures =="
"$PY" "$ROOT/tests/test_command_guard.py" || fail=1
"$PY" "$ROOT/tests/test_merge_settings.py" || fail=1
"$PY" "$ROOT/tests/test_definition_path.py" || fail=1

echo "== 4. hook integration suite =="
if command -v git >/dev/null 2>&1; then
  bash "$ROOT/tests/test_hooks.sh" || fail=1
else
  no_git test_hooks.sh
fi

echo "== 5. managed-settings + allowlist profiles (R6/R7) =="
bash "$ROOT/tests/test_managed.sh" || fail=1

echo "== 6. baseline version stamp + status tooling (Q1/Q3) =="
# R-1 lockstep: the source baselineVersion and the source hooks/VERSION must match,
# or the drift differ would report a false version against every downstream repo.
# (Every other invariant in this layer got a test; this closes the last manual one.)
cfgver="$("$PY" - "$ROOT/baseline.config.json" <<'PY'
import json, sys
try: print(json.load(open(sys.argv[1], encoding="utf-8")).get("baselineVersion", "") or "")
except Exception: print("")
PY
)"
fmkver="$(tr -d '\r\n' < "$ROOT/hooks/VERSION" 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
if [ -n "$cfgver" ] && [ "$cfgver" = "$fmkver" ]; then
  echo "   ok baselineVersion == hooks/VERSION ($cfgver)"
else
  echo "  FAIL: baseline.config.json baselineVersion ('$cfgver') != hooks/VERSION ('$fmkver')"; fail=1
fi
bash "$ROOT/tests/test_status.sh" || fail=1

echo "== 7. hot-path hook latency budgets =="
# Every other step here asserts exit codes, and an exit code has no clock on it —
# which is how a 17.4s post-write dispatcher survived a full review. This step times
# the hooks that run on every tool call and fails if one is an order of magnitude
# over budget. It installs the baseline, so it needs git like step 4; it skips
# cleanly (exit 0) on a host whose `date` has no nanosecond precision.
if command -v git >/dev/null 2>&1; then
  bash "$ROOT/tests/test_latency.sh" || fail=1
else
  no_git test_latency.sh
fi

echo "== 8. Hebrew translations in sync with the English docs =="
# The Hebrew onboarding and README make the same security claims as the English
# ones, to readers least able to cross-check them, so a stale translation fails the
# build. The fixtures prove the checker catches each defect class it claims to
# (drift, an altered or invented command, bidi controls, broken anchors, a decoder
# message gone from the hooks); then the real files are checked.
"$PY" "$ROOT/tests/test_translation_sync.py" || fail=1
"$PY" "$ROOT/tests/translation_sync.py" check || fail=1

echo "== 9. policy-change release gate =="
# The gate itself runs in CI on pull requests, against the real base branch. Here its
# regression suite runs it against scratch repositories: what counts as policy, what
# satisfies it, and that every way of not knowing the change set fails closed.
if command -v git >/dev/null 2>&1; then
  bash "$ROOT/tests/test_policy_gate.sh" || fail=1
else
  no_git test_policy_gate.sh
fi

echo ""
if [ "$fail" -eq 0 ]; then echo "ALL GREEN"; else echo "FAILURES ABOVE"; fi
exit $fail
