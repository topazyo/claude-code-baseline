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

echo "== 1. shell syntax (bash -n) =="
while IFS= read -r f; do
  bash -n "$f" || { echo "  FAIL: bash -n $f"; fail=1; }
done < <(find "$ROOT/hooks" "$ROOT/tools" -name '*.sh' 2>/dev/null)
echo "   ok"

echo "== 2. python sources compile =="
for p in "$ROOT/hooks/lib/command_guard_match.py" "$ROOT/lib/merge_settings.py"; do
  "$PY" -m py_compile "$p" && echo "   ok $(basename "$p")" || { echo "  FAIL: py_compile $p"; fail=1; }
done

echo "== 3. command-guard matcher fixtures =="
"$PY" "$ROOT/tests/test_command_guard.py" || fail=1

echo "== 4. hook integration suite =="
if command -v git >/dev/null 2>&1; then
  bash "$ROOT/tests/test_hooks.sh" || fail=1
else
  echo "   SKIP (git not available)"
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
  echo "   SKIP (git not available)"
fi

echo ""
if [ "$fail" -eq 0 ]; then echo "ALL GREEN"; else echo "FAILURES ABOVE"; fi
exit $fail
