#!/usr/bin/env bash
# claude-code-baseline :: tests/test_status.sh
#
# Tests for tools/baseline-status.sh (ROADMAP Q1 metrics + Q3 drift). Installs the
# baseline into a throwaway repo, leaves a second repo un-installed, and asserts:
#   - the --json report parses and carries the documented per-repo fields;
#   - drift is OK for a fresh install and not-installed for the bare repo;
#   - SINGLE SOURCE OF TRUTH: the script's enabledModules agrees, key-for-key, with
#     common.sh's bcl_module_enabled (the readers the hooks themselves use);
#   - --strict exits non-zero on a hand-edited (drifted) VERSION and zero once matched;
#   - LOCAL-ONLY: a static grep finds no network primitives in the script source;
#   - the tool writes nothing to CWD when --json is not passed.
# Requires bash + python3 + git. Exits non-zero on any failure.
set -uo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$(command -v python3 || command -v python || true)"
[ -z "$PY" ] && { echo "python3 (or python) is required" >&2; exit 1; }
command -v git >/dev/null 2>&1 || { echo "git is required" >&2; exit 1; }
winpath() { cygpath -m "$1" 2>/dev/null || printf '%s' "$1"; }

STATUS="$SRC/tools/baseline-status.sh"
COMMON="$SRC/hooks/lib/common.sh"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
pass=0; fail=0
ok() { pass=$((pass + 1)); }
no() { fail=$((fail + 1)); echo "  FAIL [$1]"; }

A="$(winpath "$TMP/repoA")"; B="$(winpath "$TMP/repoB")"
mkdir -p "$A" "$B"
( cd "$A" && git init -q )
( cd "$B" && git init -q )
# Same stdin hazard as test_hooks.sh: install.sh probes `claude --version`, and the
# real CLI inherits this harness's stdin and never returns. Stub it, and close stdin
# on every install so a blocked read fails fast instead of hanging the suite.
STUBBIN="$TMP/stubbin"; mkdir -p "$STUBBIN"
printf '#!/usr/bin/env bash\necho "99.0.0 (Claude Code)"\n' > "$STUBBIN/claude"
chmod +x "$STUBBIN/claude"
PATH="$STUBBIN:$PATH"; export PATH
timeout -k 5 120 bash "$SRC/install.sh" --target "$A" >/dev/null 2>&1 </dev/null
# Enable one module (and leave another off) to exercise single-source-of-truth.
"$PY" -c "import json;p=r'$A/.claude/baseline.config.json';c=json.load(open(p));c['modules']['fixTags']['enabled']=True;json.dump(c,open(p,'w'))"

echo "== baseline-status: JSON shape + drift fields =="
OUT="$(winpath "$TMP/out.json")"
timeout -k 5 60 bash "$STATUS" --drift --json "$OUT" "$A" "$B" >/dev/null 2>&1 || no "non-strict run should exit 0"
if "$PY" - "$OUT" "$A" "$B" <<'PY'
import json, sys
out, A, B = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.load(open(out, encoding="utf-8"))
assert d.get("sourceBaselineVersion"), "missing sourceBaselineVersion"
repos = {r["repo"]: r for r in d["repos"]}
assert A in repos and B in repos, list(repos)
a = repos[A]
for k in ("installed", "enforcement", "enabledModules", "minVersionOk", "baselineVersion", "drift"):
    assert k in a, ("missing field", k, a)
assert a["installed"] is True, a
assert a["drift"] == "OK", ("fresh install should match source", a["drift"])
assert a["baselineVersion"] == d["sourceBaselineVersion"], a
assert "fixTags" in a["enabledModules"], a["enabledModules"]
assert "scopeGuard" not in a["enabledModules"], a["enabledModules"]
b = repos[B]
assert b["installed"] is False, b
assert b["drift"] == "not-installed", b["drift"]
raise SystemExit(0)
PY
then ok; else no "json shape / drift fields"; fi

echo "== baseline-status: single source of truth (script == bcl_module_enabled) =="
dfix="$(CLAUDE_PROJECT_DIR="$A" bash -c "source '$COMMON'; bcl_module_enabled fixTags && echo 1 || echo 0")"
dscope="$(CLAUDE_PROJECT_DIR="$A" bash -c "source '$COMMON'; bcl_module_enabled scopeGuard && echo 1 || echo 0")"
# The JSON above asserted fixTags present + scopeGuard absent; bcl must agree (iff).
[ "$dfix" = "1" ] && ok || no "bcl_module_enabled fixTags should be true (script reported it enabled)"
[ "$dscope" = "0" ] && ok || no "bcl_module_enabled scopeGuard should be false (script reported it disabled)"

echo "== baseline-status: --strict exits non-zero on drift, zero when matched =="
echo "1970-01-01" > "$A/.claude/hooks/baseline/VERSION"   # hand-edit to an old version
if timeout -k 5 60 bash "$STATUS" --strict "$A" >/dev/null 2>&1; then no "--strict should FAIL on drifted VERSION"; else ok; fi
timeout -k 5 120 bash "$SRC/install.sh" --target "$A" >/dev/null 2>&1 </dev/null  # re-run reconciles (recopies VERSION)
if timeout -k 5 60 bash "$STATUS" --strict "$A" >/dev/null 2>&1; then ok; else no "--strict should PASS after reinstall"; fi
# A not-installed repo must NOT trip --strict (it is "not adopted", not "behind").
if timeout -k 5 60 bash "$STATUS" --strict "$B" >/dev/null 2>&1; then ok; else no "--strict should pass for a not-installed repo"; fi

echo "== baseline-status: local-only (no network primitives in source) =="
if grep -E '(curl|wget|nc |/dev/tcp|ssh |scp |https?://)' "$STATUS" >/dev/null 2>&1; then
  no "network primitive found in baseline-status.sh"
else ok; fi

echo "== baseline-status: no writes to CWD without --json =="
RO="$(winpath "$TMP/ro")"; mkdir -p "$RO"
before="$(cd "$RO" && ls -a | sort)"
( cd "$RO" && timeout -k 5 60 bash "$STATUS" --drift "$A" >/dev/null 2>&1 )
after="$(cd "$RO" && ls -a | sort)"
[ "$before" = "$after" ] && ok || no "running without --json wrote into CWD"

echo ""
echo "test_status: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
