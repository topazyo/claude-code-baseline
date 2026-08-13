#!/usr/bin/env bash
# claude-code-baseline :: tests/test_latency.sh
#
# Latency regression gate for the hooks that run on the HOT PATH — the ones a user
# pays for on every single tool call:
#   guardrails/command-guard.sh   PreToolUse, every Bash call
#   dispatcher/post-write.sh      PostToolUse, every Write/Edit
#   modules/scope-guard.sh        PreToolUse, every Write/Edit (when enabled)
#   modules/config-guard.sh       ConfigChange, every settings edit (when enabled)
#
# Why this file exists: a 17.4s post-write dispatcher and a 5.6s command-guard sat
# in the repo through a full adversarial review, because every other test in this
# suite asserts on exit codes only and an exit code does not have a clock on it. A
# security control that adds seconds to every command gets switched off, and a
# control that is switched off is a security outcome — so latency is in scope here.
#
# This test is deliberately BEHAVIOURAL: it feeds each hook a payload on stdin and
# times the process, so it keeps working across refactors of hooks/lib/common.sh and
# knows nothing about interpreter counts, memoisation, or helper internals.
#
# Requires bash + python3 + git, and a `date` with nanosecond precision (see the
# capability probe below — the test SKIPS cleanly without one). Exits non-zero on
# any hook over budget.
set -uo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$(command -v python3 || command -v python || true)"
[ -z "$PY" ] && { echo "python3 (or python) is required" >&2; exit 1; }
command -v git >/dev/null 2>&1 || { echo "git is required" >&2; exit 1; }

# Same Git Bash shim as test_hooks.sh: Windows Python cannot open MSYS '/tmp/...'
# paths, so anything Python or a payload will see gets the Windows form.
winpath() { cygpath -m "$1" 2>/dev/null || printf '%s' "$1"; }

# ---------------------------------------------------------------------------
# Capability probe: nanosecond clock.
#
# `date +%s%N` is a GNU extension. BSD date (macOS without coreutils, some *BSD)
# prints the literal 'N', and a few shells' builtins drop the format entirely and
# return plain seconds. Either would make every elapsed time come out as 0 or as
# garbage, and a latency test that reports a false failure on a developer's laptop
# gets deleted rather than fixed. So: probe, and SKIP loudly but successfully.
#
# Two checks, because the failure modes differ: non-digits catches the literal-'N'
# form, and the length floor catches a `date` that silently answered in seconds
# (10 digits) instead of nanoseconds (19 by now, and until the year 2286).
# ---------------------------------------------------------------------------
probe="$(date +%s%N 2>/dev/null || true)"
case "$probe" in
  ''|*[!0-9]*) probe="" ;;
  *) [ "${#probe}" -ge 19 ] || probe="" ;;
esac
if [ -z "$probe" ]; then
  echo "== hot-path hook latency =="
  echo "   SKIP: 'date +%s%N' does not provide nanosecond precision on this host"
  echo "         (BSD/macOS date prints a literal 'N'). Install GNU coreutils to"
  echo "         enable the latency gate; nothing here is asserted meanwhile."
  echo ""
  echo "test_latency: 0 passed, 0 failed (skipped: no nanosecond clock)"
  exit 0
fi

TMP="$(mktemp -d)"
# Same cleanup contract as test_hooks.sh: cd out before removing (a live cwd inside
# $TMP makes removal fail with "Device or resource busy"), and make the signal
# handlers exit explicitly — a bash trap on INT/TERM does not end the script by
# itself, so a handler that only cleaned up would delete $TMP and let the rest of
# the run measure a directory that no longer exists.
cleanup() { cd "$SRC" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# install.sh probes `claude --version` whenever a claude binary is on PATH. Run this
# suite from inside a Claude Code session and that is the REAL CLI, which inherits
# the harness stdin and never reaches EOF — the run would hang instead of failing.
# Shadow it for the whole run.
STUBBIN="$TMP/stubbin"; mkdir -p "$STUBBIN"
printf '#!/usr/bin/env bash\necho "99.0.0 (Claude Code)"\n' > "$STUBBIN/claude"
chmod +x "$STUBBIN/claude"
PATH="$STUBBIN:$PATH"; export PATH

WT="$(winpath "$TMP")"
cd "$WT" || exit 1
git init -q
git config user.email t@example.com; git config user.name tester
# A global commit.gpgsign or core.hooksPath inherited from the developer's own
# config would prompt for a passphrase, or run another stdin-reading hook, inside
# a timed region — and would be measured as baseline latency.
git config commit.gpgsign false; git config core.hooksPath ""
timeout -k 5 120 bash "$SRC/install.sh" --target "$WT" >/dev/null 2>&1 </dev/null

H="$WT/.claude/hooks/baseline"
CFG="$WT/.claude/baseline.config.json"
export CLAUDE_PROJECT_DIR="$WT"
pass=0; fail=0
setcfg() { "$PY" -c "import json;p=r'$CFG';c=json.load(open(p));$1;json.dump(c,open(p,'w'))"; }

# ---------------------------------------------------------------------------
# Budgets, in milliseconds — and why these numbers rather than round ones.
#
# Measured on the developer host (Windows 11, Git Bash, Python 3.13), min-of-5,
# AFTER the interpreter fix in 896d0a2 that stopped bcl_python resolving to the
# Microsoft Store app-execution alias:
#
#     dispatcher 1561ms | config-guard 636ms | command-guard 509ms
#
# and re-measured by this very script while it was being written, same host, across
# five full runs — the ranges are what a green run looks like today, and the spread
# is a reminder that even min-of-5 moves ~15% between runs on Windows:
#
#     command-guard 425-506ms | dispatcher 1341-1543ms
#     scope-guard   525-606ms | config-guard 556-672ms
#
# The regression class this gate exists to catch, same host, same hooks, before
# that fix — i.e. what a re-introduced per-call interpreter spawn costs:
#
#     dispatcher 17400ms | config-guard 10500ms | command-guard 5600ms | scope-guard 2200ms
#
# So the healthy and the broken populations are separated by ~4x to ~16x, and the
# band between them is empty. Each budget below sits inside that band, 3-6x above
# the current measurement and comfortably under the regressed value. That ratio is
# the whole design: tight enough that ONE returning interpreter spawn on a hook
# that makes several helper calls trips it, loose enough that a busy CI runner,
# a cold filesystem cache, or an antivirus scan does not. A gate tuned to a few
# percent would fire on noise, get muted, and protect nothing.
#
# The budgets are sized for the SLOWEST supported platform, Git Bash on Windows,
# which is where the regression lived — interpreter startup there is measured in
# hundreds of milliseconds, against ~30ms on Linux. CI runs ubuntu-latest, so the
# same hooks come in several times under these ceilings there and the margin is
# wider still; the numbers are not tuned to the runner.
#
# These are ceilings, not targets. Work in flight is pushing the measured numbers
# down further; that widens the margin and does not require touching this table.
# If you must RAISE a budget, treat it as a finding to explain, not a chore — and
# record the new measurement in the comment above so the next reader sees drift.
# ---------------------------------------------------------------------------
BUDGET_COMMAND_GUARD=2500     # measured 425ms; pre-fix 5600ms — 5.9x headroom, catches the regression
BUDGET_DISPATCHER=6000        # measured 1341ms; pre-fix 17400ms — it runs 5 children, so it is the slowest by design
BUDGET_SCOPE_GUARD=2000       # measured 545ms; pre-fix 2200ms — 1 spawn, the tightest band of the four
BUDGET_CONFIG_GUARD=3000      # measured 556ms; pre-fix 10500ms — 5 helper calls, the worst per-call-spawn amplifier

# Repetitions per hook. min-of-N, NOT a mean and NOT a single sample: on Windows,
# antivirus and filesystem noise produce large one-off spikes — a bare interpreter
# start was observed at both 61ms and 1150ms on the same machine within one session.
# A mean inherits every spike (and would make this test flaky in exactly the way
# that gets latency tests deleted); the minimum is the robust statistic for "how
# fast can this hook go on this host", which is the property a regression changes.
# It is also conservative in the right direction: a real regression slows down the
# fast path too, so the minimum still moves.
REPS=5
# Hard bound per invocation. A hook that hangs (the unbounded `cat` on stdin was a
# real defect here) must FAIL this test, not wedge it. 30s is ~5x the largest budget,
# so it never truncates a measurement we would otherwise report.
HARD_BOUND=30

# Payload files. Written to disk and redirected in, rather than piped from printf,
# for two reasons: a regular file hits EOF immediately (so a hook that reads stdin
# can never block), and there is no extra process inside the timed region.
mkdir -p "$TMP/payloads"
P_BASH="$TMP/payloads/bash.json"
P_WRITE="$TMP/payloads/write.json"
P_SCOPE="$TMP/payloads/scope.json"
P_CONFIG="$TMP/payloads/config.json"
printf '{"tool_name":"Bash","tool_input":{"command":"git status"}}' > "$P_BASH"
printf 'x = 1\n' > "$WT/app.py"
printf '{"tool_name":"Write","tool_input":{"file_path":"%s"}}' "$WT/app.py" > "$P_WRITE"
printf 'src/in-scope.py\n' > "$WT/.claude/active-issue-scope.txt"
printf '{"tool_name":"Write","tool_input":{"file_path":"src/in-scope.py"}}' > "$P_SCOPE"
printf '{"source":"project_settings","file_path":"%s"}' "$WT/.claude/settings.json" > "$P_CONFIG"

# measure <label> <hook-relpath> <payload-file> <budget-ms> <expected-rc>
#
# The expected-rc assertion is not decoration: without it a hook that crashed on
# line 1 would post a superb time and pass the latency gate. Every case below is a
# full-work path (matcher runs, config is read, the target file is inspected), so a
# fast run here means the hook really did its job quickly.
measure() {
  local label="$1" hook="$2" pf="$3" budget="$4" want="$5"
  local i t0 t1 ms rc best=-1 rcbad=""
  for (( i = 0; i < REPS; i++ )); do   # bash arithmetic loop, not `seq` — one less external dependency
    t0="$(date +%s%N)"
    timeout -k 5 "$HARD_BOUND" bash "$H/$hook" < "$pf" >/dev/null 2>&1
    rc=$?
    t1="$(date +%s%N)"
    ms=$(( (t1 - t0) / 1000000 ))
    if [ "$rc" != "$want" ]; then rcbad="$rc"; break; fi
    if [ "$best" -lt 0 ] || [ "$ms" -lt "$best" ]; then best="$ms"; fi
  done
  if [ -n "$rcbad" ]; then
    fail=$((fail + 1))
    printf '   %-26s %7s      %s\n' "$label" "-" "FAIL: exit $rcbad (want $want) — timing not meaningful"
    return
  fi
  # Always print the measurement, pass or fail. A hook drifting from 500ms to 2000ms
  # is still green but is the story a human reading a CI log needs to see BEFORE it
  # crosses the threshold; a gate that only speaks when it fails hides the approach.
  if [ "$best" -le "$budget" ]; then
    pass=$((pass + 1))
    printf '   %-26s %5s ms   (budget %5s ms)  ok\n' "$label" "$best" "$budget"
  else
    fail=$((fail + 1))
    printf '   %-26s %5s ms   (budget %5s ms)  FAIL\n' "$label" "$best" "$budget"
    echo "  FAIL [$label over budget: ${best}ms > ${budget}ms, min of $REPS runs]"
    echo "       A hook on the hot path got an order of magnitude slower. The usual cause is a"
    echo "       helper that spawns its own interpreter per call — check how many processes the"
    echo "       hook starts before deciding the budget is wrong."
  fi
}

echo "== hot-path hook latency (min of $REPS runs, per-hook budgets) =="

# command-guard and the dispatcher are measured under the PRISTINE installed config,
# because that is the configuration every adopter actually runs: guardrails on,
# every module off. The dispatcher still launches all five children in that state
# (each self-gates on the config), which is exactly the path that measured 17.4s.
measure "command-guard.sh"     guardrails/command-guard.sh  "$P_BASH"   "$BUDGET_COMMAND_GUARD" 0
measure "dispatcher/post-write" dispatcher/post-write.sh    "$P_WRITE"  "$BUDGET_DISPATCHER"    0

# The two opt-in modules have to be ENABLED to be measured at all: disabled, they
# return at their first gate and would time a no-op.
setcfg "c['modules']['scopeGuard']['enabled']=True; c['modules']['configGuard']['enabled']=True"
measure "scope-guard.sh"       modules/scope-guard.sh       "$P_SCOPE"  "$BUDGET_SCOPE_GUARD"   0
measure "config-guard.sh"      modules/config-guard.sh      "$P_CONFIG" "$BUDGET_CONFIG_GUARD"  0

echo ""
echo "test_latency: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
