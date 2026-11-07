#!/usr/bin/env bash
# claude-code-baseline :: tests/test_hooks.sh
#
# Integration tests: install the baseline into a throwaway repo and exercise each
# hook's block/allow behaviour and exit codes — the R1 fail-closed guarantees and
# the R2 command-guard, plus exit-2 semantics, posture toggles, scope-guard, and
# fix-tags. Requires bash + python3 + git (Linux / WSL / macOS / CI; also Git Bash
# on Windows via the cygpath shim below). Exits non-zero on any failure.
set -uo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$(command -v python3 || command -v python || true)"
[ -z "$PY" ] && { echo "python3 (or python) is required" >&2; exit 1; }
command -v git >/dev/null 2>&1 || { echo "git is required" >&2; exit 1; }

# On Git Bash (Windows), Python is the native Windows interpreter and cannot open
# MSYS '/tmp/...' paths, so feed Python a Windows-form path. On Linux/WSL/macOS,
# cygpath is absent and we use the native path unchanged.
winpath() { cygpath -m "$1" 2>/dev/null || printf '%s' "$1"; }

TMP="$(mktemp -d)"
# cd out of $TMP before removing it. The harness cd's into $WT below, and a live
# cwd inside the directory makes removal fail with "Device or resource busy" —
# which is what left stray temp dirs behind whenever this suite was interrupted.
#
# The signal handlers must exit explicitly. A bash trap on INT/TERM does NOT end
# the script by itself, so a handler that only cleans up would delete $TMP and
# then let the rest of the suite run against a directory that no longer exists —
# every later assertion failing with exit 127 as though the installer were
# broken. The hooks wrap their children in `timeout`, which signals its process
# group, so a stray TERM reaching this harness is a real scenario, not a
# theoretical one.
cleanup() { cd "$SRC" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# install.sh runs `claude --version` whenever a `claude` binary is on PATH. Run this
# suite from inside a Claude Code session — or any agent orchestrator — and that is
# the REAL CLI, which inherits the harness stdin and never reaches EOF. The suite
# then blocks forever instead of failing, and since the parent never exits the EXIT
# trap above never fires either. Shadow `claude` with a stub for the whole run; the
# version-check tests below prepend their own bin dir, so they still win over this.
STUBBIN="$TMP/stubbin"; mkdir -p "$STUBBIN"
printf '#!/usr/bin/env bash\necho "99.0.0 (Claude Code)"\n' > "$STUBBIN/claude"
chmod +x "$STUBBIN/claude"
PATH="$STUBBIN:$PATH"; export PATH
WT="$(winpath "$TMP")"     # Python/payload-facing form of the temp dir
cd "$WT" || exit 1
git init -q
git config user.email t@example.com; git config user.name tester
# A global commit.gpgsign or core.hooksPath inherited from the developer's own
# config would prompt for a passphrase, or run another stdin-reading hook, inside
# the harness. Neutralise both for this scratch repo.
git config commit.gpgsign false; git config core.hooksPath ""
# Every child that could read stdin gets /dev/null. A blocked read looks exactly
# like a slow test, so an unbounded wait turns what should be a FAIL into a hang.
timeout -k 5 120 bash "$SRC/install.sh" --target "$WT" >/dev/null 2>&1 </dev/null
cp "$WT/.claude/baseline.config.json" "$WT/.claude/_pristine.json"

H="$WT/.claude/hooks/baseline"
CFG="$WT/.claude/baseline.config.json"
RULES="$WT/.claude/security-defaults.json"
export CLAUDE_PROJECT_DIR="$WT"
pass=0; fail=0

setcfg() { "$PY" -c "import json;p=r'$CFG';c=json.load(open(p));$1;json.dump(c,open(p,'w'))"; }
resetcfg() { cp "$WT/.claude/_pristine.json" "$CFG"; }
valid_rules() { "$PY" -c "import json;json.dump({'infraPattern':'docker-compose','rules':[{'id':'no-root','appliesWhen':r'^\s*user:\s','mustMatch':'1000:1000','message':'x'}]},open(r'$RULES','w'))"; }

# run <desc> <hook-relpath> <payload> <expected-rc>
run() {
  local desc="$1" hook="$2" payload="$3" want="$4" got
  printf '%s' "$payload" | bash "$H/$hook" >/dev/null 2>&1; got=$?
  if [ "$got" = "$want" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [$desc] want=$want got=$got"; fi
}
bash_payload() { printf '{"tool_name":"Bash","tool_input":{"command":"%s"}}' "$1"; }
write_payload() { printf '{"tool_name":"Write","tool_input":{"file_path":"%s"}}' "$1"; }

echo "== command-guard (PreToolUse:Bash) =="
run "rm -rf / blocks"        guardrails/command-guard.sh "$(bash_payload 'rm -rf /')" 2
run "git push -fv blocks"    guardrails/command-guard.sh "$(bash_payload 'git push -fv origin main')" 2
run "git status allows"      guardrails/command-guard.sh "$(bash_payload 'git status')" 0
run "rm -rf ./build allows"  guardrails/command-guard.sh "$(bash_payload 'rm -rf ./build')" 0
setcfg "c['enforcement']='warn'"
run "warn posture allows rm" guardrails/command-guard.sh "$(bash_payload 'rm -rf /')" 0
resetcfg

echo "== security-defaults (PostToolUse) fail-closed + exit-2 =="
printf 'services:\n  app:\n    user: "0:0"\n' > "$WT/docker-compose.yml"
setcfg "c['modules']['securityDefaults']['enabled']=True"
valid_rules
run "violation -> exit 2"    modules/security-defaults.sh "$(write_payload "$WT/docker-compose.yml")" 2
printf 'services:\n  app:\n    user: "1000:1000"\n' > "$WT/docker-compose.yml"
run "clean -> exit 0"        modules/security-defaults.sh "$(write_payload "$WT/docker-compose.yml")" 0
rm -f "$RULES"
run "missing rules -> 2"     modules/security-defaults.sh "$(write_payload "$WT/docker-compose.yml")" 2
printf '{ "rules": [ { "appliesWhen": "^\\s" } ] }\n' > "$RULES"   # single backslash = invalid JSON
run "malformed rules -> 2"   modules/security-defaults.sh "$(write_payload "$WT/docker-compose.yml")" 2
"$PY" -c "import json;json.dump({'rules':[]},open(r'$RULES','w'))"
run "empty rules -> 2"       modules/security-defaults.sh "$(write_payload "$WT/docker-compose.yml")" 2
setcfg "c['enforcement']='warn'"
run "malformed+warn -> 0"    modules/security-defaults.sh "$(write_payload "$WT/docker-compose.yml")" 0
resetcfg; setcfg "c['modules']['securityDefaults']['enabled']=True"; setcfg "c['failClosed']=False"
run "empty+failClosed:false->0" modules/security-defaults.sh "$(write_payload "$WT/docker-compose.yml")" 0
resetcfg

echo "== dispatcher (PostToolUse) malformed-config fail-closed =="
printf '{ not valid json\n' > "$CFG"
run "malformed config -> 2"  dispatcher/post-write.sh "$(write_payload "$WT/docker-compose.yml")" 2
resetcfg

echo "== scope-guard (PreToolUse) =="
setcfg "c['modules']['scopeGuard']['enabled']=True"
printf 'src/in-scope.py\n' > "$WT/.claude/active-issue-scope.txt"
run "out-of-scope -> 2"      modules/scope-guard.sh "$(write_payload "$WT/src/other.py")" 2
run "in-scope -> 0"          modules/scope-guard.sh "$(write_payload "src/in-scope.py")" 0
run "unparseable -> 2"       modules/scope-guard.sh '{ not json' 2
resetcfg
# Subagent and skill definitions: a Write or Edit whose new text names the baseline hook
# directory is refused there, with scopeGuard off (the default) or on; elsewhere, or
# without that text, it is not. def_payload <tool> <file_path> <text key> <text>
def_payload() { printf '{"tool_name":"%s","tool_input":{"file_path":"%s","%s":"%s"}}' "$1" "$2" "$3" "$4"; }
DEFTXT="See /.claude/hooks/baseline/README for the baseline hooks."
run "agent file naming the hook dir -> 2"        modules/scope-guard.sh "$(def_payload Write "$WT/.claude/agents/helper.md" content "$DEFTXT")" 2
run "agent file, other text -> 0"                modules/scope-guard.sh "$(def_payload Write "$WT/.claude/agents/helper.md" content "A helper agent.")" 0
run "skill file via Edit new_string -> 2"        modules/scope-guard.sh "$(def_payload Edit "$WT/.claude/skills/x/SKILL.md" new_string "$DEFTXT")" 2
run "skill file, only old_string names it -> 0"  modules/scope-guard.sh "$(def_payload Edit "$WT/.claude/skills/x/SKILL.md" old_string "$DEFTXT")" 0
run "windows path, mixed case -> 2"              modules/scope-guard.sh "$(def_payload Write 'C:\\repo\\.Claude\\Agents\\h.md' content "$DEFTXT")" 2
run "relative agent path -> 2"                   modules/scope-guard.sh "$(def_payload Write ".claude/agents/h.md" content "$DEFTXT")" 2
run "same text in a source file -> 0"            modules/scope-guard.sh "$(def_payload Write "$WT/src/app.py" content "$DEFTXT")" 0
run "agent path with ./ -> 2"                    modules/scope-guard.sh "$(def_payload Write ".claude/./agents/h.md" content "$DEFTXT")" 2
run "agent path with // -> 2"                    modules/scope-guard.sh "$(def_payload Write ".claude//agents/h.md" content "$DEFTXT")" 2
run "agent path with ../ -> 2"                   modules/scope-guard.sh "$(def_payload Write ".claude/x/../agents/h.md" content "$DEFTXT")" 2
run "Edit with old and new text naming it -> 2"  modules/scope-guard.sh "$(printf '{"tool_name":"Edit","tool_input":{"file_path":".claude/agents/h.md","old_string":"%s","new_string":"%s"}}' "$DEFTXT" "$DEFTXT")" 2
run "unparseable payload naming it -> 2"         modules/scope-guard.sh '{"tool_name":"Write","tool_input":{"file_path":".claude/agents/h.md","content":"/.claude/hooks/baseline/x' 2
run "unparseable payload, module off -> 0"       modules/scope-guard.sh '{ not json' 0
run "payload the prime cannot encode, naming it -> 2" modules/scope-guard.sh "$(printf '{"tool_name":"Write","tool_input":{"file_path":".claude/agents/h.md","content":"/.claude/hooks/baseline/x \\%s"}}' ud800)" 2
setcfg "c['failClosed']=False"
run "unparseable payload naming it, failClosed false -> 0" modules/scope-guard.sh '{"tool_name":"Write","tool_input":{"file_path":".claude/agents/h.md","content":"/.claude/hooks/baseline/x' 0
resetcfg
run "an agents folder elsewhere -> 0"            modules/scope-guard.sh "$(def_payload Write "$WT/docs/agents/h.md" content "$DEFTXT")" 0
run "agents/ deeper below .claude/ -> 0"         modules/scope-guard.sh "$(def_payload Write "$WT/.claude/worktrees/w/src/agents/a.py" content "$DEFTXT")" 0
setcfg "c['modules']['scopeGuard']['enabled']=True"
out="$(def_payload Write "$WT/.claude/agents/helper.md" content "$DEFTXT" | bash "$H/modules/scope-guard.sh" 2>&1)"; rc=$?
case "$rc:$out" in 2:*"[scope-guard] REFUSED"*) pass=$((pass + 1)) ;; *) fail=$((fail + 1)); echo "  FAIL [scope-guard definition check, module on: rc=$rc]" ;; esac
setcfg "c['enforcement']='warn'"
run "agent file naming the hook dir, warn -> 0"  modules/scope-guard.sh "$(def_payload Write "$WT/.claude/agents/helper.md" content "$DEFTXT")" 0
out="$(def_payload Write "$WT/.claude/agents/helper.md" content "$DEFTXT" | bash "$H/modules/scope-guard.sh" 2>&1)"
case "$out" in *"[scope-guard] REFUSED"*) pass=$((pass + 1)) ;; *) fail=$((fail + 1)); echo "  FAIL [scope-guard definition check silent under warn]" ;; esac
# ...and under warn the scope check after it still runs (the file is outside the scope)
case "$out" in *"NOT in declared scope"*) pass=$((pass + 1)) ;; *) fail=$((fail + 1)); echo "  FAIL [scope-guard scope warning lost after the definition check under warn]" ;; esac
resetcfg

echo "== an allowed action's hook messages are shown (warn / failClosed:false) =="
# Claude Code shows no one the stderr of a hook that exits 0. On exit 0 the wired hooks
# must put exactly ONE JSON object on stdout: systemMessage (the user) and
# hookSpecificOutput.additionalContext (Claude), same text. On exit 2 stdout stays empty.
# run_out <desc> <hook> <want-rc> [env...] < payload on stdin: sets OUT and ERR apart.
run_out() {
  local desc="$1" hook="$2" want="$3" got; shift 3
  OUT="$(env "$@" bash "$H/$hook" 2>"$TMP/_err")"; got=$?
  ERR="$(cat "$TMP/_err")"
  if [ "$got" = "$want" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [$desc] want=$want got=$got"; fi
}
# notice_ok <desc> <event> <python expr over m (the message)>: OUT is one JSON object.
notice_ok() {
  if printf '%s' "$OUT" | "$PY" -c '
import json, sys
d = json.loads(sys.stdin.buffer.read().decode("utf-8"))
h = d["hookSpecificOutput"]
assert set(d) == {"systemMessage", "hookSpecificOutput"}, sorted(d)
assert h["hookEventName"] == sys.argv[1], h
assert h["additionalContext"] == d["systemMessage"]
m = d["systemMessage"]
assert eval(sys.argv[2]), m
' "$2" "$3" 2>"$TMP/_nerr"; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [$1: $(tail -1 "$TMP/_nerr") | stdout: $(printf '%s' "$OUT" | head -c 200)]"; fi
}
quiet_ok() { if [ -z "$OUT" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [$1: stdout not empty: $(printf '%s' "$OUT" | head -c 200)]"; fi; }
err_has() { case "$ERR" in *"$2"*) pass=$((pass + 1)) ;; *) fail=$((fail + 1)); echo "  FAIL [$1: stderr lacks '$2']" ;; esac; }

# command-guard
setcfg "c['enforcement']='warn'"
run_out "command-guard warn hit -> 0" guardrails/command-guard.sh 0 <<< "$(bash_payload 'rm -rf /')"
notice_ok "command-guard warn hit is shown" PreToolUse '"Would have been blocked by Claude Code baseline command-guard" in m and "enforcement: warn" in m'
err_has "command-guard warn hit still on stderr" "Would have been blocked by Claude Code baseline command-guard"
run_out "command-guard warn, clean command -> 0" guardrails/command-guard.sh 0 <<< "$(bash_payload 'ls -la')"
quiet_ok "command-guard warn, clean command prints nothing"            # regression guard
run_out "command-guard warn, unparseable -> 0" guardrails/command-guard.sh 0 <<< '{ not json'
notice_ok "command-guard degraded under warn is shown" PreToolUse '"CONTROL COULD NOT RUN" in m'
resetcfg
run_out "command-guard block hit -> 2" guardrails/command-guard.sh 2 <<< "$(bash_payload 'rm -rf /')"
quiet_ok "command-guard block hit prints nothing on stdout"           # regression guard
err_has "command-guard block reason unchanged" "Blocked by Claude Code baseline command-guard"
setcfg "c['failClosed']=False"
run_out "command-guard failClosed:false, unparseable -> 0" guardrails/command-guard.sh 0 <<< '{ not json'
notice_ok "command-guard failClosed:false degraded is shown" PreToolUse '"CONTROL COULD NOT RUN" in m and "enforcement: block, failClosed: false" in m'
resetcfg

# command-guard's own matcher-failure branches: a matcher that is gone, empty, exits
# non-zero, reports an error or overruns its 5s budget must block a CLEAN command, each
# with its own message. A stand-in matcher replaces the installed one, then the real one
# is restored. Each stand-in drains stdin first, so the hook's printf never hits SIGPIPE.
MATCHER="$H/lib/command_guard_match.py"
cp "$MATCHER" "$TMP/matcher.orig"
plant_matcher() { printf '%s\n' "import sys; sys.stdin.buffer.read(); $1" > "$MATCHER"; }
rm -f "$MATCHER"
run_out "matcher deleted -> 2" guardrails/command-guard.sh 2 <<< "$(bash_payload 'git status')"
quiet_ok "matcher deleted: nothing on stdout"
err_has "matcher deleted is named" "matcher script not found"
: > "$MATCHER"
run_out "matcher empty -> 2" guardrails/command-guard.sh 2 <<< "$(bash_payload 'git status')"
quiet_ok "matcher empty: nothing on stdout"
err_has "matcher empty is named" "matcher script empty"
plant_matcher "raise SystemExit(3)"
run_out "matcher exits 3 -> 2" guardrails/command-guard.sh 2 <<< "$(bash_payload 'git status')"
quiet_ok "matcher exits 3: nothing on stdout"
err_has "matcher exit code is reported" "matcher failed (rc=3)"
plant_matcher "print('__MATCHER_ERROR__ planted for the test')"
run_out "matcher reports an error -> 2" guardrails/command-guard.sh 2 <<< "$(bash_payload 'git status')"
quiet_ok "matcher error: nothing on stdout"
err_has "matcher error is a control that could not run" "CONTROL COULD NOT RUN"
err_has "matcher error text is passed on" "planted for the test"
# The suite already needs timeout(1) (the installs above run under it); the guard is
# belt-and-braces, and a skip is printed, never counted as a pass.
if command -v timeout >/dev/null 2>&1; then
  plant_matcher "import time; time.sleep(9)"
  run_out "matcher over its 5s budget -> 2" guardrails/command-guard.sh 2 <<< "$(bash_payload 'git status')"
  quiet_ok "matcher timeout: nothing on stdout"
  err_has "matcher timeout is reported" "exceeded its 5s budget"
else
  echo "  SKIP [matcher over its 5s budget: no timeout(1) on PATH]"
fi
setcfg "c['failClosed']=False"
plant_matcher "raise SystemExit(3)"
run_out "matcher exits 3 under failClosed:false -> 0" guardrails/command-guard.sh 0 <<< "$(bash_payload 'git status')"
notice_ok "matcher failure under failClosed:false is shown" PreToolUse '"CONTROL COULD NOT RUN" in m and "matcher failed (rc=3)" in m'
resetcfg
cp "$TMP/matcher.orig" "$MATCHER"
if cmp -s "$TMP/matcher.orig" "$MATCHER"; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [real matcher restored]"; fi
run "restored matcher: rm -rf / blocks" guardrails/command-guard.sh "$(bash_payload 'rm -rf /')" 2

# scope-guard: the definition refusal and the scope warning land in ONE object
setcfg "c['modules']['scopeGuard']['enabled']=True"; setcfg "c['enforcement']='warn'"
run_out "scope-guard warn, definition + out of scope -> 0" modules/scope-guard.sh 0 <<< "$(def_payload Write "$WT/.claude/agents/helper.md" content "$DEFTXT")"
notice_ok "scope-guard warn shows both messages" PreToolUse '"[scope-guard] REFUSED" in m and "NOT in declared scope" in m'
# JSON encoding: the scope file's first line is printed verbatim
printf 'ISSUE-7 "q" \\ tab\tcr\rctl\001 \327\251\327\234\327\225\327\235\nsrc/in-scope.py\n' > "$WT/.claude/active-issue-scope.txt"
run_out "scope-guard warn, awkward issue text -> 0" modules/scope-guard.sh 0 <<< "$(write_payload "$WT/src/other.py")"
notice_ok "awkward text round-trips through JSON" PreToolUse '"ISSUE-7 \"q\" \\ tab\tcr\rctl\x01 שלום" in m'
# Oversized: kept under Claude Code's 10,000-character cap, still one valid object
"$PY" -c "open(r'$WT/.claude/active-issue-scope.txt','w').write('A' * 20000 + '\nsrc/in-scope.py\n')"
run_out "scope-guard warn, oversized message -> 0" modules/scope-guard.sh 0 <<< "$(write_payload "$WT/src/other.py")"
notice_ok "oversized message is truncated under the cap" PreToolUse 'len(m) < 10000 and "truncated" in m'
# Multibyte, at both byte parities: one of the two cuts lands inside a 2-byte character,
# and the object must still decode as strict UTF-8 (notice_ok does). Under a C locale
# that proves the back-off; under a UTF-8 locale it proves _bcl_notice_cut's own
# `local LC_ALL=C`: without it ${s:0:8000} takes 8000 CHARACTERS (~15,850 bytes here),
# which the 10,000-character check cannot see, so the text before the suffix is measured
# in bytes (the correct cut leaves 7998 or 7999, by parity). The UTF-8 case is only
# meaningful if that locale exists: a missing one falls back to C and would pass anyway.
if [ "$(env LC_ALL=C.UTF-8 bash -c 's=ש; printf %s "${#s}"' 2>/dev/null)" = 1 ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [C.UTF-8 locale unavailable: the UTF-8 notice-cut case would prove nothing]"; fi
for loc in C C.UTF-8; do
  for pad in "" "x"; do
    "$PY" -c "open(r'$WT/.claude/active-issue-scope.txt','w',encoding='utf-8').write('$pad' + 'ש' * 9000 + '\nsrc/in-scope.py\n')"
    run_out "scope-guard warn, oversized multibyte ($loc, pad '$pad') -> 0" modules/scope-guard.sh 0 "LC_ALL=$loc" <<< "$(write_payload "$WT/src/other.py")"
    notice_ok "multibyte cut ($loc, pad '$pad') stays valid UTF-8, 7990-8000 bytes before the suffix" PreToolUse 'len(m) < 10000 and "truncated" in m and "ש" in m and 7990 <= len(m.split("\n… (truncated")[0].encode("utf-8")) <= 8000'
  done
done
printf 'src/in-scope.py\n' > "$WT/.claude/active-issue-scope.txt"
resetcfg; setcfg "c['modules']['scopeGuard']['enabled']=True"
run_out "scope-guard block, out of scope -> 2" modules/scope-guard.sh 2 <<< "$(write_payload "$WT/src/other.py")"
quiet_ok "scope-guard block prints nothing on stdout"                 # regression guard
resetcfg

# dispatcher: a child's report under warn becomes the dispatcher's ONE object
printf 'services:\n  app:\n    user: "0:0"\n' > "$WT/docker-compose.yml"; valid_rules
setcfg "c['modules']['securityDefaults']['enabled']=True"; setcfg "c['enforcement']='warn'"
run_out "post-write warn, security-defaults hit -> 0" dispatcher/post-write.sh 0 <<< "$(write_payload "$WT/docker-compose.yml")"
notice_ok "post-write warn shows the child's report" PostToolUse '"REGRESSION BLOCKER" in m and "enforcement: warn" in m'
resetcfg; setcfg "c['modules']['securityDefaults']['enabled']=True"
run_out "post-write block, security-defaults hit -> 2" dispatcher/post-write.sh 2 <<< "$(write_payload "$WT/docker-compose.yml")"
quiet_ok "post-write block prints nothing on stdout"                  # regression guard
err_has "post-write block still passes the child's report on" "REGRESSION BLOCKER"
# block + failClosed:false keeps child stderr in a file; an exit-2 report must still
# reach Claude through stderr, whole, with nothing on stdout.
setcfg "c['failClosed']=False"
run_out "post-write block+failClosed:false, security-defaults hit -> 2" dispatcher/post-write.sh 2 <<< "$(write_payload "$WT/docker-compose.yml")"
quiet_ok "post-write block+failClosed:false hit prints nothing on stdout"
err_has "post-write block+failClosed:false passes the child's report on" "REGRESSION BLOCKER"
err_has "post-write block+failClosed:false passes the report on whole" "Policy source:"
"$PY" -c "import json;json.dump({'rules':[]},open(r'$RULES','w'))"
run_out "post-write failClosed:false, empty rules -> 0" dispatcher/post-write.sh 0 <<< "$(write_payload "$WT/docker-compose.yml")"
notice_ok "post-write failClosed:false degraded child is shown" PostToolUse '"failClosed: false" in m and "security-defaults" in m'
valid_rules; printf 'services:\n  app:\n    user: "1000:1000"\n' > "$WT/docker-compose.yml"
resetcfg; setcfg "c['enforcement']='warn'"
run_out "post-write warn, nothing to report -> 0" dispatcher/post-write.sh 0 <<< "$(write_payload "$WT/notes.txt")"
quiet_ok "post-write warn, nothing to report prints nothing"          # regression guard
# run-tests: a failing check's output must reach Claude (exit 2) and the warn notice. The
# dispatcher discards its children's stdout, so the details have to go to stderr. Each
# stub prints one marker on stdout and another on stderr, so capturing one stream fails.
SCBIN="$TMP/sc-bin"; mkdir -p "$SCBIN"
printf '#!/usr/bin/env bash\necho "SC9999 out-detail"\necho "SC9999 err-detail" >&2\nexit 1\n' > "$SCBIN/shellcheck"; chmod +x "$SCBIN/shellcheck"
printf 'echo hi\n' > "$WT/stub.sh"
setcfg "c['modules']['runTests']['enabled']=True"; setcfg "c['enforcement']='warn'"
run_out "post-write warn, run-tests fails -> 0" dispatcher/post-write.sh 0 "PATH=$SCBIN:$PATH" <<< "$(write_payload "$WT/stub.sh")"
notice_ok "run-tests failure details reach the warn notice" PostToolUse '"SC9999 out-detail" in m and "SC9999 err-detail" in m and "checks failed" in m'
resetcfg; setcfg "c['modules']['runTests']['enabled']=True"
run_out "post-write block, run-tests fails -> 2" dispatcher/post-write.sh 2 "PATH=$SCBIN:$PATH" <<< "$(write_payload "$WT/stub.sh")"
quiet_ok "post-write block, run-tests fails prints nothing on stdout"
err_has "post-write block passes run-tests' stdout detail on" "SC9999 out-detail"
err_has "post-write block passes run-tests' stderr detail on" "SC9999 err-detail"
setcfg "c['failClosed']=False"
run_out "post-write block+failClosed:false, run-tests fails -> 2" dispatcher/post-write.sh 2 "PATH=$SCBIN:$PATH" <<< "$(write_payload "$WT/stub.sh")"
err_has "post-write block+failClosed:false passes run-tests' stdout detail on" "SC9999 out-detail"
err_has "post-write block+failClosed:false passes run-tests' stderr detail on" "SC9999 err-detail"
resetcfg; setcfg "c['modules']['runTests']['enabled']=True"
# The module alone: the details come first, then the verdict line.
run_out "run-tests alone, failing check -> 2" modules/run-tests.sh 2 "PATH=$SCBIN:$PATH" <<< "$(write_payload "$WT/stub.sh")"
case "$ERR" in *"SC9999 out-detail"*"checks failed"*) pass=$((pass + 1)) ;; *) fail=$((fail + 1)); echo "  FAIL [run-tests: stdout detail missing or after the verdict line]" ;; esac
case "$ERR" in *"SC9999 err-detail"*"checks failed"*) pass=$((pass + 1)) ;; *) fail=$((fail + 1)); echo "  FAIL [run-tests: stderr detail missing or after the verdict line]" ;; esac
# Truncation: a linter keeps its first 60 lines, a test runner its last lines (bats: 20),
# each with a marker; exactly the cap prints whole, no marker; an unterminated last line
# is not glued to the verdict line.
"$PY" -c "open(r'$(winpath "$SCBIN")/shellcheck','w',newline='\n').write('#!/usr/bin/env bash\n' + ''.join('echo \"LN%d.\"\n' % i for i in range(1, 71)) + 'exit 1\n')"
run_out "run-tests, 70-line linter report -> 2" modules/run-tests.sh 2 "PATH=$SCBIN:$PATH" <<< "$(write_payload "$WT/stub.sh")"
case "$ERR" in *"LN1."*"LN60."*"10 more lines omitted"*"checks failed"*) pass=$((pass + 1)) ;; *) fail=$((fail + 1)); echo "  FAIL [run-tests linter head cap: first 60 lines + marker on stderr]" ;; esac
case "$ERR" in *"LN61."*) fail=$((fail + 1)); echo "  FAIL [run-tests linter head cap printed line 61]" ;; *) pass=$((pass + 1)) ;; esac
"$PY" -c "open(r'$(winpath "$SCBIN")/shellcheck','w',newline='\n').write('#!/usr/bin/env bash\n' + ''.join('echo \"LN%d.\"\n' % i for i in range(1, 61)) + 'exit 1\n')"
run_out "run-tests, 60-line linter report -> 2" modules/run-tests.sh 2 "PATH=$SCBIN:$PATH" <<< "$(write_payload "$WT/stub.sh")"
case "$ERR" in *"LN1."*"LN60."*"checks failed"*) case "$ERR" in *omitted*) fail=$((fail + 1)); echo "  FAIL [run-tests: a report of exactly the cap got a marker]" ;; *) pass=$((pass + 1)) ;; esac ;; *) fail=$((fail + 1)); echo "  FAIL [run-tests: a report of exactly the cap was not printed whole]" ;; esac
printf '#!/usr/bin/env bash\nprintf "no newline at the end"\nexit 1\n' > "$SCBIN/shellcheck"
run_out "run-tests, unterminated report -> 2" modules/run-tests.sh 2 "PATH=$SCBIN:$PATH" <<< "$(write_payload "$WT/stub.sh")"
case "$ERR" in *"no newline at the end"$'\n'*"checks failed"*) pass=$((pass + 1)) ;; *) fail=$((fail + 1)); echo "  FAIL [run-tests: an unterminated last line was glued to the next line]" ;; esac
# bats: a passing shellcheck, a failing 25-line bats run on tests/stub.bats.
BATSBIN="$TMP/bats-bin"; mkdir -p "$BATSBIN" "$WT/tests"; : > "$WT/tests/stub.bats"
printf '#!/usr/bin/env bash\nexit 0\n' > "$BATSBIN/shellcheck"
"$PY" -c "open(r'$(winpath "$BATSBIN")/bats','w',newline='\n').write('#!/usr/bin/env bash\n' + ''.join('echo \"BT%d.\"\n' % i for i in range(1, 26)) + 'exit 1\n')"
chmod +x "$BATSBIN/shellcheck" "$BATSBIN/bats"
run_out "run-tests, 25-line bats failure -> 2" modules/run-tests.sh 2 "PATH=$BATSBIN:$PATH" <<< "$(write_payload "$WT/stub.sh")"
case "$ERR" in *"5 earlier lines omitted"*"BT6."*"BT25."*"checks failed"*) pass=$((pass + 1)) ;; *) fail=$((fail + 1)); echo "  FAIL [run-tests bats tail cap: marker + last 20 lines on stderr]" ;; esac
case "$ERR" in *"BT5."*) fail=$((fail + 1)); echo "  FAIL [run-tests bats tail cap printed line 5]" ;; *) pass=$((pass + 1)) ;; esac
rm -rf "$WT/tests"
# An inherited OUT_TMP never chooses the file the checks write.
printf 'keep\n' > "$TMP/keep-out"
printf '#!/usr/bin/env bash\necho "SC9999 out-detail"\nexit 1\n' > "$SCBIN/shellcheck"
run_out "run-tests, inherited OUT_TMP -> 2" modules/run-tests.sh 2 "PATH=$SCBIN:$PATH" "OUT_TMP=$TMP/keep-out" <<< "$(write_payload "$WT/stub.sh")"
if [ "$(cat "$TMP/keep-out")" = keep ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [run-tests wrote to an inherited OUT_TMP]"; fi
err_has "run-tests with an inherited OUT_TMP still reports the detail" "SC9999 out-detail"
# New behaviour, fails on main (a passing linter's stderr chatter became a notice): a
# passing check stays quiet under warn. The only test that kills "print on success" and
# "capture stdout only, let stderr stream"; keep it.
OKBIN="$TMP/sc-ok-bin"; mkdir -p "$OKBIN"
printf '#!/usr/bin/env bash\necho "stub ok chatter out"\necho "stub ok chatter err" >&2\nexit 0\n' > "$OKBIN/shellcheck"; chmod +x "$OKBIN/shellcheck"
setcfg "c['enforcement']='warn'"
run_out "post-write warn, run-tests passes -> 0" dispatcher/post-write.sh 0 "PATH=$OKBIN:$PATH" <<< "$(write_payload "$WT/stub.sh")"
quiet_ok "post-write warn, a passing run-tests check prints nothing"
# A grandchild a check leaves running holds run-tests' own output file, never a pipe, so
# run-tests does not wait for it and is never killed at its 27 s budget: the notice has
# the verdict line and no "exceeded" (that, not a tight clock, is what fails when a pipe
# holds run-tests: a wall-clock bound under the budget flaked at 25 s on a loaded host).
# The sleep runs from / so it never holds $TMP as its cwd.
printf '#!/usr/bin/env bash\n(cd / && exec sleep 40) &\necho "stub shellcheck: issue" >&2\nexit 1\n' > "$SCBIN/shellcheck"
t0=$(date +%s)
run_out "post-write warn, run-tests fails with a lingering grandchild -> 0" dispatcher/post-write.sh 0 "PATH=$SCBIN:$PATH" <<< "$(write_payload "$WT/stub.sh")"
t1=$(date +%s)
if [ $((t1 - t0)) -lt 30 ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [a grandchild of a run-tests check held the dispatcher for $((t1 - t0))s]"; fi
notice_ok "run-tests failure with a lingering grandchild is shown, not killed" PostToolUse '"stub shellcheck: issue" in m and "checks failed" in m and "exceeded" not in m'
resetcfg; rm -f "$WT/stub.sh"
# The dispatcher's own file (D4): a child whose grandchild holds the CHILD's stderr must
# not hold the dispatcher. A copy of the tree, with a stand-in for fix-tags.
cp -r "$H" "$TMP/h2"
printf '#!/usr/bin/env bash\n(cd / && exec sleep 40 >&2) &\necho "stand-in: lingering" >&2\nexit 0\n' > "$TMP/h2/modules/fix-tags.sh"
setcfg "c['enforcement']='warn'"
t0=$(date +%s)
H0="$H"; H="$TMP/h2"
run_out "post-write warn, a child's grandchild holds its stderr -> 0" dispatcher/post-write.sh 0 <<< "$(write_payload "$WT/notes.txt")"
H="$H0"
t1=$(date +%s)
if [ $((t1 - t0)) -lt 30 ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [a grandchild holding a child's stderr held the dispatcher for $((t1 - t0))s]"; fi
notice_ok "a child's stderr is shown though a grandchild still holds it" PostToolUse '"stand-in: lingering" in m'
resetcfg

# Inherited values cannot pre-seed a notice or aim the trap's cleanup at another file
printf 'keep\n' > "$TMP/keepme"
run_out "inherited notice, clean command -> 0" guardrails/command-guard.sh 0 _BCL_NOTICE=INJECTED _BCL_NOTICE_EVENT=PreToolUse <<< "$(bash_payload 'ls')"
quiet_ok "an inherited _BCL_NOTICE is not printed"
run_out "inherited _BCL_NOTICE_TMP, clean write -> 0" dispatcher/post-write.sh 0 "_BCL_NOTICE_TMP=$TMP/keepme" <<< "$(write_payload "$WT/notes.txt")"
if [ -f "$TMP/keepme" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [an inherited _BCL_NOTICE_TMP made the dispatcher delete another file]"; fi
rm -f "$TMP/keepme" "$TMP/_err" "$TMP/_nerr"

echo "== fix-tags (PostToolUse) =="
printf 'x = 1\n' > "$WT/app.py"; git add app.py; git commit -qm add </dev/null
printf 'x = 1\ny = 2\n' > "$WT/app.py"   # untagged added line
setcfg "c['modules']['fixTags']['enabled']=True"
run "untagged change -> 2"   modules/fix-tags.sh "$(write_payload "$WT/app.py")" 2
resetcfg

echo "== tracker-reminder (Stop): the reminder is shown to the user =="
# Plain stdout from an exit-0 hook reaches only the debug log. The reminder must be ONE
# JSON object holding only systemMessage: on Stop, additionalContext or a decision
# would send Claude back to work. sysmsg_ok <desc> <python expr over m (the message)>
sysmsg_ok() {
  if printf '%s' "$OUT" | "$PY" -c '
import json, sys
d = json.loads(sys.stdin.buffer.read().decode("utf-8"))
assert set(d) == {"systemMessage"}, sorted(d)
m = d["systemMessage"]
assert eval(sys.argv[1]), m
' "$2" 2>"$TMP/_nerr"; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [$1: $(tail -1 "$TMP/_nerr") | stdout: $(printf '%s' "$OUT" | head -c 200)]"; fi
}
TRK="c['modules']['trackerReminder']"
# Empty commits with a token no other test uses: the tree is untouched, the count is exact.
git commit -q --allow-empty -m "D3TRK-1 first" </dev/null
git commit -q --allow-empty -m "D3TRK-2 second" </dev/null
setcfg "$TRK.update(enabled=True, commitGrep='D3TRK-', tracker='CHANGELOG.md')"
run_out "tracker-reminder, 2 matching commits -> 0" modules/tracker-reminder.sh 0 <<< '{}'
sysmsg_ok "tracker-reminder prints one systemMessage object" '"2 of the last 20 commits matched" in m and "D3TRK-" in m and "confirm CHANGELOG.md is up to date" in m'
err_has "tracker-reminder text also on stderr (debug log)" "[tracker-reminder]"
run_out "tracker-reminder, inherited notice -> 0" modules/tracker-reminder.sh 0 _BCL_NOTICE=INJECTED _BCL_NOTICE_EVENT=Stop <<< '{}'
sysmsg_ok "inherited notice state adds no second object or text" '"INJECTED" not in m and "[tracker-reminder]" in m'   # regression guard
# JSON encoding: quote in the commit token; quote, backslash, TAB and non-ASCII in the tracker
git commit -q --allow-empty -m 'D3"Q quoted' </dev/null
setcfg "$TRK.update(enabled=True, commitGrep='D3\"Q', tracker='docs/\"plan\" \\\\ \\t \\u05e9\\u05dc\\u05d5\\u05dd.md')"
run_out "tracker-reminder, awkward values -> 0" modules/tracker-reminder.sh 0 <<< '{}'
sysmsg_ok "awkward tracker values round-trip through JSON" '"matched \x27D3\"Q\x27." in m and "confirm docs/\"plan\" \\ \t שלום.md is up to date" in m'
# Oversized: kept under Claude Code's 10,000-character cap, still one valid object
setcfg "$TRK.update(enabled=True, commitGrep='D3TRK-', tracker='A' * 20000)"
run_out "tracker-reminder, oversized tracker -> 0" modules/tracker-reminder.sh 0 <<< '{}'
sysmsg_ok "oversized reminder is truncated under the cap" 'len(m) < 10000 and "truncated" in m'
for pad in "" "x"; do
  setcfg "$TRK.update(enabled=True, commitGrep='D3TRK-', tracker='$pad' + '\\u05e9' * 9000)"
  run_out "tracker-reminder, oversized multibyte (pad '$pad') -> 0" modules/tracker-reminder.sh 0 LC_ALL=C <<< '{}'
  sysmsg_ok "multibyte cut (pad '$pad') stays valid UTF-8, 7990-8000 bytes before the suffix" 'len(m) < 10000 and "truncated" in m and "ש" in m and 7990 <= len(m.split("\n… (truncated")[0].encode("utf-8")) <= 8000'
done
# Nothing to remind about: stdout stays empty (regression guards)
setcfg "$TRK.update(enabled=True, commitGrep='D3TRK-NONE', tracker='CHANGELOG.md')"
run_out "tracker-reminder, no matching commit -> 0" modules/tracker-reminder.sh 0 <<< '{}'
quiet_ok "tracker-reminder, no matching commit prints nothing"
setcfg "$TRK.update(enabled=True, commitGrep='D3TRK-', tracker='')"
run_out "tracker-reminder, empty tracker -> 0" modules/tracker-reminder.sh 0 <<< '{}'
quiet_ok "tracker-reminder, empty tracker prints nothing"
# Off, with everything else set to fire: only the enabled gate can keep it quiet
setcfg "$TRK.update(enabled=False, commitGrep='D3TRK-', tracker='CHANGELOG.md')"
run_out "tracker-reminder, module off -> 0" modules/tracker-reminder.sh 0 <<< '{}'
quiet_ok "tracker-reminder, module off prints nothing"
# Per session (the Stop input's session_id): the matches are shown once, then only a NEW
# matching commit is. The memory lives in .git/baseline/tracker-reminder/<session_id>.
# Whenever it cannot be used, the module reminds at every Stop, as above with '{}'.
stop_payload() { printf '{"session_id":"%s","hook_event_name":"Stop","stop_hook_active":false}' "$1"; }
TRKOLD="2 of the last 20 commits matched"; TRKALL="3 of the last 20 commits matched"
SDIR="$WT/.git/baseline/tracker-reminder"
setcfg "$TRK.update(enabled=True, commitGrep='D3TRK-', tracker='CHANGELOG.md')"
porc0="$(git status --porcelain)"
run_out "tracker S1, first stop -> 0" modules/tracker-reminder.sh 0 <<< "$(stop_payload S1)"
sysmsg_ok "tracker S1, first stop shows the matches as before" '"'"$TRKOLD"'" in m and "confirm CHANGELOG.md" in m'
run_out "tracker S1, second stop -> 0" modules/tracker-reminder.sh 0 <<< "$(stop_payload S1)"
quiet_ok "tracker S1, second stop with nothing new prints nothing"
git commit -q --allow-empty -m "D3TRK-3 third" </dev/null
run_out "tracker S1, after a new matching commit -> 0" modules/tracker-reminder.sh 0 <<< "$(stop_payload S1)"
sysmsg_ok "tracker S1, a new matching commit is shown as 1 new" '"1 new matching commit(s) since the last reminder" in m and "D3TRK-" in m'
run_out "tracker S1, stop after that -> 0" modules/tracker-reminder.sh 0 <<< "$(stop_payload S1)"
quiet_ok "tracker S1, nothing new again prints nothing"
run_out "tracker S2, another session -> 0" modules/tracker-reminder.sh 0 <<< "$(stop_payload S2)"
sysmsg_ok "tracker S2, another session has its own memory" '"'"$TRKALL"'" in m'
# The memory is in .git, not the working tree. Guard (passes on main too): no session_id
# still reminds at every Stop.
if [ -f "$SDIR/S1" ] && [ "$(git status --porcelain)" = "$porc0" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [tracker session memory must be in .git/baseline, not the working tree]"; fi
for n in 1 2; do
  run_out "tracker no session_id, stop $n -> 0" modules/tracker-reminder.sh 0 <<< '{}'
  sysmsg_ok "tracker no session_id, stop $n reminds" '"'"$TRKALL"'" in m'
done
# Stateless, twice each: ids that are not plain names, a payload that is not JSON, no stdin.
long="$(printf 'x%.0s' $(seq 1 129))"
for bad in '../evil' 'a/b' '..' '' "$long"; do
  for n in 1 2; do
    run_out "tracker id '${bad:0:12}', stop $n -> 0" modules/tracker-reminder.sh 0 <<< "$(stop_payload "$bad")"
    sysmsg_ok "tracker id '${bad:0:12}', stop $n reminds as without a session" '"'"$TRKALL"'" in m'
  done
done
if [ ! -e "$WT/.git/baseline/evil" ] && [ ! -e "$WT/.git/evil" ] && [ ! -e "$SDIR/a" ] && [ ! -e "$SDIR/$long" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [tracker wrote a state file for an invalid session id]"; fi
run_out "tracker unparseable payload -> 0" modules/tracker-reminder.sh 0 <<< '{ not json'
sysmsg_ok "tracker unparseable payload reminds" '"'"$TRKALL"'" in m'
run_out "tracker no stdin -> 0" modules/tracker-reminder.sh 0 < /dev/null
sysmsg_ok "tracker no stdin reminds" '"'"$TRKALL"'" in m'
# Unusable memory, portable on every host: a directory where the session file belongs, and
# a plain file where the baseline directory belongs. Each reminds at every Stop.
mkdir "$SDIR/S9"
for n in 1 2; do
  run_out "tracker S9 state is a directory, stop $n -> 0" modules/tracker-reminder.sh 0 <<< "$(stop_payload S9)"
  sysmsg_ok "tracker S9 state is a directory, stop $n reminds" '"'"$TRKALL"'" in m'
done
mv "$WT/.git/baseline" "$TMP/baseline.saved"; printf 'x\n' > "$WT/.git/baseline"
for n in 1 2; do
  run_out "tracker .git/baseline is a file, stop $n -> 0" modules/tracker-reminder.sh 0 <<< "$(stop_payload S10)"
  sysmsg_ok "tracker .git/baseline is a file, stop $n reminds" '"'"$TRKALL"'" in m'
done
rm -f "$WT/.git/baseline"
# A symlinked baseline directory would aim the writes elsewhere: refused. Git Bash without
# the symlink privilege copies on `ln -s`; there a junction (no privilege needed, and MSYS
# reports it as a symlink) stands in, so Windows runs the case too.
mkdir "$TMP/elsewhere"
ln -s "$TMP/elsewhere" "$WT/.git/baseline" 2>/dev/null
if [ ! -L "$WT/.git/baseline" ] && command -v cygpath >/dev/null 2>&1; then
  rm -rf "$WT/.git/baseline"
  MSYS_NO_PATHCONV=1 cmd /c mklink /J "$(cygpath -w "$WT/.git/baseline")" "$(cygpath -w "$TMP/elsewhere")" >/dev/null 2>&1
fi
if [ -L "$WT/.git/baseline" ]; then
  for n in 1 2; do
    run_out "tracker symlinked .git/baseline, stop $n -> 0" modules/tracker-reminder.sh 0 <<< "$(stop_payload S11)"
    sysmsg_ok "tracker symlinked .git/baseline, stop $n reminds" '"'"$TRKALL"'" in m'
  done
  if [ -z "$(ls -A "$TMP/elsewhere")" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [tracker wrote through a symlinked .git/baseline]"; fi
  rm -f "$WT/.git/baseline"
else
  rm -rf "$WT/.git/baseline"
  echo "  note: symlinked-state case not run (ln -s made no symlink on this host)"
fi
mv "$TMP/baseline.saved" "$WT/.git/baseline"
# Prune: a session's first write removes memory idle for 14 days and keeps fresh memory.
: > "$SDIR/OLD"; touch -t 202001010000 "$SDIR/OLD"
run_out "tracker S12, first stop -> 0" modules/tracker-reminder.sh 0 <<< "$(stop_payload S12)"
if [ ! -e "$SDIR/OLD" ] && [ -f "$SDIR/S1" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [tracker prune: old session memory kept or fresh memory removed]"; fi
# Subject only: a commitGrep that is only in a hash does not count.
hpre="$(git log -1 --format=%H --fixed-strings --grep 'D3TRK-1 first' | cut -c1-7)"
if [ ${#hpre} -eq 7 ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [tracker subject-only case: no hash prefix found]"; fi
setcfg "$TRK.update(enabled=True, commitGrep='$hpre', tracker='CHANGELOG.md')"
run_out "tracker commitGrep in a hash only -> 0" modules/tracker-reminder.sh 0 <<< '{}'
quiet_ok "tracker matches commit subjects, not hashes"
resetcfg
rm -f "$TMP/_err" "$TMP/_nerr"

echo "== a baseline.config.json that cannot be read fails closed in every hook (M1/M7) =="
# A config that exists but cannot be read as a JSON object must fail closed in every
# wired hook, before its enabled-gate, even when its own text asks for warn and
# failClosed:false (unreadable is unreadable). tracker-reminder (Stop) only reports.
# Encoded fixtures are written as bytes from Python, never through setcfg.
err_lacks() { case "$ERR" in *"$2"*) fail=$((fail + 1)); echo "  FAIL [$1: stderr has '$2']" ;; *) pass=$((pass + 1)) ;; esac; }
resetcfg
printf '{ "enforcement": "warn", "failClosed": false, }\n' > "$CFG"   # trailing comma
run_out "unreadable config: command-guard, git status -> 2" guardrails/command-guard.sh 2 <<< "$(bash_payload 'git status')"
err_has "command-guard names the file" ".claude/baseline.config.json exists but cannot be read"
err_has "command-guard gives the parse error" "line 1 column"
err_has "command-guard says a human must fix it" "A human must fix or delete that file"
run_out "unreadable config: scope-guard (off by default) -> 2" modules/scope-guard.sh 2 <<< "$(write_payload "$WT/src/x.py")"
err_has "scope-guard reports it" "[scope-guard] CONTROL COULD NOT RUN"
run_out "unreadable config: config-guard -> 2" modules/config-guard.sh 2 <<< "$(printf '{"source":"project_settings","file_path":"%s"}' "$WT/.claude/settings.json")"
err_has "config-guard says where the user sees it" "command-guard, scope-guard and tracker-reminder report this"
run_out "unreadable config: dispatcher -> 2" dispatcher/post-write.sh 2 <<< "$(write_payload "$WT/notes.txt")"
err_has "dispatcher gives the parse error" "cannot be read (line 1 column"
run_out "unreadable config: tracker-reminder -> 0, never 2" modules/tracker-reminder.sh 0 <<< '{}'
sysmsg_ok "tracker-reminder shows the user the unreadable config" '"[tracker-reminder] CONTROL COULD NOT RUN" in m and "baseline.config.json" in m'
printf '[]\n' > "$CFG"   # valid JSON, not an object
run_out "top level not an object: command-guard -> 2" guardrails/command-guard.sh 2 <<< "$(bash_payload 'git status')"
err_has "command-guard says why" "the top level is not a JSON object"
run_out "top level not an object: dispatcher -> 2" dispatcher/post-write.sh 2 <<< "$(write_payload "$WT/notes.txt")"
# The matcher on its own: an unreadable config is an error, a missing one is "no patterns".
OUT="$(printf '%s' "$(bash_payload 'git status')" | "$PY" -I "$H/lib/command_guard_match.py" "$CFG")"
case "$OUT" in "__MATCHER_ERROR__ "*"not a JSON object"*) pass=$((pass + 1)) ;; *) fail=$((fail + 1)); echo "  FAIL [matcher: unreadable config -> __MATCHER_ERROR__, got: $OUT]" ;; esac
OUT="$(printf '%s' "$(bash_payload 'git status')" | "$PY" -I "$H/lib/command_guard_match.py" "$WT/.claude/no-such-config.json")"
if [ -z "$OUT" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [matcher: missing config -> clean verdict, got: $OUT]"; fi
resetcfg
# Encodings Windows PowerShell 5.1 writes are read, not refused: the extraPattern applies.
for codec in utf-8-sig utf-16; do
  "$PY" -c "import json,sys
c=json.load(open(sys.argv[1], encoding='utf-8'))
c['guardrails']['commandGuard']['extraPatterns']=['zz-repo-policy-zz']
c['modules']['scopeGuard']['enabled']=True
open(sys.argv[2],'wb').write(json.dumps(c).encode(sys.argv[3]))" "$WT/.claude/_pristine.json" "$CFG" "$codec"
  run_out "$codec config: extraPattern blocks" guardrails/command-guard.sh 2 <<< "$(bash_payload 'echo zz-repo-policy-zz')"
  err_has "$codec config: the repo pattern is the reason" "matched repo policy pattern"
  run_out "$codec config: git status -> 0" guardrails/command-guard.sh 0 <<< "$(bash_payload 'git status')"
  run_out "$codec config: scope-guard reads scopeGuard on" modules/scope-guard.sh 2 <<< "$(write_payload "$WT/src/other.py")"
  err_lacks "$codec config: scope-guard is not degraded" "CONTROL COULD NOT RUN"
  printf 'src/in-scope.py\n' > "$WT/.claude/active-issue-scope.txt"
  run_out "$codec config: scope-guard allows an in-scope path" modules/scope-guard.sh 0 <<< "$(write_payload "src/in-scope.py")"
  run_out "$codec config: dispatcher clean write -> 0" dispatcher/post-write.sh 0 <<< "$(write_payload "$WT/notes.txt")"
done
resetcfg
# M7: only a literal false turns the default-on command-guard off.
for v in "'TRUE'" "'True'" "1" "0" "''" "None" "'False'" "'yes'"; do
  setcfg "c['guardrails']['commandGuard']['enabled']=$v"
  run "commandGuard.enabled=$v keeps the guard on" guardrails/command-guard.sh "$(bash_payload 'git push --force origin main')" 2
done
for v in "False" "'false'"; do
  setcfg "c['guardrails']['commandGuard']['enabled']=$v"
  run "commandGuard.enabled=$v turns the guard off" guardrails/command-guard.sh "$(bash_payload 'git push --force origin main')" 0
done
resetcfg

echo "== common.sh load guard ignores the environment =="
# The library's double-source guard must not be settable from outside. An inherited
# _BCL_SOURCED used to make every hook skip common.sh: command-guard died on its first
# helper (rc 1, blocking only through onFailure) and the post-write dispatcher's
# violation report was lost as a non-blocking error.
# run_env <desc> <VAR=value> <hook-relpath> <payload> <expected-rc> <expected-output>
run_env() {
  local desc="$1" assign="$2" hook="$3" payload="$4" want="$5" needle="$6" got out
  out="$(printf '%s' "$payload" | env "$assign" bash "$H/$hook" 2>&1)"; got=$?
  if [ "$got" = "$want" ] && printf '%s' "$out" | grep -qF "$needle"; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [$desc] want=$want got=$got"; fi
}
rm -f "$TMP/rules.saved" "$TMP/compose.saved"
[ -f "$RULES" ] && cp "$RULES" "$TMP/rules.saved"
[ -f "$WT/docker-compose.yml" ] && cp "$WT/docker-compose.yml" "$TMP/compose.saved"
printf 'services:\n  app:\n    user: "0:0"\n' > "$WT/docker-compose.yml"
setcfg "c['modules']['securityDefaults']['enabled']=True"
valid_rules
# The third value is a control: bash never imports a name that is not an identifier,
# so it passed on the old scalar guard too. It pins the array design, not the old bug.
for inherited in '_BCL_SOURCED=1' '_BCL_SOURCED=([1]=1)' '_BCL_SOURCED[1]=1'; do
  run_env "command-guard, inherited $inherited"     "$inherited" guardrails/command-guard.sh "$(bash_payload 'git push --force origin main')" 2 "Blocked by Claude Code baseline command-guard"
  run_env "post-write, inherited $inherited"        "$inherited" dispatcher/post-write.sh "$(write_payload "$WT/docker-compose.yml")" 2 "REGRESSION BLOCKER"
  run_env "security-defaults, inherited $inherited" "$inherited" modules/security-defaults.sh "$(write_payload "$WT/docker-compose.yml")" 2 "REGRESSION BLOCKER"
done
resetcfg
if [ -f "$TMP/rules.saved" ]; then cp "$TMP/rules.saved" "$RULES"; else rm -f "$RULES"; fi
if [ -f "$TMP/compose.saved" ]; then cp "$TMP/compose.saved" "$WT/docker-compose.yml"; else rm -f "$WT/docker-compose.yml"; fi
# ...and the guard itself still works: with a value inherited, the first source loads
# the library, and a second source in the same shell or in a subshell returns early,
# keeping the state the first one set (re-running the file would reset it).
gs="$(env _BCL_SOURCED=1 bash -c 'set -euo pipefail
  . "$1"; type bcl_python >/dev/null 2>&1 || { printf nolib; exit 0; }
  _BCL_PRIME_STATE=sentinel; . "$1"; a="$_BCL_PRIME_STATE"
  b="$( . "$1"; printf %s "$_BCL_PRIME_STATE" )"
  printf "%s/%s" "$a" "$b"' _ "$H/lib/common.sh" 2>&1)"
if [ "$gs" = "sentinel/sentinel" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [common.sh double-source guard: got '$gs', want sentinel/sentinel]"; fi
# Inherited copies of the library's globals are dropped, not passed on: after loading,
# a child process sees no _BCL_*/BCL_* variable at all.
# An empty environment, so a variable that merely exists on the test machine cannot
# count; the end marker proves the probe reached `env` (a dead probe reports noenv).
leaked="$(env -i PATH="$PATH" _BCL_SOURCED=1 _BCL_LOOKUP=warn BCL_READ_ERROR=x _BCL_STDIN_MAX=1 _BCL_STDIN_TIMEOUT=0 \
  bash -c 'set -euo pipefail; . "$1"; env; echo __env_done__' _ "$H/lib/common.sh" 2>&1 \
  | awk '/^_?BCL_/ { n++ } /^__env_done__$/ { ok = 1 } END { print ok ? n + 0 : "noenv" }')"
if [ "$leaked" = 0 ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [common.sh passed inherited _BCL_/BCL_ variables on to a child: $leaked]"; fi

echo "== hooks launched with bash -p ignore bash startup values =="
# A plain `bash` acts on its environment before a hook's first line: it runs the file
# BASH_ENV names, imports exported functions (BASH_FUNC_<name>%%) and applies
# SHELLOPTS. Every wired hook command and every child the dispatcher starts is
# `bash -p`, which does none of that, and common.sh drops the values -p leaves alone
# (FUNCNEST among them). The values below only write a marker file when they act: with
# each set, the hooks still block with their real messages and the marker never
# appears. (Hooks only judge payloads; nothing in a payload runs.)
MARK="$TMP/startup.marker"
printf 'echo ran >> "%s"\n' "$MARK" > "$TMP/startup-mark.sh"
FN_TIMEOUT="() { echo ran >> \"$MARK\"; command timeout \"\$@\"; }"
FN_SOURCE="() { echo ran >> \"$MARK\"; builtin source \"\$@\"; }"
# run_p <desc> <hook-relpath> <payload> <expected-rc> <expected-output> <VAR=value>
run_p() {
  local desc="$1" hook="$2" payload="$3" want="$4" needle="$5" assign="$6" got out
  rm -f "$MARK"
  out="$(printf '%s' "$payload" | env "$assign" bash -p "$H/$hook" 2>&1)"; got=$?
  if [ "$got" = "$want" ] && printf '%s' "$out" | grep -qF "$needle" && [ ! -f "$MARK" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [$desc] want=$want got=$got marker=$([ -f "$MARK" ] && echo yes || echo no)"; fi
}
rm -f "$TMP/rules.saved" "$TMP/compose.saved"
[ -f "$RULES" ] && cp "$RULES" "$TMP/rules.saved"
[ -f "$WT/docker-compose.yml" ] && cp "$WT/docker-compose.yml" "$TMP/compose.saved"
printf 'services:\n  app:\n    user: "0:0"\n' > "$WT/docker-compose.yml"
setcfg "c['modules']['securityDefaults']['enabled']=True"
valid_rules
for value in "BASH_ENV=$TMP/startup-mark.sh" "BASH_FUNC_timeout%%=$FN_TIMEOUT" \
             "BASH_FUNC_source%%=$FN_SOURCE" 'SHELLOPTS=xtrace' 'FUNCNEST=1'; do
  run_p "command-guard, bash -p, ${value%%=*}"     guardrails/command-guard.sh "$(bash_payload 'git push --force origin main')" 2 "Blocked by Claude Code baseline command-guard" "$value"
  run_p "post-write, bash -p, ${value%%=*}"        dispatcher/post-write.sh "$(write_payload "$WT/docker-compose.yml")" 2 "REGRESSION BLOCKER" "$value"
  run_p "security-defaults, bash -p, ${value%%=*}" modules/security-defaults.sh "$(write_payload "$WT/docker-compose.yml")" 2 "REGRESSION BLOCKER" "$value"
done
resetcfg
if [ -f "$TMP/rules.saved" ]; then cp "$TMP/rules.saved" "$RULES"; else rm -f "$RULES"; fi
if [ -f "$TMP/compose.saved" ]; then cp "$TMP/compose.saved" "$WT/docker-compose.yml"; else rm -f "$WT/docker-compose.yml"; fi
# Controls, so the checks above cannot pass because a value had no effect at all: under
# a plain `bash` each value acts (the marker, xtrace lines), under `bash -p` it does
# not. An allowed command keeps these free of any guard verdict.
# mark_run <VAR=value> <launcher...>: the marker's line count after one command-guard run
mark_run() {
  local assign="$1"; shift
  rm -f "$MARK"
  printf '%s' "$(bash_payload 'git status')" | env "$assign" "$@" "$H/guardrails/command-guard.sh" >/dev/null 2>&1
  if [ -f "$MARK" ]; then awk 'END { print NR }' "$MARK"; else echo 0; fi
}
for spec in "BASH_ENV=$TMP/startup-mark.sh" "BASH_FUNC_timeout%%=$FN_TIMEOUT" "BASH_FUNC_source%%=$FN_SOURCE"; do
  plain="$(mark_run "$spec" bash)"; priv="$(mark_run "$spec" bash -p)"
  if [ "$plain" -ge 1 ] && [ "$priv" = 0 ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [${spec%%=*}: plain bash marker=$plain (want >=1), bash -p marker=$priv (want 0)]"; fi
done
xplain="$(printf '%s' "$(bash_payload 'git status')" | env SHELLOPTS=xtrace bash "$H/guardrails/command-guard.sh" 2>&1 | awk '/^\+/ { n++ } END { print n + 0 }')"
xpriv="$(printf '%s' "$(bash_payload 'git status')" | env SHELLOPTS=xtrace bash -p "$H/guardrails/command-guard.sh" 2>&1 | awk '/^\+/ { n++ } END { print n + 0 }')"
if [ "$xplain" -ge 1 ] && [ "$xpriv" = 0 ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [SHELLOPTS=xtrace: plain bash traced $xplain lines (want >=1), bash -p traced $xpriv (want 0)]"; fi
# A -p shell still exports BASH_ENV. common.sh drops it, so a plain bash that a hook
# starts after loading the library (bats, the sh git or npm spawn) does not run the file.
rm -f "$MARK"
env "BASH_ENV=$TMP/startup-mark.sh" bash -p -c '. "$1"; bash -c :' _ "$H/lib/common.sh" >/dev/null 2>&1
if [ ! -f "$MARK" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [a plain bash started after common.sh loaded ran BASH_ENV]"; fi
# The dispatcher's children are -p too (exported functions cannot be dropped, only
# ignored by a -p child). Statically, and with the marker on a real write: every child
# sources common.sh, so a plain-bash child would call an exported `source`.
nplain="$(awk '/bash "\$hook"/ { n++ } END { print n + 0 }' "$H/dispatcher/post-write.sh")"
npriv="$(awk '/bash -p "\$hook"/ { n++ } END { print n + 0 }' "$H/dispatcher/post-write.sh")"
if [ "$nplain" = 0 ] && [ "$npriv" = 2 ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [post-write.sh child launches: $nplain plain bash, $npriv bash -p (want 0 and 2)]"; fi
rm -f "$MARK"
printf '%s' "$(write_payload "$WT/notes.txt")" | env "BASH_FUNC_source%%=$FN_SOURCE" bash -p "$H/dispatcher/post-write.sh" >/dev/null 2>&1
if [ ! -f "$MARK" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [a dispatcher child imported an exported function under bash -p ($(awk 'END { print NR }' "$MARK") times)]"; fi
rm -f "$MARK" "$TMP/startup-mark.sh"

echo "== baseline Python is isolated from the project (-I -S -X utf8) =="
# The hooks, the installer and the status tool start Python with -c, - or a script.
# Without isolation, a json.py or shlex.py in the project (the hooks' working
# directory), anything on PYTHONPATH, or a .pth file in the interpreter's site-packages
# is imported by those helpers and decides what they report. A dedicated project gets
# marker-writing json.py and shlex.py in its root and is used as both the working
# directory and CLAUDE_PROJECT_DIR: every entry point must still do its job, and the
# marker must never appear. (The harness's own `$PY -c` calls run in $WT, not there.)
PROJ="$TMP/plant-proj"; mkdir -p "$PROJ"; ( cd "$PROJ" && git init -q )
WPROJ="$(winpath "$PROJ")"; HP="$PROJ/.claude/hooks/baseline"
PMARK="$(winpath "$TMP")/plant.marker"; rm -f "$PMARK"
for m in json shlex; do
  printf 'open(r"%s", "a").write("%s.py from the project was imported\\n")\n' "$PMARK" "$m" > "$PROJ/$m.py"
done
plant_check() {  # plant_check <desc> — counts a failure if a planted module ran
  if [ ! -e "$PMARK" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [$1: $(tr '\n' ' ' < "$PMARK")]"; rm -f "$PMARK"; fi
}
# plant_run <desc> <expected-rc> <expected-output|""> <cwd> <cmd...> — stdin comes from $PL
plant_run() {
  local desc="$1" want="$2" needle="$3" dir="$4" got out; shift 4
  out="$(cd "$dir" && printf '%s' "$PL" | "$@" 2>&1)"; got=$?
  if [ "$got" = "$want" ] && { [ -z "$needle" ] || printf '%s' "$out" | grep -qF -- "$needle"; }; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [$desc] want=$want got=$got"; fi
  plant_check "$desc"
}
# Positive control: an UNisolated Python in the project must import the planted json.py,
# or every "marker absent" check below would pass for the wrong reason.
( cd "$PROJ" && "$PY" -c 'import json' ) >/dev/null 2>&1
if [ -e "$PMARK" ]; then pass=$((pass + 1)); rm -f "$PMARK"; else fail=$((fail + 1)); echo "  FAIL [plant control: a plain python in the project did not import the planted json.py]"; fi
PL=""
plant_run "install.sh run from inside the project" 0 "Baseline written" "$PROJ" \
  timeout -k 5 120 bash "$SRC/install.sh" --target "$WPROJ" --with-openclaw-rules --enable-security-defaults
# lib/merge_settings.py runs as a script, which only PYTHONPATH can reach.
plant_run "install.sh re-run with PYTHONPATH planted" 0 "Baseline written" "$WT" \
  env PYTHONPATH="$WPROJ" timeout -k 5 120 bash "$SRC/install.sh" --target "$WPROJ"
"$PY" -c "import json;p=r'$WPROJ/.claude/baseline.config.json';c=json.load(open(p));c['modules']['configGuard']['enabled']=True;json.dump(c,open(p,'w'))"
PL="$(bash_payload 'git push --force origin main')"
plant_run "command-guard in the project" 2 "Blocked by Claude Code baseline command-guard" "$PROJ" \
  env CLAUDE_PROJECT_DIR="$WPROJ" bash "$HP/guardrails/command-guard.sh"
plant_run "command-guard with PYTHONPATH planted" 2 "Blocked by Claude Code baseline command-guard" "$WT" \
  env CLAUDE_PROJECT_DIR="$WPROJ" PYTHONPATH="$WPROJ" bash "$HP/guardrails/command-guard.sh"
printf 'services:\n  app:\n    image: nginx:1.27\n    user: root\n' > "$PROJ/docker-compose.yml"
PL="$(write_payload "$WPROJ/docker-compose.yml")"
plant_run "post-write in the project" 2 "REGRESSION BLOCKER" "$PROJ" \
  env CLAUDE_PROJECT_DIR="$WPROJ" bash "$HP/dispatcher/post-write.sh"
PL="$(printf '{"source":"project_settings","file_path":"%s"}' "$WPROJ/.claude/settings.json")"
plant_run "config-guard in the project" 0 "project settings change validated" "$PROJ" \
  env CLAUDE_PROJECT_DIR="$WPROJ" bash "$HP/modules/config-guard.sh"
PL=""; rm -f "$TMP/status.json"
plant_run "baseline-status --json in the project" 0 "installed=yes" "$PROJ" \
  bash "$SRC/tools/baseline-status.sh" --json "$(winpath "$TMP")/status.json" "$WPROJ"
if grep -q '"installed": true' "$TMP/status.json" 2>/dev/null; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [baseline-status --json wrote no report]"; fi
# A .pth file in the interpreter's own site-packages runs at startup unless -S, and an
# activated in-project .venv puts that directory inside the project. Exercised only
# when bcl_python really resolves into the venv (it prefers python3, then python).
VENV="$TMP/plant-venv"
if "$PY" -m venv --without-pip "$(winpath "$VENV")" >/dev/null 2>&1; then
  VBIN="$VENV/bin"; [ -d "$VENV/Scripts" ] && VBIN="$VENV/Scripts"
  VSITE="$("$VBIN/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])' 2>/dev/null | tr -d '\r')"
  [ -n "$VSITE" ] && VSITE="$(cygpath -u "$VSITE" 2>/dev/null || printf '%s' "$VSITE")"
  if [ -n "$VSITE" ] && [ -d "$VSITE" ]; then
    printf 'import os; open(r"%s", "a").write("a .pth file in site-packages ran\\n")\n' "$PMARK" > "$VSITE/zz_plant.pth"
  fi
  # Control: without -S the venv's own python must run the .pth, or the check proves nothing.
  "$VBIN/python" -c pass >/dev/null 2>&1
  pth_runs=0; [ -e "$PMARK" ] && pth_runs=1; rm -f "$PMARK"
  vres="$(PATH="$VBIN:$PATH" bash -c '. "$1"; command -v "$(bcl_python)"' _ "$H/lib/common.sh" 2>/dev/null)"
  if [ "$pth_runs" != 1 ]; then
    echo "  SKIP [venv .pth: the planted .pth file does not run in this venv]"
  else
    case "$vres" in
      "$VBIN"/*)
        PL="$(bash_payload 'git push --force origin main')"
        plant_run "command-guard with a venv first on PATH" 2 "Blocked by Claude Code baseline command-guard" "$WT" \
          env PATH="$VBIN:$PATH" bash "$H/guardrails/command-guard.sh" ;;
      *) echo "  SKIP [venv .pth: bcl_python resolves to ${vres:-nothing}, not the venv]" ;;
    esac
  fi
  [ -n "$VSITE" ] && rm -f "$VSITE/zz_plant.pth"
else
  echo "  SKIP [venv .pth: python -m venv is unavailable here]"
fi
rm -f "$PMARK"; PL=""
# An interpreter that is found but cannot run the helpers — a stub, a broken shim, one
# that rejects -I/-S such as Python 2 or a legacy virtualenv — must fail closed like a
# missing one. It used to make bcl_cfg read "" for every key, so command-guard took
# itself for disabled and allowed the call. (py-rejects-S runs on main, which passes no
# -S; it pins that the isolation flags cannot open that hole again.)
REALPY_ISO="$(winpath "$("$PY" -c 'import sys; sys.stdout.write(sys.executable)')")"
BROKEN="$TMP/py-broken"; NOSITE="$TMP/py-rejects-S"; NOSTDLIB="$TMP/py-no-stdlib"
mkdir -p "$BROKEN" "$NOSITE" "$NOSTDLIB"
printf '#!/usr/bin/env bash\nexit 1\n' > "$BROKEN/python3"
printf '#!/usr/bin/env bash\nfor a in "$@"; do [ "$a" = -S ] && { echo "Unknown option: -S" >&2; exit 2; }; done\nexec "%s" "$@"\n' "$REALPY_ISO" > "$NOSITE/python3"
# starts (an empty program runs) but can import nothing, like a legacy virtualenv under -S
printf '#!/usr/bin/env bash\nprev=""; for a in "$@"; do [ "$prev" = -c ] && [ -z "$a" ] && exit 0; prev="$a"; done\necho "ModuleNotFoundError: No module named json" >&2; exit 1\n' > "$NOSTDLIB/python3"
for d in "$BROKEN" "$NOSITE" "$NOSTDLIB"; do
  cp "$d/python3" "$d/python"; chmod +x "$d/python3" "$d/python"
  run_env "command-guard, interpreter that does not run ($(basename "$d"))" "PATH=$d:$PATH" \
    guardrails/command-guard.sh "$(bash_payload 'rm -rf /')" 2 "CONTROL COULD NOT RUN"
  run_env "post-write, interpreter that does not run ($(basename "$d"))" "PATH=$d:$PATH" \
    dispatcher/post-write.sh "$(write_payload "$WT/docker-compose.yml")" 2 "Python unavailable"
  run_env "scope-guard definition check, interpreter that does not run ($(basename "$d"))" "PATH=$d:$PATH" \
    modules/scope-guard.sh "$(def_payload Write ".claude/agents/h.md" content "$DEFTXT")" 2 "CONTROL COULD NOT RUN"
  def_payload Write "$WT/src/x.py" content "x = 1" | env "PATH=$d:$PATH" bash "$H/modules/scope-guard.sh" >/dev/null 2>&1; rc=$?
  if [ "$rc" = 0 ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [scope-guard, ordinary write, interpreter that does not run ($(basename "$d"))] rc=$rc"; fi
done
# ...but a WORKING interpreter whose prime script fails (here on a lone-surrogate escape
# it cannot re-encode) is a prime failure, not a missing interpreter: the per-call checks
# take over and report the real reason, and posture/failClosed still apply.
LONE="$(printf '{"tool_name":"Bash","tool_input":{"command":"rm -rf ~ # \\%s"}}' ud800)"
out="$(printf '%s' "$LONE" | bash "$H/guardrails/command-guard.sh" 2>&1)"; rc=$?
if [ "$rc" = 2 ] && printf '%s' "$out" | grep -qF "Blocked by Claude Code baseline command-guard"; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [lone surrogate: want the real block reason, got rc=$rc: $(printf '%s' "$out" | head -c 120)]"; fi
# UTF-8 mode: a non-ASCII extraPatterns entry must match a non-ASCII command on every
# platform, with or without PYTHONUTF8 (-I ignores it; Windows otherwise decodes the
# payload in its ANSI code page and the pattern never matches).
setcfg "c['guardrails']['commandGuard']['extraPatterns']=['שלום']"
run "non-ASCII extraPattern blocks" guardrails/command-guard.sh "$(bash_payload 'echo שלום')" 2
run_env "non-ASCII extraPattern, PYTHONUTF8=1" PYTHONUTF8=1 guardrails/command-guard.sh "$(bash_payload 'echo שלום')" 2 "Blocked by Claude Code baseline command-guard"
resetcfg
# ...and a rule message outside the ANSI code page must reach the report intact. A
# control on Linux; on Windows dropping -X utf8 makes the print fail, and under
# failClosed:false the violation would then pass as exit 0.
rm -f "$TMP/rules.saved" "$TMP/compose.saved"
[ -f "$RULES" ] && cp "$RULES" "$TMP/rules.saved"
[ -f "$WT/docker-compose.yml" ] && cp "$WT/docker-compose.yml" "$TMP/compose.saved"
"$PY" -c "import json;json.dump({'infraPattern':'docker-compose','rules':[{'id':'no-root','appliesWhen':r'^\s*user:\s','mustMatch':'1000:1000','message':'משתמש root אסור'}]},open(r'$RULES','w'))"
printf 'services:\n  app:\n    user: "0:0"\n' > "$WT/docker-compose.yml"
setcfg "c['modules']['securityDefaults']['enabled']=True; c['failClosed']=False"
out="$(printf '%s' "$(write_payload "$WT/docker-compose.yml")" | bash "$H/modules/security-defaults.sh" 2>&1)"; rc=$?
if [ "$rc" = 2 ] && printf '%s' "$out" | grep -qF "REGRESSION BLOCKER" && printf '%s' "$out" | grep -qF "משתמש root אסור"; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [non-ASCII rule message: rc=$rc]"; fi
resetcfg
if [ -f "$TMP/rules.saved" ]; then cp "$TMP/rules.saved" "$RULES"; else rm -f "$RULES"; fi
if [ -f "$TMP/compose.saved" ]; then cp "$TMP/compose.saved" "$WT/docker-compose.yml"; else rm -f "$WT/docker-compose.yml"; fi
# Every Python launch in shipped scripts passes `-I -S -X utf8` right after the
# interpreter, so a new launch site cannot regress silently. Each launch on a line is
# checked on its own: the interpreter variables in any spelling ($PY, ${PY}, "$PY",
# "$PYBIN"), "$(bcl_python)" used directly, and python/python3/python3.12 or a path to
# one, followed by an argument, a here-string, or a line continuation (which must keep
# the flags on the launch line). The count guards the pattern itself: if it stopped
# matching launches, an empty list would pass for the wrong reason. Allowed without the
# flags, on purpose: auto-format's `python -m black`, and run-tests' pytest probe and
# run — they execute the repo's own formatter and tests by design (both opt-in).
PYINTERP='(\$\{?(PY|py|_BCL_PY|PYBIN)\}?"?|"?\$\(bcl_python\)"?|(^|[^[:alnum:]_.$/-])(/[^[:space:]"]*/)?python[0-9.]*)'
PYLAUNCH="$PYINTERP"'(<<<|[[:space:]]+(-I -S -X utf8|[-"$\'"'"'][^[:space:]]*))'
PYALLOW='/hooks/guardrails/auto-format\.sh:[0-9]+:.*python3? -m black |/hooks/modules/run-tests\.sh:[0-9]+:.*"\$PYBIN" -(c '"'"'import pytest'"'"'|m pytest )'
launches="$( { grep -rnE --include='*.sh' "$PYLAUNCH" "$SRC/hooks" "$SRC/tools"; grep -nE "$PYLAUNCH" "$SRC/install.sh" | sed "s|^|$SRC/install.sh:|"; } \
  | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' | grep -vE "$PYALLOW")"
nlaunch=0; missing=""
while IFS= read -r line; do
  [ -n "$line" ] || continue
  while IFS= read -r m; do
    nlaunch=$((nlaunch + 1))
    case "$m" in *"-I -S -X utf8") ;; *) missing="$missing$line"$'\n' ;; esac
  done < <(printf '%s\n' "${line#*:*:}" | grep -oE "$PYLAUNCH")
done <<< "$launches"
if [ -z "$missing" ] && [ "$nlaunch" -ge 15 ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [Python launches without -I -S -X utf8 ($nlaunch found):"; printf '%s' "$missing" | sed 's/^/         /'; echo "  ]"; fi

echo "== config-guard (ConfigChange) tamper detection (R5) =="
ccp() { printf '{"source":"%s","file_path":"%s"}' "$1" "$2"; }   # ConfigChange payload
GOOD="$WT/.claude/settings.json"   # the real installed settings (baseline footprint intact)
TDIR="$WT/.claude"
# Craft tampered settings variants (valid JSON, but each weakens the baseline).
"$PY" - "$TDIR" <<'PY'
import json, os, sys
d = sys.argv[1]
DENY = ["Edit(.env*)","Read(.env*)","Edit(**/secrets/**)","Read(**/secrets/**)",
        "Edit(.claude/baseline.config.json)","Edit(.claude/settings.json)","Edit(.claude/hooks/baseline/**)"]
def c(p): return {"type":"command","command":"bash -p ${CLAUDE_PROJECT_DIR}/.claude/hooks/baseline/" + p, "timeout": 90}
def g(p, of="block"): return dict(c(p), onFailure=of)   # a PreToolUse guard (D2)
# Properly-wired: real {type:command} hooks INVOKING all five baseline scripts.
wired = {"PreToolUse":[{"hooks":[g("guardrails/command-guard.sh"), g("modules/scope-guard.sh")]}],
         "PostToolUse":[{"hooks":[c("dispatcher/post-write.sh")]}],
         "Stop":[{"hooks":[c("modules/tracker-reminder.sh")]}],
         "ConfigChange":[{"hooks":[c("modules/config-guard.sh")]}]}
# config-guard's own wiring stripped (self-protection: disabling the tamper detector is tamper).
wired_no_cg = {"PreToolUse":[{"hooks":[g("guardrails/command-guard.sh"), g("modules/scope-guard.sh")]}],
               "PostToolUse":[{"hooks":[c("dispatcher/post-write.sh")]}],
               "Stop":[{"hooks":[c("modules/tracker-reminder.sh")]}]}
# Neutered: a command-hook that MENTIONS the namespace but never `bash`-invokes a script
# (the substring-within-command evasion the launcher-anchored check must catch).
neutered = {"PreToolUse":[{"hooks":[{"type":"command","command":"echo noop /.claude/hooks/baseline/guardrails/command-guard.sh"}]}]}
def w(name, obj):
    with open(os.path.join(d, name), "w", encoding="utf-8") as f: json.dump(obj, f)
w("_t_disable.json",  {"disableAllHooks": True, "hooks": wired, "permissions": {"deny": DENY}})
w("_t_unwired.json",  {"hooks": neutered, "permissions": {"deny": DENY}})   # marker present, not invoked
w("_t_nocg.json",     {"hooks": wired_no_cg, "permissions": {"deny": DENY}})  # config-guard wiring stripped
w("_t_denygone.json", {"hooks": wired, "permissions": {"deny": [x for x in DENY if x != "Edit(.claude/settings.json)"]}})
w("_t_all.json",      {"disableAllHooks": True, "hooks": {}, "permissions": {"deny": []}})   # all 3 findings
w("_t_dah1.json",     {"disableAllHooks": 1, "hooks": wired, "permissions": {"deny": DENY}})  # truthy non-True
w("_t_list.json",     [1, 2, 3])   # valid JSON but NOT an object -> maximum tamper
# The REAL installed settings with one change: command-guard's onFailure -> "continue".
# Against "clean settings -> 0" (the same file unchanged), this isolates the D2 check.
def variant(name, change):
    real = json.load(open(os.path.join(d, "settings.json"), encoding="utf-8"))
    change(real)
    w(name, real)
def set_of(guard, value):
    def change(s):
        for grp in s["hooks"]["PreToolUse"]:
            for h in grp["hooks"]:
                if guard in h["command"]:
                    if value is None: h.pop("onFailure", None)
                    else: h["onFailure"] = value
    return change
def move_cg(s):   # command-guard moved out of PreToolUse: still "wired", guards nothing
    pre = s["hooks"]["PreToolUse"]
    cg = [g for g in pre if any("command-guard" in h["command"] for h in g["hooks"])]
    s["hooks"]["PreToolUse"] = [g for g in pre if g not in cg]
    s["hooks"].setdefault("PostToolUse", []).extend(cg)
variant("_t_soft.json", set_of("command-guard", "continue"))
variant("_t_soft_sg.json", set_of("scope-guard", "continue"))
variant("_t_of_gone.json", set_of("command-guard", None))
variant("_t_cg_moved.json", move_cg)
# Baseline hook launches other than exactly `bash -p <script>`: the old plain form (an
# install from before -p, reported as out of date), and forms that keep -p but discard
# the verdict, never run the script, or undo -p (reported as tamper).
def relaunch(script, rewrite):
    def change(s):
        for grps in s["hooks"].values():
            for grp in grps:
                for h in grp["hooks"]:
                    if script in h["command"]:
                        h["command"] = rewrite(h["command"])
    return change
plain = lambda c: c.replace("bash -p ", "bash ", 1)
variant("_t_nop.json",    relaunch("command-guard", plain))
variant("_t_nop_cg.json", relaunch("config-guard", plain))
variant("_t_stale.json",  lambda s: [relaunch(x, plain)(s) for x in ("command-guard", "scope-guard",
                                     "post-write", "tracker-reminder", "config-guard")])
variant("_t_or_true.json", relaunch("command-guard", lambda c: c + " || true"))
variant("_t_dash_c.json",  relaunch("command-guard", lambda c: c.replace("bash -p ", "bash -p -c : ", 1)))
variant("_t_plus_p.json",  relaunch("command-guard", lambda c: c.replace("bash -p ", "bash -p +p ", 1)))
variant("_t_vt.json",      relaunch("command-guard", lambda c: c.replace("bash -p ", "bash" + chr(11) + "-p ", 1)))
# The keys beside an exact command that stop it running as written.
def rekey(script, **keys):
    def change(s):
        for grps in s["hooks"].values():
            for grp in grps:
                for h in grp["hooks"]:
                    if script in h["command"]:
                        h.update(keys)
    return change
variant("_t_args.json",    rekey("command-guard", args=["-p"]))
variant("_t_shell.json",   rekey("post-write", shell="powershell"))
variant("_t_async.json",   rekey("post-write", **{"async": True}))
variant("_t_rewake.json",  rekey("config-guard", asyncRewake=True))
variant("_t_timeout.json", rekey("post-write", timeout=1))
# Where the template wires a hook (2d): its event, a group matcher covering the
# template's, no `if`. First the forms that still cover the template's values, then
# ones that do not, or that the check cannot read as covering.
DROP = object()
def rematch(script, matcher):
    def change(s):
        for grps in s["hooks"].values():
            for grp in grps:
                if any(script in h["command"] for h in grp["hooks"]):
                    if matcher is DROP: grp.pop("matcher", None)
                    else: grp["matcher"] = matcher
    return change
def move(script, event):   # the script's group, matcher and all, under another event
    def change(s):
        for grps in list(s["hooks"].values()):
            for grp in [g for g in grps if any(script in h["command"] for h in g["hooks"])]:
                grps.remove(grp)
                s["hooks"].setdefault(event, []).append(grp)
    return change
def drop_local(s):
    s["hooks"]["ConfigChange"] = [g for g in s["hooks"]["ConfigChange"] if g.get("matcher") != "local_settings"]
def one_cc(s):
    s["hooks"]["ConfigChange"] = [dict(s["hooks"]["ConfigChange"][0], matcher="project_settings|local_settings")]
def beside(s):   # a covering group stays; a copy under a narrower matcher is extra
    pre = s["hooks"]["PreToolUse"]
    cg = [g for g in pre if any("command-guard" in h["command"] for h in g["hooks"])][0]
    pre.append(dict(json.loads(json.dumps(cg)), matcher="Read"))
def nest(s):     # post-write's entry inside another entry, where Claude Code never runs it
    for grp in s["hooks"]["PostToolUse"]:
        grp["hooks"] = [{"type": "command", "command": "exit 0", "timeout": 5, "x": h} for h in grp["hooks"]]
def lower_event(s):
    s["hooks"]["posttooluse"] = s["hooks"].pop("PostToolUse")
for name, change in [
        ("_t_w_star.json", rematch("command-guard", "*")),
        ("_t_w_empty.json", rematch("command-guard", "")),
        ("_t_w_absent.json", rematch("command-guard", DROP)),
        ("_t_w_reorder.json", rematch("command-guard", "PowerShell|Bash")),
        ("_t_w_wider.json", rematch("command-guard", "Bash|PowerShell|Read")),
        ("_t_w_one_cc.json", one_cc),
        ("_t_w_beside.json", beside),
        ("_t_w_read.json", rematch("command-guard", "Read")),
        ("_t_w_bash.json", rematch("command-guard", "Bash")),
        ("_t_w_comma.json", rematch("command-guard", "Bash, PowerShell")),
        ("_t_w_spaced.json", rematch("command-guard", "PowerShell | Bash")),
        ("_t_w_regex.json", rematch("command-guard", "^(Bash|PowerShell)$")),
        ("_t_w_nl.json", rematch("command-guard", "Bash|PowerShell" + chr(10))),
        ("_t_w_tab.json", rematch("command-guard", "Bash|PowerShell" + chr(9))),
        ("_t_w_trail.json", rematch("command-guard", "Bash|PowerShell ")),
        ("_t_w_null.json", rematch("command-guard", None)),
        ("_t_w_sg.json", rematch("scope-guard", "Write")),
        ("_t_w_pw.json", rematch("post-write", "Edit")),
        ("_t_w_stop.json", rematch("tracker-reminder", "Bash")),
        ("_t_w_stop_null.json", rematch("tracker-reminder", None)),
        ("_t_w_if_cg.json", rekey("command-guard", **{"if": "Bash(git status)"})),
        ("_t_w_if_tr.json", rekey("tracker-reminder", **{"if": "Bash(git status)"})),
        ("_t_w_pw_pre.json", move("post-write", "PreToolUse")),
        ("_t_w_tr_ss.json", move("tracker-reminder", "SessionStart")),
        ("_t_w_local.json", drop_local),
        ("_t_w_nested.json", nest),
        ("_t_w_case.json", lower_event)]:
    variant(name, change)
# settings.local.json (source local_settings): an overlay the installer never writes hooks
# into. A hook entry that names a baseline script is reported, whatever its keys, as are
# disableAllHooks and a risky env value; a repo's own hook, an empty file and a removed
# file are not.
real = json.load(open(os.path.join(d, "settings.json"), encoding="utf-8"))
cg_entry = [h for grp in real["hooks"]["PreToolUse"] for h in grp["hooks"] if "command-guard" in h["command"]][0]
w("_l_copy.json",  {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [dict(cg_entry)]}]}})
w("_l_keys.json",  {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [dict(cg_entry, statusMessage="x")]}]}})
w("_l_many.json",  {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "bash /.claude/hooks/baseline/s%02d.sh" % i}
                                                for i in range(25)]}]}})
w("_l_long.json",  {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "echo /.claude/hooks/baseline/" + "a" * 500}]}]}})
w("_l_stop.json",  {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "echo /.claude/hooks/baseline/"}]}]}})
w("_l_dah.json",   {"disableAllHooks": True})
w("_l_env.json",   {"env": {"BASH_ENV": "/tmp/x.sh"}})
w("_l_own.json",   {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "bash ./scripts/team-lint.sh"}]}]},
                    "permissions": {"allow": ["Bash(cat .claude/hooks/baseline/VERSION)"]}})
w("_l_esc.json",   {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "bash /.claude/hooks/baseline/x" + chr(27) + "[2J" + chr(10) + "y.sh"}]}]}})
w("_l_args.json",  {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "bash",
                    "args": ["-p", "${CLAUDE_PROJECT_DIR}/.claude/hooks/baseline/guardrails/command-guard.sh"]}]}]}})
w("_l_empty.json", {})
w("_l_list.json",  [1])
with open(os.path.join(d, "_l_bad.json"), "w", encoding="utf-8") as f: f.write("{ not json")
# env values that can run code before the hooks, redirect them or switch them off,
# whatever the value; bash_env and Path check the case-insensitive match. Then values
# that must stay allowed.
for i, (k, v) in enumerate([("BASH_ENV", "/tmp/x.sh"), ("BASH_FUNC_timeout%%", "() { :; }"),
                            ("SHELLOPTS", "noexec"), ("Path", "/tmp/bin"),
                            ("DYLD_INSERT_LIBRARIES", "/tmp/x.dylib"),
                            ("CLAUDE_PROJECT_DIR", "/tmp"), ("_BCL_PY", "/tmp/py"),
                            ("FUNCNEST", "1"), ("CLAUDE_CODE_SHELL_PREFIX", "/tmp/wrap"),
                            ("bash_env", "/tmp/x.sh"), ("BASH_ENV", " "), ("PATH", ""),
                            ("BASH_ENV", None), ("FUNCNEST", 1), ("GIT_DIR", "/tmp/g"),
                            ("POSIXLY_CORRECT", "1"), ("CDPATH", "/tmp"), ("GIT_EXEC_PATH", "/tmp")]):
    variant("_t_env%d.json" % i, lambda s, k=k, v=v: s.setdefault("env", {}).update({k: v}))
variant("_t_env_ok.json", lambda s: s.setdefault("env", {}).update(
    {"FOO": "1", "PYTHONPATH": "/tmp/py", "NODE_ENV": "production", "GIT_AUTHOR_NAME": "a",
     "ENV": "production"}))
# A stale launch plus a real tamper is headed as tamper.
variant("_t_stale_env.json", lambda s: (relaunch("command-guard", plain)(s),
                                        s.setdefault("env", {}).update({"BASH_ENV": "/tmp/x.sh"})))
PY
setcfg "c['modules']['configGuard']['enabled']=True"
run "clean settings -> 0"        modules/config-guard.sh "$(ccp project_settings "$GOOD")" 0
run "disableAllHooks=true -> 2"  modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_disable.json")" 2
run "disableAllHooks=1 -> 2"     modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_dah1.json")" 2
run "neutered hooks -> 2"        modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_unwired.json")" 2
run "config-guard unwired -> 2"  modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_nocg.json")" 2
run "deny removed -> 2"          modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_denygone.json")" 2
run "guard onFailure softened -> 2" modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_soft.json")" 2
run "scope-guard onFailure softened -> 2" modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_soft_sg.json")" 2
run "guard onFailure removed -> 2" modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_of_gone.json")" 2
run "guard moved out of PreToolUse -> 2" modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_cg_moved.json")" 2
run "command-guard without bash -p -> 2" modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_nop.json")" 2
run "config-guard without bash -p -> 2"  modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_nop_cg.json")" 2
run "launch with || true -> 2"           modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_or_true.json")" 2
run "launch with -c : -> 2"              modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_dash_c.json")" 2
run "launch with +p -> 2"                modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_plus_p.json")" 2
run "launch with a VT separator -> 2"    modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_vt.json")" 2
run "launch with args -> 2"              modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_args.json")" 2
run "launch in powershell -> 2"          modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_shell.json")" 2
run "launch async -> 2"                  modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_async.json")" 2
run "launch asyncRewake -> 2"            modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_rewake.json")" 2
run "launch with a short timeout -> 2"   modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_timeout.json")" 2
# (2d) where the template wires each hook. A regex, a comma or space list, and a matcher
# on Stop (which ignores matchers) are reported even where they would cover: the check
# counts only forms it can read for certain. Re-running install.sh restores the group.
for spec in "star:0" "empty:0" "absent:0" "reorder:0" "wider:0" "one_cc:0" "beside:0" \
            "read:2" "bash:2" "comma:2" "spaced:2" "regex:2" "nl:2" "tab:2" "trail:2" "null:2" "sg:2" "pw:2" "stop:2" \
            "stop_null:2" "if_cg:2" "if_tr:2" "pw_pre:2" "tr_ss:2" "local:2" "nested:2" "case:2"; do
  run "wiring ${spec%%:*} -> ${spec#*:}" modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_w_${spec%%:*}.json")" "${spec#*:}"
done
# report_of <settings>: the whole report
report_of() { printf '{"source":"project_settings","file_path":"%s"}' "$1" | bash -p "$H/modules/config-guard.sh" 2>&1; }
rpt="$(report_of "$TDIR/_t_w_read.json")"
for needle in "SETTINGS TAMPER DETECTED" "not wired as the template wires them" \
              "guardrails/command-guard.sh under PreToolUse Bash|PowerShell - "; do
  case "$rpt" in *"$needle"*) pass=$((pass + 1)) ;; *) fail=$((fail + 1)); echo "  FAIL [config-guard wiring report missing: $needle]" ;; esac
done
rpt="$(report_of "$TDIR/_t_w_local.json")"
case "$rpt" in *"modules/config-guard.sh under ConfigChange local_settings - "*) pass=$((pass + 1)) ;; *) fail=$((fail + 1)); echo "  FAIL [config-guard wiring report: local_settings group]" ;; esac
# No double report: a guard (2b) finds under no PreToolUse group, or a script (2) finds
# unwired, gets no wiring line.
for spec in "_t_cg_moved.json|command-guard.sh under" "_t_nocg.json|config-guard.sh under"; do
  rpt="$(report_of "$TDIR/${spec%%|*}")"
  case "$rpt" in *"${spec#*|}"*) fail=$((fail + 1)); echo "  FAIL [config-guard double report in ${spec%%|*}]" ;; *) pass=$((pass + 1)) ;; esac
done
# local_settings: .claude/settings.local.json. A removed file and the repo's own content
# validate; a hook entry naming a baseline script, disableAllHooks and a risky env value
# are reported; an unreadable file fails closed, as for settings.json.
for spec in "copy:2" "keys:2" "long:2" "many:2" "stop:2" "esc:2" "args:2" "dah:2" "env:2" "own:0" "empty:0" "nope:0" "bad:2" "list:2"; do
  run "local_settings ${spec%%:*} -> ${spec#*:}" modules/config-guard.sh "$(ccp local_settings "$TDIR/_l_${spec%%:*}.json")" "${spec#*:}"
done
run "local_settings, no file_path, no local file -> 0" modules/config-guard.sh '{"source":"local_settings"}' 0
run "local_settings, file in a missing folder -> 2" modules/config-guard.sh "$(ccp local_settings "$TDIR/no-such-dir/settings.local.json")" 2
cp "$TDIR/_l_copy.json" "$WT/.claude/settings.local.json"
run "local_settings, no file_path, the repo's local file -> 2" modules/config-guard.sh '{"source":"local_settings"}' 2
rm -f "$WT/.claude/settings.local.json"
run "policy_settings source -> 0" modules/config-guard.sh "$(ccp policy_settings "$TDIR/_l_copy.json")" 0
run "skills source -> 0"          modules/config-guard.sh "$(ccp skills "$TDIR/_l_copy.json")" 0
local_report() { printf '{"source":"local_settings","file_path":"%s"}' "$1" | bash -p "$H/modules/config-guard.sh" 2>&1; }
rpt="$(local_report "$TDIR/_l_keys.json")"
for needle in "SETTINGS TAMPER DETECTED" ".claude/settings.local.json was changed" \
              "settings.local.json has hook entries naming baseline scripts: guardrails/command-guard.sh - " \
              "Remove the reported entries from .claude/settings.local.json"; do
  case "$rpt" in *"$needle"*) pass=$((pass + 1)) ;; *) fail=$((fail + 1)); echo "  FAIL [config-guard local report missing: $needle]" ;; esac
done
rpt="$(local_report "$TDIR/_l_env.json")"
case "$rpt" in *"RISKY ENVIRONMENT VALUE"*".claude/settings.local.json sets"*) pass=$((pass + 1)) ;; *) fail=$((fail + 1)); echo "  FAIL [config-guard local env heading]" ;; esac
# a name holding control characters is printed escaped, on one finding line
rpt="$(local_report "$TDIR/_l_esc.json")"
case "$rpt" in *$'\e'*) fail=$((fail + 1)); echo "  FAIL [config-guard local report printed a raw escape]" ;;
  *'x\x1b[2J\ny.sh'*) pass=$((pass + 1)) ;; *) fail=$((fail + 1)); echo "  FAIL [config-guard local report: escaped name missing]" ;; esac
# a long name is cut at 200 characters, so the finding stays one bounded line
rpt="$(local_report "$TDIR/_l_long.json")"
line="$(printf '%s\n' "$rpt" | awk '/naming baseline scripts/ { print; exit }')"
if [[ "$line" == *"aaa... - the installer"* ]] && [ "${#line}" -lt 450 ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [config-guard local report: long name not capped (${#line} chars)]"; fi
# many names: the first 20, then a count
rpt="$(local_report "$TDIR/_l_many.json")"
case "$rpt" in *"s19.sh, and 5 more - the installer"*) pass=$((pass + 1)) ;; *) fail=$((fail + 1)); echo "  FAIL [config-guard local report: names not capped at 20]" ;; esac
rpt="$(local_report "$TDIR/_l_args.json")"
case "$rpt" in *"naming baseline scripts: guardrails/command-guard.sh - "*) pass=$((pass + 1)) ;; *) fail=$((fail + 1)); echo "  FAIL [config-guard local report: args not named]" ;; esac
rpt="$(local_report "$TDIR/_l_own.json")"
case "$rpt" in *"local settings change validated"*) pass=$((pass + 1)) ;; *) fail=$((fail + 1)); echo "  FAIL [config-guard local validated line]" ;; esac
setcfg "c['enforcement']='warn'"
run "local_settings tamper + warn -> 0" modules/config-guard.sh "$(ccp local_settings "$TDIR/_l_keys.json")" 0
resetcfg
run "local_settings, module disabled -> 0" modules/config-guard.sh "$(ccp local_settings "$TDIR/_l_keys.json")" 0
setcfg "c['modules']['configGuard']['enabled']=True"
for i in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17; do
  run "risky env value $i -> 2"          modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_env$i.json")" 2
done
run "harmless env values -> 0"           modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_env_ok.json")" 0
# The heading follows the worst finding: an install from before -p is out of date, a
# risky env value is reported as such, and anything else is tamper.
# head_of <settings>: the report's first line
head_of() { printf '{"source":"project_settings","file_path":"%s"}' "$1" | bash -p "$H/modules/config-guard.sh" 2>&1 | awk 'NF { print; exit }'; }
for spec in "_t_stale.json|BASELINE OUT OF DATE" "_t_nop.json|BASELINE OUT OF DATE" \
            "_t_env0.json|RISKY ENVIRONMENT VALUE" "_t_stale_env.json|RISKY ENVIRONMENT VALUE" \
            "_t_or_true.json|SETTINGS TAMPER DETECTED" "_t_disable.json|SETTINGS TAMPER DETECTED"; do
  h1="$(head_of "$TDIR/${spec%%|*}")"
  case "$h1" in *"${spec#*|}"*) pass=$((pass + 1)) ;; *) fail=$((fail + 1)); echo "  FAIL [config-guard heading for ${spec%%|*}: $h1]" ;; esac
done
# FUNCNEST applies even under -p (common.sh drops it): config-guard still reports.
out="$(printf '{"source":"project_settings","file_path":"%s"}' "$TDIR/_t_disable.json" | env FUNCNEST=1 bash -p "$H/modules/config-guard.sh" 2>&1)"; rc=$?
if [ "$rc" = 2 ] && printf '%s' "$out" | grep -qF "SETTINGS TAMPER DETECTED"; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [config-guard under FUNCNEST=1: rc=$rc]"; fi
run "non-object json -> 2"       modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_list.json")" 2
run "missing settings -> 2"      modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_nope.json")" 2
run "non-watched source -> 0"    modules/config-guard.sh "$(ccp user_settings "$GOOD")" 0
run "no source -> 2"             modules/config-guard.sh '{"foo":"bar"}' 2
run "unparseable -> 2"           modules/config-guard.sh '{ not json' 2
setcfg "c['enforcement']='warn'"
run "tamper+warn -> 0"           modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_disable.json")" 0
resetcfg
run "disabled module -> 0"       modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_disable.json")" 0
# Regression guard (passes on main too): a tamper report goes to stderr, in both postures,
# and stdout stays empty. Claude Code shows a ConfigChange hook's report to no one (a
# blocked change surfaces no message; it writes a debug-log line), so the docs point to
# `claude --debug`; and a ConfigChange hook's stdout JSON is acted on as a decision, so
# none may appear by accident.
setcfg "c['modules']['configGuard']['enabled']=True"
run_out "config-guard block, tamper -> 2" modules/config-guard.sh 2 <<< "$(ccp project_settings "$TDIR/_t_disable.json")"
quiet_ok "config-guard block tamper prints nothing on stdout"
err_has "config-guard block tamper report is on stderr" "SETTINGS TAMPER DETECTED"
setcfg "c['enforcement']='warn'"
run_out "config-guard warn, tamper -> 0" modules/config-guard.sh 0 <<< "$(ccp project_settings "$TDIR/_t_disable.json")"
quiet_ok "config-guard warn tamper prints nothing on stdout"
err_has "config-guard warn tamper report is on stderr" "SETTINGS TAMPER DETECTED"
resetcfg
# Assert the rendered report is intact (not just the exit code) — guards against the
# grep-binary / CRLF corruption that mangled multi-finding output. All three findings
# must appear cleanly, with no stray "Binary file" text.
setcfg "c['modules']['configGuard']['enabled']=True"
rpt="$(printf '{"source":"project_settings","file_path":"%s"}' "$TDIR/_t_all.json" | bash "$H/modules/config-guard.sh" 2>&1)"
for needle in "disableAllHooks=True" "no longer wired" "deny-list entries removed"; do
  if printf '%s' "$rpt" | grep -qF "$needle"; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [config-guard report missing: $needle]"; fi
done
if printf '%s' "$rpt" | grep -qF "Binary file"; then fail=$((fail + 1)); echo "  FAIL [config-guard report corrupted with 'Binary file']"; else pass=$((pass + 1)); fi
# Coupling assertions: the baseline deny-list AND the wired hook scripts each live in
# BOTH settings.template.json and config-guard.sh — they must stay identical or the
# integrity check would block valid installs / miss real tamper.
if "$PY" - "$SRC" <<'PY'
import ast, json, re, sys
src = sys.argv[1]
tmpl = json.load(open(src + "/settings.template.json", encoding="utf-8"))
guard = open(src + "/hooks/modules/config-guard.sh", encoding="utf-8").read()
merge = open(src + "/lib/merge_settings.py", encoding="utf-8").read()
def pylist(name, text=guard):
    # Parse the literal rather than scraping the source text between quotes. An entry
    # containing a backslash — the Windows path forms among the PowerShell deny rules —
    # is written "\\" in the source but denotes ONE backslash, so a regex scrape
    # reports drift between two files that actually agree. (Writing a single backslash
    # in the source to satisfy the scrape would be worse: "\\baseline" as one
    # backslash is the escape \\b, a backspace.)
    m = re.search(name + r" = (\[.*?\])", text, re.S)
    return list(ast.literal_eval(m.group(1))) if m else []
# env + launch coupling: config-guard flags the same env keys, and accepts the same
# launch form, as the installer and baseline-status (lib/merge_settings.py)
def pystr(name, text=guard):
    m = re.search(name + r" = (r'[^'\n]*')", text)
    return ast.literal_eval(m.group(1)) if m else ""
env_ok = (all(pylist(n) and pylist(n) == pylist(n, merge)
              for n in ("RISKY_ENV_NAMES", "RISKY_ENV_PREFIXES", "RISKY_ENV_SUBSTRINGS"))
          and pystr("BASELINE_LAUNCH") and pystr("BASELINE_LAUNCH") == pystr("BASELINE_LAUNCH", merge))
# deny-list coupling
deny_ok = sorted(tmpl["permissions"]["deny"]) == sorted(pylist("EXPECTED_DENY")) and pylist("EXPECTED_DENY")
# wired-scripts coupling: every script the template `bash`-invokes must be in REQUIRED_HOOK_CMDS, and vice-versa
cmds = []
def walk(o):
    if isinstance(o, dict):
        if o.get("type") == "command" and isinstance(o.get("command"), str): cmds.append(o["command"])
        for v in o.values(): walk(v)
    elif isinstance(o, list):
        for it in o: walk(it)
walk(tmpl.get("hooks", {}))
wired = set(re.findall(r"\.claude/hooks/baseline/(\S+?\.sh)", " ".join(cmds)))
req = set(pylist("REQUIRED_HOOK_CMDS"))
hooks_ok = wired == req and req
# every baseline hook the template wires takes config-guard's exact launch form (2c),
# and config-guard's minimum timeouts are the template's
launch_pat = pystr("BASELINE_LAUNCH")   # "" if config-guard has none: drift, not a crash
launch_ok = bool(launch_pat) and all(re.match(launch_pat, c) for c in cmds if "/.claude/hooks/baseline/" in c)
m = re.search(r"BASELINE_TIMEOUTS = (\{.*?\})", guard, re.S)
tmpl_timeouts = {}
def walk_t(o):
    if isinstance(o, dict):
        mm = launch_pat and o.get("type") == "command" and re.match(launch_pat, o.get("command", ""))
        if mm: tmpl_timeouts[mm.group(2)] = o.get("timeout")
        for v in o.values(): walk_t(v)
    elif isinstance(o, list):
        for it in o: walk_t(it)
walk_t(tmpl.get("hooks", {}))
launch_ok = launch_ok and m and ast.literal_eval(m.group(1)) == tmpl_timeouts
raise SystemExit(0 if deny_ok and hooks_ok and env_ok and launch_ok else 1)
PY
then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [coupling drift: settings.template.json vs config-guard EXPECTED_DENY / REQUIRED_HOOK_CMDS / BASELINE_LAUNCH / BASELINE_TIMEOUTS, or config-guard vs merge_settings RISKY_ENV_* / BASELINE_LAUNCH]"; fi
# Wiring coupling: config-guard's BASELINE_WIRING is the template's wiring as
# lib/merge_settings.py reads it (from the raw template too, whose hooks hold a _comment
# string), every template matcher is names joined by | (so its names are defined), and
# the two copies of _matcher_covers, and of _wired_at, give the same answers on one table.
if "$PY" - "$SRC" <<'PY'
import ast, json, re, sys
src = sys.argv[1]
sys.dont_write_bytecode = True   # importing lib/merge_settings.py must not write into the tree
sys.path.insert(0, src + "/lib")
import merge_settings as ms
guard = open(src + "/hooks/modules/config-guard.sh", encoding="utf-8").read()
m = re.search(r"BASELINE_WIRING = (\[.*?\n\])", guard, re.S)
key = lambda r: (r[0], r[1], r[2] or "")
cg_rows = sorted(ast.literal_eval(m.group(1)), key=key) if m else None
tmpl = json.load(open(src + "/settings.template.json", encoding="utf-8"))
rows = ms.baseline_wiring(tmpl)
rows_ok = len(rows) == 6 and rows == cg_rows == ms.baseline_wiring(ms.strip_comments(tmpl))
exact_ok = all(w is None or re.fullmatch(r"[A-Za-z0-9_|-]+", w) for _, _, w in rows)
ns = {"re": re}
for fn in ("_matcher_covers(grp, wired)", "_wired_at(hooks, script, event, wired)",
           "_guard_entries(hooks, guards)"):
    f = re.search(r"^def " + re.escape(fn) + r":\n(?:    .*\n)+", guard, re.M)
    if f:
        exec(f.group(0), ns)
cg_covers, cg_wired_at = ns.get("_matcher_covers"), ns.get("_wired_at")
def g(*m): return {"matcher": m[0]} if m else {}
BP, CC = "Bash|PowerShell", "local_settings"
TABLE = [(g(), BP, True), (g(""), BP, True), (g("*"), BP, True), (g(BP), BP, True),
         (g("PowerShell|Bash"), BP, True), (g("Bash, PowerShell"), BP, False),
         (g("Bash | PowerShell"), BP, False), (g("Bash,PowerShell"), BP, False),
         (g("Bash|PowerShell|Read"), BP, True), (g("Bash|PowerShell|Read "), BP, False),
         (g("Bash||PowerShell"), BP, True), (g("Bash"), BP, False), (g("Read"), BP, False),
         (g("BashPowerShell"), BP, False), (g("Bash PowerShell"), BP, False),
         (g("bash|powershell"), BP, False), (g(BP + " "), BP, False), (g(" " + BP), BP, False),
         (g(BP + chr(10)), BP, False), (g(BP + chr(9)), BP, False), (g("Bash" + chr(0xA0) + "|PowerShell"), BP, False),
         (g("   "), BP, False), (g("^(Bash|PowerShell)$"), BP, False), (g(".*"), BP, False),
         (g("Bash|PowerShell|.*"), BP, False), (g(None), BP, False), (g([BP]), BP, False),
         (g(1), BP, False), (g(True), BP, False), (g({}), BP, False),
         (g(), None, True), (g(""), None, True), (g("*"), None, True), (g("Bash"), None, False),
         (g(None), None, False), (g(".*"), None, False),
         (g("project_settings|local_settings"), CC, True), (g("project_settings"), CC, False),
         (g("Write|Edit"), "Write|Edit", True), (g("Edit"), "Write|Edit", False)]
bad = [(gr, w) for gr, w, want in TABLE
       if cg_covers is None or (cg_covers(gr, w), ms._matcher_covers(gr, w)) != (want, want)]
for gr, w in bad:
    print("  _matcher_covers disagrees with the table:", ascii(gr), ascii(w))
# _wired_at: a direct command entry running the script (its name ending there), no `if`,
# under the exact event, in a covering group; odd shapes are not wired and do not crash.
B = "${CLAUDE_PROJECT_DIR}/.claude/hooks/baseline/"
CGS, TRS = "guardrails/command-guard.sh", "modules/tracker-reminder.sh"
def e(cmd, **k): return dict({"type": "command", "command": cmd}, **k)
def run_(script): return e('bash -p "' + B + script + '"')
def H(*entries, matcher=BP, event="PreToolUse"): return {event: [{"matcher": matcher, "hooks": list(entries)}]}
WTABLE = [(H(run_(CGS)), CGS, "PreToolUse", BP, True),
          (H(e("bash -p " + B + CGS)), CGS, "PreToolUse", BP, True),
          (H(e('bash -p "' + B + CGS + '" || true')), CGS, "PreToolUse", BP, True),   # launch form: (2c)
          (H(dict(run_(CGS), **{"if": "Bash(git status)"})), CGS, "PreToolUse", BP, False),
          (H(dict(run_(CGS), **{"if": None})), CGS, "PreToolUse", BP, False),
          (H(dict(run_(CGS), type="http")), CGS, "PreToolUse", BP, False),
          (H(e("exit 0", x=run_(CGS))), CGS, "PreToolUse", BP, False),
          (H(run_(CGS), event="pretooluse"), CGS, "PreToolUse", BP, False),
          (H(run_(CGS), matcher="Read"), CGS, "PreToolUse", BP, False),
          (H(run_(CGS + ".sh")), CGS, "PreToolUse", BP, False),
          (H(run_(CGS + "/../x.sh")), CGS, "PreToolUse", BP, False),
          (H(run_("x/.claude/hooks/baseline/" + CGS)), CGS, "PreToolUse", BP, False),
          (H(run_("modules/scope-guard.sh")), CGS, "PreToolUse", BP, False),
          (H(e("bash -p " + CGS)), CGS, "PreToolUse", BP, False),
          (H(run_("x/../" + CGS)), CGS, "PreToolUse", BP, False),
          ({"PreToolUse": [{"matcher": "Read", "hooks": [run_(CGS)]},
                           {"matcher": BP, "hooks": [run_(CGS + ".sh")]}]}, CGS, "PreToolUse", BP, False),
          ({"Stop": [{"hooks": [run_(TRS)]}]}, TRS, "Stop", None, True),
          ({"Stop": [{"matcher": "x", "hooks": [run_(TRS)]}]}, TRS, "Stop", None, False),
          (["x"], CGS, "PreToolUse", BP, False), ({"PreToolUse": "x"}, CGS, "PreToolUse", BP, False),
          ({"PreToolUse": [None, {"hooks": "x"}, {"matcher": BP, "hooks": [None, 1, e(5)]}]},
           CGS, "PreToolUse", BP, False)]
wbad = [(h, s) for h, s, ev, w, want in WTABLE
        if cg_wired_at is None or (cg_wired_at(h, s, ev, w), ms._wired_at(h, s, ev, w)) != (want, want)]
for h, s in wbad:
    print("  _wired_at disagrees with the table:", ascii(h)[:160], s)
# _guard_entries (2b): config-guard's GUARD_SCRIPTS are the template's onFailure-block
# entries, and both copies give (seen, soft) alike: direct PreToolUse entries only, the
# loose match of (2), onFailure other than "block" soft.
m = re.search(r"GUARD_SCRIPTS = (\(.*?\))", guard)
cg_guards = ast.literal_eval(m.group(1)) if m else ()
guards_ok = bool(cg_guards) and set(cg_guards) == ms.baseline_blocking(tmpl)
cg_guard_entries = ns.get("_guard_entries")
SGS = "modules/scope-guard.sh"
GS = (CGS, SGS)
def blk(script, of="block"): return dict(run_(script), onFailure=of)
GTABLE = [(H(blk(CGS)), {CGS}, set()), (H(run_(CGS)), {CGS}, {CGS}),
          (H(blk(CGS, "continue")), {CGS}, {CGS}), (H(blk(CGS, None)), {CGS}, {CGS}),
          (H(blk(CGS), run_(SGS)), {CGS, SGS}, {SGS}), (H(blk(CGS), run_(CGS)), {CGS}, {CGS}),
          (H(dict(run_(CGS), type="http")), {CGS}, {CGS}), (H(run_(CGS + ".sh")), {CGS}, {CGS}),
          (H(dict(e('bash "' + B + CGS + '" || true'), onFailure="block")), {CGS}, set()),
          (H(e("bash" + chr(0x85) + B + CGS)), {CGS}, {CGS}),
          (H(e("exit 0", x=run_(CGS))), set(), set()), (H(run_(CGS), event="SessionStart"), set(), set()),
          (H(run_(CGS), event="pretooluse"), set(), set()), (H(blk("modules/tracker-reminder.sh", None)), set(), set()),
          (["x"], set(), set()), ({"PreToolUse": "x"}, set(), set()),
          ({"PreToolUse": [None, {"hooks": "x"}, {"hooks": [None, 1, e(5)]}]}, set(), set())]
gbad = [h for h, seen, soft in GTABLE
        if cg_guard_entries is None
        or (cg_guard_entries(h, GS), ms._guard_entries(h, GS)) != ((seen, soft), (seen, soft))]
for h in gbad:
    print("  _guard_entries disagrees with the table:", ascii(h)[:160])
raise SystemExit(0 if rows_ok and exact_ok and not bad and not wbad and guards_ok and not gbad else 1)
PY
then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [wiring coupling: config-guard BASELINE_WIRING / GUARD_SCRIPTS vs settings.template.json / merge_settings, or _matcher_covers / _wired_at / _guard_entries copies]"; fi
# Local-settings coupling: config-guard's (5) names baseline hook entries exactly as
# lib/merge_settings.py's baseline_hook_names does (the script after the baseline path,
# else the command), on one table of shapes.
if "$PY" - "$SRC" <<'PY'
import re, sys
src = sys.argv[1]
sys.dont_write_bytecode = True
sys.path.insert(0, src + "/lib")
import merge_settings as ms
guard = open(src + "/hooks/modules/config-guard.sh", encoding="utf-8").read()
ns = {"re": re}
for const in ("_SCRIPT_AFTER_MARKER", "_SPACE"):
    m = re.search(r"^" + const + r" = .*$", guard, re.M)
    if m:
        exec(m.group(0), ns)
for fn in ("_named_script(command)", "_command_entries(obj)", "_entry_text(e)", "_baseline_named(hooks)"):
    m = re.search(r"^def " + re.escape(fn) + r":\n(?:    .*\n)+", guard, re.M)
    if m:
        exec(m.group(0), ns)
named = ns.get("_baseline_named")
M = "/.claude/hooks/baseline/"
CG = 'bash -p "${CLAUDE_PROJECT_DIR}' + M + 'guardrails/command-guard.sh"'
def e(cmd, **k): return dict({"type": "command", "command": cmd}, **k)
TABLE = [({"PreToolUse": [{"matcher": "Bash", "hooks": [e(CG, statusMessage="x")]}]}, ["guardrails/command-guard.sh"]),
         ({"Stop": [{"hooks": [e("echo " + M)]}]}, ["echo " + M]),
         ({"X": [{"hooks": [e("exit 0", x=e("bash " + M + "a.sh"))]}]}, ["a.sh"]),
         ({"PreToolUse": [{"hooks": [e(CG), e("bash " + M + "x/" + M + "b.sh")]}]},
          ["guardrails/command-guard.sh", "x/" + M + "b.sh"]),
         ({"PreToolUse": [{"hooks": [e("bash ./scripts/own.sh"), {"type": "http", "command": CG}, e(5)]}]}, []),
         ({"PreToolUse": [{"hooks": [e("bash", args=["-p", M + "c.sh"]), e("bash", args=[1, None])]}]}, ["c.sh"]),
         ({"PreToolUse": [{"hooks": [e("bash", args="-p " + M + "d.sh")]}]}, []),
         (None, []), ([], []), ("x", []), ({"PreToolUse": "x"}, [])]
bad = [h for h, want in TABLE
       if named is None or (named(h), ms.baseline_hook_names({"hooks": h})) != (want, want)]
for h in bad:
    print("  baseline hook naming disagrees with the table:", ascii(h)[:160])
raise SystemExit(0 if named is not None and not bad else 1)
PY
then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [local-settings coupling: config-guard _baseline_named vs merge_settings baseline_hook_names]"; fi
resetcfg

echo "== baseline version stamp + config-keep contract (Q3) =="
# Contract integrity: re-running install.sh must NOT touch an existing config —
# install.sh's advertised 'never clobber' invariant. Mutate the installed config,
# snapshot it, re-run install, and assert byte-identical (the keep path wrote nothing).
setcfg "c['modules']['fixTags']['enabled']=True; c['guardrails']['commandGuard']['extraPatterns']=['terraform destroy']"
cp "$CFG" "$WT/.claude/_precontract.json"
timeout -k 5 120 bash "$SRC/install.sh" --target "$WT" >/dev/null 2>&1 </dev/null
if cmp -s "$CFG" "$WT/.claude/_precontract.json"; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [install.sh re-run clobbered an existing baseline.config.json]"; fi
# Marker freshness: the installed VERSION equals the source hooks/VERSION after a re-run
# (install.sh replaces the whole .claude/hooks/baseline/ tree, so the marker is always truthful).
srcver="$(tr -d '\r\n' < "$SRC/hooks/VERSION" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
instver="$(tr -d '\r\n' < "$WT/.claude/hooks/baseline/VERSION" 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' || true)"
if [ -n "$srcver" ] && [ "$srcver" = "$instver" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [installed VERSION '$instver' != source '$srcver']"; fi
resetcfg
# Create-path stamp: a FRESH install prints the stamped baselineVersion in its output.
FRESH="$(winpath "$TMP/fresh")"; mkdir -p "$FRESH"; ( cd "$FRESH" && git init -q )
fout="$(timeout -k 5 120 bash "$SRC/install.sh" --target "$FRESH" 2>&1 </dev/null)"
if printf '%s' "$fout" | grep -qF "$srcver"; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [install create-path did not print baselineVersion $srcver]"; fi

echo "== install.sh --enable-security-defaults (post-write demo path) =="
# Every post-write module ships off, so a default install shows nothing on a bad
# write. --enable-security-defaults turns securityDefaults on in a NEW config in one
# step, and refuses unless a rules file will exist: an enabled module with no rules
# fails closed on every infra write.
SD1="$(winpath "$TMP/sd-norules")"; mkdir -p "$SD1"; ( cd "$SD1" && git init -q )
sdout="$(timeout -k 5 120 bash "$SRC/install.sh" --target "$SD1" --enable-security-defaults 2>&1 </dev/null)"; rc=$?
# The message, not just rc=2: an installer without the flag also exits 2 ("unknown argument").
if [ "$rc" = 2 ] && [ ! -e "$SD1/.claude" ] && printf '%s' "$sdout" | grep -qF "needs a rules file"; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [enable without rules must refuse with the rules-file message and write nothing (rc=$rc)]"; fi
SD2="$(winpath "$TMP/sd-demo")"; mkdir -p "$SD2"; ( cd "$SD2" && git init -q )
sdout="$(timeout -k 5 120 bash "$SRC/install.sh" --target "$SD2" --with-openclaw-rules --enable-security-defaults --dry-run 2>&1 </dev/null)"
if [ ! -e "$SD2/.claude" ] && printf '%s' "$sdout" | grep -qF "would set modules.securityDefaults.enabled"; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [dry-run with --enable-security-defaults wrote files or did not say what it would enable]"; fi
timeout -k 5 120 bash "$SRC/install.sh" --target "$SD2" --with-openclaw-rules --enable-security-defaults >/dev/null 2>&1 </dev/null
sd_on="$("$PY" -c "import json,sys;sys.stdout.write(str(json.load(open(r'$SD2/.claude/baseline.config.json'))['modules']['securityDefaults']['enabled']))" 2>/dev/null)"
if [ "$sd_on" = "True" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [fresh install did not enable securityDefaults (got '$sd_on')]"; fi
# The demo itself: a root-container write through the INSTALLED dispatcher is reported.
printf 'services:\n  app:\n    image: x\n    user: root\n' > "$SD2/docker-compose.yml"
( cd "$SD2" && printf '%s' "$(write_payload "$SD2/docker-compose.yml")" | CLAUDE_PROJECT_DIR="$SD2" bash "$SD2/.claude/hooks/baseline/dispatcher/post-write.sh" >/dev/null 2>&1 ); rc=$?
if [ "$rc" = 2 ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [post-write violation after enable must exit 2 (rc=$rc)]"; fi
# An existing config is never rewritten, even with the flag: FRESH (installed above
# without it) keeps securityDefaults off, the run succeeds, and says so.
cp "$FRESH/.claude/baseline.config.json" "$FRESH/.claude/_presd.json"
sdout="$(timeout -k 5 120 bash "$SRC/install.sh" --target "$FRESH" --enable-security-defaults 2>&1 </dev/null)"; rc=$?
if [ "$rc" = 0 ] && cmp -s "$FRESH/.claude/baseline.config.json" "$FRESH/.claude/_presd.json" && printf '%s' "$sdout" | grep -qF "was NOT changed"; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [--enable-security-defaults on an existing config must succeed, say so, and not rewrite it (rc=$rc)]"; fi

echo "== guard failure mode: onFailure + Git Bash note (D1/D2) =="
# The merge must carry onFailure:"block" onto both PreToolUse guards in the installed
# settings.json, so a guard that cannot start or times out blocks the call.
guards_ok="$("$PY" -c "import json,re,sys
s=json.load(open(r'$WT/.claude/settings.json'))
g=[h for grp in s['hooks']['PreToolUse'] for h in grp['hooks'] if re.search(r'(command|scope)-guard', h['command'])]
sys.stdout.write('yes' if len(g)==2 and all(h.get('onFailure')=='block' for h in g) else 'no')" 2>/dev/null)"
if [ "$guards_ok" = "yes" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [installed PreToolUse guards must carry onFailure: block]"; fi
# The Git Bash requirement is announced on Windows-like hosts, and only there.
case "$(uname -s 2>/dev/null)" in
  MINGW*|MSYS*|CYGWIN*) want_note=1 ;;
  *) want_note=0; { [ -n "${WSL_DISTRO_NAME:-}" ] || [ -e /proc/sys/fs/binfmt_misc/WSLInterop ] || grep -qi microsoft /proc/version 2>/dev/null; } && want_note=1 ;;
esac
if printf '%s' "$fout" | grep -qE "Claude Code must find Git Bash|needs Git for Windows"; then got_note=1; else got_note=0; fi
if [ "$got_note" = "$want_note" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [Git Bash note shown=$got_note, expected=$want_note on $(uname -s)]"; fi

echo "== settings merge keeps a repo's own hooks (B1) =="
# Ownership is per hook: a repo's own hook sharing a matcher group with a baseline
# hook must survive the merge, and only a group the merge itself emptied may be
# dropped. The seeded command-guard spells the path $CLAUDE_PROJECT_DIR without the
# template's braces: any command naming the baseline path is ours and is replaced,
# not duplicated. A second run is byte-identical. Shapes: test_merge_settings.py.
MG="$TMP/mergekeep"; mkdir -p "$MG/.claude"; ( cd "$MG" && git init -q )
cat > "$MG/.claude/settings.json" <<'EOF'
{
  "model": "keep-me",
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash|PowerShell", "hooks": [
        {"type": "command", "command": "bash \"$CLAUDE_PROJECT_DIR/.claude/hooks/baseline/guardrails/command-guard.sh\""},
        {"type": "command", "command": "bash ./scripts/user-audit.sh", "timeout": 7}
      ]}
    ],
    "Stop": [
      null,
      {"hooks": [{"type": "command", "command": "bash \"$CLAUDE_PROJECT_DIR/.claude/hooks/baseline/old/retired.sh\""}]}
    ],
    "PostToolUse": [
      {"matcher": "Write", "hooks": []}
    ]
  }
}
EOF
timeout -k 5 120 bash "$SRC/install.sh" --target "$(winpath "$MG")" >/dev/null 2>&1 </dev/null; rc=$?
if [ "$rc" = 0 ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [merge-keep install rc=$rc]"; fi
mk="$("$PY" -c "import json,sys
s=json.load(open(sys.argv[1],encoding='utf-8'))
h=s['hooks']; bad=[]
ua=[(g,x) for g in h['PreToolUse'] for x in g['hooks'] if 'user-audit' in x.get('command','')]
if len(ua)!=1: bad.append('user-audit appears %d times' % len(ua))
elif ua[0][0].get('matcher')!='Bash|PowerShell' or ua[0][1].get('timeout')!=7: bad.append('user-audit group or fields changed')
if h['Stop'][:1]!=[None]: bad.append('null Stop entry not kept in place')
grps=[(ev,g) for ev,gs in h.items() for g in gs if g is not None]
allh=[x for ev,g in grps for x in g['hooks']]
if sum('command-guard.sh' in x.get('command','') for x in allh)!=1: bad.append('command-guard not exactly once')
if not all(x['command'].startswith('bash -p ') for x in allh if 'command-guard.sh' in x.get('command','')): bad.append('command-guard not relaunched as bash -p')
if any('retired.sh' in x.get('command','') for x in allh): bad.append('retired baseline hook kept')
empty=[(ev,g.get('matcher')) for ev,g in grps if not g['hooks']]
if empty!=[('PostToolUse','Write')]: bad.append('empty groups %r' % (empty,))
if s.get('model')!='keep-me': bad.append('model changed')
sys.stdout.write('; '.join(bad) or 'ok')" "$(winpath "$MG/.claude/settings.json")" 2>&1)"
if [ "$mk" = "ok" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [merge-keep: $mk]"; fi
cp "$MG/.claude/settings.json" "$TMP/mergekeep.first.json"
timeout -k 5 120 bash "$SRC/install.sh" --target "$(winpath "$MG")" >/dev/null 2>&1 </dev/null
if cmp -s "$MG/.claude/settings.json" "$TMP/mergekeep.first.json"; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [merge-keep re-run changed settings.json]"; fi
# An env value that can run code before the hooks is reported by the installer and kept
# exactly as it was (never clobber an existing key).
EV="$TMP/envwarn"; mkdir -p "$EV/.claude"; ( cd "$EV" && git init -q )
printf '{"env": {"BASH_ENV": "/tmp/startup.sh", "NODE_ENV": "production"}}\n' > "$EV/.claude/settings.json"
evout="$(timeout -k 5 120 bash "$SRC/install.sh" --target "$(winpath "$EV")" 2>&1 </dev/null)"; rc=$?
evenv="$("$PY" -c "import json,sys; print(json.dumps(json.load(open(sys.argv[1],encoding='utf-8')).get('env'), sort_keys=True))" "$(winpath "$EV/.claude/settings.json")" 2>&1)"
if [ "$rc" = 0 ] && printf '%s' "$evout" | grep -qF "WARNING: settings.json env sets BASH_ENV." \
   && [ "$evenv" = '{"BASH_ENV": "/tmp/startup.sh", "NODE_ENV": "production"}' ]; then
  pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [install env warning: rc=$rc env=$evenv]"; fi

echo "== installer: dry run validates, backups only on change, tree replaced (B3-B5) =="
# inst <dir> [args...] -> IOUT (stdout+stderr), IRC
inst() { local d="$1"; shift; IOUT="$(timeout -k 5 120 bash "$SRC/install.sh" --target "$(winpath "$d")" "$@" 2>&1 </dev/null)"; IRC=$?; }
nbak() { local n=0 f; for f in "$1"/.claude/settings.json.bak.*; do [ -e "$f" ] && n=$((n + 1)); done; echo "$n"; }
ok_if() { if eval "$2"; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [$1]"; fi; }
PAST='^  (copied|wrote|backed up|merged|created|refreshed|replaced|stamped|added|enabled|removing) '
# B3: a dry run merges too, so a settings.json the real run rejects fails it, and it
# writes nothing (no hooks, no backup, no temp file under .claude).
IB="$TMP/inst-broken"; mkdir -p "$IB/.claude"; ( cd "$IB" && git init -q )
printf '{"model": "x",}\n' > "$IB/.claude/settings.json"; cp "$IB/.claude/settings.json" "$TMP/inst-broken.orig"
inst "$IB" --dry-run
ok_if "dry run on a settings.json the merge rejects exits 1 (rc=$IRC)" '[ "$IRC" = 1 ]'
ok_if "dry run names the real run's stop" 'printf "%s" "$IOUT" | grep -qF "DRY RUN: the real run would stop here"'
ok_if "dry run on a broken settings.json writes nothing" 'cmp -s "$IB/.claude/settings.json" "$TMP/inst-broken.orig" && [ "$(nbak "$IB")" = 0 ] && [ ! -e "$IB/.claude/hooks" ] && [ -z "$(ls -A "$IB/.claude" | grep -v "^settings.json$")" ]'
# ...and its env warning shows in a dry run (the merge runs), with nothing written.
IE="$TMP/inst-env"; mkdir -p "$IE/.claude"; ( cd "$IE" && git init -q )
printf '{"env": {"BASH_ENV": "/tmp/x.sh"}}\n' > "$IE/.claude/settings.json"; cp "$IE/.claude/settings.json" "$TMP/inst-env.orig"
inst "$IE" --dry-run
ok_if "dry run shows the merge's env warning, writes nothing (rc=$IRC)" '[ "$IRC" = 0 ] && printf "%s" "$IOUT" | grep -qF "WARNING: settings.json env sets BASH_ENV." && cmp -s "$IE/.claude/settings.json" "$TMP/inst-env.orig" && [ ! -e "$IE/.claude/hooks" ] && [ "$(nbak "$IE")" = 0 ]'
ok_if "dry run on an existing settings.json speaks in the conditional" '! printf "%s\n" "$IOUT" | grep -qE "$PAST" && printf "%s" "$IOUT" | grep -qF "would back up settings.json" && printf "%s" "$IOUT" | grep -qF "would merge baseline hooks"'
IF="$TMP/inst-fresh-dry"; mkdir -p "$IF"; ( cd "$IF" && git init -q )
inst "$IF" --dry-run --with-openclaw-rules --enable-security-defaults
ok_if "dry run on a fresh repo speaks in the conditional and writes nothing (rc=$IRC)" '[ "$IRC" = 0 ] && [ ! -e "$IF/.claude" ] && ! printf "%s\n" "$IOUT" | grep -qE "$PAST" && printf "%s" "$IOUT" | grep -qF "would write default .claude/baseline.config.json" && printf "%s" "$IOUT" | grep -qF "would stamp baselineVersion"'
# B4: a re-install that changes nothing writes no backup and does not rewrite the file;
# not even when the file is CRLF or starts with a BOM (native Windows Python writes CRLF).
IK="$TMP/inst-keep"; mkdir -p "$IK"; ( cd "$IK" && git init -q )
inst "$IK"; ok_if "fresh install creates settings.json without a backup (rc=$IRC)" '[ "$IRC" = 0 ] && [ -f "$IK/.claude/settings.json" ] && [ "$(nbak "$IK")" = 0 ]'
inst "$IK"; ok_if "unchanged re-install writes no backup" '[ "$IRC" = 0 ] && [ "$(nbak "$IK")" = 0 ] && printf "%s" "$IOUT" | grep -qF "already up to date"'
"$PY" -c "import sys;p=sys.argv[1];b=open(p,'rb').read().replace(b'\r\n',b'\n');open(p,'wb').write(b.replace(b'\n',b'\r\n'))" "$(winpath "$IK/.claude/settings.json")"
inst "$IK"; ok_if "unchanged CRLF settings.json: no backup (rc=$IRC)" '[ "$IRC" = 0 ] && [ "$(nbak "$IK")" = 0 ] && printf "%s" "$IOUT" | grep -qF "already up to date"'
"$PY" -c "import sys;p=sys.argv[1];b=open(p,'rb').read().replace(b'\r\n',b'\n');open(p,'wb').write(b'\xef\xbb\xbf'+b)" "$(winpath "$IK/.claude/settings.json")"
inst "$IK"; ok_if "unchanged LF settings.json with a BOM: no backup (rc=$IRC)" '[ "$IRC" = 0 ] && [ "$(nbak "$IK")" = 0 ] && printf "%s" "$IOUT" | grep -qF "already up to date"'
# Two changing installs in the same second keep two backups (a fixed `date` stamp), and
# the backups are kept out of git through the local exclude, once.
DBIN="$TMP/date-bin"; mkdir -p "$DBIN"
printf '#!/usr/bin/env bash\necho 20260101000000\n' > "$DBIN/date"; chmod +x "$DBIN/date"
drop_deny() { "$PY" -c "import json,sys;p=sys.argv[1];s=json.load(open(p,encoding='utf-8-sig'));s['permissions']['deny']=s['permissions']['deny'][1:];json.dump(s,open(p,'w',encoding='utf-8'))" "$(winpath "$IK/.claude/settings.json")"; }
drop_deny; IOUT="$(PATH="$DBIN:$PATH" timeout -k 5 120 bash "$SRC/install.sh" --target "$(winpath "$IK")" 2>&1 </dev/null)"; IRC=$?
drop_deny; IOUT="$(PATH="$DBIN:$PATH" timeout -k 5 120 bash "$SRC/install.sh" --target "$(winpath "$IK")" 2>&1 </dev/null)"; IRC=$?
ok_if "two backups in the same second both kept (rc=$IRC)" '[ -f "$IK/.claude/settings.json.bak.20260101000000" ] && [ -f "$IK/.claude/settings.json.bak.20260101000000.1" ] && [ "$(nbak "$IK")" = 2 ]'
ok_if "backups ignored by git" '( cd "$IK" && git check-ignore -q .claude/settings.json.bak.20260101000000.1 )'
ok_if "the exclude line is added once" '[ "$(grep -cxF "/.claude/settings.json.bak.*" "$IK/.git/info/exclude")" = 1 ]'
ok_if "backups never show as untracked" '[ -z "$(cd "$IK" && git status --porcelain --untracked-files=all -- .claude | grep "settings.json.bak")" ]'
# Not a git work tree: a backup is still written, and the run succeeds.
IN="$TMP/inst-nogit"; mkdir -p "$IN/.claude"; printf '{"model": "x"}\n' > "$IN/.claude/settings.json"
# ($TMP is itself a repo: a ceiling keeps git from finding it above this target.)
IOUT="$(GIT_CEILING_DIRECTORIES="$(winpath "$TMP")" timeout -k 5 120 bash "$SRC/install.sh" --target "$(winpath "$IN")" 2>&1 </dev/null)"; IRC=$?
ok_if "outside a git work tree a backup is written and the install succeeds (rc=$IRC)" '[ "$IRC" = 0 ] && [ "$(nbak "$IN")" = 1 ] && [ ! -e "$IN/.git" ] && ! grep -qF "inst-nogit" "$TMP/.git/info/exclude" 2>/dev/null'
# B5: the whole hook tree is replaced; files the baseline does not ship are named, then gone.
printf 'echo planted\n' > "$IK/.claude/hooks/baseline/planted.sh"; mkdir -p "$IK/.claude/hooks/baseline/stale"; printf 'x\n' > "$IK/.claude/hooks/baseline/stale/x"
inst "$IK"
ok_if "files the baseline does not ship are removed (rc=$IRC)" '[ "$IRC" = 0 ] && [ ! -e "$IK/.claude/hooks/baseline/planted.sh" ] && [ ! -e "$IK/.claude/hooks/baseline/stale" ] && [ -f "$IK/.claude/hooks/baseline/VERSION" ] && [ -f "$IK/.claude/hooks/baseline/lib/common.sh" ]'
ok_if "each removed file is named first" 'printf "%s" "$IOUT" | grep -qF "removing a file the baseline does not ship: .claude/hooks/baseline/planted.sh" && printf "%s" "$IOUT" | grep -qF ".claude/hooks/baseline/stale/x"'
# A symlinked (or, on Windows, junction) hook tree is unlinked, never followed.
mkdir -p "$TMP/inst-outside"; printf 'keep\n' > "$TMP/inst-outside/sentinel"
IL="$TMP/inst-link"; mkdir -p "$IL/.claude/hooks"; ( cd "$IL" && git init -q )
ln -s "$TMP/inst-outside" "$IL/.claude/hooks/baseline" 2>/dev/null
if [ ! -L "$IL/.claude/hooks/baseline" ] && command -v cygpath >/dev/null 2>&1; then
  rm -rf "$IL/.claude/hooks/baseline"
  MSYS_NO_PATHCONV=1 cmd /c mklink /J "$(cygpath -w "$IL/.claude/hooks/baseline")" "$(cygpath -w "$TMP/inst-outside")" >/dev/null 2>&1
fi
if [ -L "$IL/.claude/hooks/baseline" ]; then
  inst "$IL"
  ok_if "a linked hook tree is replaced, its target untouched (rc=$IRC)" '[ "$IRC" = 0 ] && [ -f "$TMP/inst-outside/sentinel" ] && [ ! -L "$IL/.claude/hooks/baseline" ] && [ -f "$IL/.claude/hooks/baseline/VERSION" ]'
else
  echo "  note: linked-hook-tree case not run (no symlink or junction could be made here)"
fi
# A dry run names a planted file but deletes nothing, and leaves the git exclude as is.
printf 'x\n' > "$IK/.claude/hooks/baseline/planted2.sh"; cp "$IK/.git/info/exclude" "$TMP/inst-excl.before"
drop_deny; cp "$IK/.claude/settings.json" "$TMP/inst-keep.before"
inst "$IK" --dry-run
ok_if "dry run names a planted file and keeps it (rc=$IRC)" '[ "$IRC" = 0 ] && printf "%s" "$IOUT" | grep -qF "would remove a file the baseline does not ship: .claude/hooks/baseline/planted2.sh" && [ -f "$IK/.claude/hooks/baseline/planted2.sh" ]'
ok_if "dry run leaves settings.json and the git exclude byte-identical" 'cmp -s "$IK/.claude/settings.json" "$TMP/inst-keep.before" && cmp -s "$IK/.git/info/exclude" "$TMP/inst-excl.before"'
# comm must collate like the C sorts feeding it: names sorting before ./dispatcher under C
# (.DS_Store, A.sh) made it report unsorted input and abort the install in en_US.UTF-8.
: > "$IK/.claude/hooks/baseline/.DS_Store"; : > "$IK/.claude/hooks/baseline/A.sh"
loc_utf8="$(locale -a 2>/dev/null | grep -i -m1 -E '^en_US\.utf-?8$' || true)"
IOUT="$(env LC_ALL="${loc_utf8:-C}" timeout -k 5 120 bash "$SRC/install.sh" --target "$(winpath "$IK")" 2>&1 </dev/null)"; IRC=$?
ok_if "un-shipped files listed exactly, whatever the locale (${loc_utf8:-C}, rc=$IRC)" '[ "$IRC" = 0 ] && [ "$(printf "%s\n" "$IOUT" | grep -c "does not ship")" = 3 ] && ! printf "%s" "$IOUT" | grep -qF "does not ship: .claude/hooks/baseline/VERSION" && [ ! -e "$IK/.claude/hooks/baseline/A.sh" ]'
[ -n "$loc_utf8" ] || echo "  note: no en_US UTF-8 locale here; the comm case ran under C only"
# An exclude file without a final newline gets the line on a line of its own.
IX="$TMP/inst-excl"; mkdir -p "$IX/.claude"; ( cd "$IX" && git init -q ); printf 'keep-me' > "$IX/.git/info/exclude"
printf '{"model": "x"}\n' > "$IX/.claude/settings.json"
inst "$IX"; ok_if "exclude line appended on its own line (rc=$IRC)" '[ "$IRC" = 0 ] && grep -qxF "keep-me" "$IX/.git/info/exclude" && grep -qxF "/.claude/settings.json.bak.*" "$IX/.git/info/exclude"'
# A target below a repo's top level: a backup is written, the parent repo's exclude is not.
IP="$TMP/inst-parent"; mkdir -p "$IP/sub/.claude"; ( cd "$IP" && git init -q ); cp "$IP/.git/info/exclude" "$TMP/inst-parent.excl"
printf '{"model": "x"}\n' > "$IP/sub/.claude/settings.json"
inst "$IP/sub"; ok_if "a sub-directory target leaves the parent repo's exclude alone (rc=$IRC)" '[ "$IRC" = 0 ] && [ "$(nbak "$IP/sub")" = 1 ] && cmp -s "$IP/.git/info/exclude" "$TMP/inst-parent.excl"'
# A .claude that is a link is refused before anything is written.
mkdir -p "$TMP/inst-out2"; IS="$TMP/inst-symclaude"; mkdir -p "$IS"; ( cd "$IS" && git init -q )
ln -s "$TMP/inst-out2" "$IS/.claude" 2>/dev/null
if [ ! -L "$IS/.claude" ] && command -v cygpath >/dev/null 2>&1; then
  rm -rf "$IS/.claude"
  MSYS_NO_PATHCONV=1 cmd /c mklink /J "$(cygpath -w "$IS/.claude")" "$(cygpath -w "$TMP/inst-out2")" >/dev/null 2>&1
fi
if [ -L "$IS/.claude" ]; then
  inst "$IS"; ok_if "a linked .claude is refused, nothing written through it (rc=$IRC)" '[ "$IRC" = 2 ] && printf "%s" "$IOUT" | grep -qF "is a symbolic link" && [ -z "$(ls -A "$TMP/inst-out2")" ]'
  rm -f "$IS/.claude"
else
  echo "  note: linked-.claude case not run (no symlink or junction could be made here)"
fi
# The installer refuses to delete a baseline source vendored inside the destination.
IV="$TMP/inst-vendored"; VS="$IV/.claude/hooks/baseline/src"; mkdir -p "$VS"; ( cd "$IV" && git init -q )
( cd "$SRC" && tar cf - install.sh lib hooks settings.template.json baseline.config.json baseline.config.schema.json examples ) | ( cd "$VS" && tar xf - )
IOUT="$(timeout -k 5 120 bash "$VS/install.sh" --target "$(winpath "$IV")" 2>&1 </dev/null)"; IRC=$?
ok_if "a source inside the destination is refused, nothing removed (rc=$IRC)" '[ "$IRC" = 2 ] && printf "%s" "$IOUT" | grep -qF "is inside" && [ -f "$VS/install.sh" ] && [ ! -e "$IV/.claude/settings.json" ]'
echo "== install.sh picks a Python that runs (B2) =="
# On Windows `python3` is usually the Store app execution alias, which is a stub when
# Python was not installed from the Store: it exits 9009 (49 to bash). The installer
# takes the interpreter the hooks will use (bcl_python: skips the alias unless it is
# all there is), launches it once, and refuses before writing anything unless it is
# Python 3.7+ — not fail later at the merge, nor succeed while the hooks cannot run.
REALPY="$(winpath "$("$PY" -c 'import sys; sys.stdout.write(sys.executable)')")"
[ -n "$REALPY" ] || { fail=$((fail + 1)); echo "  FAIL [cannot resolve a real interpreter for the B2 shims]"; }
PYSTUBLOG="$TMP/pystub.log"
PYT="$TMP/pytarget"
mkpy() {  # mkpy <dir> <name> stub|real|broken|old|noisy
  mkdir -p "$1"
  case "$3" in
    stub)   printf '#!/usr/bin/env bash\necho "%s" >> "%s"\necho "Python was not found; run without arguments to install from the Microsoft Store." >&2\nexit 49\n' "$2" "$PYSTUBLOG" > "$1/$2" ;;
    real)   printf '#!/usr/bin/env bash\nexec "%s" "$@"\n' "$REALPY" > "$1/$2" ;;
    broken) printf '#!/usr/bin/env bash\nexit 1\n' > "$1/$2" ;;
    old)    printf '#!/usr/bin/env bash\necho PYVER=3.6\n' > "$1/$2" ;;  # answers the version probe as 3.6
    noisy)  printf '#!/usr/bin/env bash\necho "startup banner"\nexec "%s" "$@"\n' "$REALPY" > "$1/$2" ;;
  esac
  chmod +x "$1/$2"
}
pyinstall() {  # pyinstall <PATH-prefix> — sets $pyout and $pyrc
  rm -rf "$PYT" "$PYSTUBLOG"; mkdir -p "$PYT"; ( cd "$PYT" && git init -q )
  pyout="$(PATH="$1:$PATH" timeout -k 5 120 bash "$SRC/install.sh" --target "$(winpath "$PYT")" 2>&1 </dev/null)"; pyrc=$?
}
# (a) Store stub first on PATH, a real `python` after it: installs, stub never launched.
mkpy "$TMP/py-a/WindowsApps" python3 stub; mkpy "$TMP/py-a/bin" python real
pyinstall "$TMP/py-a/WindowsApps:$TMP/py-a/bin"
if [ "$pyrc" = 0 ] && [ -f "$PYT/.claude/settings.json" ] && [ ! -e "$PYSTUBLOG" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [store stub skipped for a real python: rc=$pyrc stub-launched=$([ -e "$PYSTUBLOG" ] && echo yes || echo no)]"; fi
# (b) Only Store stubs: refuses with a clear message and writes nothing.
mkpy "$TMP/py-b/WindowsApps" python3 stub; mkpy "$TMP/py-b/WindowsApps" python stub
pyinstall "$TMP/py-b/WindowsApps"
if [ "$pyrc" = 1 ] && printf '%s' "$pyout" | grep -qF "no working Python 3" && printf '%s' "$pyout" | grep -qF "App execution aliases" \
   && ! printf '%s' "$pyout" | grep -qF "Fix the JSON error" && [ ! -e "$PYT/.claude" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [only store stubs must refuse before writing: rc=$pyrc]"; fi
# (c) The alias is the only interpreter but it runs (a Store-installed Python, or the
#     Python install manager's alias): used. Old code passes this too — it guards the
#     last-resort pass, so the alias skip can never lock out a working install.
mkpy "$TMP/py-c/WindowsApps" python3 real; mkpy "$TMP/py-c/WindowsApps" python stub
pyinstall "$TMP/py-c/WindowsApps"
if [ "$pyrc" = 0 ] && [ -f "$PYT/.claude/settings.json" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [a working store alias is a valid last resort: rc=$pyrc]"; fi
# (d) A python3 outside WindowsApps that does not run, a working python after it: the
#     hooks would run python3 and fail on every call, so the install refuses rather
#     than reporting success with the merge done by a different interpreter.
mkpy "$TMP/py-d/bin" python3 broken; mkpy "$TMP/py-d/bin" python real
pyinstall "$TMP/py-d/bin"
if [ "$pyrc" = 1 ] && printf '%s' "$pyout" | grep -qF "'python3' (" && printf '%s' "$pyout" | grep -qF "did not run" \
   && ! printf '%s' "$pyout" | grep -qF "Fix the JSON error" && [ ! -e "$PYT/.claude" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [a python3 the hooks cannot run must refuse before writing: rc=$pyrc]"; fi
# (e) The hooks' interpreter is older than 3.7 (the merge and the matcher need 3.7+): refused.
mkpy "$TMP/py-e/bin" python3 old; mkpy "$TMP/py-e/bin" python real
pyinstall "$TMP/py-e/bin"
if [ "$pyrc" = 1 ] && printf '%s' "$pyout" | grep -qF "is Python 3.6" && [ ! -e "$PYT/.claude" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [python older than 3.7 must refuse before writing: rc=$pyrc]"; fi
# (f) A Python that prints at startup: command-guard would read that output as a block
#     reason on every shell call, so refused — and reported as such, not "did not run".
mkpy "$TMP/py-f/bin" python3 noisy; mkpy "$TMP/py-f/bin" python real
pyinstall "$TMP/py-f/bin"
if [ "$pyrc" = 1 ] && printf '%s' "$pyout" | grep -qF "printed unexpected output" && [ ! -e "$PYT/.claude" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [a python that prints at startup must refuse, named as such: rc=$pyrc]"; fi

echo "== install.sh version check (R4) =="
# Stub a fake 'claude' on PATH (prepended, so it wins over any real CLI) and assert
# install.sh's advisory version check. --dry-run runs the check but changes nothing.
VBIN="$TMP/vbin"; mkdir -p "$VBIN"
VTARGET="$TMP/vtarget"
make_claude() {  # make_claude <version-string-or-"none">
  if [ "$1" = "none" ]; then printf '#!/usr/bin/env bash\necho "dev build"\n' > "$VBIN/claude"
  else printf '#!/usr/bin/env bash\necho "%s (Claude Code)"\n' "$1" > "$VBIN/claude"; fi
  chmod +x "$VBIN/claude"
}
# vcheck <desc> <fake-version|none> <expected-substring>
vcheck() {
  local desc="$1" ver="$2" want="$3" out
  rm -rf "$VTARGET"; mkdir -p "$VTARGET"; ( cd "$VTARGET" && git init -q )
  make_claude "$ver"
  out="$(PATH="$VBIN:$PATH" timeout -k 5 120 bash "$SRC/install.sh" --target "$(winpath "$VTARGET")" --dry-run 2>&1 </dev/null)"
  if printf '%s' "$out" | grep -qF "$want"; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [$desc] missing: $want"; fi
}
vcheck "old version warns"        "2.0.0" "is older than the baseline's required"
vcheck "patch below pin warns"    "2.1.294" "is older than the baseline's required"
vcheck "equal version ok"         "2.1.295" ">= required v"
vcheck "newer minor ok"           "2.9.0"  ">= required v"
# The warn/ok cases above would FAIL if the stub couldn't execute on this platform
# (they assert a version-specific path), so they prove the stub is invocable — which
# is what makes the "skip" assertion below meaningful rather than a false pass.
vcheck "unparseable version skips" "none"  "could not detect a 'claude' CLI"
# Marker anchoring (R4 review): a misleading leading semver on an earlier line must
# not win over the version tied to the '(Claude Code)' marker. Without anchoring the
# first-semver grep would pick 0.0.1 and warn; with anchoring it picks 2.1.295 and OKs.
printf '#!/usr/bin/env bash\necho "node v0.0.1 runtime"\necho "2.1.295 (Claude Code)"\n' > "$VBIN/claude"; chmod +x "$VBIN/claude"
rm -rf "$VTARGET"; mkdir -p "$VTARGET"; ( cd "$VTARGET" && git init -q )
out="$(PATH="$VBIN:$PATH" timeout -k 5 120 bash "$SRC/install.sh" --target "$(winpath "$VTARGET")" --dry-run 2>&1 </dev/null)"
if printf '%s' "$out" | grep -qF "Claude Code v2.1.295 detected"; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [marker anchoring picks Claude Code semver]"; fi

echo ""
echo "test_hooks: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
