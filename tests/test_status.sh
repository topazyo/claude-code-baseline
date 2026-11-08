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
# NOTE: these probes source the SOURCE tree's common.sh, which has no INSTALL_SCOPE
# marker, so it reads as a managed deployment: the managed keys (enforcement,
# failClosed, guardrails.*.enabled, modules.runTests.enabled) would come from defaults,
# not from repo A. fixTags and scopeGuard are not managed keys, so these stay valid.
# Do not add a managed-key probe here without setting _BCL_CFG_PER_REPO=1 after the
# source, as baseline-status.sh does.
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

echo "== baseline-status: settings findings (risky env, hook launch) =="
# The one detector outside Claude Code, so the shell a risky env value reaches cannot
# switch it off. A fresh install has no finding; a BASH_ENV and a disableAllHooks in
# settings.local.json, and a command-guard launched as plain `bash`, are reported and
# fail --strict.
OUT2="$(winpath "$TMP/out2.json")"
findings() {
  rm -f "$OUT2"   # a run that did not finish must not leave the previous report to be read
  timeout -k 5 60 bash "$STATUS" --json "$OUT2" "$A" >/dev/null 2>&1
  "$PY" -c "import json,sys; r=json.load(open(sys.argv[1],encoding='utf-8'))['repos'][0]; print(r['settingsEnvRisk'], r['hookLaunchProblems'])" "$OUT2" 2>&1
}
got="$(findings)"
[ "$got" = "[] []" ] && ok || no "fresh install should have no settings finding: $got"
cp "$A/.claude/settings.json" "$TMP/settings.saved"
printf '{"env": {"BASH_ENV": "/tmp/x.sh", "NODE_ENV": "production"}, "disableAllHooks": true}\n' > "$A/.claude/settings.local.json"
"$PY" -c "import json,sys
p=sys.argv[1]; s=json.load(open(p,encoding='utf-8'))
for g in s['hooks']['PreToolUse']:
    for h in g['hooks']:
        if 'command-guard.sh' in h['command']: h['command']=h['command'].replace('bash -p ','bash ',1)
json.dump(s,open(p,'w',encoding='utf-8'))" "$A/.claude/settings.json"
got="$(findings)"
[ "$got" = "['settings.local.json:BASH_ENV'] ['guardrails/command-guard.sh', 'settings.local.json disableAllHooks']" ] && ok || no "settings findings not reported: $got"
if timeout -k 5 60 bash "$STATUS" --strict "$A" >/dev/null 2>&1; then no "--strict should FAIL on a settings finding"; else ok; fi
cp "$TMP/settings.saved" "$A/.claude/settings.json"; rm -f "$A/.claude/settings.local.json"
# HOME pointed elsewhere moves the user's git config under the hooks' git.
printf '{"env": {"HOME": "/tmp/h"}}\n' > "$A/.claude/settings.local.json"
got="$(findings)"
[ "$got" = "['settings.local.json:HOME'] []" ] && ok || no "a HOME env value not reported: $got"
rm -f "$A/.claude/settings.local.json"
if timeout -k 5 60 bash "$STATUS" --strict "$A" >/dev/null 2>&1; then ok; else no "--strict should PASS once the settings are restored"; fi
# Where the template wires each hook: a command-guard group whose matcher no longer
# covers the template's is reported as such and fails --strict; a scope-guard that is
# not wired at all is reported once, by name, with no wiring entry beside it.
# rewire <python statement on the settings object s>
rewire() {
  "$PY" - "$A/.claude/settings.json" "$1" <<'PY'
import json, sys
p = sys.argv[1]
s = json.load(open(p, encoding="utf-8"))
exec(sys.argv[2])
json.dump(s, open(p, "w", encoding="utf-8"))
PY
}
rewire 's["hooks"]["PreToolUse"][0]["matcher"] = "Read"'
got="$(findings)"
[ "$got" = "[] ['guardrails/command-guard.sh not under PreToolUse Bash|PowerShell']" ] && ok || no "mis-wired matcher not reported: $got"
if timeout -k 5 60 bash "$STATUS" --strict "$A" >/dev/null 2>&1; then no "--strict should FAIL on a mis-wired matcher"; else ok; fi
cp "$TMP/settings.saved" "$A/.claude/settings.json"
# The same with the covering group running a longer script name (an exact launch of a
# script the template does not wire), so only the wiring check sees it.
rewire 'g = s["hooks"]["PreToolUse"][0]; s["hooks"]["PreToolUse"].append(dict(g, matcher="Read")); g["hooks"] = [dict(g["hooks"][0], command=g["hooks"][0]["command"].replace("command-guard.sh", "command-guard.sh.sh"))]'
got="$(findings)"
[ "$got" = "[] ['guardrails/command-guard.sh not under PreToolUse Bash|PowerShell']" ] && ok || no "longer script name in the covering group not reported: $got"
cp "$TMP/settings.saved" "$A/.claude/settings.json"
rewire 'g = s["hooks"]["PreToolUse"][0]; s["hooks"]["PreToolUse"].append(dict(g, matcher="Read")); g["hooks"] = [dict(g["hooks"][0], command=g["hooks"][0]["command"].replace("baseline/guardrails/", "baseline/x/.claude/hooks/baseline/guardrails/"))]'
got="$(findings)"
[ "$got" = "[] ['guardrails/command-guard.sh not under PreToolUse Bash|PowerShell']" ] && ok || no "repeated baseline path in the covering group not reported: $got"
cp "$TMP/settings.saved" "$A/.claude/settings.json"
rewire 's["hooks"]["PreToolUse"] = s["hooks"]["PreToolUse"][:1]'
got="$(findings)"
[ "$got" = "[] ['modules/scope-guard.sh']" ] && ok || no "unwired script not reported once: $got"
cp "$TMP/settings.saved" "$A/.claude/settings.json"
# A hook entry in settings.local.json that names a baseline script is reported (the
# installer never writes one there) and fails --strict; without it, nothing is.
printf '{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "bash -p \\"${CLAUDE_PROJECT_DIR}/.claude/hooks/baseline/guardrails/command-guard.sh\\"", "statusMessage": "x"}]}]}}\n' > "$A/.claude/settings.local.json"
got="$(findings)"
[ "$got" = "[] ['settings.local.json runs guardrails/command-guard.sh']" ] && ok || no "baseline hook in settings.local.json not reported: $got"
if timeout -k 5 60 bash "$STATUS" --strict "$A" >/dev/null 2>&1; then no "--strict should FAIL on a baseline hook in settings.local.json"; else ok; fi
printf '{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "bash ./scripts/team-lint.sh"}]}]}}\n' > "$A/.claude/settings.local.json"
got="$(findings)"
[ "$got" = "[] []" ] && ok || no "a repo's own hook in settings.local.json should not be reported: $got"
rm -f "$A/.claude/settings.local.json"
# A subagent or skill definition that names the baseline hook directory is reported and
# fails --strict; once removed, nothing is.
mkdir -p "$A/.claude/agents"
printf -- '---\nname: helper\ndescription: A helper.\n---\nSee /.claude/hooks/baseline/README.\n' > "$A/.claude/agents/helper.md"
got="$(findings)"
[ "$got" = "[] ['.claude/agents/helper.md names the baseline hook directory']" ] && ok || no "agent file naming the hook directory not reported: $got"
if timeout -k 5 60 bash "$STATUS" --strict "$A" >/dev/null 2>&1; then no "--strict should FAIL on an agent file naming the hook directory"; else ok; fi
printf -- '---\nname: helper\ndescription: A helper.\n---\nHelps.\n' > "$A/.claude/agents/helper.md"
got="$(findings)"
[ "$got" = "[] []" ] && ok || no "an ordinary agent file should not be reported: $got"
mkdir -p "$A/.claude/skills/x"
printf -- '---\nname: x\ndescription: A skill.\n---\nSee /.claude/hooks/baseline/README.\n' > "$A/.claude/skills/x/SKILL.md"
got="$(findings)"
[ "$got" = "[] ['.claude/skills/x/SKILL.md names the baseline hook directory']" ] && ok || no "skill file naming the hook directory not reported: $got"
rm -rf "$A/.claude/skills"
# a symlinked skill folder is followed, and a link back up is not walked twice (only where
# ln -s makes a real symlink: Linux and macOS). A relative target is read from the link's
# own folder, so nest/up -> .. is .claude/skills.
case "$(uname -s)" in Linux|Darwin)
  mkdir -p "$TMP/shared-skill" "$A/.claude/skills/nest"
  printf -- '---\nname: s\ndescription: A skill.\n---\nSee /.claude/hooks/baseline/README.\n' > "$TMP/shared-skill/SKILL.md"
  ln -s "$TMP/shared-skill" "$A/.claude/skills/shared"
  ln -s .. "$A/.claude/skills/nest/up"
  got="$(findings)"
  [ "$got" = "[] ['.claude/skills/shared/SKILL.md names the baseline hook directory']" ] && ok || no "symlinked skill folder not followed once: $got"
  rm -rf "$A/.claude/skills" "$TMP/shared-skill" ;;
esac
# a FIFO is not read (it would block). Exercised on Linux and macOS: Git Bash's mkfifo
# makes a file native Python sees as a regular .lnk file, so there it is only listed.
if mkfifo "$A/.claude/agents/pipe" 2>/dev/null; then
  got="$(findings)"
  [ "$got" = "[] []" ] && ok || no "a FIFO in .claude/agents should be skipped: $got"
fi
rm -rf "$A/.claude/agents"
# A PreToolUse guard entry without onFailure "block" is reported, as config-guard reports
# it, and fails --strict.
rewire 's["hooks"]["PreToolUse"][0]["hooks"][0]["onFailure"] = "continue"'
got="$(findings)"
[ "$got" = "[] ['guardrails/command-guard.sh without onFailure block']" ] && ok || no "guard without onFailure block not reported: $got"
if timeout -k 5 60 bash "$STATUS" --strict "$A" >/dev/null 2>&1; then no "--strict should FAIL on a guard without onFailure block"; else ok; fi
cp "$TMP/settings.saved" "$A/.claude/settings.json"
got="$(findings)"
[ "$got" = "[] []" ] && ok || no "restored settings should have no settings finding: $got"

echo "== baseline-status: the baseline deny-list in settings.json (M10) =="
# The same rule as config-guard (3): every template permissions.deny entry, by exact
# string, in settings.json as parsed (a duplicate key is last-wins, as in Claude Code).
TPL="$(winpath "$SRC/settings.template.json")"
# deny_check <python predicate over m (denyListMissing) and t (template deny)> <label>
deny_check() {
  rm -f "$OUT2"   # never read a report an earlier run left behind
  timeout -k 5 60 bash "$STATUS" --json "$OUT2" "$A" >/dev/null 2>&1
  if "$PY" -c "import json,sys
m=json.load(open(sys.argv[1],encoding='utf-8'))['repos'][0]['denyListMissing']
t=[d for d in json.load(open(sys.argv[2],encoding='utf-8'))['permissions']['deny'] if isinstance(d,str)]
sys.exit(0 if ($1) else 1)" "$OUT2" "$TPL"; then ok; else no "$2"; fi
}
strict_fails() { if timeout -k 5 60 bash "$STATUS" --strict "$A" >/dev/null 2>&1; then no "--strict should FAIL: $1"; else ok; fi; }
deny_check 'm == []' "fresh install: no deny entry missing"
case "$(timeout -k 5 60 bash "$STATUS" "$A" 2>&1)" in *"deny-list: ok"*) ok ;; *) no "fresh install: text report says deny-list ok" ;; esac
rewire 's["permissions"]["deny"] = []'
deny_check 'm == t and len(t) >= 30' "deny = [] lists every template entry, in template order"
case "$(timeout -k 5 60 bash "$STATUS" "$A" 2>&1)" in *"deny-list: baseline entries missing"*"Edit(.env*)"*) ok ;; *) no "text report names the missing entries" ;; esac
strict_fails "an empty deny-list"
cp "$TMP/settings.saved" "$A/.claude/settings.json"
rewire 's["permissions"]["deny"].remove("Edit(.claude/settings.json)")'
deny_check 'm == ["Edit(.claude/settings.json)"]' "one stripped entry is named exactly"
strict_fails "one stripped deny entry"
cp "$TMP/settings.saved" "$A/.claude/settings.json"
rewire 's["permissions"]["deny"] = [d for d in s["permissions"]["deny"] if "\\" not in d]'
deny_check 'm == [d for d in t if chr(92) in d] and m' "Windows-path entries come back byte-exact, backslashes and all"
cp "$TMP/settings.saved" "$A/.claude/settings.json"
"$PY" -c "import json,sys
p=sys.argv[1]; txt=json.dumps(json.load(open(p,encoding='utf-8')))
open(p,'w',encoding='utf-8').write(txt[:-1] + ', \"permissions\": {\"deny\": []}}')" "$(winpath "$A/.claude/settings.json")"
deny_check 'm == t' "a duplicate permissions key is read last-wins, as Claude Code reads it"
strict_fails "a stripped duplicate permissions key"
cp "$TMP/settings.saved" "$A/.claude/settings.json"
rewire 's["permissions"] = ["Edit(.env*)"]'
deny_check 'm == t' "permissions that is not an object holds no deny entry"
cp "$TMP/settings.saved" "$A/.claude/settings.json"
rewire 's["permissions"]["deny"].append("Read(./private/**)"); s["permissions"]["deny"].append(7)'
deny_check 'm == []' "a repo's own extra entries (and a non-string) beside the full list: nothing missing"
cp "$TMP/settings.saved" "$A/.claude/settings.json"
# No readable settings.json holds no deny entry: never reported as "ok".
rm -f "$A/.claude/settings.json"
deny_check 'm == t' "an absent settings.json is missing every entry"
case "$(timeout -k 5 60 bash "$STATUS" "$A" 2>&1)" in *"deny-list: ok"*) no "an absent settings.json must not read deny-list ok" ;; *) ok ;; esac
printf '{"permissions": {"deny": [' > "$A/.claude/settings.json"
deny_check 'm == t' "an unreadable settings.json is missing every entry"
cp "$TMP/settings.saved" "$A/.claude/settings.json"
# A deny check that cannot run is null in JSON, check-failed in the text, and fails
# --strict: a copy of the tool whose template has no deny-list to compare with.
CS="$TMP/src-nodeny"; mkdir -p "$CS"
cp -R "$SRC/tools" "$SRC/lib" "$SRC/hooks" "$CS/"
cp "$SRC/baseline.config.json" "$SRC/baseline.config.schema.json" "$CS/"
"$PY" -c "import json,sys;t=json.load(open(sys.argv[1],encoding='utf-8'));t['permissions'].pop('deny');json.dump(t,open(sys.argv[2],'w',encoding='utf-8'))" "$TPL" "$(winpath "$CS/settings.template.json")"
rm -f "$OUT2"
CSOUT="$(timeout -k 5 60 bash "$CS/tools/baseline-status.sh" --json "$OUT2" "$A" 2>&1)"
if "$PY" -c "import json,sys;r=json.load(open(sys.argv[1],encoding='utf-8'))['repos'][0];sys.exit(0 if r['denyListMissing'] is None and 'check-failed' in r['hookLaunchProblems'] else 1)" "$OUT2"; then ok; else no "a deny check that could not run is null in JSON"; fi
case "$CSOUT" in *"deny-list: check-failed"*) ok ;; *) no "a deny check that could not run says check-failed in the text" ;; esac
if timeout -k 5 60 bash "$CS/tools/baseline-status.sh" --strict "$A" >/dev/null 2>&1; then no "--strict should FAIL when the deny check could not run"; else ok; fi
# A check that exits 0 but prints only two fields (an older or broken copy) is a failed
# check, not an intact deny-list: a copy of the tool patched to drop the third field.
# The full template goes back first, whatever happens next: a patch that misses its
# anchor must FAIL here, not pass because the no-deny template still fails the check.
cp "$TPL" "$CS/settings.template.json"
"$PY" -c "import sys
p=sys.argv[1]; t=open(p,encoding='utf-8').read()
old=' + \"\\\\x1f\" + json.dumps(deny_missing))'
if t.count(old) != 1: sys.exit(1)
open(p,'w',encoding='utf-8',newline='\n').write(t.replace(old, ')'))" "$(winpath "$CS/tools/baseline-status.sh")" \
  || no "the two-field patch found its anchor in the copied tool"
rm -f "$OUT2"
timeout -k 5 60 bash "$CS/tools/baseline-status.sh" --json "$OUT2" "$A" >/dev/null 2>&1
if "$PY" -c "import json,sys;r=json.load(open(sys.argv[1],encoding='utf-8'))['repos'][0];sys.exit(0 if r['denyListMissing'] is None else 1)" "$OUT2"; then ok; else no "a two-field settings check reads as check-failed, never as an intact deny-list"; fi
got="$(findings)"
[ "$got" = "[] []" ] && ok || no "restored settings should have no settings finding after the deny cases: $got"

echo "== baseline-status: guardrails read as the hooks read them; unreadable config (L11/L13) =="
ACFG="$A/.claude/baseline.config.json"
cp "$ACFG" "$TMP/acfg.keep"
# autoFormat is opt-in (its hook reads it with bcl_guardrail_opted_in), commandGuard is
# default-on: with both keys absent only commandGuard is enabled.
"$PY" -c "import json;p=r'$ACFG';c=json.load(open(p));[c['guardrails'][g].pop('enabled',None) for g in ('autoFormat','commandGuard')];json.dump(c,open(p,'w'))"
OUT="$(winpath "$TMP/g.json")"
timeout -k 5 60 bash "$STATUS" --json "$OUT" "$A" >/dev/null 2>&1
if "$PY" -c "import json,sys;r=json.load(open(sys.argv[1],encoding='utf-8'))['repos'][0];g=r['enabledGuardrails'];sys.exit(0 if 'commandGuard' in g and 'autoFormat' not in g else 1)" "$OUT"; then ok; else no "absent enabled keys: commandGuard on, autoFormat off"; fi
# A config that exists but cannot be read: the hooks fail closed, so status must not
# show the defaults as the repo's posture, and --strict must fail.
printf '{ "enforcement": "block", }\n' > "$ACFG"
SOUT="$(timeout -k 5 60 bash "$STATUS" --json "$OUT" "$A" 2>&1)"
case "$SOUT" in *"baseline.config.json cannot be read (line 1 column"*) ok ;; *) no "unreadable config is reported with its parse error" ;; esac
if "$PY" -c "import json,sys;r=json.load(open(sys.argv[1],encoding='utf-8'))['repos'][0];sys.exit(0 if r['enforcement']=='unknown' and r['failClosed'] is None and not r['enabledGuardrails'] and 'baseline.config.json unreadable' in r['hookLaunchProblems'] else 1)" "$OUT"; then ok; else no "unreadable config: posture unknown, a finding, no guardrails claimed"; fi
if timeout -k 5 60 bash "$STATUS" --strict "$A" >/dev/null 2>&1; then no "--strict should FAIL on an unreadable config"; else ok; fi
cp "$TMP/acfg.keep" "$ACFG"

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
