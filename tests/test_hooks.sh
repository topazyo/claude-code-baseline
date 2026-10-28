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

echo "== fix-tags (PostToolUse) =="
printf 'x = 1\n' > "$WT/app.py"; git add app.py; git commit -qm add </dev/null
printf 'x = 1\ny = 2\n' > "$WT/app.py"   # untagged added line
setcfg "c['modules']['fixTags']['enabled']=True"
run "untagged change -> 2"   modules/fix-tags.sh "$(write_payload "$WT/app.py")" 2
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
def c(p): return {"type":"command","command":"bash ${CLAUDE_PROJECT_DIR}/.claude/hooks/baseline/" + p}
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
run "non-object json -> 2"       modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_list.json")" 2
run "missing settings -> 2"      modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_nope.json")" 2
run "non-watched source -> 0"    modules/config-guard.sh "$(ccp user_settings "$GOOD")" 0
run "no source -> 2"             modules/config-guard.sh '{"foo":"bar"}' 2
run "unparseable -> 2"           modules/config-guard.sh '{ not json' 2
setcfg "c['enforcement']='warn'"
run "tamper+warn -> 0"           modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_disable.json")" 0
resetcfg
run "disabled module -> 0"       modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_disable.json")" 0
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
def pylist(name):
    # Parse the literal rather than scraping the source text between quotes. An entry
    # containing a backslash — the Windows path forms among the PowerShell deny rules —
    # is written "\\" in the source but denotes ONE backslash, so a regex scrape
    # reports drift between two files that actually agree. (Writing a single backslash
    # in the source to satisfy the scrape would be worse: "\\baseline" as one
    # backslash is the escape \\b, a backspace.)
    m = re.search(name + r" = (\[.*?\])", guard, re.S)
    return list(ast.literal_eval(m.group(1))) if m else []
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
raise SystemExit(0 if deny_ok and hooks_ok else 1)
PY
then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [coupling drift: settings.template.json vs config-guard EXPECTED_DENY / REQUIRED_HOOK_CMDS]"; fi
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
# (install.sh:107 cp -R recopies the hook subtree wholesale, so the marker is always truthful).
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
if any('retired.sh' in x.get('command','') for x in allh): bad.append('retired baseline hook kept')
empty=[(ev,g.get('matcher')) for ev,g in grps if not g['hooks']]
if empty!=[('PostToolUse','Write')]: bad.append('empty groups %r' % (empty,))
if s.get('model')!='keep-me': bad.append('model changed')
sys.stdout.write('; '.join(bad) or 'ok')" "$(winpath "$MG/.claude/settings.json")" 2>&1)"
if [ "$mk" = "ok" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [merge-keep: $mk]"; fi
cp "$MG/.claude/settings.json" "$TMP/mergekeep.first.json"
timeout -k 5 120 bash "$SRC/install.sh" --target "$(winpath "$MG")" >/dev/null 2>&1 </dev/null
if cmp -s "$MG/.claude/settings.json" "$TMP/mergekeep.first.json"; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [merge-keep re-run changed settings.json]"; fi

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
