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
trap 'rm -rf "$TMP"' EXIT
WT="$(winpath "$TMP")"     # Python/payload-facing form of the temp dir
cd "$WT" || exit 1
git init -q
git config user.email t@example.com; git config user.name tester
bash "$SRC/install.sh" --target "$WT" >/dev/null 2>&1
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
printf 'x = 1\n' > "$WT/app.py"; git add app.py; git commit -qm add
printf 'x = 1\ny = 2\n' > "$WT/app.py"   # untagged added line
setcfg "c['modules']['fixTags']['enabled']=True"
run "untagged change -> 2"   modules/fix-tags.sh "$(write_payload "$WT/app.py")" 2
resetcfg

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
# Properly-wired: real {type:command} hooks INVOKING all five baseline scripts.
wired = {"PreToolUse":[{"hooks":[c("guardrails/command-guard.sh"), c("modules/scope-guard.sh")]}],
         "PostToolUse":[{"hooks":[c("dispatcher/post-write.sh")]}],
         "Stop":[{"hooks":[c("modules/tracker-reminder.sh")]}],
         "ConfigChange":[{"hooks":[c("modules/config-guard.sh")]}]}
# config-guard's own wiring stripped (self-protection: disabling the tamper detector is tamper).
wired_no_cg = {"PreToolUse":[{"hooks":[c("guardrails/command-guard.sh"), c("modules/scope-guard.sh")]}],
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
PY
setcfg "c['modules']['configGuard']['enabled']=True"
run "clean settings -> 0"        modules/config-guard.sh "$(ccp project_settings "$GOOD")" 0
run "disableAllHooks=true -> 2"  modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_disable.json")" 2
run "disableAllHooks=1 -> 2"     modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_dah1.json")" 2
run "neutered hooks -> 2"        modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_unwired.json")" 2
run "config-guard unwired -> 2"  modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_nocg.json")" 2
run "deny removed -> 2"          modules/config-guard.sh "$(ccp project_settings "$TDIR/_t_denygone.json")" 2
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
import json, re, sys
src = sys.argv[1]
tmpl = json.load(open(src + "/settings.template.json", encoding="utf-8"))
guard = open(src + "/hooks/modules/config-guard.sh", encoding="utf-8").read()
def pylist(name):
    m = re.search(name + r" = \[(.*?)\]", guard, re.S)
    return re.findall(r'"([^"]+)"', m.group(1)) if m else []
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
bash "$SRC/install.sh" --target "$WT" >/dev/null 2>&1
if cmp -s "$CFG" "$WT/.claude/_precontract.json"; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [install.sh re-run clobbered an existing baseline.config.json]"; fi
# Marker freshness: the installed VERSION equals the source hooks/VERSION after a re-run
# (install.sh:107 cp -R recopies the hook subtree wholesale, so the marker is always truthful).
srcver="$(tr -d '\r\n' < "$SRC/hooks/VERSION" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
instver="$(tr -d '\r\n' < "$WT/.claude/hooks/baseline/VERSION" 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' || true)"
if [ -n "$srcver" ] && [ "$srcver" = "$instver" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [installed VERSION '$instver' != source '$srcver']"; fi
resetcfg
# Create-path stamp: a FRESH install prints the stamped baselineVersion in its output.
FRESH="$(winpath "$TMP/fresh")"; mkdir -p "$FRESH"; ( cd "$FRESH" && git init -q )
fout="$(bash "$SRC/install.sh" --target "$FRESH" 2>&1)"
if printf '%s' "$fout" | grep -qF "$srcver"; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [install create-path did not print baselineVersion $srcver]"; fi

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
  out="$(PATH="$VBIN:$PATH" bash "$SRC/install.sh" --target "$(winpath "$VTARGET")" --dry-run 2>&1)"
  if printf '%s' "$out" | grep -qF "$want"; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [$desc] missing: $want"; fi
}
vcheck "old version warns"        "2.0.0" "is older than the baseline's required"
vcheck "patch below pin warns"    "2.1.79" "is older than the baseline's required"
vcheck "equal version ok"         "2.1.80" ">= required v"
vcheck "newer minor ok"           "2.9.0"  ">= required v"
# The warn/ok cases above would FAIL if the stub couldn't execute on this platform
# (they assert a version-specific path), so they prove the stub is invocable — which
# is what makes the "skip" assertion below meaningful rather than a false pass.
vcheck "unparseable version skips" "none"  "could not detect a 'claude' CLI"
# Marker anchoring (R4 review): a misleading leading semver on an earlier line must
# not win over the version tied to the '(Claude Code)' marker. Without anchoring the
# first-semver grep would pick 0.0.1 and warn; with anchoring it picks 2.1.80 and OKs.
printf '#!/usr/bin/env bash\necho "node v0.0.1 runtime"\necho "2.1.80 (Claude Code)"\n' > "$VBIN/claude"; chmod +x "$VBIN/claude"
rm -rf "$VTARGET"; mkdir -p "$VTARGET"; ( cd "$VTARGET" && git init -q )
out="$(PATH="$VBIN:$PATH" bash "$SRC/install.sh" --target "$(winpath "$VTARGET")" --dry-run 2>&1)"
if printf '%s' "$out" | grep -qF "Claude Code v2.1.80 detected"; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  FAIL [marker anchoring picks Claude Code semver]"; fi

echo ""
echo "test_hooks: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
