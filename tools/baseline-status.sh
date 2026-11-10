#!/usr/bin/env bash
# claude-code-baseline :: tools/baseline-status.sh
#
# Read-only, local-only reporter for the baseline across one or more repos.
#
# Primary job (--drift): compare each repo's INSTALLED hook-version marker
# (.claude/hooks/baseline/VERSION) against THIS source tree's canonical
# baseline.config.json -> baselineVersion, so an org can see at a glance which
# repos are on an old baseline. Reconciliation is just a re-run of install.sh.
#
# The per-repo posture table (enforcement / enabled guardrails + modules) is a
# BYPRODUCT of the same per-repo read. It is resolved through the baseline's OWN
# config readers (hooks/lib/common.sh bcl_*), so it can never silently diverge
# from what the hooks actually enforce — there is exactly one notion of "enabled".
#
# It only READS on-disk files and shells out to python3/git for parsing. It makes
# no remote requests and writes nothing unless you pass --json <file>. See
# tools/README.md for the deferred one-liner signals and the design rationale.
#
# Usage:
#   tools/baseline-status.sh [--drift] [--strict] [--json <outfile>] <repo>...
#     --drift           (default view) report version drift + posture per repo.
#     --strict          exit non-zero if ANY installed repo has drifted from the
#                       source version, or has a settings finding (a risky env value,
#                       or a baseline hook not run, or not wired, as the template
#                       wires it, or a hook tree without its INSTALL_SCOPE marker).
#                       An un-installed repo does NOT trip this.
#     --json <outfile>  ALSO write the full per-repo report as JSON to <outfile>
#                       (the only filesystem write this tool ever performs).
#
# Requires: bash, python3 (or python).
set -uo pipefail

SRC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../hooks/lib/common.sh
source "$SRC_ROOT/hooks/lib/common.sh"
# This tool reports each repo's OWN install, read with the source tree's library, which
# carries no INSTALL_SCOPE marker and would otherwise read as a managed deployment and
# ignore the repo's posture keys (see _bcl_cfg_scope). Set after sourcing: common.sh
# unsets every _BCL_CFG_ name when it loads, so a hook can never inherit this.
_BCL_CFG_PER_REPO=1
# The source tree's own root, restored after reading a repo whose tree is read as managed.
SRC_CFG_ROOT="$_BCL_CFG_ROOT"

STRICT=0
JSON_OUT=""
REPOS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --drift)   shift ;;                      # default behaviour; accepted for clarity
    --strict)  STRICT=1; shift ;;
    # A missing or empty file name is a usage error: `shift 2` with one argument left
    # shifts nothing, and the loop would never end.
    --json)    [[ $# -ge 2 && -n "$2" ]] || { echo "--json needs a file name" >&2; exit 2; }
               JSON_OUT="$2"; shift 2 ;;
    --json=*)  JSON_OUT="${1#*=}"
               [[ -n "$JSON_OUT" ]] || { echo "--json needs a file name" >&2; exit 2; }
               shift ;;
    -h|--help) grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --)        shift; while [[ $# -gt 0 ]]; do REPOS+=("$1"); shift; done ;;
    -*)        echo "unknown option: $1" >&2; exit 2 ;;
    *)         REPOS+=("$1"); shift ;;
  esac
done

PY="$(bcl_python)"
[[ -z "$PY" ]] && { echo "python3 (or python) is required: $(bcl_nopy_reason)" >&2; exit 1; }
# A Python that is found but cannot run (or cannot import the stdlib modules used
# here) would make every config read fall back to its default, and the report would
# present those defaults as the repo's settings.
"$PY" -I -S -X utf8 -c 'import json, os, re, shlex, sys' >/dev/null 2>&1 </dev/null \
  || { echo "python ($PY) is on PATH but cannot run the baseline's helpers; cannot read any config" >&2; exit 1; }
# Only an interpreter the hooks accept (install.sh refuses the rest): on a Windows Python
# older than 3.8 os.path.realpath does not resolve a junction, so the definition scan
# below could not tell a junction loop from a tree; a Cygwin or MSYS Python reads the
# repo's Windows paths as POSIX paths.
PY_ANS="$(bcl_python_probe "$PY")"
if ! bcl_python_floor "$PY_ANS"; then
  case "$PY_ANS" in
    badout) echo "python ($PY) prints at startup; the baseline hooks read its output, so they refuse it" >&2 ;;
    norun)  echo "python ($PY) did not run" >&2 ;;
    *)      echo "python ($PY) is not one the baseline hooks accept: they need Python 3.7+, 3.8+ for a Windows Python, and never a Cygwin or MSYS one" >&2 ;;
  esac
  exit 1
fi
[[ ${#REPOS[@]} -eq 0 ]] && { echo "usage: baseline-status.sh [--drift] [--strict] [--json <file>] <repo>..." >&2; exit 2; }

# Read a top-level scalar key from the canonical SOURCE config (this tree).
read_src_key() {
  "$PY" -I -S -X utf8 - "$SRC_ROOT/baseline.config.json" "$1" <<'PY'
import json, sys
try:
    print(json.load(open(sys.argv[1], encoding="utf-8")).get(sys.argv[2], "") or "")
except Exception:
    print("")
PY
}
SRC_VER="$(read_src_key baselineVersion)"
SRC_MIN="$(read_src_key minClaudeCodeVersion)"

# settings_check <repo> -> "<env findings>\x1f<launch findings>\x1f<deny missing>"; the
# first two comma-separated, the third a JSON list of the template's permissions.deny
# entries settings.json lacks (exact strings, as config-guard (3); [] when none).
# env: keys of the repo's settings.json / settings.local.json `env` that can run code
# before the baseline hooks, redirect them or switch them off. launch: baseline scripts
# the template wires that settings.json does not run exactly as `bash -p <script>`
# with the template's keys, a guard a PreToolUse entry runs without onFailure "block"
# ("<script> without onFailure block"), or a script it does not wire under the
# template's event in a group whose matcher covers the template's, with no `if`
# ("<script> not under <event> [<matcher>]"), a hook entry in settings.local.json that
# names a baseline script in its command or args ("settings.local.json runs <script>";
# the installer never writes one there), a file under .claude/agents/, .claude/skills/ or
# .claude/commands/
# that names the baseline hook directory ("<path> names the baseline hook directory",
# or "<path> unreadable"; scope-guard refuses every Claude write there), and a disableAllHooks in
# either file.
# The env list is the installer's; the launch rules follow config-guard's, applied to
# every entry naming a baseline path (both through lib/merge_settings.py). This tool
# runs outside Claude Code, so unlike config-guard it is not started by the shell
# those values reach.
settings_check() {
  "$PY" -I -S -X utf8 - "$SRC_ROOT" "$1" <<'PY'
import contextlib, io, os, sys
src, repo = sys.argv[1], sys.argv[2]
sys.dont_write_bytecode = True   # importing lib/merge_settings.py must not write into the source tree
sys.path.insert(0, os.path.join(src, "lib"))
import merge_settings as ms

def read(path):
    with contextlib.redirect_stderr(io.StringIO()):   # ms.load reports on stderr
        try:
            return ms.load(path, "settings")
        except SystemExit:
            return None

def name(text):
    # ascii()-escaped, commas too: a key name cannot shift the report's fields. Capped.
    t = ascii(text)[1:-1].replace(",", "\\x2c")
    return t if len(t) <= 200 else t[:200] + "..."

template = ms.strip_comments(read(os.path.join(src, "settings.template.json")) or {})
mins, wiring = ms.baseline_timeouts(template), ms.baseline_wiring(template)
guards = ms.baseline_blocking(template)
expected_deny = ms.baseline_deny(template)
if not mins or not wiring or not guards or not expected_deny:   # nothing to compare with: the check could not run
    sys.exit("settings.template.json unreadable, or wires no baseline hook, or has no deny-list")
env, launch, deny_missing = [], set(), []
for fname in ("settings.json", "settings.local.json"):
    path = os.path.join(repo, ".claude", fname)
    # No readable settings.json holds no deny entry: every one is missing, as config-guard
    # (3) finds none in a file it cannot read — never an "ok" for a check that saw nothing.
    if not os.path.exists(path):
        if fname == "settings.json":
            launch.add("no settings.json")
            deny_missing = list(expected_deny)
        continue
    data = read(path)
    if not isinstance(data, dict):
        env.append(fname + ":unreadable")
        if fname == "settings.json":
            launch.add("settings.json unreadable")
            deny_missing = list(expected_deny)
        continue
    env += [fname + ":" + name(k) for k in ms.risky_env_keys(data)]
    if ms.disables_all_hooks(data):
        launch.add(fname + " disableAllHooks")   # same reading as config-guard (1)
    if fname == "settings.json":
        # The baseline deny-list (secrets + self-protection) lives here: config-guard (3).
        deny_missing = ms.missing_deny(data, expected_deny)
        launch |= {name(s) for s in ms.baseline_launch_problems(data, mins)}
        launch |= {name(s + " without onFailure block") for s in ms.baseline_soft_guards(data, guards)}   # config-guard (2b)
        unlaunched = set(mins) - ms.baseline_launches(data, mins)
        launch |= unlaunched
        # where the template wires it; a script not launched at all is reported once, above
        launch |= {name("%s not under %s%s" % (s, ev, " " + m if m else ""))
                   for s, ev, m in ms.baseline_wiring_problems(data, wiring) if s not in unlaunched}
    else:   # the installer never writes a baseline hook here: config-guard (5)
        launch |= {name(fname + " runs " + s) for s in ms.baseline_hook_names(data)}
# subagent, skill and command definitions in the repo (.claude/agents/, .claude/skills/,
# .claude/commands/) that name the baseline hook directory; scope-guard refuses every
# Claude write there, so one is a human's. Regular files
# only (a FIFO would block the read); each is read in full, in chunks. A file or
# folder that cannot be read is reported, not skipped. Symlinked folders are followed,
# each real folder once; each of the two folders is scanned up to 5000 files and 256 MiB,
# beyond which it is reported as not fully scanned.
import stat
marker = ms.BASELINE_MARKER.encode()
def names_marker(path):
    tail = b""
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                return False
            if marker in tail + chunk:
                return True
            tail = chunk[-(len(marker) - 1):]
def rel(path):
    return os.path.relpath(path, repo).replace(os.sep, "/")
for sub in ("agents", "skills", "commands"):
    walk_errors, seen_dirs = [], set()
    files_left, bytes_left = 5000, 256 << 20
    for dirpath, dirs, files in os.walk(os.path.join(repo, ".claude", sub), onerror=walk_errors.append,
                                        followlinks=True):
        real = os.path.realpath(dirpath)
        if real in seen_dirs:
            dirs[:] = []
            continue
        seen_dirs.add(real)
        if files_left <= 0 or bytes_left <= 0:
            launch.add(name(".claude/" + sub + " scan incomplete"))
            break
        for fn in files:
            path = os.path.join(dirpath, fn)
            try:
                st = os.stat(path)
                if not stat.S_ISREG(st.st_mode):
                    continue
                files_left, bytes_left = files_left - 1, bytes_left - st.st_size
                if names_marker(path):
                    launch.add(name(rel(path) + " names the baseline hook directory"))
            except OSError:
                launch.add(name(rel(path) + " unreadable"))
    for err in walk_errors:
        if getattr(err, "filename", None) and os.path.exists(err.filename):
            launch.add(name(rel(err.filename) + " unreadable"))
# The deny field is JSON (ensure_ascii: no tab, \x1f or newline can appear in it), so the
# entries reach --json exactly as the template spells them, backslashes included.
import json
print(",".join(env) + "\x1f" + ",".join(sorted(launch)) + "\x1f" + json.dumps(deny_missing))
PY
}

GUARDRAILS=(commandGuard autoFormat)
MODULES=(securityDefaults fixTags scopeGuard configGuard runTests trackerReminder autoStage)

RECORDS=""
any_drift=0
any_settings=0

echo "baseline status — source baselineVersion: ${SRC_VER:-<unset>}  (min Claude Code pin: ${SRC_MIN:-<unset>})"
echo

for repo in "${REPOS[@]}"; do
  installed=0; enf=""; fc=""; guards=""; mods=""; minver=""; minok=0; instver=""; drift="not-installed"
  envrisk=""; launch=""; denymiss=""; cfg_bad=""; unmarked=0; cfg_bad_file=""
  hooks_dir="$repo/.claude/hooks/baseline"
  ver_file="$hooks_dir/VERSION"

  if [[ -d "$hooks_dir" ]]; then
    installed=1
    export CLAUDE_PROJECT_DIR="$repo"
    # install.sh marks the tree it copies with INSTALL_SCOPE. Hooks that look for the
    # marker and do not find it run as a managed tree: enforcement, failClosed and the
    # guardrail and runTests switches come from managed.config.json beside them (safe defaults
    # without one), not from this repo's config. Read such a tree the way its hooks do,
    # so the posture below is what they enforce. A tree from before the marker existed
    # has neither the marker nor the code that reads it and follows the repo's config;
    # the version drift below already reports it.
    # The hooks take their tree as lib/.. of the common.sh they source, so a linked lib/
    # decides it; read the same path.
    scope_root="$hooks_dir/lib/.."
    if [[ ! -f "$scope_root/INSTALL_SCOPE" ]] && grep -qF "_bcl_cfg_scope() {" "$hooks_dir/lib/common.sh" 2>/dev/null; then
      unmarked=1
      _BCL_CFG_PER_REPO=""; _BCL_CFG_ROOT="$scope_root"
    fi
    # A config that exists but cannot be read makes the hooks fail closed, so its
    # defaults are not the repo's posture: report "unknown" and a finding instead.
    cfg_bad=""
    if bcl_config_malformed; then
      cfg_bad="${_BCL_CFG_ERROR:-unreadable}"
      if [[ "$_BCL_CFG_BAD_FILE" == managed ]]; then cfg_bad_file="managed.config.json"; else cfg_bad_file="baseline.config.json"; fi
    fi
    if [[ -n "$cfg_bad" ]]; then
      enf="unknown"; fc="unknown"; minver="unknown"
    else
      enf="$(bcl_posture)"
      fc="$(bcl_cfg failClosed true)"
      minver="$(bcl_cfg minClaudeCodeVersion "")"
      # autoFormat runs repo code, so its hook reads it opt-in (default off); report it
      # with the same reader. commandGuard is default-on.
      for g in "${GUARDRAILS[@]}"; do
        if [[ "$g" == autoFormat ]]; then
          bcl_guardrail_opted_in "$g" && guards="${guards:+$guards,}$g"
        else
          bcl_guardrail_enabled "$g" && guards="${guards:+$guards,}$g"
        fi
      done
      for m in "${MODULES[@]}"; do bcl_module_enabled "$m" && mods="${mods:+$mods,}$m"; done
    fi
    _BCL_CFG_PER_REPO=1; _BCL_CFG_ROOT="$SRC_CFG_ROOT"
    [[ -n "$minver" && "$minver" == "$SRC_MIN" ]] && minok=1 || minok=0
    if [[ -f "$ver_file" ]]; then
      instver="$(tr -d '\r\n' < "$ver_file" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    fi
    if   [[ -z "$instver" ]]; then drift="no-version"
    elif [[ -z "$SRC_VER" ]];  then drift="no-source-version"
    elif [[ "$instver" == "$SRC_VER" ]]; then drift="OK"
    else drift="DRIFT"; fi
    [[ "$drift" != "OK" ]] && any_drift=1
    # A check that could not run is a finding, never a clean report.
    # \x1f, not a tab: read collapses a leading tab, which would shift an empty env
    # field's neighbour into it.
    # Three fields; fewer separators means the check did not finish, and an absent deny
    # field must not read as an intact deny-list.
    sc="$(settings_check "$repo")" || sc=$'check-failed\x1fcheck-failed\x1fcheck-failed'
    sc="${sc//$'\r'/}"   # Windows Python print() emits CRLF
    [[ "$sc" == *$'\x1f'*$'\x1f'* ]] || sc=$'check-failed\x1fcheck-failed\x1fcheck-failed'
    IFS=$'\x1f' read -r envrisk launch denymiss <<< "$sc"
    [[ -n "$cfg_bad" ]] && launch="${launch:+$launch,}$cfg_bad_file unreadable"
    # No commas in a finding: the JSON report splits this list on them.
    [[ $unmarked -eq 1 ]] && launch="${launch:+$launch,}no INSTALL_SCOPE marker (hooks run as a managed tree)"
    [[ -n "$envrisk$launch" ]] && any_settings=1
    [[ "$denymiss" == "[]" ]] || any_settings=1
  fi

  # Human-readable per-repo block (the report; --json is the machine form).
  echo "$repo"
  if [[ $installed -eq 1 ]]; then
    echo "  installed=yes  posture=$enf  failClosed=$fc  version=${instver:-<none>}  drift=$drift"
    if [[ $unmarked -eq 1 ]]; then
      if [[ -f "$scope_root/managed.config.json" ]]; then
        echo "  .claude/hooks/baseline has no INSTALL_SCOPE marker: its hooks run as a managed tree and take enforcement, failClosed and the guardrail and runTests switches from the managed.config.json beside them, not from this repo's baseline.config.json (this report shows the posture they read). Re-run install.sh."
      else
        echo "  .claude/hooks/baseline has no INSTALL_SCOPE marker: its hooks run as a managed tree and use the safe defaults for enforcement, failClosed and the guardrail and runTests switches, not this repo's baseline.config.json (this report shows the posture they read). Re-run install.sh."
      fi
    fi
    if [[ -n "$cfg_bad" ]]; then
      echo "  $cfg_bad_file cannot be read ($cfg_bad): the hooks fail closed until a human fixes or deletes it"
    fi
    echo "  minClaudeCodeVersion=${minver:-<none>}  (canonical $SRC_MIN, ok=$([[ $minok -eq 1 ]] && echo yes || echo no))"
    if [[ -n "$cfg_bad" ]]; then
      echo "  guardrails: unknown   modules: unknown"
    else
      echo "  guardrails: ${guards:-<none>}   modules: ${mods:-<none>}"
    fi
    echo "  settings: risky env=${envrisk:-none}   hook wiring=${launch:-ok}"
    case "$denymiss" in
      "[]") echo "  deny-list: ok (every baseline entry present in settings.json)" ;;
      "check-failed") echo "  deny-list: check-failed" ;;
      *) echo "  deny-list: baseline entries missing from settings.json permissions.deny: $denymiss" ;;
    esac
  else
    echo "  installed=no   (no .claude/hooks/baseline/ — baseline not adopted here)"
  fi
  echo

  RECORDS+="$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' \
    "$repo" "$installed" "$enf" "$fc" "$guards" "$mods" "$minver" "$minok" "$instver" "$drift" \
    "$envrisk" "$launch" "$denymiss")"$'\n'
done

if [[ -n "$JSON_OUT" ]]; then
  # NOTE: use `-c <code>` (code as an argument), NOT `python - <<HEREDOC`, because the
  # records arrive on STDIN via the pipe — a heredoc would itself claim stdin and the
  # piped records would never be read. (Same pattern as common.sh's bcl_extract_*.)
  printf '%s' "$RECORDS" | "$PY" -I -S -X utf8 -c '
import json, sys
srcver, srcmin, out = sys.argv[1], sys.argv[2], sys.argv[3]
recs = []
for line in sys.stdin.read().splitlines():
    if not line:
        continue
    f = line.split("\t")
    while len(f) < 13:
        f.append("")
    repo, installed, enf, fc, guards, mods, minver, minok, instver, drift, envrisk, launch, denymiss = f[:13]
    # Not installed: nothing to check ([]). A check that did not run: null, and its
    # hookLaunchProblems already say check-failed.
    try:
        deny_missing = json.loads(denymiss) if denymiss else []
    except ValueError:
        deny_missing = None
    recs.append({
        "repo": repo,
        "installed": installed == "1",
        "enforcement": enf or None,
        "failClosed": (fc == "true") if fc in ("true", "false") else None,
        "enabledGuardrails": [x for x in guards.split(",") if x],
        "enabledModules": [x for x in mods.split(",") if x],
        "minClaudeCodeVersion": minver or None,
        "minVersionOk": minok == "1",
        "baselineVersion": instver or None,
        "drift": drift,
        "settingsEnvRisk": [x for x in envrisk.split(",") if x],
        "hookLaunchProblems": [x for x in launch.split(",") if x],
        "denyListMissing": deny_missing,
    })
with open(out, "w", encoding="utf-8") as fh:
    json.dump({"sourceBaselineVersion": srcver or None,
               "sourceMinClaudeCodeVersion": srcmin or None,
               "repos": recs}, fh, indent=2)
    fh.write("\n")
' "$SRC_VER" "$SRC_MIN" "$JSON_OUT"
  echo "wrote JSON report: $JSON_OUT"
fi

if [[ $STRICT -eq 1 && $any_drift -eq 1 ]]; then
  echo "drift detected (--strict): one or more installed repos are not on baselineVersion ${SRC_VER:-<unset>}" >&2
  exit 1
fi
if [[ $STRICT -eq 1 && $any_settings -eq 1 ]]; then
  echo "settings findings (--strict): one or more installed repos lack baseline deny-list entries in settings.json, or set a risky env value, or do not run the baseline hooks as the template wires them (bash -p, its keys, onFailure block on the guards, its event and matcher, no disableAllHooks), or keep a subagent or skill definition naming the baseline hook directory, or have a baseline.config.json (or, beside a hook tree without its INSTALL_SCOPE marker, a managed.config.json) that cannot be read, or have a hook tree without that marker" >&2
  exit 1
fi
exit 0
