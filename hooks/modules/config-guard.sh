#!/usr/bin/env bash
# claude-code-baseline :: modules/config-guard.sh
#
# ConfigChange module. Fires when Claude Code detects a change to a settings file
# DURING a session. This is the in-session tamper-detection control: it catches a
# repo-controlled .claude/settings.json being edited to strip out the baseline
# hooks, remove the deny-list, or set disableAllHooks — the CVE-2025-59536 vector —
# including HUMAN/external edits the agent-only deny-list cannot see.
#
# Scope (deliberate): it watches `project_settings` (.claude/settings.json), where
# the baseline's own footprint lives. ConfigChange's domain is Claude Code SETTINGS
# files (source ∈ user_settings|project_settings|local_settings|policy_settings|
# skills) — NOT arbitrary files, so it does NOT fire for .claude/baseline.config.json
# or .claude/hooks/baseline/** (those stay protected against the agent by the
# permissions deny-list; non-overridable human/external coverage is R6's managed
# settings). user_settings/local_settings are per-developer/out-of-repo and are
# left to R6 as well.
#
# Config (baseline.config.json):
#   "modules": { "configGuard": { "enabled": true } }
#
# Posture: under "block", a detected tamper exits 2 (Claude Code rejects the change
# for the session); under "warn", it reports and exits 0. Off by default.
#
# Payload (ConfigChange, on stdin): { "source": "project_settings",
#   "file_path": "<changed settings file>" }  (file_path is optional).

set -uo pipefail

# ${BASH_SOURCE[0]%/*} rather than $(dirname ...): dirname is an external binary
# under Git Bash and a fork measures ~21ms here — paid by every hook, on every tool call.
HERE="${BASH_SOURCE[0]%/*}"
[[ "$HERE" == "${BASH_SOURCE[0]}" ]] && HERE=.
HERE="$(cd "$HERE" && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"

# Opt-in: off unless the org enabled it. NOTE: this gate needs Python to read the
# config, so on a host with NO Python this module is inert (config unreadable =>
# treated as disabled), like every other opt-in module. The no-Python case is
# covered elsewhere: the always-on command-guard guardrail fails closed without
# Python, and the secrets/tamper deny-list is a permission rule (no Python needed).
# Read stdin BEFORE the enable-gate, then prime once from what we read: the gate
# needs the config and priming needs the payload, and doing them separately would
# cost two interpreter starts. Acting on a read failure is deferred until after the
# gate so a repo that disabled configGuard still exits 0 rather than being blocked.
read_rc=0
bcl_read_payload PAYLOAD || read_rc=1

# ONE interpreter for the config, the payload state, and both payload fields this
# module extracts. That is 5 interpreter starts down to 2 — this prime, plus the
# settings integrity check below, which is the only one doing real work.
bcl_prime "$PAYLOAD"

bcl_module_enabled configGuard || exit 0

# Reaching here means the module is enabled, which required Python above. Resolve it
# for the integrity check; if it somehow went missing, fail closed rather than skip.
PY="$(bcl_python)"
if [[ -z "$PY" ]]; then
  echo "[config-guard] CONTROL COULD NOT RUN — Python unavailable; the settings change was NOT integrity-checked." >&2
  bcl_failclosed_exit; exit $?
fi

# Could not read stdin at all: distinct from both "empty" and "unparseable", and
# reported separately so the cause stays diagnosable. `cat` used to block until EOF,
# so this hook ran until Claude Code killed it — and a killed hook never reaches the
# fail-closed branches at all, meaning the tamper check silently did not run.
if [[ $read_rc -ne 0 ]]; then
  echo "[config-guard] CONTROL COULD NOT RUN — could not read the ConfigChange payload from stdin: $BCL_READ_ERROR; the change was NOT integrity-checked." >&2
  bcl_failclosed_exit; exit $?
fi

# Empty payload => nothing to inspect (consistent with the other guards). A
# present-but-unparseable payload IS a "control could not read its input" state.
[[ -z "${PAYLOAD//[[:space:]]/}" ]] && exit 0
if bcl_payload_unparseable "$PAYLOAD"; then
  echo "[config-guard] CONTROL COULD NOT RUN — ConfigChange payload unparseable; the change was NOT integrity-checked." >&2
  bcl_failclosed_exit; exit $?
fi

SOURCE="$(bcl_extract_value "$PAYLOAD" source)"
case "$SOURCE" in
  project_settings) : ;;
  "")
    # Parseable payload with no 'source' — we cannot tell what changed.
    echo "[config-guard] CONTROL COULD NOT RUN — ConfigChange payload had no 'source'; the change was NOT integrity-checked." >&2
    bcl_failclosed_exit; exit $?
    ;;
  *)
    # A settings source the baseline does not manage (user/local/policy/skills).
    exit 0
    ;;
esac

FILE_PATH="$(bcl_extract_value "$PAYLOAD" file_path)"
if [[ -n "$FILE_PATH" ]]; then
  SETTINGS_FILE="$FILE_PATH"
else
  SETTINGS_FILE="$(bcl_repo_root)/.claude/settings.json"
fi
case "$SETTINGS_FILE" in /*|?:*) : ;; *) SETTINGS_FILE="$(bcl_repo_root)/$SETTINGS_FILE" ;; esac

OUT="$("$PY" -I -S -X utf8 - "$SETTINGS_FILE" <<'PY'
import json, re, sys

settings_file = sys.argv[1]

# Baseline-managed permissions.deny entries. These MIRROR settings.template.json;
# a change there must change this list too (a test asserts the two agree, and
# tests/policy-change-gate.sh requires a fixture update when either side moves).
# This is an EXACT-STRING membership check on the baseline-owned entries — it does
# not normalize globs (a semantically-equal but textually-different rewrite reads as
# "removed") and does not inspect permissions.allow (allow-shadowing is mitigated by
# the version pin: since v2.1.77 a hook's allow no longer bypasses deny).
EXPECTED_DENY = [
    "Edit(.env*)",
    "Read(.env*)",
    "Edit(**/secrets/**)",
    "Read(**/secrets/**)",
    "Edit(.claude/baseline.config.json)",
    "Edit(.claude/settings.json)",
    "Edit(.claude/settings.local.json)",
    "Edit(.claude/hooks/baseline/**)",
    "Bash(*.claude/baseline.config.json*)",
    "Bash(*.claude/settings.json*)",
    "Bash(*.claude/settings.local.json*)",
    "Bash(*.claude/hooks/baseline/*)",
    "PowerShell(*.claude/baseline.config.json*)",
    "PowerShell(*.claude\\baseline.config.json*)",
    "PowerShell(*.claude/settings.json*)",
    "PowerShell(*.claude\\settings.json*)",
    "PowerShell(*.claude/settings.local.json*)",
    "PowerShell(*.claude\\settings.local.json*)",
    "PowerShell(*.claude/hooks/baseline/*)",
    "PowerShell(*.claude\\hooks\\baseline\\*)",
    "PowerShell(Remove-Item *)",
    "PowerShell(rm *)",
    "PowerShell(rm.exe *)",
    "PowerShell(del *)",
    "PowerShell(rmdir *)",
    "PowerShell(Invoke-WebRequest *)",
    "PowerShell(iwr *)",
    "PowerShell(Invoke-RestMethod *)",
    "PowerShell(irm *)",
    "PowerShell(curl *)",
    "PowerShell(curl.exe *)",
    "PowerShell(wget *)",
    "PowerShell(wget.exe *)",
    "PowerShell(Invoke-Expression *)",
    "PowerShell(iex *)",
    "PowerShell(git push*--force*)",
    "PowerShell(git.exe push*--force*)",
]
# Every script the baseline wires must remain wired as a real command hook —
# including config-guard itself (self-protection: stripping the tamper detector is
# tamper). MIRRORS settings.template.json; a test asserts the two agree. The check
# (below) is launcher-anchored — a command must actually `bash` the script, so an
# entry that merely MENTIONS the path (echo / a comment) does not satisfy it.
REQUIRED_HOOK_CMDS = [
    "guardrails/command-guard.sh",
    "modules/scope-guard.sh",
    "dispatcher/post-write.sh",
    "modules/tracker-reminder.sh",
    "modules/config-guard.sh",
]
# Environment values a project settings `env` block must not set, whatever the value:
# each can run code before a baseline hook, redirect it, or switch it off. MIRRORED in
# lib/merge_settings.py (install.sh and tools/baseline-status.sh report them); a test
# asserts the two agree. Names are compared upper-cased (Windows names are not
# case-sensitive).
#   BASH_ENV SHELLOPTS BASHOPTS POSIXLY_CORRECT BASH_COMPAT, BASH_FUNC_ anywhere in a
#       name: bash startup. The hooks run as `bash -p`, which ignores the first three
#       and exported functions, but the shell Claude Code runs the hook command string
#       in comes first (bash by default per the hooks docs; its exact argv is not
#       documented), and no hook can protect it. Function-export encodings vary, hence
#       "anywhere".
#   FUNCNEST EXECIGNORE CDPATH GLOBIGNORE   honoured even under -p (bash 3.2's -p keeps
#                              the last two). common.sh drops them; an install from
#                              before that does not.
#   CLAUDE_CODE_SHELL_PREFIX   wraps every hook command; CLAUDE_CODE_GIT_BASH_PATH picks
#                              the Windows shell that runs it (set it outside the repo).
#   PATH                       which bash / python / git / timeout run (even empty: then
#                              the hook command finds no bash at all).
#   LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT DYLD_*   code loaded into every process.
#   CLAUDE_PROJECT_DIR         which scripts the hook commands run and which config they read.
#   GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR GIT_CEILING_DIRECTORIES
#   GIT_EXEC_PATH GIT_EXTERNAL_DIFF GIT_CONFIG_*   what the git calls in fix-tags,
#                              auto-stage and tracker-reminder see.
#   BCL_* _BCL_*               the baseline's own names: posture comes from the config only.
# Not listed: PYTHON*. The baseline's own interpreter runs -I -S, which ignores them; the
# repo's own test runs (run-tests) are meant to see them. ENV: only an interactive POSIX
# shell reads it, none runs here, and it is a common application variable.
RISKY_ENV_NAMES = ["BASH_ENV", "SHELLOPTS", "BASHOPTS", "POSIXLY_CORRECT", "BASH_COMPAT",
                   "FUNCNEST", "EXECIGNORE", "CDPATH", "GLOBIGNORE",
                   "CLAUDE_CODE_SHELL_PREFIX", "CLAUDE_CODE_GIT_BASH_PATH", "PATH",
                   "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "CLAUDE_PROJECT_DIR",
                   "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
                   "GIT_CEILING_DIRECTORIES", "GIT_EXEC_PATH", "GIT_EXTERNAL_DIFF"]
RISKY_ENV_PREFIXES = ["DYLD_", "BCL_", "_BCL_", "GIT_CONFIG_"]
RISKY_ENV_SUBSTRINGS = ["BASH_FUNC_"]
def _risky_env(name):
    n = name.upper()
    return (n in RISKY_ENV_NAMES or any(n.startswith(p) for p in RISKY_ENV_PREFIXES)
            or any(s in n for s in RISKY_ENV_SUBSTRINGS))
# The one form a baseline hook command may take: `bash -p` and a script under the
# project's baseline directory, nothing else on the line (a trailing `|| true`, an
# earlier `-c :` or a later `+p` would discard the verdict, skip the script or undo -p).
# Group 2 is the script. Only space and tab separate words here, and \Z ends the line:
# the shell splits on nothing else, so a VT, NBSP or newline where a space should be
# makes a different command. STALE_LAUNCH is the same without -p, the form installs
# wrote before -p. MIRRORS lib/merge_settings.py; a test asserts the two agree.
BASELINE_LAUNCH = r'^[ \t]*bash[ \t]+-p[ \t]+("?)(?:\$\{CLAUDE_PROJECT_DIR\}|\$CLAUDE_PROJECT_DIR)/\.claude/hooks/baseline/([A-Za-z0-9_./-]+\.sh)\1[ \t]*\Z'
STALE_LAUNCH = r'^[ \t]*bash[ \t]+("?)(?:\$\{CLAUDE_PROJECT_DIR\}|\$CLAUDE_PROJECT_DIR)/\.claude/hooks/baseline/([A-Za-z0-9_./-]+\.sh)\1[ \t]*\Z'
# The keys beside such a command can still stop it running as written: `args` (exec
# form: `command` becomes an executable name), a `shell` other than bash, `async` or
# `asyncRewake` (the verdict is not waited for), or a `timeout` below the template's
# (the hook is killed before its checks end). Minimum timeouts, MIRRORING
# settings.template.json; a test asserts the two agree.
BASELINE_TIMEOUTS = {"guardrails/command-guard.sh": 10, "modules/scope-guard.sh": 10,
                     "dispatcher/post-write.sh": 90, "modules/tracker-reminder.sh": 5,
                     "modules/config-guard.sh": 10}
def _entry_runs_as_written(h, script):
    t = h.get("timeout")
    return ("args" not in h and h.get("shell") in (None, "bash")
            and not h.get("async") and not h.get("asyncRewake")
            and isinstance(t, (int, float)) and not isinstance(t, bool)
            and t >= BASELINE_TIMEOUTS.get(script, 0))

try:
    with open(settings_file, encoding="utf-8") as fh:
        data = json.load(fh)
except FileNotFoundError:
    print("__UNREADABLE__ project settings file not found: " + settings_file)
    raise SystemExit(0)
except Exception as exc:
    print("__UNREADABLE__ project settings file is not valid JSON: %s" % exc)
    raise SystemExit(0)

# Valid JSON that is not an object means Claude Code sees no hooks/permissions at
# all — maximum tamper. Treat as unreadable (fail closed), never "validated".
if not isinstance(data, dict):
    print("__UNREADABLE__ project settings is not a JSON object (top-level %s)" % type(data).__name__)
    raise SystemExit(0)

findings = []

# Finding text is ASCII-only ON PURPOSE. This script now runs in UTF-8 mode (-X utf8),
# but run without it, Windows Python's stdout is the legacy code page (an em-dash
# becomes a lone cp1252 byte, not UTF-8) and would render mojibake. The bash-emitted
# decoration below (❌, header) is fine — bash emits the file's UTF-8 bytes verbatim.
# (1) disableAllHooks turns off EVERY hook, including this baseline - highest signal.
#     Flag ANY present value that is not explicitly false/absent (truthy ints/strings
#     like 1 or "true" are a tamper signal even if Claude Code only honors real true).
dah = data.get("disableAllHooks", False)
if dah not in (False, 0, None, "", "false", "False", "0", "no", "off"):
    findings.append("settings sets disableAllHooks=%r - this disables ALL hooks, including the baseline guardrails." % (dah,))

# (2) Every baseline script must still be wired as an actual command hook. Walk the
#     hooks tree, collect command strings from real {type:"command"} entries only, and
#     require each script to be *invoked* (the command must `bash` the baseline path,
#     not merely contain it — an echo / commented-out line does not count).
def _entries(obj, acc):
    if isinstance(obj, dict):
        if obj.get("type") == "command" and isinstance(obj.get("command"), str):
            acc.append(obj)
        for v in obj.values():
            _entries(v, acc)
    elif isinstance(obj, list):
        for item in obj:
            _entries(item, acc)

ents = []
_entries(data.get("hooks", {}), ents)
cmds = [h["command"] for h in ents]
def _invoked(script):
    pat = re.compile(r"^\s*bash\s.*?/\.claude/hooks/baseline/" + re.escape(script))
    return any(pat.search(c) for c in cmds)
missing_hooks = [h for h in REQUIRED_HOOK_CMDS if not _invoked(h)]
if missing_hooks:
    findings.append("baseline hooks are no longer wired/invoked in settings.json: " + ", ".join(missing_hooks) + " - those hooks will not run.")

# (2b) The PreToolUse guards must keep onFailure:"block" (Claude Code 2.1.295+), or a
#      guard that cannot start or times out lets the call through. Setting it to
#      "continue", or dropping it, is a one-key disarm of that fail-closed path.
GUARD_SCRIPTS = ("guardrails/command-guard.sh", "modules/scope-guard.sh")
hooks_obj = data.get("hooks")
pre = hooks_obj.get("PreToolUse") if isinstance(hooks_obj, dict) else None
soft, seen = set(), set()
for grp in pre if isinstance(pre, list) else []:
    entries = grp.get("hooks") if isinstance(grp, dict) else None
    for h in entries if isinstance(entries, list) else []:
        if not isinstance(h, dict) or not isinstance(h.get("command"), str):
            continue
        for s in GUARD_SCRIPTS:
            if re.search(r"^\s*bash\s.*?/\.claude/hooks/baseline/" + re.escape(s), h["command"]):
                seen.add(s)
                if h.get("onFailure") != "block":
                    soft.add(s)
# A guard wired under some OTHER event satisfies check (2) but guards nothing.
soft |= {s for s in GUARD_SCRIPTS if s not in seen and s not in missing_hooks}
if soft:
    findings.append("baseline guard hooks are not PreToolUse hooks with onFailure: block: " + ", ".join(sorted(soft)) + " - a guard that cannot start or times out would let the call through.")

# (2c) Every entry that runs a baseline script takes exactly the BASELINE_LAUNCH form,
#      with keys beside it that let it run as written (_entry_runs_as_written). A plain
#      `bash` runs an inherited BASH_ENV file, imports exported functions and applies
#      SHELLOPTS/BASHOPTS before the hook's first line, and anything else on the line
#      can discard the verdict or undo -p. Which entries run a script is matched
#      loosely (\s, any trailing text), so every variant reaches the exact check. The
#      old plain form is reported as STALE (an install from before -p), not as tamper.
stale, weak = set(), set()
for s in REQUIRED_HOOK_CMDS:
    runs = re.compile(r"^\s*bash\s.*?/\.claude/hooks/baseline/" + re.escape(s))
    for h in ents:
        if not runs.search(h["command"]):
            continue
        as_written = _entry_runs_as_written(h, s)
        m = re.match(BASELINE_LAUNCH, h["command"])
        if m and m.group(2) == s and as_written:
            continue
        m = re.match(STALE_LAUNCH, h["command"])
        (stale if m and m.group(2) == s and as_written else weak).add(s)
if weak:
    findings.append("baseline hooks are not launched exactly as bash -p <script> with the template's keys: " + ", ".join(sorted(weak)) + " - anything else on the line, or args, a non-bash shell, async or a short timeout beside it, can discard the hook's verdict, skip the script or undo -p.")
if stale:
    findings.append("STALE baseline hooks are launched without bash -p: " + ", ".join(sorted(stale)) + " - an inherited BASH_ENV file, exported function or SHELLOPTS would run before them. Installs made before this check wire them this way; re-run install.sh.")

# (3) The baseline-managed deny-list (secrets + self-protection) must still be present.
perms = data.get("permissions")
deny = []
if isinstance(perms, dict) and isinstance(perms.get("deny"), list):
    deny = [d for d in perms["deny"] if isinstance(d, str)]
missing = [d for d in EXPECTED_DENY if d not in deny]
if missing:
    findings.append("baseline deny-list entries removed from permissions.deny: " + ", ".join(missing))

# (4) No environment value that runs code before the hooks, redirects them or switches
#     them off (RISKY_ENV_* above), whatever its value: an empty PATH or
#     CLAUDE_PROJECT_DIR breaks the hook command as surely as a hostile one.
#     Reported as ENVRISK, under its own heading: a deliberate PATH belongs in the user
#     environment or ~/.claude/settings.json, but it is not tamper. Names are printed
#     ascii()-escaped, so a control character or non-ASCII name cannot break the report.
env = data.get("env")
risky = [k for k in (env if isinstance(env, dict) else {}) if _risky_env(k)]
if risky:
    findings.append("ENVRISK settings env sets " + ", ".join(sorted(ascii(k)[1:-1] for k in risky)) + " - such values can run code before the baseline hooks, redirect them, or switch them off. Set what you need in your user environment or ~/.claude/settings.json instead.")

for f in findings:
    print(f)
PY
)"
rc=$?   # A non-zero Python exit (unhandled error) must fail closed, never validate.
OUT="${OUT//$'\r'/}"   # Windows Python print() emits CRLF; strip CR before parsing.
if [[ $rc -ne 0 ]]; then
  echo "[config-guard] CONTROL COULD NOT RUN — settings integrity check errored (rc=$rc); treat as tampered." >&2
  bcl_failclosed_exit; exit $?
fi

# NOTE: filter $OUT with bash string ops, never grep — the finding messages contain
# UTF-8 (em-dashes), and grep declares such stdin "binary" and drops the lines.
if [[ "$OUT" == "__UNREADABLE__"* ]]; then
  {
    echo "[config-guard] CONTROL COULD NOT RUN — ${OUT#__UNREADABLE__ }"
    echo "   The project settings.json just changed but cannot be read/parsed — treat as tampered."
    echo "   Restore a valid .claude/settings.json (re-run install.sh), or set failClosed:false to warn only."
  } >&2
  bcl_failclosed_exit; exit $?
fi

if [[ -n "${OUT//[[:space:]]/}" ]]; then
  # The heading follows the worst finding: any untagged one is tamper; else an ENVRISK
  # one is a risky environment value; else only STALE ones (an install from before
  # `bash -p`) are out of date. Every one of them still exits through the posture.
  tamper=0; envrisk=0
  while IFS= read -r f; do
    [[ -z "${f//[[:space:]]/}" ]] && continue
    case "$f" in STALE\ *) ;; ENVRISK\ *) envrisk=1 ;; *) tamper=1 ;; esac
  done <<< "$OUT"
  {
    echo ""
    if [[ $tamper -eq 1 ]]; then
      echo "[config-guard] SETTINGS TAMPER DETECTED — .claude/settings.json was changed in a way that weakens the baseline:"
    elif [[ $envrisk -eq 1 ]]; then
      echo "[config-guard] RISKY ENVIRONMENT VALUE — .claude/settings.json sets values that can run code before the baseline hooks or switch them off:"
    else
      echo "[config-guard] BASELINE OUT OF DATE — .claude/settings.json launches the baseline hooks the old way:"
    fi
    while IFS= read -r f; do
      [[ -z "${f//[[:space:]]/}" ]] && continue
      f="${f#STALE }"; echo "   ❌ ${f#ENVRISK }"
    done <<< "$OUT"
    echo ""
    echo "   File: $SETTINGS_FILE"
    echo "   Re-run install.sh to restore the baseline wiring + deny-list, or revert the change."
  } >&2
  bcl_violation_exit; exit $?
fi

echo "[config-guard] project settings change validated — baseline hooks + deny-list intact."
exit 0
