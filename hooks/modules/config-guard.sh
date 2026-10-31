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
# settings). It also watches `local_settings` (.claude/settings.local.json), an
# overlay that outranks settings.json: there it reports disableAllHooks, a risky env
# value and any hook entry that names a baseline script, since the installer never
# writes one there. user_settings is per-developer and is left to R6.
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
  project_settings|local_settings) : ;;
  "")
    # Parseable payload with no 'source' — we cannot tell what changed.
    echo "[config-guard] CONTROL COULD NOT RUN — ConfigChange payload had no 'source'; the change was NOT integrity-checked." >&2
    bcl_failclosed_exit; exit $?
    ;;
  *)
    # A settings source the baseline does not manage (user/policy/skills).
    exit 0
    ;;
esac

if [[ "$SOURCE" == local_settings ]]; then
  LABEL=".claude/settings.local.json"; FIX="Remove the reported entries from .claude/settings.local.json, or revert the change."
else
  LABEL=".claude/settings.json"; FIX="Re-run install.sh to restore the baseline wiring + deny-list, or revert the change."
fi
FILE_PATH="$(bcl_extract_value "$PAYLOAD" file_path)"
if [[ -n "$FILE_PATH" ]]; then
  SETTINGS_FILE="$FILE_PATH"
else
  SETTINGS_FILE="$(bcl_repo_root)/$LABEL"
fi
case "$SETTINGS_FILE" in /*|?:*) : ;; *) SETTINGS_FILE="$(bcl_repo_root)/$SETTINGS_FILE" ;; esac

OUT="$("$PY" -I -S -X utf8 - "$SETTINGS_FILE" "$SOURCE" <<'PY'
import json, os, re, sys

settings_file, source = sys.argv[1], sys.argv[2]
which = "local" if source == "local_settings" else "project"

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
# Where the template wires each script: (script, event, the group's matcher or None for a
# group without one). MIRRORS settings.template.json; a test asserts the two agree.
BASELINE_WIRING = [
    ("guardrails/command-guard.sh", "PreToolUse", "Bash|PowerShell"),
    ("modules/scope-guard.sh", "PreToolUse", "Write|Edit"),
    ("dispatcher/post-write.sh", "PostToolUse", "Write|Edit"),
    ("modules/tracker-reminder.sh", "Stop", None),
    ("modules/config-guard.sh", "ConfigChange", "project_settings"),
    ("modules/config-guard.sh", "ConfigChange", "local_settings"),
]
# How Claude Code reads a group's matcher (hooks docs, "Matcher patterns"): absent, "" or
# "*" match every value; a value of only letters, digits, _, -, space, comma and | is an
# exact name or a list split on | or ,; anything else is an unanchored JavaScript regex.
# True only when group grp certainly runs for every value a template group with matcher
# `wired` (None: every value) runs for. It errs toward False. Only names joined by |
# count: read as exact names or as a regex, they cover those names (a list with a space
# or comma is not counted, in case a supported release reads it as a regex). A regex never
# counts (a pattern from settings could make Python's backtracking outlast this hook's
# timeout, and Python and JavaScript read some patterns differently), nor does a null
# matcher, nor any matcher where the template group has none: Stop ignores matchers today,
# but it is reported anyway so the check does not depend on which events support them.
# MIRRORED in lib/merge_settings.py; a test runs both on one table.
def _matcher_covers(grp, wired):
    if "matcher" not in grp:
        return True
    m = grp["matcher"]
    if m in ("", "*"):
        return True
    if wired is None or not isinstance(m, str) or not re.fullmatch(r"[A-Za-z0-9_|-]+", m):
        return False
    return set(wired.split("|")) <= set(m.split("|"))
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
    if which == "local" and os.path.isdir(os.path.dirname(settings_file)):
        print("__ABSENT__")   # settings.local.json is optional: removing it removes nothing of ours
        raise SystemExit(0)
    if which == "local":
        print("__UNREADABLE__ local settings file not found, nor its folder: " + settings_file)
        raise SystemExit(0)
    print("__UNREADABLE__ project settings file not found: " + settings_file)
    raise SystemExit(0)
except Exception as exc:
    print("__UNREADABLE__ %s settings file is not valid JSON: %s" % (which, exc))
    raise SystemExit(0)

# Valid JSON that is not an object means Claude Code sees no hooks/permissions at
# all — maximum tamper. Treat as unreadable (fail closed), never "validated".
if not isinstance(data, dict):
    print("__UNREADABLE__ %s settings is not a JSON object (top-level %s)" % (which, type(data).__name__))
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
    shown_dah = ascii(dah)
    shown_dah = shown_dah if len(shown_dah) <= 200 else shown_dah[:200] + "..."
    findings.append("settings sets disableAllHooks=%s - this disables ALL hooks, including the baseline guardrails." % shown_dah)

# (4) No environment value that runs code before the hooks, redirects them or switches
#     them off (RISKY_ENV_* above), whatever its value: an empty PATH or
#     CLAUDE_PROJECT_DIR breaks the hook command as surely as a hostile one.
#     Reported as ENVRISK, under its own heading: a deliberate PATH belongs in the user
#     environment or ~/.claude/settings.json, but it is not tamper. Names are printed
#     ascii()-escaped, so a control character or non-ASCII name cannot break the report.
def _env_findings(data):
    env = data.get("env")
    risky = [k for k in (env if isinstance(env, dict) else {}) if _risky_env(k)]
    if not risky:
        return []
    return ["ENVRISK settings env sets " + ", ".join(sorted(ascii(k)[1:-1] for k in risky)) + " - such values can run code before the baseline hooks, redirect them, or switch them off. Set what you need in your user environment or ~/.claude/settings.json instead."]

# (5) settings.local.json (source local_settings): no hook entry may name a baseline
#     script in its command or args. The installer never writes one there, so one there
#     is reported. Each is named by the script after the baseline path, else by its
#     text; the scan is one pass. MIRRORED in lib/merge_settings.py
#     (baseline_hook_names); a test runs both on one table. That file is an overlay:
#     the wiring and deny-list checks (2)-(3) are settings.json's, so a local_settings
#     change ends here.
_SCRIPT_AFTER_MARKER = re.compile(r"\S+?\.sh")
_SPACE = re.compile(r"\s")
def _named_script(command):
    i = command.find("/.claude/hooks/baseline/")
    while i != -1:
        start = i + len("/.claude/hooks/baseline/")
        m = _SCRIPT_AFTER_MARKER.match(command, start)
        if m:
            return m.group(0)
        gap = _SPACE.search(command, start)
        if gap is None:
            return None
        i = command.find("/.claude/hooks/baseline/", gap.end())
    return None
def _command_entries(obj):
    if isinstance(obj, dict):
        if obj.get("type") == "command" and isinstance(obj.get("command"), str):
            yield obj
        for v in obj.values():
            yield from _command_entries(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _command_entries(item)
def _entry_text(e):
    args = e.get("args") if isinstance(e.get("args"), list) else []
    return " ".join([e["command"]] + [a for a in args if isinstance(a, str)])
def _baseline_named(hooks):
    return sorted({_named_script(t) or t.strip()
                   for t in map(_entry_text, _command_entries(hooks)) if "/.claude/hooks/baseline/" in t})
if which == "local":
    named = _baseline_named(data.get("hooks"))
    if named:
        shown = [ascii(n)[1:-1] if len(n) <= 200 else ascii(n[:200])[1:-1] + "..." for n in named[:20]]
        if len(named) > 20:
            shown.append("and %d more" % (len(named) - 20))
        findings.append("settings.local.json has hook entries naming baseline scripts: " + ", ".join(shown) + " - the installer never writes baseline hooks there; remove them or revert the change.")
    findings += _env_findings(data)
    for f in findings:
        print(f)
    raise SystemExit(0)

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
#      (seen, soft): the guards some direct PreToolUse entry runs, and those of them some
#      such entry runs without onFailure "block". GUARD_SCRIPTS are the template's
#      PreToolUse entries with onFailure "block". MIRRORED in lib/merge_settings.py (baseline-status
#      reports soft guards too); a test runs both on one table.
GUARD_SCRIPTS = ("guardrails/command-guard.sh", "modules/scope-guard.sh")
hooks_obj = data.get("hooks")
def _guard_entries(hooks, guards):
    pre = hooks.get("PreToolUse") if isinstance(hooks, dict) else None
    seen, soft = set(), set()
    for grp in pre if isinstance(pre, list) else []:
        entries = grp.get("hooks") if isinstance(grp, dict) else None
        for h in entries if isinstance(entries, list) else []:
            if not isinstance(h, dict) or not isinstance(h.get("command"), str):
                continue
            for s in guards:
                if re.search(r"^\s*bash\s.*?/\.claude/hooks/baseline/" + re.escape(s), h["command"]):
                    seen.add(s)
                    if h.get("onFailure") != "block":
                        soft.add(s)
    return seen, soft
seen, soft = _guard_entries(hooks_obj, GUARD_SCRIPTS)
# A guard wired under some OTHER event satisfies check (2) but guards nothing.
soft |= {s for s in GUARD_SCRIPTS if s not in seen and s not in missing_hooks}
if soft:
    findings.append("baseline guard hooks are not PreToolUse hooks with onFailure: block: " + ", ".join(sorted(soft)) + " - a guard that cannot start or times out would let the call through.")

# (2d) Each BASELINE_WIRING row needs a group under its event whose matcher covers the
#      template's (_matcher_covers) and that holds, as a direct entry, a command running
#      the script with no `if` (an `if` narrows a tool event, and on any other event the
#      hook never runs). Wired anywhere else, the hook may not run for everything the
#      template runs it for. Which entries run a script is the loose match of (2c), which
#      owns the launch form, narrowed to the script right after the command's first
#      baseline path and ending where a path word ends; scripts (2) or (2b) already
#      report are skipped. MIRRORED in lib/merge_settings.py; a test runs both on one table.
def _wired_at(hooks, script, event, wired):
    runs = re.compile(r"^\s*bash\s(?:(?!/\.claude/hooks/baseline/).)*/\.claude/hooks/baseline/"
                      + re.escape(script) + r"(?![A-Za-z0-9_./-])")
    groups = hooks.get(event) if isinstance(hooks, dict) else None
    for grp in groups if isinstance(groups, list) else []:
        entries = grp.get("hooks") if isinstance(grp, dict) else None
        if not isinstance(entries, list) or not _matcher_covers(grp, wired):
            continue
        if any(isinstance(h, dict) and h.get("type") == "command" and "if" not in h
               and isinstance(h.get("command"), str) and script in h["command"]
               and runs.search(h["command"])
               for h in entries):
            return True
    return False
skip = set(missing_hooks) | {s for s in GUARD_SCRIPTS if s not in seen}
miswired = ["%s under %s%s" % (s, ev, " " + m if m else "") for s, ev, m in BASELINE_WIRING
            if s not in skip and not _wired_at(hooks_obj, s, ev, m)]
if miswired:
    findings.append("baseline hooks are not wired as the template wires them (its event, a matcher covering its matcher, no if): " + ", ".join(miswired) + " - they may not run for everything the template runs them for.")

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

# (4) (defined above, before the local_settings exit) environment values.
findings += _env_findings(data)

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
if [[ "$OUT" == "__ABSENT__" ]]; then
  echo "[config-guard] $LABEL removed — nothing in it to check."
  exit 0
fi
if [[ "$OUT" == "__UNREADABLE__"* ]]; then
  {
    echo "[config-guard] CONTROL COULD NOT RUN — ${OUT#__UNREADABLE__ }"
    if [[ "$SOURCE" == local_settings ]]; then
      echo "   $LABEL just changed but cannot be read/parsed — treat as tampered."
      echo "   Fix or remove $LABEL, or set failClosed:false to warn only."
    else
      echo "   The project settings.json just changed but cannot be read/parsed — treat as tampered."
      echo "   Restore a valid $LABEL (re-run install.sh), or set failClosed:false to warn only."
    fi
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
      echo "[config-guard] SETTINGS TAMPER DETECTED — $LABEL was changed in a way that weakens the baseline:"
    elif [[ $envrisk -eq 1 ]]; then
      echo "[config-guard] RISKY ENVIRONMENT VALUE — $LABEL sets values that can run code before the baseline hooks or switch them off:"
    else
      echo "[config-guard] BASELINE OUT OF DATE — $LABEL launches the baseline hooks the old way:"
    fi
    while IFS= read -r f; do
      [[ -z "${f//[[:space:]]/}" ]] && continue
      f="${f#STALE }"; echo "   ❌ ${f#ENVRISK }"
    done <<< "$OUT"
    echo ""
    echo "   File: $SETTINGS_FILE"
    echo "   $FIX"
  } >&2
  bcl_violation_exit; exit $?
fi

if [[ "$SOURCE" == local_settings ]]; then
  echo "[config-guard] local settings change validated — no baseline hook, disableAllHooks or risky env value."
else
  echo "[config-guard] project settings change validated — baseline hooks + deny-list intact."
fi
exit 0
