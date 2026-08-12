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

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"

# Opt-in: off unless the org enabled it. NOTE: this gate needs Python to read the
# config, so on a host with NO Python this module is inert (config unreadable =>
# treated as disabled), like every other opt-in module. The no-Python case is
# covered elsewhere: the always-on command-guard guardrail fails closed without
# Python, and the secrets/tamper deny-list is a permission rule (no Python needed).
bcl_module_enabled configGuard || exit 0

# Reaching here means the module is enabled, which required Python above. Resolve it
# for the integrity check; if it somehow went missing, fail closed rather than skip.
PY="$(bcl_python)"
if [[ -z "$PY" ]]; then
  echo "[config-guard] CONTROL COULD NOT RUN — Python unavailable; the settings change was NOT integrity-checked." >&2
  bcl_failclosed_exit; exit $?
fi

PAYLOAD="$(cat 2>/dev/null || true)"
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

OUT="$("$PY" - "$SETTINGS_FILE" <<'PY'
import json, re, sys

settings_file = sys.argv[1]

# Baseline-managed permissions.deny entries. These MIRROR settings.template.json;
# a change there must change this list too (a test asserts the two agree, and
# tests/policy-change-gate.sh requires a fixture update when either side moves).
# This is an EXACT-STRING membership check on the baseline-owned entries — it does
# not normalize globs (a semantically-equal but textually-different rewrite reads as
# "removed") and does not inspect permissions.allow (allow-shadowing is mitigated by
# the v2.1.80 version pin, where allow no longer bypasses deny).
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

# Finding text is ASCII-only ON PURPOSE: on Windows, Python's stdout encoding is
# the legacy code page (an em-dash becomes a lone cp1252 byte, not UTF-8), so it
# would render mojibake. The bash-emitted decoration below (❌, header) is fine —
# bash emits the file's UTF-8 bytes verbatim.
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
def _commands(obj, acc):
    if isinstance(obj, dict):
        if obj.get("type") == "command" and isinstance(obj.get("command"), str):
            acc.append(obj["command"])
        for v in obj.values():
            _commands(v, acc)
    elif isinstance(obj, list):
        for item in obj:
            _commands(item, acc)

cmds = []
_commands(data.get("hooks", {}), cmds)
def _invoked(script):
    pat = re.compile(r"^\s*bash\s.*?/\.claude/hooks/baseline/" + re.escape(script))
    return any(pat.search(c) for c in cmds)
missing_hooks = [h for h in REQUIRED_HOOK_CMDS if not _invoked(h)]
if missing_hooks:
    findings.append("baseline hooks are no longer wired/invoked in settings.json: " + ", ".join(missing_hooks) + " - those hooks will not run.")

# (3) The baseline-managed deny-list (secrets + self-protection) must still be present.
perms = data.get("permissions")
deny = []
if isinstance(perms, dict) and isinstance(perms.get("deny"), list):
    deny = [d for d in perms["deny"] if isinstance(d, str)]
missing = [d for d in EXPECTED_DENY if d not in deny]
if missing:
    findings.append("baseline deny-list entries removed from permissions.deny: " + ", ".join(missing))

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
  {
    echo ""
    echo "[config-guard] SETTINGS TAMPER DETECTED — .claude/settings.json was changed in a way that weakens the baseline:"
    while IFS= read -r f; do [[ -n "${f//[[:space:]]/}" ]] && echo "   ❌ $f"; done <<< "$OUT"
    echo ""
    echo "   File: $SETTINGS_FILE"
    echo "   Re-run install.sh to restore the baseline wiring + deny-list, or revert the change."
  } >&2
  bcl_violation_exit; exit $?
fi

echo "[config-guard] project settings change validated — baseline hooks + deny-list intact."
exit 0
