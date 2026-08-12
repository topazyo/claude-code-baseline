#!/usr/bin/env bash
# claude-code-baseline :: tests/test_managed.sh
#
# Validates the R6 managed/ enterprise-floor profiles. Managed settings are a
# Claude Code runtime mechanism (can't be exercised by the hook harness), so this
# checks the artifacts structurally: valid JSON, the deny-list is a SUPERSET of the
# baseline deny-list (the floor can't be weaker than the per-repo template), the
# guardrail hooks are wired, and the strict profile carries the lockdown keys.
# Requires python3 (or python). Exits non-zero on any failure.
set -uo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$(command -v python3 || command -v python || true)"
[ -z "$PY" ] && { echo "python3 (or python) is required" >&2; exit 1; }

"$PY" - "$SRC" <<'PY'
import json, re, sys, pathlib
src = pathlib.Path(sys.argv[1])
fails = []

def load(rel):
    try:
        return json.loads((src / rel).read_text(encoding="utf-8"))
    except Exception as exc:
        fails.append(f"{rel} is not valid JSON: {exc}")
        return None

bal    = load("managed/managed-settings.json")
strict = load("managed/managed-settings.strict.json")
tmpl   = load("settings.template.json")

base_deny = set(tmpl["permissions"]["deny"]) if tmpl else set()
# The managed floor is the per-repo deny-list PLUS the one entry only a
# non-overridable tier can usefully own (the per-repo template/config-guard
# deliberately omit it — see managed/README.md). Pin the exact expected set so
# both the floor invariant (>= template) AND the intentional extra are locked.
expected_deny = base_deny | {"Edit(.claude/settings.local.json)"}

# Expected guardrail wiring: event -> (matcher, script the command must reference).
EXPECTED_HOOKS = {
    "PreToolUse":  ("Bash|PowerShell", "guardrails/command-guard.sh"),
    "PostToolUse": ("Write|Edit", "dispatcher/post-write.sh"),
}

# Each repo profile is a TEMPLATE: it must still carry the literal placeholder so a
# future edit that hardcodes a path (and would ship a machine-specific file) is caught.
for name, rel in [("balanced", "managed/managed-settings.json"), ("strict", "managed/managed-settings.strict.json")]:
    if "<BASELINE_PREFIX>" not in (src / rel).read_text(encoding="utf-8"):
        fails.append(f"{name}: profile lost the <BASELINE_PREFIX> placeholder (templates must keep it)")

for name, prof in [("balanced", bal), ("strict", strict)]:
    if prof is None:
        continue
    deny = set(prof.get("permissions", {}).get("deny", []))
    if deny != expected_deny:
        fails.append(f"{name}: managed deny != expected; missing={sorted(expected_deny - deny)} extra={sorted(deny - expected_deny)}")
    # Validate the hooks STRUCTURE (not just a substring): each expected event has a
    # group with the right matcher and a {type:command, command, timeout} hook that
    # invokes the right script.
    hooks = prof.get("hooks", {})
    for event, (want_matcher, want_script) in EXPECTED_HOOKS.items():
        groups = hooks.get(event)
        if not isinstance(groups, list) or not groups:
            fails.append(f"{name}: hooks.{event} missing or not a non-empty array")
            continue
        ok = False
        # Launcher-anchored (mirrors R5 config-guard): the command must `bash` the
        # script as a single argument token, not merely mention its name (e.g. in a
        # trailing comment or a different path segment).
        launches = re.compile(r'(^|\s)bash\s+"?\S*' + re.escape(want_script) + r'"?(\s|$)')
        for g in groups:
            if not isinstance(g, dict) or g.get("matcher") != want_matcher:
                continue
            for h in (g.get("hooks") or []):
                if (isinstance(h, dict) and h.get("type") == "command"
                        and isinstance(h.get("command"), str) and launches.search(h["command"])
                        and isinstance(h.get("timeout"), int)):
                    ok = True
        if not ok:
            fails.append(f"{name}: hooks.{event} has no {{type:command,timeout}} entry with matcher '{want_matcher}' invoking {want_script}")

# strict profile must carry the lockdown floor
if strict is not None:
    if strict.get("allowManagedHooksOnly") is not True:
        fails.append("strict: allowManagedHooksOnly must be true")
    if strict.get("allowManagedPermissionRulesOnly") is not True:
        fails.append("strict: allowManagedPermissionRulesOnly must be true")
    spc = strict.get("strictPluginOnlyCustomization")
    if not isinstance(spc, list) or not spc:
        fails.append("strict: strictPluginOnlyCustomization must be a non-empty array")

# R7 allowlist-primary profile
allowlist = load("managed/allowlist.example.json")
if allowlist is not None:
    perms = allowlist.get("permissions", {})
    # default-deny posture: only dontAsk auto-denies unlisted actions (verified semantics)
    if perms.get("defaultMode") != "dontAsk":
        fails.append("allowlist: permissions.defaultMode must be 'dontAsk' (the verified default-deny mode)")
    # the allowlist itself must be non-empty
    if not isinstance(perms.get("allow"), list) or not perms.get("allow"):
        fails.append("allowlist: permissions.allow must be a non-empty array")
    # the secrets/tamper deny backstop must be present (deny beats allow -> the Read
    # TOOL stays blocked from secrets even though Read/Edit(./**) is allowlisted)
    a_deny = set(perms.get("deny", []))
    if not expected_deny <= a_deny:
        fails.append(f"allowlist: deny backstop missing entries: {sorted(expected_deny - a_deny)}")
    # FOOTGUN GUARD: if a secrets Read deny is present, the example allow must NOT also
    # grant a file-reading Bash verb — `cat .env`/`rg . .env` read through the OS and
    # bypass the Read-tool deny, defeating the advertised secrets backstop. (dontAsk also
    # auto-permits read-only Bash, so this is about not ADVERTISING the leak in the example.)
    READ_VERBS = ("cat", "rg", "grep", "egrep", "fgrep", "head", "tail", "less",
                  "more", "xxd", "od", "strings", "nl", "tac", "awk", "sed")
    if any(d.startswith("Read(.env") for d in a_deny):
        for entry in perms.get("allow", []):
            m = re.match(r"Bash\(\s*([A-Za-z0-9_./-]+)", entry)
            if m and m.group(1).rsplit("/", 1)[-1] in READ_VERBS:
                fails.append(f"allowlist: allow grants file-reading Bash '{entry}' alongside a secrets deny — it would leak .env via subprocess; drop it (see managed/README.md R7 limits)")
    # sandbox filesystem paths must NOT use project-relative './' (verified: absolute / ~ / //)
    fsb = (allowlist.get("sandbox") or {}).get("filesystem") or {}
    for key in ("allowWrite", "denyWrite", "denyRead"):
        for p in (fsb.get(key) or []):
            if isinstance(p, str) and (p.startswith("./") or p == "."):
                fails.append(f"allowlist: sandbox.filesystem.{key} entry '{p}' uses unsupported project-relative './' syntax (use absolute / ~ / //)")
    if "sandbox" in allowlist and allowlist["sandbox"].get("enabled") is not True:
        fails.append("allowlist: sandbox present but sandbox.enabled is not true")

for f in fails:
    print("  FAIL " + f)
print("test_managed: %d checks failed" % len(fails))
sys.exit(1 if fails else 0)
PY
