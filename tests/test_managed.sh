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
# ...and each is wired as settings.template.json wires that script (lib/merge_settings.py
# reads the template's rows), so a template matcher or event change fails here until the
# managed profiles follow it.
sys.dont_write_bytecode = True   # importing lib/merge_settings.py must not write into the tree
sys.path.insert(0, str(src / "lib"))
import merge_settings as ms
tmpl_rows = set(ms.baseline_wiring(tmpl)) if tmpl else set()
want_rows = {(script, event, matcher) for event, (matcher, script) in EXPECTED_HOOKS.items()}
for script in sorted({r[0] for r in want_rows}):
    got = {r for r in tmpl_rows if r[0] == script}
    if got != {r for r in want_rows if r[0] == script}:
        fails.append(f"managed wiring of {script} is not how settings.template.json wires it: template {sorted(got, key=str)}")
mins = ms.baseline_timeouts(tmpl) if tmpl else {}

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
        # Exactly the launch config-guard's (2c) accepts for a repo install: `bash -p` and
        # the quoted script under the placeholder, nothing else on the line (a trailing
        # `|| true` would discard the verdict). -p: a plain bash runs an inherited
        # BASH_ENV file and imports exported functions before the hook.
        launches = re.compile(r'\Abash -p "' + re.escape("<BASELINE_PREFIX>/" + want_script) + r'"\Z')
        # ...with the keys beside it that config-guard requires: no args, a bash shell, not
        # async, at least the template's timeout (2c), and no `if` (2d).
        want_timeout = mins.get(want_script)
        if not ms._is_number(want_timeout):
            fails.append(f"{name}: settings.template.json gives {want_script} no numeric timeout to compare with")
            continue
        for g in groups:
            if not isinstance(g, dict) or g.get("matcher") != want_matcher:
                continue
            for h in (g.get("hooks") or []):
                t = h.get("timeout") if isinstance(h, dict) else None
                if (isinstance(h, dict) and h.get("type") == "command"
                        and isinstance(h.get("command"), str) and launches.search(h["command"])
                        and "args" not in h and h.get("shell") in (None, "bash")
                        and not h.get("async") and not h.get("asyncRewake") and "if" not in h
                        and ms._is_number(t) and t >= want_timeout):
                    ok = True
        if not ok:
            fails.append(f"{name}: hooks.{event} has no entry with matcher '{want_matcher}' running {want_script} as the template does (type command, bash -p, a bash shell, no args/async/if, timeout >= {want_timeout})")

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
    # sandbox filesystem paths must NOT use project-relative './': the docs define it only for
    # project and user settings, and this profile is deployed as managed settings (absolute,
    # ~/ and // are defined everywhere). managed/README.md says what to add per deployment.
    # Bare relative paths (no prefix) have the same problem and are not rejected yet.
    fsb = (allowlist.get("sandbox") or {}).get("filesystem") or {}
    for key in ("allowWrite", "denyWrite", "denyRead"):
        for p in (fsb.get(key) or []):
            if isinstance(p, str) and (p.startswith("./") or p == "."):
                fails.append(f"allowlist: sandbox.filesystem.{key} entry '{p}' uses project-relative './', which has no documented meaning in managed settings (use absolute / ~ / //)")
    if "sandbox" in allowlist and allowlist["sandbox"].get("enabled") is not True:
        fails.append("allowlist: sandbox present but sandbox.enabled is not true")
    # The sandbox's read block holds only while commands actually run sandboxed: not on a
    # retry outside it (an allow rule that matches a command approves the retry), not on a
    # machine where the sandbox cannot start; and dontAsk decides sandboxed Bash only while
    # auto-allow is off (managed/README.md, R7).
    if "sandbox" in allowlist:
        for key, want in (("allowUnsandboxedCommands", False), ("autoAllowBashIfSandboxed", False),
                          ("failIfUnavailable", True)):
            if allowlist["sandbox"].get(key) is not want:
                fails.append(f"allowlist: sandbox.{key} must be {str(want).lower()} (see managed/README.md R7)")

# D2: a PreToolUse guard that cannot start or times out must BLOCK the call, not let
# it through -- onFailure:"block" (Claude Code 2.1.295+) on every guard hook.
for name, doc in (("template", tmpl), ("managed", bal), ("strict", strict)):
    guards = [h for g in (doc.get("hooks") or {}).get("PreToolUse", [])
              for h in g.get("hooks", [])
              if re.search(r"(command|scope)-guard\.sh", h.get("command", ""))]
    if not guards:
        fails.append(f"{name}: no PreToolUse guard hook found")
    for h in guards:
        if h.get("onFailure") != "block":
            fails.append(f"{name}: guard hook {h.get('command')!r} lacks onFailure: \"block\"")

for f in fails:
    print("  FAIL " + f)
print("test_managed: %d checks failed" % len(fails))
sys.exit(1 if fails else 0)
PY
