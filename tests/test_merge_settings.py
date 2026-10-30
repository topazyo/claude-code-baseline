#!/usr/bin/env python3
"""Unit fixtures for the install-time settings merge (lib/merge_settings.py).

Exercises merge_hooks() directly against the real settings.template.json hooks:
ownership is per hook entry, a repo's own entries and keys are never dropped, and
merging the output again changes nothing. test_hooks.sh covers the same merge end
to end through install.sh.
Run:  python tests/test_merge_settings.py   (exits non-zero on any failure)
"""
import json
import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "lib"))
import merge_settings as ms  # noqa: E402

TEMPLATE = ms.strip_comments(ms.load(os.path.join(ROOT, "settings.template.json"), "baseline template"))["hooks"]
# CG is command-guard as installs before `bash -p` wired it; CG_P is the template's.
CG = 'bash "${CLAUDE_PROJECT_DIR}/.claude/hooks/baseline/guardrails/command-guard.sh"'
CG_P = 'bash -p "${CLAUDE_PROJECT_DIR}/.claude/hooks/baseline/guardrails/command-guard.sh"'
OLD = 'bash "$CLAUDE_PROJECT_DIR/.claude/hooks/baseline/old/retired.sh"'
USER = {"type": "command", "command": "bash ./scripts/user-audit.sh", "timeout": 7}


def ours(cmd):
    return {"type": "command", "command": cmd}


def merge(hooks):
    # Round-trip through JSON so no fixture object is shared with the result.
    return ms.merge_hooks(json.loads(json.dumps(hooks)), TEMPLATE)


def commands(event_groups):
    return [h.get("command") for g in event_groups if isinstance(g, dict)
            for h in g.get("hooks", []) if isinstance(h, dict)]


EXISTING = {
    "PreToolUse": [
        # a repo's own hook sharing a group with two of ours, plus a key we don't know
        {"matcher": "Bash|PowerShell", "x-team": {"owner": "sec"}, "hooks": [ours(CG), USER, "not-a-hook", ours(OLD)]},
        None,                                   # unrecognised shapes are kept verbatim, in place
        {"matcher": "Read"},
        {"matcher": "Glob", "hooks": "not-a-list"},
    ],
    "Stop": [
        {"hooks": []},                          # already empty: the repo's, kept
        {"hooks": [ours(OLD)]},                 # only ours: emptied by the merge, dropped
    ],
    "SessionStart": [{"hooks": [USER]}],        # an event the template does not use
}

B = "${CLAUDE_PROJECT_DIR}/.claude/hooks/baseline/"
LAUNCH_CASES = {"hooks": {"PreToolUse": [{"hooks": [
    ours(CG_P),                                                   # the template's form
    ours('bash "' + B + 'modules/scope-guard.sh"'),               # plain bash (stale)
    ours('bash -p "' + B + 'dispatcher/post-write.sh" || true'),  # discards the verdict
    ours('bash -p -c : "' + B + 'modules/tracker-reminder.sh"'),  # never runs the script
    ours('bash -p +p "' + B + 'modules/config-guard.sh"'),        # undoes -p
    ours('bash -p' + chr(11) + '"' + B + 'guardrails/auto-format.sh"'),  # VT: one word to sh
    USER,                                                         # not ours: ignored
]}]}}
MINS = ms.baseline_timeouts(ms.strip_comments(ms.load(os.path.join(ROOT, "settings.template.json"), "baseline template")))


def launch(script, **keys):
    return dict(ours('bash -p "' + B + script + '"'), **keys)



SIBLING_CASES = {"hooks": {"PreToolUse": [{"hooks": [
    launch("guardrails/command-guard.sh", timeout=10),             # as the template has it
    launch("modules/scope-guard.sh", timeout=10, args=["-p"]),     # exec form
    launch("dispatcher/post-write.sh", timeout=90, shell="powershell"),
    launch("modules/tracker-reminder.sh", timeout=5, **{"async": True}),
    launch("modules/config-guard.sh", timeout=1),                  # killed before it ends
    launch("modules/config-guard.sh", timeout=10, asyncRewake=True),  # not waited for either
]}]}}
ASYNC_REWAKE = {"hooks": {"Stop": [{"hooks": [
    launch("modules/tracker-reminder.sh", timeout=5, asyncRewake=True)]}]}}
# Where the template wires each script, and installs that move one of them.
WIRING = ms.baseline_wiring({"hooks": TEMPLATE})
INSTALLED = {"hooks": ms.merge_hooks({}, TEMPLATE)}


def rewired(change):
    """A fresh install with change(hooks) applied."""
    s = json.loads(json.dumps(INSTALLED))
    change(s["hooks"])
    return ms.baseline_wiring_problems(s, WIRING)


def set_key(event, i, **keys):
    def change(hooks):
        hooks[event][i].update(keys)
    return change


def set_entry_key(event, i, **keys):
    def change(hooks):
        hooks[event][i]["hooks"][0].update(keys)
    return change


def lookalike(old, new):
    """command-guard's covering group runs another path ending or holding its name; the
    real one sits in a group that does not cover the template's matcher."""
    def change(hooks):
        real = hooks["PreToolUse"][0]["hooks"][0]
        hooks["PreToolUse"].append({"matcher": "Read", "hooks": [dict(real)]})
        real["command"] = real["command"].replace(old, new)
    return change


def merge_env_run():
    """main() end to end on a settings.json whose env sets BASH_ENV: the merge must
    succeed, name the key on stderr, and leave env exactly as it was."""
    import subprocess
    import tempfile
    env = {"BASH_ENV": "/tmp/startup.sh", "FOO": "1"}
    with tempfile.TemporaryDirectory() as d:
        existing, merged = os.path.join(d, "settings.json"), os.path.join(d, "out.json")
        with open(existing, "w", encoding="utf-8") as fh:
            json.dump({"env": env}, fh)
        proc = subprocess.run(
            [sys.executable, "-I", os.path.join(ROOT, "lib", "merge_settings.py"), existing,
             os.path.join(ROOT, "settings.template.json"), merged],
            capture_output=True, text=True, timeout=60)
        with open(merged, encoding="utf-8") as fh:
            out_env = json.load(fh).get("env")
    return (proc.returncode == 0 and "WARNING: settings.json env sets BASH_ENV." in proc.stderr
            and "FOO" not in proc.stderr and out_env == env)


before = json.dumps(EXISTING), json.dumps(TEMPLATE)
out = ms.merge_hooks(EXISTING, TEMPLATE)        # the real objects: neither may be mutated
after = json.dumps(EXISTING), json.dumps(TEMPLATE)
out = json.loads(json.dumps(out))               # detach from the inputs before checking
pre = out["PreToolUse"]
checks = [
    ("shared group keeps the repo's hook, its fields and the group's keys in order",
     pre[0] == {"matcher": "Bash|PowerShell", "x-team": {"owner": "sec"}, "hooks": [USER, "not-a-hook"]}
     and list(pre[0]) == ["matcher", "x-team", "hooks"]),
    ("unrecognised groups kept verbatim and in place",
     pre[1:4] == [None, {"matcher": "Read"}, {"matcher": "Glob", "hooks": "not-a-list"}]),
    ("command-guard exactly once, as bash -p; the old plain launch and a retired hook gone",
     sum(c == CG_P for c in commands(pre)) == 1 and CG not in commands(pre)
     and OLD not in commands(pre) + commands(out["Stop"])),
    ("repo's already-empty group kept, group we emptied dropped",
     out["Stop"][0] == {"hooks": []} and sum(g == {"hooks": []} for g in out["Stop"]) == 1),
    ("template groups appended after the repo's",
     pre[4:] == TEMPLATE["PreToolUse"] and out["Stop"][1:] == TEMPLATE["Stop"]),
    ("event outside the template untouched", out["SessionStart"] == [{"hooks": [USER]}]),
    ("idempotent: merging the result again changes nothing",
     json.dumps(merge(out)) == json.dumps(out)),
    ("existing hooks and template not mutated", before == after),
    # env keys that can run code before the baseline hooks: names and prefixes, compared
    # upper-cased (Windows environment names are case-insensitive)
    ("risky env keys reported",
     ms.risky_env_keys({"env": {"BASH_ENV": "x", "Path": "y", "BASH_FUNC_t%%": "() { :; }",
                                "dyld_insert_libraries": "z", "_BCL_PY": "p", "FOO": "1"}})
     == sorted(["BASH_ENV", "Path", "BASH_FUNC_t%%", "dyld_insert_libraries", "_BCL_PY"])),
    # whatever the value: an empty PATH breaks the hook command too
    ("risky env keys reported whatever the value",
     ms.risky_env_keys({"env": {"BASH_ENV": "", "SHELLOPTS": None, "FUNCNEST": 1, "PATH": "",
                                "CLAUDE_CODE_SHELL_PREFIX": " ", "x_BASH_FUNC_y": "z",
                                "GIT_CONFIG_COUNT": "1", "claude_code_git_bash_path": "c"}})
     == sorted(["BASH_ENV", "SHELLOPTS", "FUNCNEST", "PATH", "CLAUDE_CODE_SHELL_PREFIX",
                "x_BASH_FUNC_y", "GIT_CONFIG_COUNT", "claude_code_git_bash_path"])),
    ("bash startup and git names reported",
     ms.risky_env_keys({"env": {"POSIXLY_CORRECT": "1", "CDPATH": ".", "GIT_EXEC_PATH": "x"}})
     == ["CDPATH", "GIT_EXEC_PATH", "POSIXLY_CORRECT"]),
    ("PYTHON*, ENV, near-miss names and a non-object env not reported",
     ms.risky_env_keys({"env": {"PYTHONPATH": "x", "NODE_ENV": "p", "MYBCL_X": "1",
                                "GIT_AUTHOR_NAME": "a", "ENV": "production"}}) == []
     and ms.risky_env_keys({"env": ["BASH_ENV"]}) == [] and ms.risky_env_keys({}) == []),
    # the one launch form: bash -p and the script, nothing else on the line, and only
    # space or tab between the words
    ("launches: only exact bash -p <script> counts",
     ms.baseline_launches(LAUNCH_CASES) == {"guardrails/command-guard.sh"}),
    ("launches: plain bash, trailing tokens, -c, +p and a VT separator reported",
     ms.baseline_launch_problems(LAUNCH_CASES)
     == ["dispatcher/post-write.sh", "guardrails/auto-format.sh", "modules/config-guard.sh",
         "modules/scope-guard.sh", "modules/tracker-reminder.sh"]),
    # ...and the keys beside it: no args, a bash shell, not async, the template's timeout
    ("launches: args, a powershell shell, async and a short timeout reported",
     ms.baseline_launches(SIBLING_CASES, MINS) == {"guardrails/command-guard.sh"}
     and ms.baseline_launch_problems(SIBLING_CASES, MINS)
     == ["dispatcher/post-write.sh", "modules/config-guard.sh", "modules/scope-guard.sh",
         "modules/tracker-reminder.sh"]),
    ("launches: asyncRewake reported",
     ms.baseline_launch_problems(ASYNC_REWAKE, MINS) == ["modules/tracker-reminder.sh"]
     and ms.baseline_launches(ASYNC_REWAKE, MINS) == set()),
    ("launches: a non-numeric template minimum skips the timeout check, no crash",
     ms.baseline_launches({"hooks": {"Stop": [{"hooks": [launch("modules/tracker-reminder.sh")]}]}},
                          {"modules/tracker-reminder.sh": None}) == {"modules/tracker-reminder.sh"}),
    ("template timeouts read for every baseline script",
     MINS == {"guardrails/command-guard.sh": 10, "modules/scope-guard.sh": 10,
              "dispatcher/post-write.sh": 90, "modules/tracker-reminder.sh": 5,
              "modules/config-guard.sh": 10}),
    ("merge warns about a risky env key and keeps env as it was", merge_env_run()),
    # where the template wires each script: event, group matcher, no `if`
    ("template wiring read for every baseline group",
     WIRING == [("dispatcher/post-write.sh", "PostToolUse", "Write|Edit"),
                ("guardrails/command-guard.sh", "PreToolUse", "Bash|PowerShell"),
                ("modules/config-guard.sh", "ConfigChange", "local_settings"),
                ("modules/config-guard.sh", "ConfigChange", "project_settings"),
                ("modules/scope-guard.sh", "PreToolUse", "Write|Edit"),
                ("modules/tracker-reminder.sh", "Stop", None)]),
    ("wiring: a fresh install has no problem, nor does a match-all or wider matcher",
     rewired(lambda h: None) == [] and rewired(set_key("PreToolUse", 0, matcher="*")) == []
     and rewired(set_key("PreToolUse", 0, matcher="Read|PowerShell|Bash")) == []),
    ("wiring: a narrower, comma-list or regex matcher reported",
     rewired(set_key("PreToolUse", 0, matcher="Bash"))
     == [("guardrails/command-guard.sh", "PreToolUse", "Bash|PowerShell")]
     and rewired(set_key("PreToolUse", 1, matcher="Write, Edit"))
     == [("modules/scope-guard.sh", "PreToolUse", "Write|Edit")]
     and rewired(set_key("PostToolUse", 0, matcher="^(Write|Edit)$"))
     == [("dispatcher/post-write.sh", "PostToolUse", "Write|Edit")]),
    ("wiring: a matcher on Stop, and an if on any event, reported",
     rewired(set_key("Stop", 0, matcher="Bash")) == [("modules/tracker-reminder.sh", "Stop", None)]
     and rewired(set_entry_key("ConfigChange", 1, **{"if": "Bash(git status)"}))
     == [("modules/config-guard.sh", "ConfigChange", "local_settings")]),
    ("wiring: another event, and an entry nested inside another entry, reported",
     rewired(lambda h: h.update(SessionStart=h.pop("Stop")))
     == [("modules/tracker-reminder.sh", "Stop", None)]
     and rewired(lambda h: h["PreToolUse"][1].update(
         hooks=[{"type": "command", "command": "exit 0", "x": h["PreToolUse"][1]["hooks"][0]}]))
     == [("modules/scope-guard.sh", "PreToolUse", "Write|Edit")]),
    ("wiring: a longer script name in the covering group does not count",
     rewired(lookalike("command-guard.sh", "command-guard.sh.sh"))
     == [("guardrails/command-guard.sh", "PreToolUse", "Bash|PowerShell")]),
    ("wiring: a path that holds the baseline path again does not count",
     rewired(lookalike("baseline/guardrails/", "baseline/x/.claude/hooks/baseline/guardrails/"))
     == [("guardrails/command-guard.sh", "PreToolUse", "Bash|PowerShell")]),
    ("wiring: no hooks object, or a wrong-typed one, reports every row, no crash",
     ms.baseline_wiring_problems({}, WIRING) == WIRING
     and ms.baseline_wiring_problems({"hooks": ["x"]}, WIRING) == WIRING
     and ms.baseline_wiring_problems({"hooks": {"Stop": "x", "PreToolUse": [None, {"hooks": "x"}]}},
                                     WIRING) == WIRING),
]

failed = [label for label, ok in checks if not ok]
for label in failed:
    print(f"  FAIL [{label}]")
print(f"test_merge_settings: {len(checks) - len(failed)} passed, {len(failed)} failed")
sys.exit(1 if failed else 0)
