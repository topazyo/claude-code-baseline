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
CG = 'bash "${CLAUDE_PROJECT_DIR}/.claude/hooks/baseline/guardrails/command-guard.sh"'
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
    ("command-guard exactly once, retired baseline hook gone",
     sum(c == CG for c in commands(pre)) == 1 and OLD not in commands(pre) + commands(out["Stop"])),
    ("repo's already-empty group kept, group we emptied dropped",
     out["Stop"][0] == {"hooks": []} and sum(g == {"hooks": []} for g in out["Stop"]) == 1),
    ("template groups appended after the repo's",
     pre[4:] == TEMPLATE["PreToolUse"] and out["Stop"][1:] == TEMPLATE["Stop"]),
    ("event outside the template untouched", out["SessionStart"] == [{"hooks": [USER]}]),
    ("idempotent: merging the result again changes nothing",
     json.dumps(merge(out)) == json.dumps(out)),
    ("existing hooks and template not mutated", before == after),
]

failed = [label for label, ok in checks if not ok]
for label in failed:
    print(f"  FAIL [{label}]")
print(f"test_merge_settings: {len(checks) - len(failed)} passed, {len(failed)} failed")
sys.exit(1 if failed else 0)
