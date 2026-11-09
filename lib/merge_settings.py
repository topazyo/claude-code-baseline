#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Merge the baseline settings fragment into a target repo's .claude/settings.json.

Usage: merge_settings.py <existing.json|-> <template.json> <output.json>

Rules:
  * hooks: for every event present in the template, remove each existing hook
    entry whose command references a baseline path (".../.claude/hooks/baseline/"),
    then append the template's groups. Removal is per hook: a repo's own hook in the
    same matcher group stays, and a group is dropped only when removing our entries
    left it empty. This makes re-running the installer idempotent — baseline entries
    are replaced, not duplicated. Events outside the template are left exactly as
    they are; a baseline entry found under one is reported on stderr, not removed
    (it can only have been wired by hand). The one exception is RETIRED_EVENTS: an
    event a past template wired and the current one no longer does is swept the same
    way, its key dropped only if removing our entries emptied it.
  * permissions.deny: union with the existing list (order-preserving, de-duplicated).
  * Everything else in the existing file (model, permissions.allow, env, ...) keeps
    its value. An `env` key that can run code before the baseline hooks, redirect
    them or set their posture (RISKY_ENV_NAMES), and a `disableAllHooks` that turns
    them all off, are reported on stderr, not removed.
  * Form, not values: '//' comments are dropped (JSON has none; reported on stderr,
    and the installer's backup keeps them). Text is written as UTF-8, except the
    characters in ESCAPED_CHARS — the default-ignorable code points (zero-width,
    bidi controls, variation selectors, tags), non-ASCII spaces, controls,
    surrogates and private use — which are written as \\uXXXX escapes, so none of
    them sits unseen in the file. (Other blank-looking or format characters, such as
    U+2800 or U+0600, are written as is.)

Failure model — deliberately FAIL LOUD. An existing settings.json that cannot be
read, cannot be parsed, or has a shape this merge cannot preserve is *not* treated
as empty. Treating it as empty is silent data loss: the output would be the
baseline template alone, and the caller would overwrite the consumer's own deny
rules, hooks, allow list and model while printing success. Instead we print a
FATAL naming the file and the reason, and exit non-zero so install.sh can abort
before it overwrites anything.

Tolerated (real files in the wild look like this, and refusing them would abort
installs for a cosmetic reason):
  * a UTF-8 BOM — PowerShell 5.1 'Set-Content -Encoding utf8', Notepad and
    VS Code's 'utf8bom' all write one; json.loads rejects it outright.
  * '//' line comments, string-aware so a '//' inside a value survives.
Not tolerated (they are ambiguous to repair, so we report instead of guessing):
  trailing commas, '/* */' block comments, UTF-16 encodings.

Exit codes:
  0  merged; output written
  2  wrong usage
  3  an input file could not be read, decoded, or parsed
  4  an input file parsed but has a shape this merge cannot safely preserve
  5  the output file could not be written
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable, NoReturn

BASELINE_MARKER = "/.claude/hooks/baseline/"
# Events an earlier settings.template.json wired and the current one no longer does.
# Their baseline entries are removed on install, like the template events'. Every
# template so far has wired the same four events, so this is empty; add an event here
# in the same change that removes it from the template.
RETIRED_EVENTS: tuple[str, ...] = ()

# Environment values a project settings `env` block must not set, whatever the value.
# MIRRORS RISKY_ENV_* in hooks/modules/config-guard.sh, which explains each entry; a
# test asserts the two agree. Names are compared upper-cased.
RISKY_ENV_NAMES = ["BASH_ENV", "SHELLOPTS", "BASHOPTS", "POSIXLY_CORRECT", "BASH_COMPAT",
                   "FUNCNEST", "EXECIGNORE", "CDPATH", "GLOBIGNORE",
                   "CLAUDE_CODE_SHELL_PREFIX", "CLAUDE_CODE_GIT_BASH_PATH", "PATH",
                   "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "CLAUDE_PROJECT_DIR",
                   "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
                   "GIT_CEILING_DIRECTORIES", "GIT_EXEC_PATH", "GIT_EXTERNAL_DIFF",
                   "HOME", "XDG_CONFIG_HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH"]
RISKY_ENV_PREFIXES = ["DYLD_", "BCL_", "_BCL_", "GIT_CONFIG_"]
RISKY_ENV_SUBSTRINGS = ["BASH_FUNC_"]
# The one form a baseline hook command may take (group 2: the script), and the keys
# beside it that let it run as written. MIRRORS BASELINE_LAUNCH and
# _entry_runs_as_written in hooks/modules/config-guard.sh, which explains them.
BASELINE_LAUNCH = r'^[ \t]*bash[ \t]+-p[ \t]+("?)(?:\$\{CLAUDE_PROJECT_DIR\}|\$CLAUDE_PROJECT_DIR)/\.claude/hooks/baseline/([A-Za-z0-9_./-]+\.sh)\1[ \t]*\Z'

# disableAllHooks values that leave hooks on. Any other value present is reported: a
# truthy int or string is a tamper signal even if Claude Code honours only a real true.
# MIRRORS config-guard (1) in hooks/modules/config-guard.sh; a test asserts the two
# agree. (Python's False == 0 makes 0 and False one entry here, as there.)
DISABLE_ALL_HOOKS_OFF = (False, 0, None, "", "false", "False", "0", "no", "off")

# Code points written as \uXXXX escapes (a surrogate pair above U+FFFF) rather than as
# UTF-8: the whole Default_Ignorable_Code_Point list (invisible characters, variation
# selectors, tags, Hangul fillers, bidi controls), the non-ASCII space characters, the
# line and paragraph separators, the interlinear-annotation controls, DEL and the C1
# controls, surrogates (a lone one cannot be encoded as UTF-8) and the private-use areas.
# A fixed list, not unicodedata, so the result does not depend on the Python build's
# Unicode version. json.dumps already escapes U+0000-U+001F. JSON's structural characters
# are ASCII, so these only occur inside strings, where an escape means the same.
ESCAPED_CHARS = re.compile(
    "[\u007f-\u00a0\u00ad\u034f\u061c\u115f\u1160\u1680\u17b4\u17b5\u180b-\u180f"
    "\u2000-\u200f\u2028-\u202f\u205f-\u206f\u3000\u3164\ufe00-\ufe0f\ufeff\uffa0"
    "\ufff0-\ufffb\ud800-\udfff\ue000-\uf8ff"
    "\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0000-\U000e0fff\U000f0000-\U0010ffff]")

EXIT_PARSE = 3
EXIT_SHAPE = 4
EXIT_WRITE = 5


def fatal(code: int, message: str, hint: str = "") -> NoReturn:
    """Report on stderr and exit non-zero. The caller (install.sh) keys off the
    exit status to skip the mv that would overwrite the consumer's file."""
    sys.stderr.write(f"FATAL: {message}\n")
    if hint:
        sys.stderr.write(f"       {hint}\n")
    raise SystemExit(code)


def _strip_jsonc_comments(text: str) -> str:
    """Drop '//' line comments without touching string values.

    The scan is string-aware on purpose: a '//' inside a value is legitimate and
    must survive — e.g. the absolute-path permission rule Read(//tmp/**), a
    "https://..." URL, or a UNC path. Newlines are kept so a later parse error
    still reports the line number the user sees in their editor. Valid JSON is
    returned unchanged (JSON has no bare '//' outside a string), so this can run
    unconditionally.
    """
    out: list[str] = []
    in_string = False
    escaped = False
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            nl = text.find("\n", i)
            if nl == -1:
                break  # comment runs to EOF
            i = nl  # keep the newline itself
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def load(path: str, label: str) -> dict:
    """Read and parse a settings document. Never returns {} for a file that
    exists but could not be understood — see the module docstring."""
    return load_noting_comments(path, label)[0]


def load_noting_comments(path: str, label: str) -> tuple[dict, bool]:
    """load(), and whether '//' comments were dropped to parse the file. A '//' inside
    a string value is kept by the stripper, so it does not count."""
    if path == "-":
        return {}, False
    p = Path(path)
    if not p.exists():
        return {}, False
    try:
        # utf-8-sig accepts plain UTF-8 too; it only strips a BOM if one is there.
        raw = p.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        fatal(
            EXIT_PARSE,
            f"{label} {p} is not UTF-8 text: {exc}",
            # ASCII only: this goes to stderr, and plain ASCII reads the same on any
            # console and in any log, whatever its code page.
            "If it was written by PowerShell '>' redirection it is probably UTF-16. "
            "Re-save it as UTF-8 and re-run.",
        )
    except OSError as exc:
        fatal(EXIT_PARSE, f"{label} {p} could not be read: {exc}")
    text = _strip_jsonc_comments(raw)
    try:
        data: Any = json.loads(text)
    except ValueError as exc:
        fatal(
            EXIT_PARSE,
            f"{label} {p} exists but is not valid JSON: {exc}",
            "Nothing was merged and the file was NOT modified. Common causes: a trailing "
            "comma, a '/* */' block comment, or a truncated write. Fix it and re-run.",
        )
    if not isinstance(data, dict):
        fatal(
            EXIT_SHAPE,
            f"{label} {p} must hold a JSON object at the top level, found "
            f"{type(data).__name__}.",
        )
    return data, text != raw


def _escape_char(match: re.Match) -> str:
    cp = ord(match.group())
    if cp > 0xFFFF:
        cp -= 0x10000
        return "\\u%04x\\u%04x" % (0xD800 | (cp >> 10), 0xDC00 | (cp & 0x3FF))
    return "\\u%04x" % cp


def to_json_text(obj: Any) -> str:
    """The settings file's text: indented JSON in UTF-8 form, ESCAPED_CHARS escaped."""
    return ESCAPED_CHARS.sub(_escape_char, json.dumps(obj, indent=2, ensure_ascii=False)) + "\n"


def disables_all_hooks(settings: dict) -> bool:
    """Whether settings sets disableAllHooks to anything but an off value (config-guard (1))."""
    return "disableAllHooks" in settings and settings["disableAllHooks"] not in DISABLE_ALL_HOOKS_OFF


def strip_comments(obj):
    """Drop the template's own '_comment*' documentation keys."""
    if isinstance(obj, dict):
        return {k: strip_comments(v) for k, v in obj.items() if not str(k).startswith("_comment")}
    if isinstance(obj, list):
        return [strip_comments(v) for v in obj]
    return obj


def as_object(value: Any, key: str, label: str) -> dict:
    """Coerce an absent value to {}; refuse a wrong-typed one.

    A missing or null key is genuinely absent, so {} loses nothing. A key that
    holds the wrong type does hold consumer data, and quietly replacing it with
    {} is exactly the silent deletion this merge must not perform — so we stop
    and name the key instead.
    """
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    fatal(
        EXIT_SHAPE,
        f'{label} "{key}" must be a JSON object, found {type(value).__name__}.',
        "Refusing to merge: continuing would discard it. Correct the key and re-run.",
    )


def as_rule_list(value: Any, key: str, label: str) -> list:
    """Normalize a permission-rule list. A lone string is a single rule written
    without its array — wrap it (nothing is lost). Any other type is refused."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return list(value)
    fatal(
        EXIT_SHAPE,
        f'{label} "{key}" must be an array of rule strings, found {type(value).__name__}.',
        "Refusing to merge: continuing would discard it. Correct the key and re-run.",
    )


def _dedupe_key(item: Any) -> str:
    """Stable identity for a deny entry. Entries are normally strings; anything
    else is preserved verbatim but still needs a hashable key to de-duplicate on
    (a raw dict/list would raise TypeError against a set)."""
    if isinstance(item, str):
        return item
    return "\0json\0" + json.dumps(item, sort_keys=True, default=str)


def hook_is_baseline(hook: Any) -> bool:
    """True for a hook entry whose command names the baseline hook path. That is
    every entry we installed, and also one hand-wired to our scripts; both are
    treated as ours. Anything with an unexpected shape is somebody else's entry and
    is reported as not-ours, so it is kept rather than replaced."""
    return isinstance(hook, dict) and BASELINE_MARKER in str(hook.get("command", ""))


def without_baseline_hooks(groups: list) -> list:
    """Return an event's existing hook groups with our own hook entries removed.

    Ownership is per hook, not per group: a repo's own hook that shares a matcher
    group with a baseline hook is the consumer's, and dropping the whole group
    deleted it silently. So such a group is kept without our entries, its other
    keys untouched. A group is dropped only when removing our entries left it
    empty — one the consumer already had empty is theirs and is kept. A group with
    no baseline hook, or with a shape we don't recognise (null included), is kept
    as is.
    """
    out = []
    for group in groups:
        hooks = group.get("hooks") if isinstance(group, dict) else None
        if not isinstance(hooks, list):
            out.append(group)
            continue
        kept = [hook for hook in hooks if not hook_is_baseline(hook)]
        if len(kept) == len(hooks):
            out.append(group)
        elif kept:
            out.append({**group, "hooks": kept})
    return out


def merge_hooks(existing_hooks: dict, template_hooks: dict) -> dict:
    out = dict(existing_hooks)
    for event, groups in template_hooks.items():
        if not isinstance(groups, list):
            fatal(
                EXIT_SHAPE,
                f'baseline template "hooks.{event}" must be an array, found '
                f"{type(groups).__name__}.",
            )
        current = out.get(event)
        if current is None:
            current = []
        elif not isinstance(current, list):
            fatal(
                EXIT_SHAPE,
                f'existing settings "hooks.{event}" must be an array, found '
                f"{type(current).__name__}.",
                "Refusing to merge: continuing would discard the repo's own hooks for "
                "that event. Correct the key and re-run.",
            )
        out[event] = without_baseline_hooks(current) + list(groups)
    for event in RETIRED_EVENTS:
        current = out.get(event)
        if event in template_hooks or not isinstance(current, list):
            continue
        kept = without_baseline_hooks(current)
        if kept or not current:
            out[event] = kept
        else:
            del out[event]   # only our entries were there: we emptied it
    return out


def baseline_outside_template(hooks: Any, template_hooks: dict) -> list[str]:
    """Events outside the template (and RETIRED_EVENTS) that still hold a baseline
    hook entry. The merge keeps them as they are; main() reports them."""
    found = []
    if not isinstance(hooks, dict):
        return found
    for event, groups in hooks.items():
        if event in template_hooks or event in RETIRED_EVENTS or not isinstance(groups, list):
            continue
        for group in groups:
            entries = group.get("hooks") if isinstance(group, dict) else None
            if isinstance(entries, list) and any(hook_is_baseline(h) for h in entries):
                found.append(event)
                break
    return found


def merge_deny(existing_perms: dict, template_perms: dict) -> list:
    perms_existing = as_rule_list(existing_perms.get("deny"), "permissions.deny", "existing settings")
    perms_template = as_rule_list(template_perms.get("deny"), "permissions.deny", "baseline template")
    seen, merged = set(), []
    for item in perms_existing + perms_template:
        key = _dedupe_key(item)
        if key not in seen:
            seen.add(key)
            merged.append(item)
    return merged


def baseline_deny(template: dict) -> list[str]:
    """The template's permissions.deny string entries, in order: the deny-list the
    installer merges into settings.json (config-guard's EXPECTED_DENY mirrors it)."""
    perms = template.get("permissions")
    deny = perms.get("deny") if isinstance(perms, dict) else None
    return [d for d in deny if isinstance(d, str)] if isinstance(deny, list) else []


def missing_deny(settings: dict, expected: list[str]) -> list[str]:
    """The expected deny entries absent from settings' permissions.deny, in the order of
    expected. The same rule as config-guard (3): exact strings, only string entries of a
    list under an object (anything else holds none), the parsed object as is (a duplicate
    key is last-wins, as in Claude Code). A rewritten but equivalent glob reads as missing."""
    perms = settings.get("permissions")
    deny = perms.get("deny") if isinstance(perms, dict) else None
    have = {d for d in deny if isinstance(d, str)} if isinstance(deny, list) else set()
    return [d for d in expected if d not in have]


def risky_env_keys(settings: dict) -> list[str]:
    """The keys of settings["env"] that RISKY_ENV_* cover, whatever their value (an
    empty PATH breaks the hook command too), sorted."""
    env = settings.get("env")
    if not isinstance(env, dict):
        return []
    return sorted(
        k for k in env
        if k.upper() in RISKY_ENV_NAMES
        or any(k.upper().startswith(p) for p in RISKY_ENV_PREFIXES)
        or any(s in k.upper() for s in RISKY_ENV_SUBSTRINGS))


def hook_entries(obj: Any):
    """Every {type: command} entry with a string command anywhere under obj."""
    if isinstance(obj, dict):
        if obj.get("type") == "command" and isinstance(obj.get("command"), str):
            yield obj
        for value in obj.values():
            yield from hook_entries(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from hook_entries(item)


def _launched_script(entry: dict, min_timeouts: dict):
    """The script entry runs as BASELINE_LAUNCH with keys that let it run as written
    (no args, bash shell, not async, timeout at least min_timeouts[script] when that is
    a number), else None."""
    m = re.match(BASELINE_LAUNCH, entry["command"])
    if not m:
        return None
    script, timeout = m.group(2), entry.get("timeout")
    want = min_timeouts.get(script)
    if ("args" in entry or entry.get("shell") not in (None, "bash")
            or entry.get("async") or entry.get("asyncRewake")):
        return None
    if _is_number(want) and not (_is_number(timeout) and timeout >= want):
        return None
    return script


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def baseline_timeouts(template: dict) -> dict:
    """{script: timeout} for every baseline script the template launches."""
    return {m.group(2): e.get("timeout") for e in hook_entries(template.get("hooks"))
            for m in [re.match(BASELINE_LAUNCH, e["command"])] if m}


def baseline_launches(settings: dict, min_timeouts: dict | None = None) -> set:
    """The baseline scripts some entry runs exactly as written (_launched_script)."""
    mins = min_timeouts or {}
    return {s for e in hook_entries(settings.get("hooks"))
            for s in [_launched_script(e, mins)] if s}


def baseline_launch_problems(settings: dict, min_timeouts: dict | None = None) -> list[str]:
    """The baseline scripts (path under BASELINE_MARKER) that some entry runs in any
    other way, sorted. An entry naming no script is listed by its command."""
    mins, found = min_timeouts or {}, set()
    for e in hook_entries(settings.get("hooks")):
        if BASELINE_MARKER not in e["command"] or _launched_script(e, mins):
            continue
        found.add(_named_script(e["command"]) or e["command"].strip())
    return sorted(found)


_SCRIPT_AFTER_MARKER = re.compile(r"\S+?\.sh")
_SPACE = re.compile(r"\s")


def _named_script(command: str) -> str | None:
    """The script named right after a BASELINE_MARKER in command, the first that is: the
    result of re.search(re.escape(BASELINE_MARKER) + r"(\\S+?\\.sh)", command), found in
    one pass. When no script follows one marker, none follows a later marker before the
    next whitespace either (the scan from the first already covered that stretch), so
    the search resumes after it."""
    i = command.find(BASELINE_MARKER)
    while i != -1:
        start = i + len(BASELINE_MARKER)
        m = _SCRIPT_AFTER_MARKER.match(command, start)
        if m:
            return m.group(0)
        gap = _SPACE.search(command, start)
        if gap is None:
            return None
        i = command.find(BASELINE_MARKER, gap.end())
    return None


def baseline_blocking(template: dict) -> set[str]:
    """The baseline scripts the template launches under PreToolUse with onFailure:
    "block" (its guards)."""
    hooks = template.get("hooks")
    pre = hooks.get("PreToolUse") if isinstance(hooks, dict) else None
    return {m.group(2) for e in hook_entries(pre)
            for m in [re.match(BASELINE_LAUNCH, e["command"])]
            if m and e.get("onFailure") == "block"}


def _guard_entries(hooks: Any, guards: Iterable[str]) -> tuple[set, set]:
    """(seen, soft): the guards some direct PreToolUse entry of hooks runs, and those of
    them some such entry runs without onFailure: "block". MIRRORS _guard_entries in
    hooks/modules/config-guard.sh (check 2b); a test runs both on one table."""
    pre = hooks.get("PreToolUse") if isinstance(hooks, dict) else None
    seen, soft = set(), set()
    for grp in pre if isinstance(pre, list) else []:
        entries = grp.get("hooks") if isinstance(grp, dict) else None
        for h in entries if isinstance(entries, list) else []:
            if not isinstance(h, dict) or not isinstance(h.get("command"), str):
                continue
            for s in guards:
                if re.search(r"^\s*bash\s.*?" + re.escape(BASELINE_MARKER + s), h["command"]):
                    seen.add(s)
                    if h.get("onFailure") != "block":
                        soft.add(s)
    return seen, soft


def _entry_text(entry: dict) -> str:
    """A command hook entry's command and its string args, joined by spaces."""
    args = entry.get("args") if isinstance(entry.get("args"), list) else []
    return " ".join([entry["command"]] + [a for a in args if isinstance(a, str)])


def baseline_hook_names(settings: dict) -> list[str]:
    """Every baseline script a command hook entry anywhere in settings names in its
    command or args (the script after BASELINE_MARKER, or the stripped text when none
    follows), sorted. For settings.local.json, where the installer never writes one.
    MIRRORS _baseline_named in hooks/modules/config-guard.sh (check 5); a test runs both
    on one table."""
    return sorted({_named_script(t) or t.strip()
                   for t in map(_entry_text, hook_entries(settings.get("hooks")))
                   if BASELINE_MARKER in t})


def baseline_soft_guards(settings: dict, guards: Iterable[str]) -> list[str]:
    """The guards (baseline_blocking) that some direct PreToolUse entry of settings runs
    without onFailure: "block", sorted. Whether a guard is wired there at all is
    baseline_wiring_problems' to report."""
    return sorted(_guard_entries(settings.get("hooks"), guards)[1])


def _matcher_covers(grp: dict, wired: str | None) -> bool:
    """True only when hook group grp certainly runs for every value a template group with
    matcher `wired` (None: every value) runs for. MIRRORS _matcher_covers in
    hooks/modules/config-guard.sh, which explains it; a test runs both on one table."""
    if "matcher" not in grp:
        return True
    m = grp["matcher"]
    if m in ("", "*"):
        return True
    if wired is None or not isinstance(m, str) or not re.fullmatch(r"[A-Za-z0-9_|-]+", m):
        return False
    return set(wired.split("|")) <= set(m.split("|"))


def baseline_wiring(template: dict) -> list[tuple]:
    """(script, event, group matcher or None) for every template group entry that runs a
    baseline script (BASELINE_LAUNCH), sorted. A match-all or non-string matcher reads as
    None (only a match-all matcher then covers the row)."""
    rows = set()
    hooks = template.get("hooks")
    for event, groups in (hooks.items() if isinstance(hooks, dict) else ()):
        for grp in groups if isinstance(groups, list) else ():
            if not isinstance(grp, dict):
                continue
            wired = grp.get("matcher")
            wired = wired if isinstance(wired, str) and wired not in ("", "*") else None
            for e in hook_entries(grp.get("hooks")):
                m = re.match(BASELINE_LAUNCH, e["command"])
                if m:
                    rows.add((m.group(2), event, wired))
    return sorted(rows, key=lambda r: (r[0], r[1], r[2] or ""))


def _wired_at(hooks: dict, script: str, event: str, wired: str | None) -> bool:
    """Some group under hooks[event] whose matcher covers `wired` holds, as a direct
    entry, a command running script (right after its first BASELINE_MARKER, the name
    ending where a path word ends) with no `if`. MIRRORS _wired_at in
    hooks/modules/config-guard.sh (check 2d); a test runs both on one table."""
    marker = re.escape(BASELINE_MARKER)
    runs = re.compile(r"^\s*bash\s(?:(?!" + marker + r").)*" + marker
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


def baseline_wiring_problems(settings: dict, wiring: list) -> list[tuple]:
    """The rows of wiring (baseline_wiring) that settings does not wire (_wired_at)."""
    hooks = settings.get("hooks")
    hooks = hooks if isinstance(hooks, dict) else {}
    return [row for row in wiring if not _wired_at(hooks, *row)]


def main() -> int:
    if len(sys.argv) != 4:
        sys.stderr.write("usage: merge_settings.py <existing|-> <template> <output>\n")
        return 2

    existing, had_comments = load_noting_comments(sys.argv[1], "existing settings")
    template = strip_comments(load(sys.argv[2], "baseline template"))
    output_path = sys.argv[3]

    merged = dict(existing)
    merged["hooks"] = merge_hooks(
        as_object(existing.get("hooks"), "hooks", "existing settings"),
        as_object(template.get("hooks"), "hooks", "baseline template"),
    )

    existing_perms = as_object(existing.get("permissions"), "permissions", "existing settings")
    template_perms = as_object(template.get("permissions"), "permissions", "baseline template")
    deny = merge_deny(existing_perms, template_perms)
    if deny:
        perms = dict(existing_perms)
        perms["deny"] = deny
        merged["permissions"] = perms

    try:
        Path(output_path).write_text(to_json_text(merged), encoding="utf-8")
    except OSError as exc:
        fatal(EXIT_WRITE, f"could not write merged settings to {output_path}: {exc}")
    # Reports, in this order: disableAllHooks, risky env, comments, outside-template.
    if disables_all_hooks(existing):
        shown = ascii(existing["disableAllHooks"])
        shown = shown if len(shown) <= 200 else shown[:200] + "..."
        sys.stderr.write(
            f"WARNING: settings.json sets disableAllHooks={shown}. While Claude Code reads it as "
            "true it runs no hooks except managed ones, so none of the baseline's hooks run. "
            "Kept as is; remove it unless you set it on purpose.\n")
    # ascii()-escaped: a key name cannot carry control sequences to the terminal.
    risky = [ascii(k)[1:-1] for k in risky_env_keys(existing)]
    if risky:
        sys.stderr.write(
            f"WARNING: settings.json env sets {', '.join(risky)}. Such values can run code "
            "before the baseline hooks, redirect them, or change their posture. Kept as is; "
            "remove them unless you set them on purpose.\n")
    if had_comments:
        sys.stderr.write(
            "NOTE: settings.json has // comments. JSON has no comments, so the merged file "
            "leaves them out; the backup the installer makes before writing keeps them.\n")
    outside = [ascii(e)[1:-1] for e in
               baseline_outside_template(merged["hooks"], as_object(template.get("hooks"), "hooks", "baseline template"))]
    if outside:
        sys.stderr.write(
            f"NOTE: settings.json wires baseline scripts under {', '.join(outside)}, which the "
            "baseline template does not use. Kept as is; remove them unless you wired them on "
            "purpose.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
