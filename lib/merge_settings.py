#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Merge the baseline settings fragment into a target repo's .claude/settings.json.

Usage: merge_settings.py <existing.json|-> <template.json> <output.json>

Rules:
  * hooks: for every event present in the template, drop any existing hook group
    that references a baseline command (".../.claude/hooks/baseline/"), then append
    the template's groups. Non-baseline groups are preserved. This makes re-running
    the installer idempotent — baseline entries are replaced, not duplicated.
  * permissions.deny: union with the existing list (order-preserving, de-duplicated).
  * Everything else in the existing file (model, permissions.allow, env, ...) is
    left exactly as it was.

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
import sys
from pathlib import Path
from typing import Any, NoReturn

BASELINE_MARKER = "/.claude/hooks/baseline/"

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
    if path == "-":
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    try:
        # utf-8-sig accepts plain UTF-8 too; it only strips a BOM if one is there.
        raw = p.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        fatal(
            EXIT_PARSE,
            f"{label} {p} is not UTF-8 text: {exc}",
            "If it was written by PowerShell '>' redirection it is probably UTF-16 — "
            "re-save it as UTF-8 and re-run.",
        )
    except OSError as exc:
        fatal(EXIT_PARSE, f"{label} {p} could not be read: {exc}")
    try:
        data: Any = json.loads(_strip_jsonc_comments(raw))
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
    return data


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


def group_is_baseline(group: Any) -> bool:
    """True only for a hook group we ourselves installed. Anything with an
    unexpected shape is somebody else's entry and is reported as not-ours, so it
    is kept rather than replaced."""
    if not isinstance(group, dict):
        return False
    hooks = group.get("hooks")
    if not isinstance(hooks, list):
        return False
    for hook in hooks:
        if isinstance(hook, dict) and BASELINE_MARKER in str(hook.get("command", "")):
            return True
    return False


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
        kept = [g for g in current if not group_is_baseline(g)]
        out[event] = kept + list(groups)
    return out


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


def main() -> int:
    if len(sys.argv) != 4:
        sys.stderr.write("usage: merge_settings.py <existing|-> <template> <output>\n")
        return 2

    existing = load(sys.argv[1], "existing settings")
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
        Path(output_path).write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        fatal(EXIT_WRITE, f"could not write merged settings to {output_path}: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
