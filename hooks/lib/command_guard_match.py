#!/usr/bin/env python3
"""claude-code-baseline :: command-guard matcher (R2).

Reads a Claude Code tool payload (JSON) on stdin and the baseline config path as
argv[1]. Prints a human-readable block reason to stdout if the proposed shell
command matches a destructive / unapproved pattern, or nothing if it is allowed.
ALWAYS exits 0 (command-guard.sh treats a non-zero exit as "matcher failed ->
fail closed"); on an internal error it prints a line starting with __MATCHER_ERROR__.

Design (R2, hardened after adversarial review):
  * Normalize: lowercase; strip quotes (' ") and backslashes; collapse whitespace.
  * Split the command on shell operators (; && || | & newline) into sub-commands;
    each sub-command is judged INDEPENDENTLY (no whole-string segment, which used
    to cross-contaminate `git push … && rm -f …` style compounds).
  * Detection is anchored to each sub-command's COMMAND WORD (after skipping
    wrappers: env/sudo/time/nice/xargs/VAR=val, and sh/bash -c). So `echo "git
    reset --hard"` and `grep "delete from"` are NOT blocked, while `git reset
    --hard` and `psql -c 'drop table'` are.
  * Delete targets are CANONICALIZED (collapse //, resolve /., strip leading ./
    and trailing /) before the catastrophic-target check, so `//`, `/./`, `./*`,
    `$HOME/` are caught — but a targeted `rm -rf ./build` stays allowed.

This is BEST-EFFORT, defense-in-depth — not an evasion-proof boundary. It cannot
see through encoding (base64), arbitrary variable indirection (only the literal
$HOME/${HOME} home tokens are caught), or runtime aliases.
"""
from __future__ import annotations

import json
import re
import sys

# Catastrophic delete "roots" (after canonicalization). Targeted paths are allowed.
_DANGER_ROOTS = {"/", ".", "*", "~", "$home", "${home}", "/*"}

# Command-position wrappers to skip when finding the effective command word.
_WRAPPERS = {"env", "sudo", "doas", "time", "nice", "ionice", "nohup", "setsid",
             "stdbuf", "xargs", "command", "builtin", "exec", "then", "do", "else"}
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "fish"}
_SQL_RUNNERS = {"psql", "mysql", "mariadb", "mysqlsh", "sqlite3", "sqlite", "sqlcmd",
                "mongo", "mongosh", "cqlsh", "clickhouse-client", "cockroach", "duckdb"}
_GIT_OPTS_WITH_ARG = {"-c", "-C", "--git-dir", "--work-tree", "--namespace",
                      "--exec-path", "--super-prefix"}


def _find_key(obj, key):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key and isinstance(v, str):
                return v
            r = _find_key(v, key)
            if r:
                return r
    elif isinstance(obj, list):
        for item in obj:
            r = _find_key(item, key)
            if r:
                return r
    return ""


def _normalize(raw: str) -> str:
    s = raw.lower().replace('"', " ").replace("'", " ").replace("\\", " ")
    return re.sub(r"\s+", " ", s).strip()


def _is_danger_target(tok: str) -> bool:
    if not tok:
        return False
    t = re.sub(r"/{2,}", "/", tok)            # // /// -> /
    if t in _DANGER_ROOTS:
        return True
    while t.startswith("./") and len(t) > 2:  # ./* -> *, ./foo -> foo
        t = t[2:]
    if t in _DANGER_ROOTS:
        return True
    if len(t) > 1 and t.endswith("/"):        # ~/ -> ~, $home/ -> $home, ./ -> .
        t = t.rstrip("/") or "/"
        if t in _DANGER_ROOTS:
            return True
    t = re.sub(r"(/\.)+$", "", t) or "/"      # /. -> /, /./ (post-strip /.) -> /
    return t in _DANGER_ROOTS


def _effective_cmd_index(toks):
    """Index of the effective command word, skipping wrappers and VAR=val prefixes."""
    i, n = 0, len(toks)
    while i < n:
        t = toks[i]
        base = t.split("/")[-1]
        if re.match(r"^[a-z_][a-z0-9_]*=", t):      # VAR=val environment prefix
            i += 1; continue
        if base in _WRAPPERS:
            i += 1; continue
        if base in _SHELLS:                          # sh/bash -c '<inline cmd>'
            i += 1
            if i < n and toks[i].startswith("-"):
                i += 1                               # skip -c/-lc; inline command follows
            continue
        if t.startswith("-"):                        # stray leading flag
            i += 1; continue
        return i
    return None


def _git_subcommand(args):
    i = 0
    while i < len(args):
        a = args[i]
        if not a.startswith("-"):
            return a, args[i + 1:]
        if a in _GIT_OPTS_WITH_ARG:
            i += 2; continue
        i += 1
    return None, []


def _first_positional(args):
    for a in args:
        if not a.startswith("-"):
            return a
    return None


def _has_force_flag(args) -> bool:
    for a in args:
        if a.startswith("--"):
            if a.split("=", 1)[0] in ("--force", "--force-with-lease"):
                return True  # bare or =value form (--force-with-lease=main)
        elif a.startswith("-") and len(a) > 1 and "f" in a[1:]:
            return True  # short-flag bundle containing f, in any position (-f, -fv, -vf)
    return False


def _reasons_for(seg: str):
    out = []
    toks = seg.split(" ")
    idx = _effective_cmd_index(toks)
    if idx is None:
        return out
    cmd = toks[idx].split("/")[-1]
    args = toks[idx + 1:]

    if cmd == "rm":
        recursive = force = target = False
        for a in args:
            if a.startswith("--"):
                recursive = recursive or a == "--recursive"
                force = force or a == "--force"
            elif a.startswith("-") and len(a) > 1:
                recursive = recursive or "r" in a[1:]
                force = force or "f" in a[1:]
            elif _is_danger_target(a):
                target = True
        if recursive and force and target:
            out.append("recursive force-delete of a root/cwd/home target (rm -rf)")

    elif cmd == "git":
        sub, sargs = _git_subcommand(args)
        if sub == "push" and _has_force_flag(sargs):
            out.append("forced git push is forbidden")
        elif sub == "reset" and "--hard" in sargs:
            out.append("hard git reset is forbidden")

    elif cmd in ("curl", "wget"):
        if re.search(r"[a-z][a-z0-9+.\-]*://", seg):  # require a real scheme://, not bare "http"
            out.append("direct remote fetch with curl/wget is forbidden")

    elif cmd in ("npm", "pnpm"):
        if _first_positional(args) in ("install", "i", "add"):
            out.append("package installation requires explicit approval")
    elif cmd == "yarn":
        if _first_positional(args) == "add":
            out.append("package installation requires explicit approval")
    elif cmd in ("pip", "pip3"):
        if _first_positional(args) == "install":
            out.append("package installation requires explicit approval")
    elif cmd in ("python", "python3"):
        m_pip = ("-m" in args and "pip" in args) or any(a == "-mpip" for a in args)
        if m_pip and "install" in args:
            out.append("package installation requires explicit approval")

    # SQL only when the command word is a known SQL client (so non-SQL tools that
    # use -c/-e like grep/sed/awk/perl are not blocked on a keyword substring).
    # `sh -c 'psql ...'` still fires because the inline command re-splits to psql.
    if cmd in _SQL_RUNNERS:
        if "drop table" in seg or "truncate table" in seg:
            out.append("dangerous SQL (drop/truncate table)")
        if "delete from" in seg:
            out.append("potentially destructive SQL (delete from)")

    return out


def evaluate(raw: str, extra_patterns=()):
    """Return the list of block reasons for a raw command string (+ optional query).
    Pure function — no I/O — so it is directly unit-testable."""
    norm = _normalize(raw)
    if not norm:
        return []
    # Each sub-command judged independently — NO whole-string segment.
    segments = [p.strip() for p in re.split(r"[;|&\n]+", norm) if p.strip()]
    reasons = []
    for seg in segments:
        for r in _reasons_for(seg):
            if r not in reasons:
                reasons.append(r)
    for p in extra_patterns or ():
        if isinstance(p, str) and p.strip() and p.strip().lower() in norm and \
                f"matched repo policy pattern: {p.strip()}" not in reasons:
            reasons.append(f"matched repo policy pattern: {p.strip()}")
    return reasons


def main() -> int:
    cfg_path = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        data = json.load(sys.stdin)
    except Exception as exc:  # payload should be pre-validated; be defensive anyway
        print(f"__MATCHER_ERROR__ payload parse failed: {exc}")
        return 0

    raw = " ".join(x for x in (_find_key(data, "command"), _find_key(data, "query")) if x)

    extra = []
    try:
        if cfg_path:
            with open(cfg_path, encoding="utf-8") as fh:
                cfg = json.load(fh)
            extra = (((cfg.get("guardrails") or {}).get("commandGuard") or {}).get("extraPatterns") or [])
    except Exception:
        extra = []  # extraPatterns are optional; core rules still evaluated

    reasons = evaluate(raw, extra)
    if reasons:
        print("; ".join(reasons))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
