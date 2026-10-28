#!/usr/bin/env python3
"""claude-code-baseline :: command-guard matcher (R2).

Reads a Claude Code tool payload (JSON) on stdin and the baseline config path as
argv[1]. Prints a human-readable block reason to stdout if the proposed shell
command matches a destructive / unapproved pattern, or nothing if it is allowed.
ALWAYS exits 0 (command-guard.sh treats a non-zero exit as "matcher failed ->
fail closed"); on an internal error it prints a line starting with __MATCHER_ERROR__.

Design (R2, rewritten after adversarial review -- the previous string-munging
normalizer was defeated by ordinary shell quoting):
  * Size cap FIRST: a command longer than _MAX_INSPECT_LEN is not parsed at all,
    it is blocked as uninspectable. Parsing is linear here, but a guard that can
    be made slow can be made to hit the hook timeout, and a timed-out PreToolUse
    hook never emits exit 2 -- it fails OPEN. A cheap cap beats a clever parser.
  * Split on UNQUOTED NEWLINES, before any whitespace handling, so a two-line
    "cd /tmp" + "rm -rf /" payload is two commands, not one. A newline inside a
    quoted string is part of the string, and a trailing backslash continues the
    line, so a multi-line commit message, PR body or backslash-continued command is one
    command -- splitting those on every newline used to block them as unbalanced.
    A logical line that spans several physical lines is also inspected piecewise:
    every physical line, and every chain of continued lines ignoring quotes and
    comments, each read with its quotes deleted and with quotes kept. This quote
    scanner does not model bash comments, the fresh quoting context inside "$(...)",
    $'...' strings or heredoc bodies, and a divergence there could otherwise pass a
    real command off as part of a string; the quote-blind pass still inspects it,
    including a `bash -c "..."` script on that line. A command whose every line
    already tokenizes on its own is evaluated exactly as before.
  * Real tokenization per line via shlex(posix=True): quotes are REMOVED and
    backslash escapes are RESOLVED, so quote-splicing (--fo"rce", r''m) and
    escape-splicing (-r\f) tokenize to their bare equivalents instead of being
    shredded into extra tokens by a blind quote-to-space substitution.
  * Unbalanced quoting raises ValueError -> the command cannot be seen -> BLOCK
    ("uninspectable"). Never silently allow something that could not be parsed.
  * ${IFS} / $IFS are expanded to a space before tokenizing (rm${IFS}-rf${IFS}/).
  * Sub-commands: each segment between ; && || | & ( ) ` < > is judged
    INDEPENDENTLY (no whole-string segment, which used to cross-contaminate
    "git push ... && rm -f ..." style compounds). Grouping/negation punctuation
    ( { } ! ) is stripped, so a subshell or brace group is inspected like a bare
    command.
  * Detection is anchored to each sub-command's COMMAND WORD (after skipping
    wrappers: env/sudo/time/nice/xargs/busybox/VAR=val, shell keywords
    (if/while/for/then/do/else), and sh/bash -c). So `echo "git reset --hard"`
    and `grep "delete from"` are NOT blocked, while `git reset --hard` and
    `psql -c 'drop table'` are.
  * The command word is normalized like a path: split on BOTH / and \\ (Git Bash
    / Windows) with a trailing .exe/.cmd/.bat/.com stripped, so a "git.exe" or
    "C:/tools/rm.exe" invocation is matched like its bare equivalent.
  * A command word that is itself a shell expansion ($CMD, ${CMD}, or the bare $
    left behind by $(...)) is uninspectable -> BLOCK.
  * Delete targets are CANONICALIZED (collapse //, resolve /., strip leading ./,
    trailing /, and the /* and /.* globs) before the catastrophic-target check,
    so //, /./, ./*, ~/*, $HOME/* and .. are caught -- but a targeted
    `rm -rf ./build` stays allowed.

This is BEST-EFFORT, defense-in-depth -- not an evasion-proof boundary. It cannot
see through encoding (base64), arbitrary variable indirection (only the literal
$HOME/${HOME} home tokens are caught), or runtime aliases. Two residual limits of
the tokenizer itself, stated here rather than claimed away elsewhere: POSIX escape
resolution consumes backslashes, so an *unquoted* Windows path is only recovered
for drive-letter/UNC forms (see _slashify_windows_paths); and a shell separator
inside a quoted string still ends a segment -- conservative, so it can over-block
a quoted sentence but never under-block a real command. Multi-line limits: the
second, quote-blind pass over a multi-line string blocks a line of it that STARTS
with a blocked command (a commit body line "git push --force ..."), or that names
one in backticks ("Run `npm install` first" -- right for a plain -m "...", where
bash runs it, a false positive inside a <<'EOF' heredoc body); an odd number of
double quotes inside a "$(cat <<'EOF' ...)" body, or an unbalanced quote in a
top-level heredoc body, still fails to tokenize and is blocked.
"""
from __future__ import annotations

import json
import re
import shlex
import sys

# Hard input cap. Anything larger is blocked unparsed (see docstring; review S1).
_MAX_INSPECT_LEN = 4096
# Cap on the text the continuation-chain pass may build from one command (it is
# quadratic in the length of a run of continued lines). Past it: BLOCK.
_MAX_CHAIN_CHARS = 131072

# Catastrophic delete "roots" (after canonicalization). Targeted paths are allowed.
_DANGER_ROOTS = {"/", ".", "..", "*", "~", "$home", "${home}", "/*"}

# Command-position wrappers and shell keywords to skip when finding the effective
# command word. then/do/else were already here; the LEADING halves (if/while/for)
# were the uncovered side, which let an `if <destructive>; then :; fi` form through.
_WRAPPERS = {"env", "sudo", "doas", "time", "nice", "ionice", "nohup", "setsid",
             "stdbuf", "xargs", "command", "builtin", "exec", "busybox", "toybox",
             "if", "elif", "then", "while", "until", "for", "do", "else", "fi",
             "done", "esac"}
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "fish"}
_SQL_RUNNERS = {"psql", "mysql", "mariadb", "mysqlsh", "sqlite3", "sqlite", "sqlcmd",
                "mongo", "mongosh", "cqlsh", "clickhouse-client", "cockroach", "duckdb"}
_GIT_OPTS_WITH_ARG = {"-c", "-C", "--git-dir", "--work-tree", "--namespace",
                      "--exec-path", "--super-prefix"}

# Long options are matched by PREFIX: git accepts unambiguous abbreviations, so a
# truncated --force-w or --har is the same request as the full flag (review S2).
_PUSH_FORCE_LONGS = ("--force", "--force-with-lease", "--force-if-includes")
_RESET_HARD_LONGS = ("--hard",)

# Short options that CONSUME THE NEXT ARGUMENT, per fetch tool. Needed so the
# bare-host rule below does not mistake `-d payload.json` / `-i list.txt` for a
# download target. Deliberately per-tool: curl's -i takes no value, wget's does.
_CURL_VALUE_SHORTS = set("bcCdDeEFHKmoQrtTuUwxXyYzA")
_WGET_VALUE_SHORTS = set("iOoPTtQUeBDIXARC")
# Long options that consume the next argument. --url is deliberately EXCLUDED:
# its value is exactly the fetch target the bare-host rule needs to see.
_FETCH_VALUE_LONGS = {"--data", "--data-raw", "--data-binary", "--data-urlencode",
                      "--header", "--form", "--output", "--user", "--user-agent",
                      "--referer", "--cookie", "--cookie-jar", "--config",
                      "--input-file", "--output-document", "--directory-prefix",
                      "--proxy", "--range", "--write-out", "--max-time",
                      "--connect-timeout", "--upload-file"}
# host[.tld][:port][/path] with no scheme -- curl/wget default to HTTP, so a bare
# host is still a remote fetch. One unbounded class (no nested quantifier) on purpose.
_BARE_HOST_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}(?::[0-9]+)?(?:/.*)?$")

# Shell operators that end a sub-command. Backtick and parens are included so a
# command substitution's BODY is judged as its own segment.
_SEP_SPLIT_RE = re.compile(r"([;|&()`<>]+)")
_SEP_ONLY_RE = re.compile(r"^[;|&()`<>]+$")
# Group-opening / negation punctuation, stripped from the LEFT of a token only:
# an rstrip would eat the closing brace of ${HOME} and destroy the home target.
_LEAD_GROUP_CHARS = "{!"

# Drive-letter (C:\dir\tool.exe) and UNC (\\host\share\tool.exe) paths only. POSIX
# tokenization would otherwise eat those separators; a single character class keeps
# this linear (no backtracking), unlike a nested (?:[^\\]+\\)+ form.
_WINPATH_RE = re.compile(r"(?i)(?:[a-z]:\\|\\\\)[^\s\"'|&;()<>]*")

# A PowerShell here-string opener: @' or @" as the last thing on a line.
_PS_HERESTRING_RE = re.compile(r"@['\"]\s*$")


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


def _slashify_windows_paths(line: str) -> str:
    r"""Rewrite \ to / inside drive-letter/UNC paths, before shlex consumes them."""
    return _WINPATH_RE.sub(lambda m: m.group(0).replace("\\", "/"), line)


def _expand_ifs(line: str) -> str:
    """${IFS} is a space. Expanded pre-tokenization, so the command really splits."""
    return line.replace("${IFS}", " ").replace("$IFS", " ")


def _cmd_word(tok: str) -> str:
    r"""Basename of a command token: path-split on / and \, strip a .exe-class suffix."""
    base = re.split(r"[\\/]", tok)[-1]
    return re.sub(r"\.(exe|cmd|bat|com)$", "", base)


def _is_danger_target(tok: str) -> bool:
    if not tok:
        return False
    t = re.sub(r"/{2,}", "/", tok)                # // /// -> /
    # Bounded peel loop, re-testing after every step. Replaces the old
    # re.sub(r"(/\.)+$", "", t), whose nested quantifier backtracked
    # catastrophically on /././././...x (review S1: 40k pairs = 16.5 s against a
    # 10 s hook timeout -- i.e. a computable fail-open).
    for _ in range(len(t) + 1):
        if t in _DANGER_ROOTS:
            return True
        if t.startswith("./") and len(t) > 2:     # ./* -> *, ./foo -> foo
            t = t[2:]
            continue
        if t.endswith("/.*") and len(t) >= 3:     # ~/.* -> ~, /.* -> /
            t = t[:-3] or "/"
            continue
        if t.endswith("/*") and len(t) > 2:       # ~/* -> ~, $home/* -> $home
            t = t[:-2]
            continue
        if t.endswith("/.") and len(t) >= 2:      # /. -> /, foo/. -> foo
            t = t[:-2] or "/"
            continue
        if t.endswith("/") and len(t) > 1:        # ~/ -> ~, $home/ -> $home, ./ -> .
            t = t[:-1] or "/"
            continue
        break
    return t in _DANGER_ROOTS


def _effective_cmd_index(toks):
    """(index of the effective command word, saw_xargs), skipping wrappers/VAR=val.

    saw_xargs matters because xargs feeds arguments from STDIN: the dangerous
    target never appears in the token list at all, so "no target" has to be read
    as an UNKNOWN target rather than a safe one.
    """
    i, n = 0, len(toks)
    saw_xargs = False
    while i < n:
        t = toks[i]
        base = _cmd_word(t)
        if re.match(r"^[a-z_][a-z0-9_]*=", t):      # VAR=val environment prefix
            i += 1; continue
        if base in _WRAPPERS:
            saw_xargs = saw_xargs or base == "xargs"
            i += 1; continue
        if base in _SHELLS:                          # sh/bash -c '<inline cmd>'
            i += 1
            if i < n and toks[i].startswith("-"):
                i += 1                               # skip -c/-lc; inline command follows
            continue
        if t.startswith("-"):                        # stray leading flag
            i += 1; continue
        return i, saw_xargs
    return None, saw_xargs


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


def _matches_long(arg: str, longs) -> bool:
    """True if arg is one of longs, or an abbreviated prefix form of one."""
    head = arg.split("=", 1)[0]
    if len(head) <= 2 or not head.startswith("--"):
        return False
    return any(long_opt.startswith(head) for long_opt in longs)


def _has_force_flag(args) -> bool:
    for a in args:
        if a.startswith("--"):
            if _matches_long(a, _PUSH_FORCE_LONGS):
                return True  # bare, abbreviated (--force-w) or =value (--force-with-lease=main)
        elif a.startswith("-") and len(a) > 1 and "f" in a[1:]:
            return True  # short-flag bundle containing f, in any position (-f, -fv, -vf)
    return False


def _has_force_refspec(args) -> bool:
    """A leading + on a refspec (origin +main) forces the push with no flag at all."""
    for a in args:
        if a.startswith("+") and len(a) > 1:
            return True
    return False


def _fetch_targets(cmd: str, args):
    """Positionals of curl/wget that are not the value of a preceding option."""
    value_shorts = _CURL_VALUE_SHORTS if cmd == "curl" else _WGET_VALUE_SHORTS
    out, skip = [], False
    for a in args:
        if skip:
            skip = False
            continue
        if a.startswith("--"):
            if "=" not in a and a in _FETCH_VALUE_LONGS:
                skip = True
            continue
        if a.startswith("-") and len(a) > 1:
            if a[-1] in value_shorts:               # bundle whose LAST letter takes a value
                skip = True
            continue
        out.append(a)
    return out


def _reasons_for(toks):
    out = []
    seg = " ".join(toks)
    idx, saw_xargs = _effective_cmd_index(toks)
    if idx is None:
        return out
    cmd = _cmd_word(toks[idx])
    args = toks[idx + 1:]

    # A command word that is itself a shell expansion cannot be inspected: the
    # binary that will actually run is not in the payload. Fail closed. (Expansion
    # in ARGUMENT position stays allowed -- see the "known limits" fixtures.)
    if "$" in cmd:
        out.append("uninspectable command word (shell expansion in command position)")
        return out

    if cmd == "rm":
        recursive = force = target = False
        positional = 0
        for a in args:
            if a.startswith("--"):
                recursive = recursive or _matches_long(a, ("--recursive",))
                force = force or _matches_long(a, ("--force",))
            elif a.startswith("-") and len(a) > 1:
                recursive = recursive or "r" in a[1:]
                force = force or "f" in a[1:]
            else:
                positional += 1
                if _is_danger_target(a):
                    target = True
        if recursive and force and target:
            out.append("recursive force-delete of a root/cwd/home target (rm -rf)")
        elif recursive and force and positional == 0 and saw_xargs:
            # Targets arrive on stdin, so they are UNKNOWN -- not absent.
            out.append("recursive force-delete with targets piped from xargs "
                       "(unknown scope)")

    elif cmd == "git":
        sub, sargs = _git_subcommand(args)
        if sub == "push" and _has_force_flag(sargs):
            out.append("forced git push is forbidden")
        elif sub == "push" and _has_force_refspec(sargs):
            out.append("forced git push via +refspec is forbidden")
        elif sub == "reset" and any(_matches_long(a, _RESET_HARD_LONGS) for a in sargs):
            out.append("hard git reset is forbidden")

    elif cmd == "find":
        # find deletes without ever naming a delete command word: -delete, or
        # -exec/-execdir rm. Scoped to catastrophic roots so a targeted
        # `find ./build -name "*.o" -delete` stays allowed.
        deletes = "-delete" in args or (
            any(a in ("-exec", "-execdir") for a in args)
            and any(_cmd_word(a) == "rm" for a in args))
        if deletes:
            # `find [path...] [expression]`: only the LEADING non-flag tokens are
            # paths. Scanning every positional would mistake the value of -name
            # ('*.tmp') for a search root and miss the implicit-cwd form.
            paths = []
            for a in args:
                if a.startswith("-"):
                    break
                paths.append(a)
            # No path at all means find walks the cwd tree -> unknown/dangerous.
            if not paths or any(_is_danger_target(p) for p in paths):
                out.append("recursive delete via find (-delete / -exec rm) on a "
                           "root/cwd/home target")

    elif cmd in ("curl", "wget"):
        if re.search(r"[a-z][a-z0-9+.\-]*://", seg):   # explicit scheme://
            out.append("direct remote fetch with curl/wget is forbidden")
        elif any(_BARE_HOST_RE.match(t) for t in _fetch_targets(cmd, args)):
            # curl/wget default to HTTP, so a scheme-less host is still a fetch.
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
    # `sh -c "psql ..."` still fires because the inline command re-splits to psql.
    if cmd in _SQL_RUNNERS:
        if "drop table" in seg or "truncate table" in seg:
            out.append("dangerous SQL (drop/truncate table)")
        if "delete from" in seg:
            out.append("potentially destructive SQL (delete from)")

    return out


def _split_inline_script(toks):
    """Split `sh -c "<script>"` into (outer tokens, inline script string).

    POSIX tokenization keeps the quoted script as ONE word, so its command word
    would be the whole string and no rule could anchor to it. The script token is
    REMOVED from the outer segment so it is not judged twice -- and so a `$` inside
    it is not mistaken for an expansion in command-word position.
    """
    shell_at = None
    for i, t in enumerate(toks):
        if _cmd_word(t) in _SHELLS:
            shell_at = i
            break
    if shell_at is None:
        return toks, None
    for j in range(shell_at + 1, len(toks)):
        t = toks[j]
        if not t.startswith("-"):
            break                                  # `sh script.sh`: not an inline -c
        if "c" in t[1:] and j + 1 < len(toks):      # -c, -lc, -xc ...
            return toks[:j + 1] + toks[j + 2:], toks[j + 1]
    return toks, None


def _scan_line(line: str, state: str, ps_herestrings: bool = False):
    """Advance the quote state across one physical line, exactly as shlex(posix) reads it.

    state is "" (unquoted), "'" or '"'. Backslash escapes the next character outside
    single quotes (shlex posix: inside double quotes it consumes the next character
    too, so an escaped quote never closes the string). No comment handling, because
    shlex.split(comments=False) has none either. Returns (state, continued, here_at):
    continued is True when the line ends in an unescaped backslash outside single
    quotes, a line continuation; here_at is the index of a PowerShell here-string
    opener (@' or @" ending the line in unquoted state), if ps_herestrings is set.
    """
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if state == "'":
            if c == "'":
                state = ""
        elif c == "\\":
            if i + 1 >= n:
                return state, True, None
            i += 1                                   # escaped char cannot open/close
        elif state == '"':
            if c == '"':
                state = ""
        elif ps_herestrings and c == "@" and _PS_HERESTRING_RE.match(line, i):
            return state, False, i
        elif c in "'\"":
            state = c
        i += 1
    return state, False, None


def _logical_lines(text: str, shell: str = "bash"):
    """Split on UNQUOTED newlines. Returns [(logical_line, physical_lines)].

    A physical line that ends inside an open quote is joined to the next with the
    newline kept (it is part of the string); one that ends in a continuation
    backslash is joined with the backslash-newline removed, as bash does. For a
    PowerShell payload, an @'...'@ / @"..."@ here-string becomes one POSIX
    single-quoted word; an unterminated one is left raw, so it fails to tokenize and
    is blocked. Split points are str.splitlines()'s, the same as before this change,
    so a command whose every line already tokenizes yields logical == physical lines.
    """
    phys = text.splitlines()
    ps = shell == "powershell"
    out, i, n = [], 0, len(phys)
    while i < n:
        parts, members, state, cont = [], [], "", False
        while i < n:
            line = phys[i]
            i += 1
            members.append(line)
            while True:
                start = state
                state, cont, here_at = _scan_line(line, start, ps)
                if here_at is None:
                    break
                close = line[here_at + 1] + "@"      # '@ or "@, at the start of a line
                j = i
                while j < n and not phys[j].startswith(close):
                    j += 1
                if j >= n:                           # unterminated: leave it raw
                    state, cont, _ = _scan_line(line, start, False)
                    break
                members.extend(phys[i:j + 1])
                body = "\n".join(phys[i:j]).replace("'", "'\"'\"'")
                parts.append(line[:here_at] + "'" + body + "'")
                line, i, state = phys[j][2:], j + 1, ""
            if cont:
                parts.append(line[:-1])
                continue
            parts.append(line)
            if not state:
                break
            parts.append("\n")
        out.append(("".join(parts), members))
    return out


def _words_to_segments(words):
    """Operator pieces end a segment; group/negation punctuation is stripped."""
    segments, cur = [], []
    for word in words:
        for piece in _SEP_SPLIT_RE.split(word.lower()):
            if not piece:
                continue
            if _SEP_ONLY_RE.match(piece):
                if cur:
                    segments.append(cur)
                cur = []
                continue
            piece = piece.lstrip(_LEAD_GROUP_CHARS)
            if not piece or piece == "}":   # `{ ... ; }` closer: no command meaning
                continue
            cur.append(piece)
    if cur:
        segments.append(cur)
    return segments


def _lenient_words(line: str):
    """One physical line with escapes resolved and every quote character deleted.

    Used only as a second pass over the lines of a multi-line logical line. Deleting
    the quotes makes every separator on the line visible, so a command that bash would
    run is inspected even where the quote scanner took it for part of a string -- the
    scanner does not model comments, the fresh quoting context inside "$(...)", or
    heredoc bodies, and a divergence there must not become a bypass.
    """
    resolved = re.sub(r"\\(.)", r"\1", line)
    return resolved.replace("'", "").replace('"', "").split()


def _segments(raw: str, _depth: int = 0, shell: str = "bash"):
    """Tokenize into independent sub-commands. Raises ValueError if unparseable.

    Returns a list of token lists. The text is split on unquoted newlines (see
    _logical_lines), each logical line is really tokenized (shlex, posix), then
    operator tokens end a segment. A logical line that spans several physical lines
    is ALSO inspected line by line, leniently (see _lenient_words).
    """
    segments, lenient = [], []
    text = _expand_ifs(_slashify_windows_paths(raw))
    for logical, physical in _logical_lines(text, shell):
        if not logical.strip():
            continue
        # ValueError (unbalanced quoting) -> caller blocks
        segments.extend(_words_to_segments(shlex.split(logical, posix=True)))
        if len(physical) > 1:
            # Physical lines, plus every continuation chain regardless of quote
            # state: a desync that leaves the scanner inside a quote also stops it
            # joining `git push \` + newline + `--force`, which bash still joins.
            for line in dict.fromkeys(physical + _cont_chains(physical)):
                for toks in _words_to_segments(_lenient_words(line)):
                    lenient.append(toks)
                    lenient.extend(_lenient_inline(toks))
                # The quote-blind pass resolves backslashes and splits on spaces,
                # which shreds a quoted Windows path ("C:\Program Files\Git\bin\
                # bash.exe" -c ...). Also read the line on its own with quotes kept
                # and backslashes as /, through the main pipeline (inline sh -c
                # recursion included). A line that does not tokenize alone adds
                # nothing; the passes above still cover it.
                try:
                    segments.extend(_words_to_segments(
                        shlex.split(line.replace("\\", "/"), posix=True)))
                except ValueError:
                    pass
    # Re-tokenize inline `sh -c` scripts. Depth-bounded so a nested
    # `sh -c 'sh -c "..."'` chain cannot recurse without limit.
    if _depth < 3:
        expanded = []
        for toks in segments:
            outer, inline = _split_inline_script(toks)
            if outer:
                expanded.append(outer)
            if inline and inline.strip():
                expanded.extend(_segments(inline, _depth + 1))
        segments = expanded
    # Lenient segments skip the inline split: with the quotes deleted, the script
    # of `bash -c "rm -rf ~"` is already bare tokens. Splitting would take only its
    # first word as the script and strand the arguments; _lenient_inline judges
    # every word after the -c instead.
    return segments + lenient


def _lenient_inline(toks):
    """In a quote-blind segment, the words after EVERY shell -c flag, one segment each.

    Judging the segment in place is not enough: a wrapper that takes an argument
    (`timeout 5 bash -c ...`, `sudo -u root bash -c ...`) makes that argument the
    command word. Any short-flag bundle containing c that follows a shell word
    starts a segment -- every one, not just the first, so a nested
    `sh -c "timeout 5 bash -c '...'"` reaches the innermost script, and option
    values (`bash -o pipefail -c ...`) are stepped over. The stricter reading,
    which a quote-blind pass can afford. Segments are whole suffixes, so a script's
    arguments are never cut off. A c-bundle followed directly by another c-bundle
    emits nothing: the later one emits a suffix that _effective_cmd_index, which
    skips leading flags, resolves to the same command word. That keeps a
    `sh -c -c -c ...` payload from emitting one long suffix per flag; the remaining
    worst case is bounded by the input cap.
    """
    out, seen_shell = [], False
    for j, a in enumerate(toks):
        if _cmd_word(a) in _SHELLS:
            seen_shell = True
        elif (seen_shell and _is_c_bundle(a) and j + 1 < len(toks)
              and not _is_c_bundle(toks[j + 1])):
            out.append(toks[j + 1:])
    return out


class _Uninspectable(ValueError):
    """Input the extra passes refuse to expand; evaluate() blocks it."""


def _continues(line: str) -> bool:
    return (len(line) - len(line.rstrip("\\"))) % 2 == 1


def _cont_chains(physical):
    """Every continuation chain: from EACH line, joined with the lines it continues into.

    Quotes are ignored, and so are comments: bash never continues a comment line,
    but whether a `#` starts a comment depends on the quoting this pass does not
    trust. So a chain starts at every line, not only at the first line of a run of
    continued lines -- `echo ok #\\` + `git push \\` + `--force` must yield the
    chain starting at `git push`. That is quadratic in the run length, so the
    joined text is capped and anything past the cap is blocked, never skipped.
    """
    out, total, n = [], 0, len(physical)
    for s in range(n):
        if not _continues(physical[s]):
            continue                     # a lone line is inspected on its own already
        buf, j = "", s
        while j < n and _continues(physical[j]):
            buf += physical[j][:-1]
            j += 1
        chain = buf + (physical[j] if j < n else "")
        total += len(chain)
        if total > _MAX_CHAIN_CHARS:
            raise _Uninspectable(
                f"continued lines too long to inspect (> {_MAX_CHAIN_CHARS} chars joined)")
        out.append(chain)
    return out


def _is_c_bundle(tok: str) -> bool:
    """A short-flag bundle containing c (-c, -lc, -xc), not a --long option."""
    return tok.startswith("-") and not tok.startswith("--") and "c" in tok[1:]


def evaluate(raw: str, extra_patterns=(), shell: str = "bash"):
    """Return the list of block reasons for a raw command string (+ optional query).
    Pure function -- no I/O -- so it is directly unit-testable. shell is "bash" or
    "powershell" (the payload's tool_name); it only enables here-string handling."""
    if raw is None:
        return []
    if len(raw) > _MAX_INSPECT_LEN:
        # Do NOT parse it. A guard that can be made slow can be made to hit the
        # hook timeout, and a timed-out PreToolUse hook fails OPEN.
        return ["command too large to inspect safely "
                f"({len(raw)} chars > {_MAX_INSPECT_LEN})"]
    if not raw.strip():
        return []

    try:
        segments = _segments(raw, shell=shell)
    except _Uninspectable as exc:
        return [f"uninspectable command ({exc})"]
    except ValueError as exc:
        # Unbalanced quoting: the real command words cannot be recovered, so this
        # must not be waved through. Fail closed, like the hook's other
        # "CONTROL COULD NOT RUN" paths.
        return [f"uninspectable command (unbalanced quoting: {exc})"]

    reasons = []
    for toks in segments:
        for r in _reasons_for(toks):
            if r not in reasons:
                reasons.append(r)

    # extraPatterns are documented as case-insensitive SUBSTRING matches. Test them
    # against both the tokenized form (quotes removed, so an ${IFS}-spliced pattern
    # is visible) and the collapsed raw form (so a pattern that spans a shell
    # operator still hits).
    tok_norm = " ; ".join(" ".join(t) for t in segments)
    raw_norm = re.sub(r"\s+", " ", _expand_ifs(raw).lower()).strip()
    for p in extra_patterns or ():
        if not isinstance(p, str) or not p.strip():
            continue
        needle = p.strip().lower()
        label = f"matched repo policy pattern: {p.strip()}"
        if (needle in tok_norm or needle in raw_norm) and label not in reasons:
            reasons.append(label)
    return reasons


def main() -> int:
    cfg_path = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        data = json.load(sys.stdin)
    except Exception as exc:  # payload should be pre-validated; be defensive anyway
        print(f"__MATCHER_ERROR__ payload parse failed: {exc}")
        return 0

    raw = " ".join(x for x in (_find_key(data, "command"), _find_key(data, "query")) if x)
    tool = data.get("tool_name") if isinstance(data, dict) else ""
    shell = "powershell" if str(tool or "").strip().lower() == "powershell" else "bash"

    extra = []
    try:
        if cfg_path:
            with open(cfg_path, encoding="utf-8") as fh:
                cfg = json.load(fh)
            extra = (((cfg.get("guardrails") or {}).get("commandGuard") or {}).get("extraPatterns") or [])
    except Exception:
        extra = []  # extraPatterns are optional; core rules still evaluated

    reasons = evaluate(raw, extra, shell=shell)
    if reasons:
        print("; ".join(reasons))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
