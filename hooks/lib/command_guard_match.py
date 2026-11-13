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
    hook never emits exit 2. Under onFailure:block (Claude Code 2.1.295+) the
    timeout blocks the call; below 2.1.295 it fails OPEN, so the cap still
    matters. A cheap cap beats a clever parser.
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
    including a `bash -c "..."` script on that line, and a separate reading follows
    bash's own comments, heredocs and substitution bodies (see _bash_substitutions).
    A command whose every line
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
  * Wrappers are skipped WITH their option values (`sudo -u root`, `nice -n 10`,
    `timeout 5`, `xargs -n 1`), read both with and without consuming a value so
    a table gap cannot hide the command. `eval`, `watch "..."`, `env -S` (found
    after env's own options; the words after the script run with it),
    `su/script/flock -c` and `bash <<< '...'` are inline scripts like `sh -c`, and
    so is what a Windows runner at the command position runs: `cmd /c|/r|/k`,
    `pwsh|powershell -Command` (and Windows PowerShell's positional command), and
    `wsl` (see _runner_rests); `pwsh -EncodedCommand` is uninspectable -> BLOCK.
    git's global options are read under every reading of which take a value
    (_git_candidates), and its -c push settings are judged.
    A redirection does not end a command (`>/dev/null rm -rf /` is rm), and a
    shell reading its script from a pipe, a here-string or a process substitution
    (`... | sh`, `bash - <<< ...`, `source <(...)`) is uninspectable -> BLOCK, as is
    `eval "$(...)"`, and so is a cmd or PowerShell runner reading its commands from a
    heredoc (`pwsh <<EOF`; see _heredoc_check). An `rm -rf` fed by xargs, directly or
    through an inline script xargs runs, has targets of unknown scope -> BLOCK.
  * The command word is normalized like a path: split on BOTH / and \\ (Git Bash
    / Windows) with a trailing .exe/.cmd/.bat/.com stripped, so a "git.exe" or
    "C:/tools/rm.exe" invocation is matched like its bare equivalent.
  * A command word that is itself a shell expansion ($CMD, ${CMD}, or the bare $
    left behind by $(...)) is uninspectable -> BLOCK.
  * Delete targets are CANONICALIZED (collapse //, resolve /. and name/.., strip
    leading ./, trailing / and /.., and a last component made only of glob syntax
    such as /*, /.*, /** or /[a-z]*) before the catastrophic-target check, so //,
    /./, ./*, ~/*, $HOME/*, .., build/../* and ~/.. are caught, and so are the
    directories bash names with a tilde (~+ the cwd, ~-, ~name) and $PWD/$OLDPWD --
    but a targeted `rm -rf ./build` or `rm -rf build/*` stays allowed.

This is BEST-EFFORT, defense-in-depth -- not an evasion-proof boundary. It cannot
see through encoding (base64), arbitrary variable indirection (only the literal
$HOME/${HOME} home tokens are caught), or runtime aliases. A residual limit of the
tokenizer itself, stated here rather than claimed away elsewhere: POSIX escape
resolution consumes backslashes, so an *unquoted* Windows path is only recovered
for drive-letter/UNC forms (see _slashify_windows_paths), and text holding one is
judged both that way and as the shell reads it (see _segments) -- so multi-line
text (a heredoc commit or PR body, say) with a long run of lines that each end in a
path's backslash (about 90 such lines of a typical path) is refused as a
continuation chain too long to inspect. A quoted separator stays inside its word,
as in bash (see _shell_words), so a `sh -c` script is judged whole and a quoted
sentence is not mistaken for commands; a command substitution inside a
double-quoted argument (`echo "$(...)"`) is judged by a reading of its own body (see
_bash_substitutions), as is a $( ) subexpression in a PowerShell string. Multi-line limits: the
second, quote-blind pass over a multi-line string blocks a line of it that STARTS
with a blocked command (a commit body line "git push --force ..."), or that names
one in backticks ("Run `npm install` first" -- right for a plain -m "...", where
bash runs it, a false positive inside a <<'EOF' heredoc body); an odd number of
double quotes inside a "$(cat <<'EOF' ...)" body, or an unbalanced quote in a
top-level heredoc body, still fails to tokenize and is blocked.

PowerShell payloads are also judged as the text PowerShell produces with its own
quoting, backtick escapes and typographic quotes (so an inline `bash -c` script is
read as PowerShell quotes it, not only as bash would), with PowerShell 7's and
Windows PowerShell 5.1's escapes, with the Unicode space characters PowerShell
separates words on read as spaces, and with a ( ) / $( ) / @( ) group around one word
and every { } read away, so
`git reset ("--hard")` and `& {...}` are judged as the words they become (see
_ps_unescape, _PS_SPACES, _ps_ungroup and _powershell_segments). Limits: a $( )
subexpression holding a nested "..." string is scanned as if the inner quote closed
the outer string (the context-free reading still decodes every escape in it); --%
(stop-parsing) is not modelled, so the text after it is judged decoded as well as
raw, and the raw readings give what the program receives there (for cmd, the text
after it is also read as the script cmd gets: _ps_stop_parsing_cmd_scripts); and PowerShell
cmdlets (Remove-Item ...) are matched by the deny-list only. The context-free reading
decodes escapes inside '...' too, so a single-quoted commit message holding `n
followed by a blocked command at the start of the next line is blocked, the cost the
multi-line pass already accepts for a real newline; a "..." message whose decoded
line starts with one is blocked the same way.
"""
from __future__ import annotations

import functools
import json
import os
import re
import shlex
import sys

# Hard input cap. Anything larger is blocked unparsed (see docstring; review S1).
_MAX_INSPECT_LEN = 4096
# Cap on the text the continuation-chain pass may build from one command (it is
# quadratic in the length of a run of continued lines). Past it: BLOCK.
_MAX_CHAIN_CHARS = 131072
# Cap on the Windows-runner script text one evaluation may tokenize (the readings of
# nested runners multiply; see _runner_segments). Past it: BLOCK.
_MAX_RUNNER_CHARS = 524288
# Levels of inline script (`sh -c`, eval, a Windows runner's command, ...) _segments()
# expands. A segment at the limit that still holds one: BLOCK (see _segments).
_MAX_INLINE_DEPTH = 3

# Catastrophic delete "roots" (after canonicalization). Targeted paths are allowed.
_DANGER_ROOTS = {"/", ".", "..", "*", "~", "$home", "${home}", "/*",
                 "$pwd", "${pwd}", "$oldpwd", "${oldpwd}", "$(pwd)", "`pwd`"}
# ${HOME:?}, ${PWD:-x}, ${OLDPWD#y}: a root parameter with a modifier, read as the bare
# parameter. No nested quantifier; anchored at the start of the word.
_ROOT_PARAM_RE = re.compile(r"^\$\{(home|pwd|oldpwd)[:?#%/=+\-][^}]*\}")

# Command-position wrappers and shell keywords to skip when finding the effective
# command word. then/do/else were already here; the LEADING halves (if/while/for)
# were the uncovered side, which let an `if <destructive>; then :; fi` form through.
_WRAPPERS = {"env", "sudo", "doas", "time", "nice", "ionice", "nohup", "setsid",
             "stdbuf", "xargs", "command", "builtin", "exec", "busybox", "toybox",
             "timeout", "watch", "winpty", "runuser", "chroot", "flock", "coproc",
             "if", "elif", "then", "while", "until", "for", "do", "else", "fi",
             "done", "esac"}
# Wrapper options that CONSUME THE NEXT WORD, per wrapper, so that `sudo -u root rm`
# or `nice -n 10 rm` does not take the option's value for the command word. In a
# short bundle the FIRST listed letter takes the value: the rest of the bundle if
# any (-n10, -uroot), else the next word. Case-exact: xargs -P takes a value, -p
# does not. Options whose value must be glued (--replace=R) are not listed. These
# tables can be wrong or incomplete, so wrapper options are read BOTH ways -- value
# consumed and not -- and a rule that fires on either reading blocks.
_WRAPPER_VALUE_SHORTS = {"sudo": "ughprtCDRTU", "doas": "uC", "nice": "n",
                         "ionice": "cnpP", "timeout": "ks", "env": "uCS",
                         "stdbuf": "ioe", "xargs": "nLPsdEIa", "time": "fo",
                         "exec": "a", "watch": "n", "runuser": "ug", "flock": "wE"}
_WRAPPER_VALUE_LONGS = {
    "sudo": {"--user", "--group", "--host", "--prompt", "--role", "--type", "--chdir",
             "--chroot", "--close-from", "--command-timeout", "--other-user"},
    "nice": {"--adjustment"},
    "ionice": {"--class", "--classdata", "--pid", "--pgid", "--uid"},
    "timeout": {"--kill-after", "--signal"},
    "env": {"--unset", "--chdir", "--split-string"},
    "stdbuf": {"--input", "--output", "--error"},
    "xargs": {"--max-args", "--max-lines", "--max-procs", "--max-chars", "--delimiter",
              "--arg-file"},
    "time": {"--format", "--output"},
    "watch": {"--interval"},
    "runuser": {"--user", "--group"},
    "flock": {"--timeout", "--conflict-exit-code"},
}
# A third reading, "wide": the table above plus these value options. They are kept out of
# the table itself so that its reading stays as it was (an entry there changes which
# word that reading takes for the command, so it could only move blocks, not add them).
# env: GNU -a/--argv0; BSD -P, -L, -U.
_WIDE = "wide"
_WRAPPER_VALUE_SHORTS_WIDE = {"env": "aPLU"}
_WRAPPER_VALUE_LONGS_WIDE = {"env": {"--argv0"}}
# The readings of wrapper options every rule is judged under: values consumed per the
# table, no values consumed, and values consumed per the wider table.
_READINGS = (True, False, _WIDE)
# Wrappers whose leading positionals are arguments, not the command: timeout
# DURATION, chroot NEWROOT, flock LOCKFILE.
_WRAPPER_LEADING_POSITIONALS = {"timeout": 1, "chroot": 1, "flock": 1}
# Commands whose -c / --command value is a shell script: `su -c "..."`,
# `script -c "..."`, `flock -c "..."`, `runuser -c "..."`.
_DASH_C_RUNNERS = {"su", "runuser", "script", "flock"}
# Script paths that mean "read the script from stdin".
_STDIN_PATHS = {"-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"}
# env's options that take a value (GNU -u -C -a; BSD -u -C -P -L -U), as lowercase letters:
# a bundle holding a `/` or a space is lowercased by the tokenizer (see _words_to_segments),
# so env's letters are compared without case. env has no lowercase option they would hide.
_ENV_VALUE_LETTERS = "ucapl"
_ENV_VALUE_LONGS = ("--unset", "--chdir", "--argv0")
# Text appended to the size-cap reasons: Claude Code's long commit and PR bodies are the
# usual way to reach them, and a file is the way around them that keeps the cap.
_FILE_HINT = ("; pass a long commit message or PR body in a file instead: write it with the "
              "Write tool, then use `git commit -F <file>` or `gh pr create --body-file <file>`")
# Shell operators, so a run such as `;>` or `(>` splits into `;` + `>`.
_OP_RE = re.compile(r"&>>?|[<>]&|>>|>\||<<<|<<|<>|\|\||&&|\|&|;;|[;|&()`<>]")
# Shell options that consume the next word: `bash -o pipefail -c ...`.
_SHELL_VALUE_OPTS = ("o", "O")
_SHELL_VALUE_LONGS = {"--rcfile", "--init-file"}
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "fish"}
_SQL_RUNNERS = {"psql", "mysql", "mariadb", "mysqlsh", "sqlite3", "sqlite", "sqlcmd",
                "mongo", "mongosh", "cqlsh", "clickhouse-client", "cockroach", "duckdb"}
_GIT_OPTS_WITH_ARG = {"-c", "-C", "--git-dir", "--work-tree", "--namespace",
                      "--exec-path", "--super-prefix", "--config-env", "--attr-source"}
# A remote's push refspec or mirror switch set for one command (`git -c KEY=VALUE push`).
_GIT_REMOTE_CFG_RE = re.compile(r"^remote\..+\.(push|mirror)$")
# Remote refs whose deletion (`git push --delete main`, `git push origin :main`) is blocked.
# Best effort: the matcher cannot know a repo's default branch, so other names stay allowed.
_PROTECTED_REFS = {"main", "master", "head"}

# Windows runners that take a command line or a command (see _runner_rests).
_PS_RUNNERS = {"pwsh", "powershell"}
# A pwsh/powershell command that reads the runner's stdin itself and turns text into code
# (`$input | iex`), so what is fed to it runs; see _runner_reads_stdin. Reading stdin as
# data (`git diff | pwsh -c '$input | Out-String'`) is not enough.
_PS_STDIN_RE = re.compile(r"\$input\b|console\]::(?:in\b|read)|readtoend|readline"
                          r"|read-host|openstandardinput", re.IGNORECASE)
_PS_EVAL_RE = re.compile(r"\biex\b|invoke-expression|scriptblock\]|newscriptblock"
                         r"|invokescript|add-type\b[^;|]*-typedefinition", re.IGNORECASE)
# Characters pwsh's command-line parser accepts as a switch prefix: -, /, and the dashes.
_PS_SWITCH_CHARS = "-/–—―"
# pwsh / powershell options that take a value, by full name; a switch matches by prefix.
_PS_VALUE_OPTS = ("executionpolicy", "ep", "windowstyle", "inputformat", "outputformat",
                  "configurationname", "configurationfile", "custompipename", "version",
                  "psconsolefile", "workingdirectory", "wd", "settingsfile")
# What may follow a $ word that starts a PowerShell expression statement.
_PS_ASSIGN = {"=", "+=", "-=", "*=", "/=", "%=", "??="}
_PS_EXPR_NEXT = _PS_ASSIGN | {
    "-eq", "-ne", "-gt", "-lt", "-ge", "-le", "-like", "-notlike", "-match", "-notmatch",
    "-replace", "-contains", "-notcontains", "-in", "-notin", "-and", "-or", "-is",
    "-isnot", "-as", "-split", "-join"}
# More binary operators PowerShell accepts after a value: the case-sensitive (-c) and
# explicitly case-insensitive (-i) comparisons, the logical -xor, the bitwise, format and
# arithmetic ones. Not in _PS_EXPR_NEXT, which a runner's script also reads (_rules_at): an
# outer shell may have expanded the $ word there, and an expanded command could take these
# words as its own flags. A script an outer shell is known to expand gets no relaxation at
# all (ps_outer); the narrow set stays as the backstop where that reading cannot tell.
# _ps_statement_tail and _ps_command_mode read them after a variable, and
# _ps_argument_group before a `(` once _ps_command_mode has found no command:
# at the start of a pipeline `-f` is a command name (`$y = -f (` calls -f), which
# _ps_command_mode reads as one.
_PS_CMP = ("eq", "ne", "gt", "lt", "ge", "le", "like", "notlike", "match", "notmatch",
           "replace", "contains", "notcontains", "in", "notin", "split")
_PS_BINARY_MORE = frozenset(
    {"-" + p + op for op in _PS_CMP for p in "ci"}
    | {"-xor", "-band", "-bor", "-bxor", "-shl", "-shr", "-f",
       "+", "-", "*", "/", "%", "..", "??"})
_PS_TOOL_EXPR_NEXT = _PS_EXPR_NEXT | _PS_BINARY_MORE
# A PowerShell number literal (`2`, `-1`, `0x1F`, `1.5e3`, `10kb`, `5L`): a value. Any other
# word that starts with a digit (`7z`) names a command.
_PS_NUMBER_RE = re.compile(
    r"[+-]?(?:0x[0-9a-f]+|0b[01]+|(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?)(?:u?[lsy]|[dnu])?(?:[kmgtp]b)?",
    re.I)
# A word such as `-f` or `-foo` at the start of a pipeline is read as a command name. A unary
# operator (`-not`, `-split`) reads so too: the stricter reading of the `(` after it.
_PS_DASH_NAME_RE = re.compile(r"-[a-z_][\w-]*", re.I)
# A PowerShell tool statement may start with a variable, with member or index steps (see
# _ps_statement_tail). No other scope prefix: `$alias:g`, `$function:g` and `${c:\f}` name
# a provider's item, and assigning one defines a command or writes a file.
_PS_VAR = (r"\$(?:\{[^{}$:]+\}|(?:(?:env|global|script|local|private|using):)?\w+|\?)"
           r"(?:\.\w+|\[[^\]()]*\])*")
_PS_VAR_WORD_RE = re.compile(_PS_VAR + r"(?:\+\+|--)?\}*", re.I)
# `$x=value`, one word: variable, operator, value.
_PS_GLUED_ASSIGN_RE = re.compile("(" + _PS_VAR + r")((?:[-+*/%]|\?\?)?=)(.*)", re.I | re.S)
# `key=value` in a hashtable; the value runs as a pipeline.
_PS_GLUED_KEY_RE = re.compile(r"[^=]*=(.+)", re.S)
# A word up to a value's opening quote: `$x=`, `$a=$b=`, `key=`, after any `{` or `!`.
_PS_VALUE_PREFIX_RE = re.compile(
    "[{!]*(?:(?:" + _PS_VAR + r"(?:[-+*/%]|\?\?)?=)+|\w*=)", re.I | re.S)
# Words that may stand before a statement's variable (_effective_cmd_index skips them).
_PS_STATEMENT_PREFIX = {"-not", "do", "else"}
# A `(` after one of these, at the start of a statement, opens the keyword's own header.
_PS_HEADER_KEYWORDS = {"if", "elseif", "while", "until", "switch", "foreach", "for", "param"}
# Words a brace block's statement can follow once the braces are read away.
_PS_BLOCK_WORDS = {"do", "else", "try", "catch", "finally"}
# A condition's opening keyword, at the start of its statement.
_PS_CONDITION_RE = re.compile(r"(?:^|[;{}\n(|&])\s*(?:if|elseif|while|until|switch)$")
# The word before a method call's `(`: `$x.Run(`, `$a = $b.Run(`.
_PS_CALLED_WORD_RE = re.compile(r"\$.*[\w\]]$", re.S)
# Programs that run what their arguments name: a group passed to one is as uninspectable
# as `sudo $c` (see ps_call on _Seg).
_PS_PROGRAM_RUNNERS = ((_WRAPPERS - {"if", "elif", "then", "while", "until", "for", "do",
                                     "else", "fi", "done", "esac"})
                       | _SHELLS | _PS_RUNNERS | _DASH_C_RUNNERS | {"cmd", "wsl"})
# A dot-invocation glued to a quoted name: `.'git' push`, which _shell_words reads as `.git`.
_PS_DOT_QUOTE_RE = re.compile(r"""(^|[\s;|({=])\.(?=['"])""")
_PS_BLOCK_COMMENT_RE = re.compile(r"<#.*?#>", re.S)
# wsl options that take a value (`wsl -d Ubuntu -u root -- cmd`).
_WSL_VALUE_OPTS = {"-d", "--distribution", "--distribution-id", "-u", "--user", "--cd",
                   "--shell-type"}

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
# A whole word that is an http(s) URL to this machine: localhost, 127.0.0.0/8 or [::1],
# an optional port, then nothing or a path/query/fragment. The authority runs to the
# first `/ ? #` as curl reads it, so anything else in it — `@` (userinfo), `\`, a quote,
# `%`, a brace, whitespace — fails the full match and the word blocks. A brace anywhere
# in the word blocks too: bash brace expansion and curl's own URL glob turn
# `{http://localhost/,https://evil.example/x}` into a second, outside URL, and the
# tokenizer strips the leading `{` (the closing `}` stays). That holds only
# because the words are the real tokens and _WINPATH_RE never rewrites a `\` in the
# middle of a word. ASCII digits only, and no leading zeros (curl reads 0177 as octal).
_LOOPBACK_URL_RE = re.compile(
    r"https?://(localhost|127(?:\.(?:0|[1-9][0-9]{0,2})){3}|\[::1\])(?::[0-9]{1,5})?(?:[/?#][^{}]*)?",
    re.ASCII)


# A word that reads as a URL: `://` anywhere, or a scheme of two or more letters followed
# by a backslash (`http:\\host`; one letter is a drive, `C:\`). Each must be loopback.
_BACKSLASH_SCHEME_RE = re.compile(r"[a-z][a-z0-9+.\-]+:/*\\")
# A positional whose authority carries userinfo: `@evil.example/`, `a@evil.example/x`.
# curl and wget take the host after the `@`. Option values (`-d @file`) are not
# positionals. (A URL that NEL / U+2028 / U+2029 would split is judged whole by the
# in-word reading in _segments; this covers the remainder a split reading leaves.)
_USERINFO_TARGET_RE = re.compile(r"[^/?#]*@[^/?#@]")


def _url_like(word: str) -> bool:
    return "://" in word or bool(_BACKSLASH_SCHEME_RE.match(word))


def _is_loopback_url(word: str) -> bool:
    """True when <word> is entirely an http(s) URL to localhost, 127/8 or [::1]."""
    m = _LOOPBACK_URL_RE.fullmatch(word)
    if not m:
        return False
    host = m.group(1)
    return not host.startswith("127.") or all(int(o) <= 255 for o in host.split(".")[1:])

# Shell operators that end a sub-command. Backtick and parens are included so a
# command substitution's BODY is judged as its own segment.
_SEP_SPLIT_RE = re.compile(r"([;|&()`<>]+)")
_SEP_ONLY_RE = re.compile(r"^[;|&()`<>]+$")
# A separator piece that is really a REDIRECTION: it does not end the command, and
# the word after it is its target, not a command word. <( and >( (process
# substitution) are not in here, so their bodies still become segments.
_SHORT_FLAG_RE = re.compile(r"^-[A-Za-z0-9]+$")
_NAMED_FD_RE = re.compile(r"^[a-z_][a-z0-9_]*\}$")     # {x}> after the { is stripped
_REDIR_RE = re.compile(r"^(?:&>>?|[<>]&|>>|>\||<<<|<<|<>|<|>)$")
# Catastrophic delete targets beyond _DANGER_ROOTS: a drive root (C:, Git Bash /c,
# WSL /mnt/c, Cygwin /cygdrive/c) and a path made only of `..` steps.
_DRIVE_ROOT_RE = re.compile(r"^(?:[a-z]:|/[a-z]|/mnt/[a-z]|/cygdrive/[a-z])$")
_PARENT_ONLY_RE = re.compile(r"^\.\.(?:/\.\.)*$")
# Package-manager options that consume the next word, skipped to find the subcommand.
_NPM_VALUE_OPTS = {"--prefix", "--registry", "--cache", "--userconfig", "--globalconfig",
                   "--workspace", "--loglevel", "--dir", "--filter", "--reporter",
                   "--cwd", "--modules-folder", "--cache-folder", "-w", "-C", "-F"}
_PIP_VALUE_OPTS = {"--proxy", "--cert", "--client-cert", "--cache-dir", "--log",
                   "--log-file", "--timeout", "--retries", "--exists-action",
                   "--trusted-host", "--python", "--keyring-provider", "--use-feature",
                   "--use-deprecated", "--index-url", "--extra-index-url", "-i"}
_NPM_INSTALL = {"install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta",
                "isntal", "isntall", "add", "it", "install-test"}
_PIP_RE = re.compile(r"^pip[0-9.]*$")
_PYTHON_RE = re.compile(r"^(?:python[0-9.]*|py|pypy[0-9.]*)$")
# Group-opening / negation punctuation, stripped from the LEFT of a token only:
# an rstrip would eat the closing brace of ${HOME} and destroy the home target.
_LEAD_GROUP_CHARS = "{!"

# Drive-letter (C:\dir\tool.exe) and UNC (\\host\share\tool.exe) paths only. POSIX
# tokenization would otherwise eat those separators; a single character class keeps
# this linear (no backtracking), unlike a nested (?:[^\\]+\\)+ form.
# A drive letter is a single letter, not the end of a word (`http:\` is not drive P:),
# and a UNC path starts a word: rewriting a `\\` in mid-word would turn
# `http://localhost\\@evil.example/` into a loopback-looking URL.
_WINPATH_RE = re.compile(r"(?i)(?:(?<![a-z0-9])[a-z]:\\|(?<![^\s\"'=(])\\\\)[^\s\"'|&;()<>]*")

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
    # bash expands a tilde prefix only at the start of a word: `./~build` is a file.
    tilde = tok.startswith("~")
    # ${PWD:?}, ${HOME:-x}: a parameter modifier does not change the directory it names.
    t = _ROOT_PARAM_RE.sub(r"${\1}", tok, count=1)
    t = re.sub(r"/{2,}", "/", t)                  # // /// -> /
    t = re.sub(r"/(?:\./)+", "/", t)              # interior /./ -> / (.././.. -> ../..)
    t = _collapse_parents(t)                      # build/../* -> *, /home/.. -> /
    # Bounded peel loop, re-testing after every step. Replaces the old
    # re.sub(r"(/\.)+$", "", t), whose nested quantifier backtracked
    # catastrophically on /././././...x (review S1: 40k pairs = 16.5 s against a
    # 10 s hook timeout -- i.e. a computable fail-open below Claude Code 2.1.295;
    # onFailure:block turns the timeout into a block on 2.1.295+).
    for _ in range(len(t) + 1):
        if _is_root_like(t, tilde):
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
        if t.endswith("/.."):                     # ~/.. -> ~: a root's parent holds the root
            t = t[:-3] or "/"                     # (only bases _collapse_parents keeps get here)
            continue
        k = t.rfind("/")
        if 0 <= k < len(t) - 1 and _glob_all(t[k + 1:]):   # /** -> /, ~/.[!.]* -> ~
            t = t[:k] or "/"
            continue
        break
    return _is_root_like(t, tilde)


def _is_root_like(t: str, tilde: bool = False) -> bool:
    # tilde: the word started with `~`, so a tilde prefix with no slash left is a directory
    # bash expands: ~+ (the cwd), ~- (the previous one), ~name (a home), ~+1 (the
    # directory stack). An unexpanded ~word is only a file name, so blocking it costs a
    # false positive, never a bypass. The glob test needs a single component; checking
    # for a slash first keeps the peel loop from rescanning a long path on every step.
    return (t in _DANGER_ROOTS or bool(_DRIVE_ROOT_RE.match(t) or _PARENT_ONLY_RE.match(t))
            or (tilde and t.startswith("~") and "/" not in t)
            or ("/" not in t and _glob_all(t)))


def _glob_all(comp: str) -> bool:
    """True for a path component made only of glob syntax with at least one `*`: an
    optional leading `.`, then `*`, `?` and `[...]` groups (`*`, `**`, `?*`, `[a-z]*`,
    `.[!.]*`, `.??*`). It names everything, or nearly everything, in its directory.
    A linear scan, no regex: the input can be 4 KB."""
    s = comp[1:] if comp.startswith(".") else comp
    star, k, n = False, 0, len(s)
    while k < n:
        c = s[k]
        if c == "*":
            star = True
            k += 1
        elif c == "?":
            k += 1
        elif c == "[":
            start = k + 2 if s[k + 1:k + 2] in ("!", "^") else k + 1
            end = s.find("]", start + 1)          # a ] first in the group is literal
            if end < 0:
                return False
            k = end + 1
        else:
            return False
    return star


def _collapse_parents(t: str) -> str:
    """t with each `name/..` removed, as the path resolves lexically (build/../* -> *,
    /home/.. -> /, a/b/../.. -> .). The name must be an ordinary one: not the root,
    `.` or `..`, not a `~` or `$` word (its value is unknown here), not a drive `c:`.
    Linear: one pass over the components."""
    if ".." not in t:
        return t
    out = []
    for c in t.split("/"):
        prev = out[-1] if out else None
        if (c == ".." and prev not in (None, "", ".", "..")
                and not prev.startswith(("~", "$"))
                and not (len(prev) == 2 and prev[1] == ":" and prev[0].isalpha())):
            out.pop()
        else:
            out.append(c)
    return "/".join(out) or ("/" if t.startswith("/") else ".")


def _skip_wrapper_args(base: str, toks, i: int, consume: bool = True) -> int:
    """Index after a wrapper's options (and their values) and leading positionals.

    consume=False skips flags without consuming any value: the other reading, so a
    wrong value-option table entry costs a false positive, never a bypass.
    consume=_WIDE consumes the values of the wider table too (see _READINGS).
    """
    shorts = _WRAPPER_VALUE_SHORTS.get(base, "") if consume else ""
    longs = _WRAPPER_VALUE_LONGS.get(base, ()) if consume else ()
    if consume == _WIDE:
        shorts += _WRAPPER_VALUE_SHORTS_WIDE.get(base, "")
        longs = set(longs) | _WRAPPER_VALUE_LONGS_WIDE.get(base, set())
    n = len(toks)
    while i < n and toks[i].startswith("-") and toks[i] != "-":
        t = toks[i]
        i += 1
        if t == "--":
            break
        if t.startswith("--"):
            if "=" not in t and t in longs:
                i += 1
            continue
        letters = t[1:]
        for k, ch in enumerate(letters):
            if ch in shorts:                         # case-exact: -P takes a value, -p not
                if k == len(letters) - 1:
                    i += 1                           # the value is the next word
                break
    return min(n, i + _WRAPPER_LEADING_POSITIONALS.get(base, 0))


def _effective_cmd_index(toks, consume: bool = True):
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
        # `. git push`: PowerShell's dot-source call operator (bash's `.` is source) runs
        # the next word as the command. Not a _WRAPPERS entry, so _shell_index still sees
        # `. /dev/stdin`. In a segment read as PowerShell a `$` word after it is the command
        # too: `. $y` calls what $y names, as `& $y` does. In bash, `.` only sources a file,
        # so there a `$` word stays behind the `.` (`. $VENV/bin/activate`).
        ps = getattr(toks, "ps_tool", False) or getattr(toks, "ps_script", False)
        if t == "." and i + 1 < n and (ps or "$" not in toks[i + 1]):
            i += 1; continue
        if base in _WRAPPERS:
            saw_xargs = saw_xargs or base == "xargs"
            i = _skip_wrapper_args(base, toks, i + 1, consume); continue
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
    """(subcommand, its args, the global options before it) of git's args, taking the
    values of _GIT_OPTS_WITH_ARG. The first candidate of _git_candidates."""
    i = 0
    while i < len(args):
        a = args[i]
        if not a.startswith("-"):
            return a, args[i + 1:], args[:i]
        if a in _GIT_OPTS_WITH_ARG:
            i += 2; continue
        i += 1
    return None, [], args


def _git_candidates(args):
    """Every (subcommand, its args, global options) git may be running: the table's
    reading, then each word that could be the subcommand under any reading of which
    global options take a value -- every word directly after an option, up to and
    including the first word that does not follow one (no option can have taken that
    as its value). So an option missing from _GIT_OPTS_WITH_ARG, or listed there
    wrongly, costs a false positive, never a miss. Linear in the words."""
    out = [_git_subcommand(args)]
    after_opt = False
    for i, a in enumerate(args):
        if a.startswith("-"):
            after_opt = "=" not in a                 # --opt=value takes no next word
            continue
        out.append((a, args[i + 1:], args[:i]))
        if not after_opt:
            break
        after_opt = False
    return out


def _git_push_config_reasons(globals_):
    """Reasons from git's global options that reconfigure a push for this command:
    `-c remote.<name>.push=+<refspec>` (a forced refspec), `-c remote.<name>.mirror`
    (any value; with no `=` git reads it as true), and `--config-env` naming either key,
    whose value comes from an environment variable not in the payload."""
    out = []
    for j, a in enumerate(globals_):
        nxt = globals_[j + 1] if j + 1 < len(globals_) else None
        if a == "-c" and nxt is not None:
            key, _eq, val = nxt.partition("=")
            m = _GIT_REMOTE_CFG_RE.match(key)
            if m and m.group(1) == "mirror":
                out.append("mirror git push (force-updates and deletes remote refs) "
                           "is forbidden")
            elif m and val.startswith("+"):
                out.append("forced git push via +refspec is forbidden")
            elif m and val.startswith(":") and _ref_name(val[1:]) in _PROTECTED_REFS:
                out.append("deleting a main/master/HEAD remote ref is forbidden")
        env = nxt if a == "--config-env" else (
            a.split("=", 1)[1] if a.startswith("--config-env=") else None)
        if env is not None and _GIT_REMOTE_CFG_RE.match(env.partition("=")[0]):
            out.append("git push reconfigured from an environment variable "
                       "(remote push/mirror setting, uninspectable)")
    return out


def _ref_name(ref: str) -> str:
    return ref[len("refs/heads/"):] if ref.startswith("refs/heads/") else ref


def _deletes_protected_ref(args) -> bool:
    """`git push --delete <remote> main`, `git push -d …`, or a `:main` refspec. Only
    the refs after the remote count (a remote may be called main) -- all of them when
    --repo names the remote; `HEAD:main` pushes."""
    deleting = any(_matches_long(a, ("--delete",))
                   or (a.startswith("-") and not a.startswith("--") and "d" in a[1:].lower())
                   for a in args)
    positionals, repo, skip = [], False, False
    for a in args:
        if skip:
            skip = False
        elif a == "--repo":
            repo = skip = True
        elif a.startswith("--repo="):
            repo = True
        elif not a.startswith("-"):
            positionals.append(a)
    refs = positionals if repo else positionals[1:]
    if deleting and any(_ref_name(r) in _PROTECTED_REFS for r in refs):
        return True
    return any(r.startswith(":") and _ref_name(r[1:]) in _PROTECTED_REFS for r in refs)


def _git_rules(sub, sargs, globals_):
    out = []
    if sub == "push":
        if _has_force_flag(sargs):
            out.append("forced git push is forbidden")
        elif _has_force_refspec(sargs):
            out.append("forced git push via +refspec is forbidden")
        if any(_matches_long(a, ("--mirror",)) for a in sargs):
            out.append("mirror git push (force-updates and deletes remote refs) is forbidden")
        if any(_matches_long(a, ("--prune",)) for a in sargs):
            out.append("git push --prune (deletes remote refs) is forbidden")
        if _deletes_protected_ref(sargs):
            out.append("deleting a main/master/HEAD remote ref is forbidden")
        out += _git_push_config_reasons(globals_)
    elif sub == "reset" and any(_matches_long(a, _RESET_HARD_LONGS) for a in sargs):
        out.append("hard git reset is forbidden")
    return out


def _subcommand(args, value_opts):
    """(first positional, the args after it), skipping options and their values."""
    i = 0
    while i < len(args):
        a = args[i]
        if a in value_opts:
            i += 2
            continue
        if a.startswith("-") and a != "-":           # a bare - is a positional (stdin)
            i += 1
            continue
        return a, args[i + 1:]
    return None, []


def _shell_index(toks, consume: bool = True):
    """Index of the command word after wrappers and VAR=val, NOT skipping shells."""
    i, n = 0, len(toks)
    while i < n:
        t = toks[i]
        base = _cmd_word(t)
        if re.match(r"^[a-z_][a-z0-9_]*=", t):
            i += 1
        elif base in _WRAPPERS:
            i = _skip_wrapper_args(base, toks, i + 1, consume)
        elif t.startswith("-") and t != "-":
            i += 1                                   # stray leading flag
        else:
            return i
    return None


def _shell_script_index(toks, i):
    """For a shell word at toks[i]: index of its inline -c script, else None.

    Walks the shell's options -- flags, `--`, and the values of -o/+o/-O/+O and
    --rcfile/--init-file -- so `bash -o pipefail -c ...`, `bash -c -- ...` and
    `bash -c -x ...` all find the script. A word before any c-bundle is a script
    FILE (`sh build.sh`): not inline.
    """
    saw_c, n, j = False, len(toks), i + 1
    while j < n:
        t = toks[j]
        if t == "--":
            j += 1
            continue
        if t == "--command":                         # fish --command <script>
            saw_c = True
            j += 1
            continue
        if t.startswith("--"):
            j += 2 if ("=" not in t and t in _SHELL_VALUE_LONGS) else 1
            continue
        if len(t) > 1 and t[0] in "-+":
            saw_c = saw_c or (t[0] == "-" and "c" in t[1:])
            j += 2 if t[-1] in _SHELL_VALUE_OPTS else 1
            continue
        return j if saw_c else None
    return None


def _shell_reads_stdin(toks) -> bool:
    """True if the segment's command takes its script from stdin.

    A shell with no -c script and no script file (`... | sh`), with -s, or whose
    script file is stdin itself (`bash /dev/stdin`, `bash -`, `source /dev/stdin`).
    Both readings of wrapper options are tried.
    """
    for consume in _READINGS:
        i = _shell_index(toks, consume)
        if i is None:
            continue
        base, rest = _cmd_word(toks[i]), toks[i + 1:]
        if base in ("source", "."):
            # `source <(...)` reaches here as a fed `source` with no word left: the file it
            # runs is the process substitution's output. `--` ends options; bash 5.3's
            # `-p PATH` takes a value. (A piped `source` with no file is an error in bash;
            # judging it like the fed one costs nothing.)
            while rest and rest[0] in ("--", "-p"):
                rest = rest[2:] if rest[0] == "-p" else rest[1:]
            if not rest or rest[0] in _STDIN_PATHS:
                return True
            continue
        if _runner_reads_stdin(base, rest):
            return True
        if base not in _SHELLS:
            continue
        if any(len(t) > 1 and t[0] == "-" and t[1] != "-" and "s" in t[1:] for t in rest):
            return True                              # -s: read commands from stdin
        if _shell_script_index(toks, i) is not None:
            continue                                 # -c script: inspected inline
        script = _subcommand(rest, _SHELL_VALUE_LONGS | {"-o", "+o", "-O", "+O"})[0]
        if script is None or script in _STDIN_PATHS:
            return True
    return False


def _runner_reads_heredoc(toks) -> bool:
    """True if the segment's command is cmd, pwsh or powershell reading its commands from
    stdin (see _runner_reads_stdin), past wrappers. Not wsl or a POSIX shell: the body of
    their heredoc is shell text, judged line by line as the rest of the payload is."""
    for consume in _READINGS:
        i = _shell_index(toks, consume)
        if i is None:
            continue
        base = _cmd_word(toks[i])
        if (base == "cmd" or base in _PS_RUNNERS) and _runner_reads_stdin(base, toks[i + 1:]):
            return True
    return False


# A shell function the text defines (`f() {`, `function f`, also in an eval's string): a
# heredoc on a call of it feeds the commands in its body. Names are lowercased like the
# tokens.
_DEFINED_NAME_RE = re.compile(
    r"""(?:^|[\s;&|(){}'"])(?:function\s+([^\s;&|(){}<>'"`$=]+)"""
    r"""|([^\s;&|(){}<>'"`$=]+)\s*\(\s*\))""")


def _exec_only(words) -> bool:
    """An exec (perhaps behind wrappers) with no command: only redirects. With a heredoc
    or here-string (`exec <<EOF`, `exec 2>&1 3<<EOF`, `command exec <<<x`) it redirects
    the shell's own stdin for every later command, so the segment is marked heredoc_wide;
    in an eval's script, that reaches the text around the eval (see _expand_scripts)."""
    return (any(_cmd_word(t) == "exec" for t in words)
            and all(_shell_index(words, c) is None for c in _READINGS))


def _heredoc_feeds_all(seg, defined) -> bool:
    """A heredoc on seg reaches every command of the text: the command reads its script
    from stdin (`bash <<EOF`: each body line runs with the rest of the body as its stdin,
    so a body line `pwsh` reads the lines after it), or calls a function the text
    defines. (A shell the command's own scripts start, `bash -c bash <<EOF`, is found
    when they are expanded: see _segments; an exec: see _exec_only.)"""
    return _shell_reads_stdin(seg) or _calls_defined(seg, defined)


def _calls_defined(seg, defined) -> bool:
    """seg's command word (past wrappers) is a function or alias the text defines."""
    return any(i is not None and _cmd_word(seg[i]) in defined
               for i in (_shell_index(seg, c) for c in _READINGS))


def _alias_names(segs):
    """The NAMEs of every `alias NAME=VALUE` word among the segments (dequoted tokens,
    as _split_inline_script reads the values)."""
    out = set()
    for seg in segs:
        for consume in (True, False):
            k = _shell_index(seg, consume)
            if k is not None and _cmd_word(seg[k]) == "alias":
                out.update(t.split("=", 1)[0] for t in seg[k + 1:] if "=" in t)
    return out


def _heredoc_check(text, main, lenient, lenient_fed, orphan, inherited: bool) -> bool:
    """Refuse a cmd or PowerShell runner that a heredoc feeds: the heredoc's body is its
    commands, and it is not read as cmd or PowerShell here (bash heredoc bodies are judged
    line by line, as bash). Raises _Uninspectable (a block), as for a runner fed by a pipe.

    The fed segments: every segment of the text when it is the script of a fed command
    (inherited), when a heredoc or here-string is on a group or compound command
    (heredoc_wide, or orphan: on a closer with no segment before it on its line) or on an
    exec with no command (heredoc_wide too, see _exec_only), or when a heredoc is on a
    command that reaches every command of the text
    (_heredoc_feeds_all, which a runner reading the heredoc itself satisfies; for the
    quote-blind pass, a shell reading stdin among the segments of a heredoc's line, the
    inline scripts _lenient_inline took from it included). Otherwise the quote-blind
    segments of a line holding one (lenient_fed). (An alias's value is a script fed by
    any heredoc in the text: see _expand_scripts.) Returns whether every segment is fed,
    for the scripts _segments expands from this text."""
    here = [s for s in main + lenient if getattr(s, "heredoc", False)]
    # A here-string on a function or alias call feeds its body too. (One on the runner
    # itself is a piped one, refused as such.)
    strs = [s for s in main + lenient if getattr(s, "herestr_fed", False)]
    defined = set()
    if here or strs:
        # Functions, and aliases (whose value may call a function: `alias p=f`).
        defined = {n.lower() for m in _DEFINED_NAME_RE.finditer(text) for n in m.groups() if n}
        defined |= _alias_names(main + lenient)
    wide = (inherited or orphan
            or any(getattr(s, "heredoc_wide", False) for s in main + lenient)
            or any(_heredoc_feeds_all(s, defined) for s in here)
            or any(_calls_defined(s, defined) for s in strs)
            or any(_shell_reads_stdin(s) for s in lenient_fed))
    # A runner a heredoc is on reads stdin, so it already made the text wide.
    fed = main + lenient if wide else lenient_fed
    for toks in fed:
        if _runner_reads_heredoc(toks):
            raise _Uninspectable("Windows runner reading its commands from a heredoc")
    return wide


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
        elif a.startswith("-") and len(a) > 1 and "f" in a[1:].lower():
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
    """The block reasons for one segment. A PowerShell assignment in it (`$out = cmd`)
    hands back the command after the `=` (see _rules_at), judged here in turn: a
    worklist, not a recursion, so a long chain of assignments cannot exhaust the stack.
    Each remainder is a strict suffix of the segment, and a suffix is judged once, so
    the loop ends."""
    out, work, queued = [], [toks], {len(toks)}
    while work:
        seg = work.pop()
        # `echo "rm -rf /" | sh`: the shell's script arrives on stdin, so it is not in
        # the payload to inspect. Fail closed (the curl | sh shape, without the curl).
        if getattr(seg, "piped", False) and _shell_reads_stdin(seg):
            r = "shell reading its commands from a pipe (uninspectable)"
            if r not in out:
                out.append(r)
        # A cmd script's command word that cmd's variable expansion decides (`call %x%`,
        # `!x!`, `%COMSPEC% /c ...`): the program is not in the payload. Fail closed. Read
        # at cmd's own command position, not the bash finders' (which take the condition
        # of `if %a% neq 0 exit` for the command).
        if (getattr(seg, "cmd_script", False) and seg
                and _cmd_expansion_word(seg[_cmd_command_index(seg)])):
            r = "uninspectable command word (cmd variable expansion in command position)"
            if r not in out:
                out.append(r)
        # Judge the command word under both readings of wrapper options (see
        # _WRAPPER_VALUE_SHORTS): a rule that fires on either one blocks.
        seen, rest = set(), []
        for consume in _READINGS:
            idx, saw_xargs = _effective_cmd_index(seg, consume)
            if idx is None or idx in seen:
                continue
            seen.add(idx)
            for r in _rules_at(seg, idx, saw_xargs, rest):
                if r not in out:
                    out.append(r)
        for r in rest:
            if len(r) not in queued:
                queued.add(len(r))
                work.append(r)
    return out


def _ps_statement_start(toks):
    return 1 if len(toks) > 1 and toks[0].lower() in _PS_STATEMENT_PREFIX else 0


def _ps_statement_tail(toks):
    """For an ordinary statement of a PowerShell tool payload whose first word is a
    variable (`$x = 1`, `if ($LASTEXITCODE -ne 0)`, `foreach ($f in $l)`), the words it
    goes on to run, as a list (empty when nothing is left to judge); None for any other
    segment. The tool's payload has no outer shell, so the variable is no expansion.
    Not after a call operator (`& $x`, `. ($x)`), not a method call (`$x.Run(...)`, or one
    as a later word), not fed by a pipe, and not `$x <word>`.

    The words are what follows an `=`, an operator or a foreach header's `in` (its
    collection is a pipeline), past a chain `$a = $b = cmd`, with a glued `$x=value` read
    as the same three words. A value that opens with a quote is a string, not a command."""
    if not getattr(toks, "ps_tool", False) or toks.ps_call or toks.piped:
        return None
    start = _ps_statement_start(toks)
    i, word, walked, value_of_glue = start, toks[start], False, False
    while True:
        glued = _PS_GLUED_ASSIGN_RE.fullmatch(word)
        if glued:
            walked, word, value_of_glue = True, glued[3], True
            if word:
                continue
            i += 1                     # `$x= 1`: the value is the next word
            if i >= len(toks):
                return []
            word, value_of_glue = toks[i], False
            continue
        if _PS_VAR_WORD_RE.fullmatch(word):
            nxt = toks[i + 1].lower() if i + 1 < len(toks) else None
            if nxt is None:
                return []
            if nxt in _PS_TOOL_EXPR_NEXT or (nxt == "in" and toks.ps_foreach):
                walked, value_of_glue = True, False
                i += 2
                if i >= len(toks):
                    return []
                word = toks[i]
                continue
        if not walked:
            return None
        if i in (toks.ps_quoted_value if value_of_glue else toks.ps_quoted):
            return []
        return [word] + list(toks[i + 1:])


def _ps_hash_value(toks):
    """A hashtable's value, as words, when the segment reads as `key = value` (the brace
    reading turns `@{ a = git status }` into that), in the forms PowerShell accepts:
    `a = v`, `a =v`, `a=v`, and `= v` or `=v` after a parenthesized key. None otherwise,
    and [] for a value that opens with a quote, which is a string."""
    glued = _PS_GLUED_KEY_RE.fullmatch(toks[0])
    if glued:
        return [] if 0 in toks.ps_quoted_value else [glued[1]] + list(toks[1:])
    if "$" in toks[0]:
        return None
    if toks[0] == "=":
        return [] if 1 in toks.ps_quoted else list(toks[1:])
    if len(toks) > 2 and toks[1] == "=":
        return [] if 2 in toks.ps_quoted else list(toks[2:])
    if len(toks) > 1 and toks[1].startswith("=") and len(toks[1]) > 1:
        return [toks[1][1:]] + list(toks[2:])
    return None


def _ps_tail_segment(words, called=False, piped=False, expanding=frozenset()):
    """words as a segment of the tool's payload. `. cmd` dot-invokes cmd, so the words
    are judged without the dot, and `. $y` is a call of $y, not an ordinary statement.
    A leading number goes too: in `$x=2>&1 rm -rf /` the 2 was a redirect's.
    called, piped: the source segment's ps_call and pipe, for words taken from one that
    is not an ordinary statement (`'x' | . bash` feeds bash). expanding: the indexes of
    the words that hold a `$` the shell expands (see expanding on _Seg)."""
    dot = words[0] == "." and len(words) > 1
    drop = dot or (words[0].isdigit() and len(words) > 1)
    seg = _new_seg(words[1:] if drop else words, piped)
    seg.ps_tool, seg.ps_call = True, called or (dot and "$" in words[1])
    seg.expanding = frozenset(e - drop for e in expanding if e >= drop)
    return seg


def _suffix_expanding(src, words):
    """The expanding indexes of src (see _Seg) for words, which end as src does."""
    k = len(src) - len(words)
    return frozenset(e - k for e in getattr(src, "expanding", ()) if e >= k)


def _ps_statement_tails(segments):
    """What the ordinary statements of a PowerShell tool payload go on to run, as segments
    of their own, so the caller tokenizes inline scripts in them and judges them like any
    other segment: see _ps_statement_tail and _ps_hash_value. `$x = $(cmd)`: the body is
    its own segment. Each input yields at most two segments, so this stays linear."""
    out = []
    for toks in segments:
        if not getattr(toks, "ps_tool", False):
            continue
        tail = _ps_statement_tail(toks)
        if tail is None:
            value = (list(toks[1:]) if toks[0] == "." and len(toks) > 1 and "$" not in toks[1]
                     else _ps_hash_value(toks))   # `. cmd args`: cmd is the command
            if not value or value == ["$"]:
                continue
            seg = _ps_tail_segment(value, toks.ps_call, toks.piped, _suffix_expanding(toks, value))
            # `@{ a = $y = cmd }`: one more step
            out.append(seg)
            tail, src = _ps_statement_tail(seg), seg
        else:
            src = toks
        if tail and tail != ["$"]:
            out.append(_ps_tail_segment(tail, expanding=_suffix_expanding(src, tail)))
    return out


def _rules_at(toks, idx, saw_xargs, rest=None):
    """The block reasons for the segment, taking toks[idx] as its command word. A
    PowerShell assignment's right-hand side is appended to rest, for the caller to
    judge (see _reasons_for); with rest None it is not judged."""
    out = []
    seg = " ".join(toks)
    cmd = _cmd_word(toks[idx])
    args = toks[idx + 1:]

    # A command word that is itself a shell expansion cannot be inspected: the
    # binary that will actually run is not in the payload. Fail closed. (Expansion
    # in ARGUMENT position stays allowed -- see the "known limits" fixtures.)
    # A quoted substitution ("$(rm -rf /)") is one word now, and its basename can
    # hide the $, so also test the whole token for a leading substitution.
    # In a script handed to pwsh/powershell (ps_script, see _runner_scripts) a $ word at
    # statement start is an expression when it stands alone (`$PSVersionTable`,
    # `$x="y"`) or an assignment or operator follows it (`$x = 1`, `$a -eq 2`).
    # PowerShell refuses `$x <word>`, so that shape only runs after an OUTER shell
    # expanded it (`pwsh -c "$CMD -rf /"` from bash): it stays uninspectable.
    # A destructuring target (`$a, $b = 1, 2`) ends in a comma. The right-hand side of
    # an assignment runs as a pipeline (`$out = git push --force`): judge it.
    # Only the statement's own first word: not one a call operator, a dot or a wrapper
    # runs (`& $y`, `. $y`, `sudo $x`), nor one in a called group (ps_call). A script an
    # outer shell expands is marked ps_outer, and gets none of this (see expanding on _Seg).
    if "$" in cmd or toks[idx].startswith(("$(", "`")):
        # A PowerShell tool payload has no outer shell: see _ps_statement_tail.
        start = _ps_statement_start(toks)
        if idx == start and _ps_statement_tail(toks) is not None:
            return out
        nxt = toks[idx + 1].lower() if idx + 1 < len(toks) else None
        if not (getattr(toks, "ps_script", False) and idx == start
                and not getattr(toks, "ps_call", False)
                and not getattr(toks, "ps_outer", False)
                and (nxt is None or nxt in _PS_EXPR_NEXT or toks[idx].endswith(","))):
            out.append("uninspectable command word (shell expansion in command position)")
        elif nxt in _PS_ASSIGN and idx + 2 < len(toks) and rest is not None:
            # `$out = cmd`: the caller judges the command after the `=` (a chained
            # `$a = $b = cmd` comes back here for `$b`, one link per worklist item).
            rhs = _new_seg(toks[idx + 2:], getattr(toks, "piped", False))
            rhs.ps_script = True
            rest.append(rhs)
        return out

    if cmd == "rm":
        recursive = force = target = False
        for a in args:
            if a.startswith("--"):
                recursive = recursive or _matches_long(a, ("--recursive",))
                force = force or _matches_long(a, ("--force",))
            elif a.startswith("-") and len(a) > 1:
                recursive = recursive or "r" in a[1:].lower()   # -r, -R
                force = force or "f" in a[1:].lower()
            elif _is_danger_target(a):
                target = True
        if recursive and force and target:
            out.append("recursive force-delete of a root/cwd/home target (rm -rf)")
        elif recursive and force and (saw_xargs or getattr(toks, "xargs_fed", False)):
            # Targets arrive on stdin, so they are UNKNOWN -- not absent. Positionals do
            # not make them known: xargs appends its items after them, or (-I, -i,
            # --replace) substitutes an item into them. xargs_fed: this is a segment of
            # an inline script xargs runs (`xargs sh -c 'rm -rf "$@"' _`).
            out.append("recursive force-delete with targets piped from xargs "
                       "(unknown scope)")

    elif cmd == "git":
        for cand in _git_candidates(args):
            for r in _git_rules(*cand):
                if r not in out:
                    out.append(r)

    elif cmd in _PS_RUNNERS and _ps_encoded(args):
        out.append("PowerShell -EncodedCommand (uninspectable)")

    elif cmd == "find":
        # find deletes without ever naming a delete command word: -delete, or
        # -exec/-execdir/-ok/-okdir rm (-ok asks first; `yes |` answers). Scoped to
        # catastrophic roots so a targeted `find ./build -name "*.o" -delete` stays allowed.
        deletes = "-delete" in args or (
            any(a in ("-exec", "-execdir", "-ok", "-okdir") for a in args)
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
        # Every word holding `://` (any scheme, a glob such as `{https,x}://`, an option
        # value, a header) must be a loopback http(s) URL; one that is not blocks, as
        # before. The bare-host rule below still runs on the positionals either way.
        # The words are the tokens themselves, never a re-split of the joined segment:
        # str.split() also splits on NBSP and other Unicode spaces that bash keeps
        # inside a word, which would cut `http://localhost<NBSP>@evil.example/` in two.
        if any(not _is_loopback_url(w) for w in toks if _url_like(w)):
            out.append("direct remote fetch with curl/wget is forbidden")
        elif any(_BARE_HOST_RE.match(t) or _USERINFO_TARGET_RE.match(t)
                 for t in _fetch_targets(cmd, args)):
            # curl/wget default to HTTP, so a scheme-less host is still a fetch.
            out.append("direct remote fetch with curl/wget is forbidden")

    elif cmd in ("npm", "pnpm"):
        sub, _rest = _subcommand(args, _NPM_VALUE_OPTS)
        if sub in (_NPM_INSTALL if cmd == "npm" else ("install", "i", "add")):
            out.append("package installation requires explicit approval")
    elif cmd == "yarn":
        # Bare `yarn` installs the lockfile's dependencies, like `yarn install`.
        sub, rest = _subcommand(args, _NPM_VALUE_OPTS)
        if (sub in ("add", "install") or not args
                or (sub == "global" and _subcommand(rest, _NPM_VALUE_OPTS)[0] == "add")):
            out.append("package installation requires explicit approval")
    elif cmd == "uv":                                # uv pip install ...
        sub, rest = _subcommand(args, _PIP_VALUE_OPTS)
        if sub == "pip" and _subcommand(rest, _PIP_VALUE_OPTS)[0] == "install":
            out.append("package installation requires explicit approval")
    elif _PIP_RE.match(cmd):
        if _subcommand(args, _PIP_VALUE_OPTS)[0] == "install":
            out.append("package installation requires explicit approval")
    elif _PYTHON_RE.match(cmd):
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


def _env_split_loose(toks, i):
    """For an env word at toks[i]: (outer tokens, script) from the first -S among the
    dash words that follow it, or None. The original, loose reading of env -S; kept
    beside _env_split so that reading only ever adds what is judged. The outer tokens
    lose only the script word, so a `$` in it is not read as a command word."""
    for j in range(i + 1, len(toks)):
        a = toks[j]
        if a in ("-S", "--split-string") and j + 1 < len(toks):
            return toks[:j + 1] + toks[j + 2:], toks[j + 1]
        if a.startswith("--split-string="):
            return toks[:j] + toks[j + 1:], a.split("=", 1)[1]
        if a[:2] in ("-S", "-s") and len(a) > 2:   # glued; lowercased if it has spaces
            return toks[:j] + toks[j + 1:], a[2:]
        if not a.startswith("-"):
            break
    return None


def _env_split(toks, i):
    """For an env word at toks[i]: (index of the word holding -S, index after the script,
    the script text), or None when env's options end without one.

    Walks env's options as getopt does: a short bundle's letters in turn (`-iS`, `-0iS`),
    a value letter taking the rest of its bundle or the next word (`-u FOO`, `-C/dir`),
    long options by unambiguous prefix (`--unset FOO`, `--split-string=...`), a lone `-`
    (GNU: -i) as a flag. Letters are compared without case (see _ENV_VALUE_LETTERS), and a
    character that is not a letter or digit can only be inside a value, so it ends the
    bundle. The first operand (NAME=VALUE, the command) or `--` ends the walk.
    """
    n, j = len(toks), i + 1
    while j < n:
        a = toks[j]
        if a == "--" or not a.startswith("-"):
            return None
        if a.startswith("--"):
            head, eq, value = a.partition("=")
            if _matches_long(head, ("--split-string",)):
                if eq:
                    return j, j + 1, value
                return (j, j + 2, toks[j + 1]) if j + 1 < n else None
            j += 2 if not eq and _matches_long(head, _ENV_VALUE_LONGS) else 1
            continue
        letters, step = a[1:], 1
        for k, ch in enumerate(letters):
            if not ch.isalnum():
                break
            c = ch.lower()
            if c == "s":
                if k < len(letters) - 1:
                    return j, j + 1, letters[k + 1:]
                return (j, j + 2, toks[j + 1]) if j + 1 < n else None
            if c in _ENV_VALUE_LETTERS:
                if k == len(letters) - 1:
                    step = 2                         # the value is the next word
                break
        j += step
    return None


def _split_inline_script(toks):
    """Split `sh -c "<script>"` into (outer tokens, inline script string). For env -S
    the second item is a tuple of scripts, one per reading, each judged on its own.

    POSIX tokenization keeps the quoted script as ONE word, so its command word
    would be the whole string and no rule could anchor to it. The script token is
    REMOVED from the outer segment so it is not judged twice -- and so a `$` inside
    it is not mistaken for an expansion in command-word position.
    """
    def keep(new):
        # The outer segment keeps its redirect targets but not its pipe flag: its
        # stdin goes to the inline script, whose segments _segments marks piped.
        return _new_seg(new, False, getattr(toks, "redirs", ()))

    # Scripts only the added readings find (the getopt walk of env -S, the wide reading
    # of wrapper options). They never replace the split below: done() returns that
    # split unchanged, with these after it as further scripts, each judged on its own
    # (joined, a quote left open in one could swallow another).
    extras = []
    walked = False

    def done(outer, inline):
        if not extras:
            return outer, inline
        first = inline if isinstance(inline, tuple) else ((inline,) if inline else ())
        return outer, tuple(dict.fromkeys(first + tuple(extras)))

    # `eval <words>` at the command position: bash joins the words and runs them.
    for consume in (True, False):
        k = _shell_index(toks, consume)
        if k is not None and _cmd_word(toks[k]) == "eval":
            return keep(toks[:k + 1]), " ".join(toks[k + 1:])
    k = _shell_index(toks, _WIDE)
    if k is not None and _cmd_word(toks[k]) == "eval":
        extras.append(" ".join(toks[k + 1:]))
    # `alias NAME=VALUE ...`: each value is text the shell runs where NAME is called
    # (under expand_aliases), so each is judged as a script, as eval's words are.
    for consume in ((True, False) if any("alias" in t for t in toks) else ()):
        k = _shell_index(toks, consume)
        if k is not None and _cmd_word(toks[k]) == "alias":
            values = tuple(t.split("=", 1)[1] for t in toks[k + 1:] if "=" in t)
            if values:
                return keep(toks[:k + 1]), values
    for i, t in enumerate(toks):
        base = _cmd_word(t)
        if base == "watch":                        # watch hands its joined words to sh -c
            j = _skip_wrapper_args("watch", toks, i + 1)
            if j < len(toks):
                return done(keep(toks[:j]), " ".join(toks[j:]))
        if base in _DASH_C_RUNNERS:                # su / script / flock / runuser -c
            for j in range(i + 1, len(toks)):
                a = toks[j]
                # -c, or a bundle ending in it (`script -qc`, `su -lc`)
                if ((a == "--command" or (_is_c_bundle(a) and a.endswith("c")))
                        and j + 1 < len(toks)):
                    return done(keep(toks[:j + 1] + toks[j + 2:]), toks[j + 1])
                if a.startswith("--command="):
                    return done(keep(toks[:j] + toks[j + 1:]), a.split("=", 1)[1])
        if base == "env":                          # env -S "<script>" splits and runs it
            # Two readings. The loose scan (_env_split_loose) takes the first -S it meets
            # among env's leading flags, and its split is used as it always was. The
            # getopt walk (_env_split) follows env's own option parsing; its script is
            # an extra, and the scan goes on either way. The walk runs for the first env
            # word only: its script holds every later word, so the next depth judges
            # those, and walking each one here would multiply the extras per depth
            # (`env -iS x env -iS x ...` would run toward the hook timeout).
            hit = None if walked else _env_split(toks, i)
            walked = walked or hit is not None
            if hit:
                j, end, script = hit
                # env puts the split words back in its argument list and keeps parsing,
                # so the words after the script belong to the command it runs: the
                # script is `env <script> <those words>`, judged with env's wrapper
                # rules again.
                walked_script = "env " + script.replace("\\_", " ")   # GNU: \_ is a space
                if toks[end:]:
                    # shlex.join is 3.8+; this is its body, for the 3.7 floor.
                    walked_script += " " + " ".join(shlex.quote(t) for t in toks[end:])
                extras.append(walked_script)
            loose = _env_split_loose(toks, i)
            if loose:
                return done(keep(loose[0]), loose[1])
        if base in _SHELLS:
            for j in range(i + 1, len(toks)):      # fish --command=<script>
                if toks[j].startswith("--command="):
                    return done(keep(toks[:j] + toks[j + 1:]), toks[j].split("=", 1)[1])
            j = _shell_script_index(toks, i)
            if j is None:
                return done(toks, None)            # `sh script.sh`: not an inline -c
            return done(keep(toks[:j] + toks[j + 1:]), toks[j])
    return done(toks, None)


def _ps_switch_name(tok: str):
    """The lowercased name of a pwsh/powershell switch (`-Command` -> command; `/c`,
    `--command` and an en-dash `–c` too), up to a `:` value; None if tok is not one."""
    if len(tok) < 2 or tok[0] not in _PS_SWITCH_CHARS:
        return None
    name = tok[2:] if tok[1] in _PS_SWITCH_CHARS else tok[1:]
    name = name.split(":", 1)[0].lower()
    return name or None


def _ps_switch(tok: str):
    """"command", "encoded", "file" or "other" for a pwsh/powershell switch; None if tok is
    not a switch. Names match by prefix, as pwsh matches them (`-c`, `-com`, `-cwa`)."""
    name = _ps_switch_name(tok)
    if name is None:
        return None
    if "commandwithargs".startswith(name) or name == "cwa":
        return "command"
    if name in ("e", "ec", "ea") or (name.startswith("en") and (
            "encodedcommand".startswith(name) or "encodedarguments".startswith(name))):
        return "encoded"
    if "file".startswith(name):
        return "file"
    return "other"


def _ps_decisive_switch(args):
    """(kind, index) of the first -Command / -EncodedCommand / -File switch in a
    pwsh/powershell argument list, stepping over other switches and their values; else
    (None, -1)."""
    for j, a in enumerate(args):
        kind = _ps_switch(a)
        if kind in ("command", "encoded", "file"):
            return kind, j
    return None, -1


def _ps_encoded(args) -> bool:
    """An -EncodedCommand switch among pwsh/powershell's OWN switches: those before the
    first positional word, -Command or -File (values of _PS_VALUE_OPTS stepped over).
    After it the switches are the command's or script's (`powershell Get-ChildItem
    -ea 0`, -ea being -ErrorAction there)."""
    j = 0
    while j < len(args):
        kind = _ps_switch(args[j])
        if kind == "encoded":
            return True
        if kind != "other":
            return False
        j += 2 if _ps_takes_value(args[j]) else 1
    return False


def _ps_takes_value(tok: str) -> bool:
    """A pwsh/powershell switch other than -Command/-EncodedCommand/-File whose name is a
    prefix of a _PS_VALUE_OPTS entry, with no `:value` glued to it."""
    name = _ps_switch_name(tok)
    return (name is not None and ":" not in tok and _ps_switch(tok) == "other"
            and any(v.startswith(name) for v in _PS_VALUE_OPTS))


def _ps_positionals(args, consume: bool):
    """Windows PowerShell 5.1 runs its first positional word as a command: the words from
    there on. consume: a switch named in _PS_VALUE_OPTS takes the next word as its value
    (the other reading takes no value, so a table gap cannot hide the command)."""
    j = 0
    while j < len(args):
        a = args[j]
        if _ps_switch_name(a) is None:
            return args[j:]
        j += 2 if consume and _ps_takes_value(a) else 1
    return []


def _cmd_run_switch(args):
    """(index, glued text) of cmd's /c, /r (the same as /c) or /k switch, which may share
    a word with other switches or with the command (`/d/c`, `/cgit`, `//c` from Git
    Bash); else None."""
    for j, a in enumerate(args):
        if not a.startswith("/"):
            continue
        start = 0
        for part in a.split("/"):
            if part[:1] in ("c", "k", "r"):
                return j, a[start + 1:]
            start += len(part) + 1
    return None


def _wsl_rests(args):
    """The command words wsl runs: after -e/--exec (no shell) or `--`, else from its first
    non-option word (handed to the default shell). Read with and without the value of
    _WSL_VALUE_OPTS consumed; a leading `~` (wsl's start-in-home shorthand) is also
    stepped over."""
    rests = []
    for consume in (True, False):
        j, rest = 0, []
        while j < len(args):
            a = args[j]
            if a in ("-e", "--exec", "--"):
                rest = args[j + 1:]
                break
            if a.startswith("-"):
                j += 2 if consume and a in _WSL_VALUE_OPTS else 1
                continue
            rest = args[j:]
            break
        rests.append(rest)
        if rest[:1] == ["~"]:
            rests.append(rest[1:])
    return rests


def _runner_rests(toks):
    """(kind, words, outer) for each command a Windows runner at the command position would
    run: `cmd /c|/r|/k ...`, `pwsh|powershell -Command ...` (and 5.1's positional command),
    and `wsl ...`. Both readings of wrapper options are tried. Empty commands are dropped.
    outer: a word after the runner holds a `$` the shell expands (see expanding on _Seg),
    so the words are not the text the runner gets."""
    out = []
    for consume in _READINGS:
        i = _shell_index(toks, consume)
        if i is None:
            continue
        base, args = _cmd_word(toks[i]), list(toks[i + 1:])
        if getattr(toks, "ps_script", False):
            # A runner in a pwsh script: PowerShell's quoting is not the one `expanding`
            # follows (`\"` opens a string there), so any $ word after it counts.
            outer = any("$" in w for w in toks[i + 1:])
        else:
            outer = any(e > i for e in getattr(toks, "expanding", ()))
        found = len(out)
        if base == "cmd":
            # An empty argument reaches cmd as `""` (`cmd //c if "" equ "" x`), a word to it.
            empties = getattr(toks, "empties", ())
            if empties:
                args = [w for k in range(i + 1, len(toks) + 1)
                        for w in [""] * empties.count(k) + list(toks[k:k + 1])]
            # cmd also takes , = ; and Unicode spaces before its switches (`cmd ,/c x`,
            # `cmd <U+3000>/c x`, which bash keeps in one word): its words are also read
            # as cmd reads them (_CMD_DELIMS).
            # In PowerShell text a `--%` word after the switch is PowerShell's, not cmd's
            # (the rest of the line is read by _ps_stop_parsing_cmd_scripts); one glued to
            # the switch (`/c--%`) is cmd's.
            ps = getattr(toks, "ps_tool", False) or getattr(toks, "ps_script", False)
            for words in (args, " ".join(args).translate(_CMD_DELIMS).replace(";", " ").split()):
                sw = _cmd_run_switch(words)
                if sw is not None:
                    j, glued = sw
                    rest = ([glued] if glued else []) + words[j + 1:]
                    out.append(("cmd", rest[1:] if ps and not glued and rest[:1] == ["--%"]
                                else rest))
        elif base in _PS_RUNNERS:
            kind, j = _ps_decisive_switch(args)
            if kind == "command":
                out.append(("ps", args[j + 1:]))
            # 5.1's positional command too, whatever switch follows it: in
            # `powershell git push -f` the -f is git's, not -File.
            if base == "powershell":
                out += [("ps", _ps_positionals(args, c)) for c in (True, False)]
        elif base == "wsl":
            out += [("wsl", r) for r in _wsl_rests(args)]
        elif base == "start" and not any(getattr(toks, a, False) for a in
                                         ("cmd_script", "ps_script", "ps_tool")):
            # Git for Windows' start (/usr/bin/start) is `"$COMSPEC" //c start "$@"`: the
            # words are a cmd script, whose own start _cmd_prefix_variants reads. Not in
            # a cmd script (that start is read there, and a runner would recurse) nor in
            # PowerShell text, where start is Start-Process. (A quote-blind segment of a
            # pwsh script is marked ps_script only after its runners are read, so there a
            # start is also read as cmd's: an extra reading, which only adds blocks.)
            out.append(("cmd", ["start"] + args))
        out[found:] = [(kind, words, outer) for kind, words in out[found:]]
    seen, uniq = set(), []
    for kind, words, outer in out:
        if words and (kind, tuple(words), outer) not in seen:
            seen.add((kind, tuple(words), outer))
            uniq.append((kind, words, outer))
    return uniq


def _cmd_texts(words):
    """The texts a cmd script of these words is read as: joined with spaces; also with
    each word after the first that is empty or holds a space quoted, as the command line
    cmd gets quotes it (Git Bash and PowerShell build it so), which keeps `start "a
    title" /b x` a one-word title (not the first word: a quoted script, `cmd /c "echo
    $x"`, is unquoted by /c); each of those with an empty "" or '' kept as a word (an `if`
    operand: `if "" equ "" x`); each of all those with its ^ escapes removed; and each of all
    those with cmd's , = ' and Unicode spaces read as cmd reads them (_CMD_DELIMS:
    `call,git ...`, `echo ' & x & '`, `call<NBSP>git ...`)."""
    texts = [" ".join(words)]
    if any(not w or any(c.isspace() for c in w) for w in words[1:]):
        texts.append(" ".join(words[:1] + ['"' + w + '"' if not w or any(
            c.isspace() for c in w) else w for w in words[1:]]))
    # An empty "" or '' is a word to cmd (an `if` operand: `if "" equ "" x`), where the
    # bash reading leaves no word at all: also read with each one a word of its own.
    texts += [t.replace('""', '"_"').replace("''", "_") for t in texts
              if '""' in t or "''" in t]
    texts += [t.replace("^", "") for t in texts]
    return texts + [t.translate(_CMD_DELIMS) for t in texts]


def _runner_scripts(toks):
    """(script text, kind, outer) for every command a Windows runner in the segment would run.

    A runner's words are joined with spaces, as a runner that hands a command LINE to a
    parser sees them (cmd /c, pwsh -Command, wsl's default shell): `cmd /c "git reset
    --hard"` is `git reset --hard`. (A quoted script for a shell later in the words,
    `wsl -e bash -c '...'`, is still found whole by _split_inline_script.) cmd's text is
    also read as _cmd_texts gives it. A pwsh/powershell script is also read with each
    of _PS_SPACES a space, as PowerShell separates words on them; then each of those two
    in its grouping and block readings (_ps_ungroup, _ps_block_statements), and all of
    those with PowerShell's own quoting (_ps_unescape; see _powershell_segments) and with
    its backtick escapes decoded. The spaces are read before the escapes, so a space an
    escape produces stays inside its word. Both decoders read the same base texts, never
    each other's output, so no escape is decoded twice. kind is the runner's
    ("cmd", "ps" or "wsl"): "ps" marks a PowerShell script (see ps_script in _rules_at),
    "cmd" a cmd script (see cmd_script on _Seg); outer, see _runner_rests.
    """
    out = []
    for kind, words, outer in _runner_rests(toks):
        texts = _cmd_texts(words) if kind == "cmd" else [" ".join(words)]
        if kind == "ps":
            texts = _ps_script_texts(texts[0])
        out += [(t, kind, outer) for t in texts]
    return list(dict.fromkeys(out))


def _ps_script_texts(text: str):
    """The texts a pwsh/powershell script is read as (see _runner_scripts)."""
    texts = [text]
    spaced = text.translate(_PS_AS_SPACE)
    if spaced != text:
        texts.append(spaced)
    plain = list(texts)
    texts += [_ps_ungroup(t) for t in plain]
    texts += [_ps_block_statements(t) for t in plain if "{" in t or "}" in t]
    base = list(texts)
    texts += [_ps_unescape(t) for t in base]
    texts += [_ps_unescape_everywhere(t) for t in base if "`" in t]
    return texts


def _lenient_runner(toks, outer_expanded=False):
    """In a quote-blind segment, the command words of each Windows runner, one segment
    each (the counterpart of _lenient_inline): `echo "$(wsl rm -rf ~)"` is judged as
    `rm -rf ~`."""
    out = []
    for kind, words, outer in _runner_rests(toks):
        variants = [words]
        if kind == "cmd":
            variants.append([w.replace("^", "") for w in words])
            # cmd's , = ' and Unicode spaces (see _CMD_DELIMS), as _runner_scripts reads them.
            variants += [" ".join(v).translate(_CMD_DELIMS).split() for v in list(variants)]
        for v in variants:
            seg = _new_seg(v, getattr(toks, "piped", False))
            # Quote-blind: any $ word counts as one the shell expands (see expanding).
            seg.ps_script = kind == "ps"
            seg.ps_outer = outer_expanded or outer
            seg.cmd_script = kind == "cmd"
            out.append(seg)
            if seg.cmd_script:
                out += _cmd_prefix_variants(seg)
    return out


def _ps_no_exit(args) -> bool:
    """-NoExit among pwsh/powershell's OWN switches (before the first positional word or
    -Command/-File/-EncodedCommand), on either reading of value switches. pwsh matches it
    by prefix, `-noe` at the shortest (`-no` is ambiguous). The runner runs its command,
    then reads stdin as more commands."""
    for consume in (True, False):
        j = 0
        while j < len(args):
            kind, name = _ps_switch(args[j]), _ps_switch_name(args[j])
            if kind != "other":
                break
            if len(name) >= 3 and "noexit".startswith(name):
                return True
            j += 2 if consume and _ps_takes_value(args[j]) else 1
    return False


def _ps_evals_stdin(words) -> bool:
    """A pwsh/powershell command (its words) that reads stdin and turns text into code."""
    text = " ".join(words)
    return bool(_PS_STDIN_RE.search(text) and _PS_EVAL_RE.search(text))


def _runner_reads_stdin(base: str, args) -> bool:
    """A Windows runner taking its commands from stdin: cmd with no /c or /r run switch,
    or with /k (it keeps running after the command); pwsh or powershell with `-Command -`, `-File -`, a
    `-` as its first positional word, no command, file or positional word, -NoExit (see
    _ps_no_exit), or a command that evaluates what it reads from stdin (_ps_evals_stdin);
    wsl with nothing but value options (its default shell then reads stdin)."""
    if base == "cmd":
        run = _cmd_run_switch(args)
        if run is None:
            return True
        j, glued = run
        return args[j][len(args[j]) - len(glued) - 1] == "k"
    if base in _PS_RUNNERS:
        if _ps_no_exit(args):
            return True
        kind, j = _ps_decisive_switch(args)
        if kind == "command" and _ps_evals_stdin(args[j + 1:]):
            return True                     # `pwsh -c '$input | iex'`: stdin becomes code
        if kind in ("command", "file"):
            return args[j + 1:j + 2] in ([], ["-"])
        # No decisive switch: 5.1 runs its positional words as a command (which may
        # evaluate stdin), and a `-` there is stdin itself, for pwsh (`-File -`) and 5.1.
        return kind is None and any(_ps_positionals(args, c)[:1] in ([], ["-"])
                                    or _ps_evals_stdin(_ps_positionals(args, c))
                                    for c in (True, False))
    if base == "wsl":
        j = 0
        while j < len(args):
            if args[j] not in _WSL_VALUE_OPTS:
                return False
            j += 2
        return True
    return False


# PowerShell grouping: a ( ) / $( ) / @( ) around ONE word (a quoted string or a bare
# word), and { } outside a ${name} variable. Both linear: no nested quantifier.
_PS_GROUP_RE = re.compile(r"""[$@]?\([ \t]*('[^']*'|"[^"]*"|[^\s()'"]+)[ \t]*\)""")
_PS_BRACE_RE = re.compile(r"(\$\{[^{}]*\})|[{}]")


def _ps_keep_group(m):
    """A lone variable in a statement's condition (`if ($x)`), which the tool's ungrouped
    reading leaves alone: `if $x` would read the condition as a command word. Anywhere
    else the group is opened as usual: `git push ($x) --force` is `git push $x --force`."""
    return (_PS_VAR_WORD_RE.fullmatch(m.group(1).lstrip("!"))
            and _PS_CONDITION_RE.search(m.string[:m.start()].rstrip().lower()))


def _ps_block_statements(text: str) -> str:
    """Every brace outside ${...} read as a statement end: `if ($a) { $x = 1 } else
    { git push --force }` runs its blocks' commands. An added reading: a brace inside a
    string stays in its word."""
    return _PS_BRACE_RE.sub(lambda m: m.group(1) or " ; ", text)


def _ps_ungroup(text: str, keep_variables: bool = False) -> str:
    """PowerShell's grouping read away: `git reset ("--hard")`, `$("--force")`, `& ('git')`
    and `& {git reset --hard}` pass the grouped value on as the word itself. Only a group
    around a single word is opened (nested up to 4 deep), so `(Join-Path $HOME x)` stays a
    group; braces become spaces. A paren or brace inside a quoted string becomes a space
    inside the same word, and no quote character changes, so quoting is unaffected."""
    out = _PS_BRACE_RE.sub(lambda m: m.group(1) or " ", text)
    for _ in range(4):
        new = _PS_GROUP_RE.sub(lambda m: (m.group(0) if keep_variables and _ps_keep_group(m)
                                          else " " + m.group(1) + " "), out)
        if new == out:
            break
        out = new
    return out


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
        if state == "$'":                            # ANSI-C string, as in _shell_words
            if c == "\\":
                i += 1
            elif c == "'":
                state = ""
        elif state == "'":
            if c == "'":
                state = ""
        elif state == "" and c == "$" and line[i + 1:i + 2] == "$":
            i += 1                                   # $$: the 2nd $ opens nothing
        elif state == "" and c == "$" and line[i + 1:i + 2] == "'":
            state = "$'"
            i += 1
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
    PowerShell payload, an @'...'@ here-string becomes one POSIX single-quoted word and
    an @"..."@ one, whose $ PowerShell expands, one double-quoted word (see expanding
    on _Words); an unterminated one is left raw, so it fails to tokenize and
    is blocked. _segments() only passes text whose line breaks are all "\n" (see
    _WORD_BREAKS), so splitlines() splits exactly there, and a command whose every
    line already tokenizes yields logical == physical lines.
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
                body = "\n".join(phys[i:j])
                if line[here_at + 1] == '"':      # @"..."@ expands $ as "..." does
                    body = body.replace("\\", "\\\\").replace('"', '\\"')
                    parts.append(line[:here_at] + '"' + body + '"')
                else:
                    body = body.replace("'", "'\"'\"'")
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


class _Words(list):
    """_shell_words' result. subst: the line holds a command substitution ($( or a
    backtick) outside single quotes -- something bash runs that may sit inside a
    word, so the line also gets the piecewise pass (see _segments). expanding: the
    indexes of the words that hold a `$` the shell expands (outside single quotes and
    $'...', not escaped), so their text is not what a program they are handed sees."""
    subst = False
    expanding = frozenset()


class _Op(str):
    """An UNQUOTED shell operator run (`;`, `&&`, `|`, `>`...), as opposed to a word.

    glued: the run touches the word before it (the 2 of `2>` is an fd number).
    """
    glued = False


_OP_CHARS = set("();<>|&`")
_ANSI_SIMPLE = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "e": "\x1b",
                "E": "\x1b", "f": "\f", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}
_HEX = set("0123456789abcdefABCDEF")


def _ansi_escape(s: str, i: int):
    """Decode the escape at s[i] (a backslash) inside $'...'; return (text, next index).

    Decoded as bash does, so `rm -rf $'\\x2f'` is seen as `rm -rf /`.
    """
    c = s[i + 1]
    if c in _ANSI_SIMPLE:
        return _ANSI_SIMPLE[c], i + 2
    if c in "xuU":
        width = {"x": 2, "u": 4, "U": 8}[c]
        j = i + 2
        while j < len(s) and j < i + 2 + width and s[j] in _HEX:
            j += 1
        if j > i + 2:
            code = int(s[i + 2:j], 16)
            if code <= 0x10FFFF:
                return chr(code), j
    elif c in "01234567":
        j = i + 1
        while j < len(s) and j < i + 4 and s[j] in "01234567":
            j += 1
        return chr(int(s[i + 1:j], 8) & 0xFF), j
    elif c == "c" and i + 2 < len(s):
        return chr(ord(s[i + 2]) & 0x1F), i + 3
    return "\\" + c, i + 2                           # unknown escape: bash keeps the \


def _shell_words(s: str):
    """Words of a logical line, exactly as shlex.split(s, posix=True) reads them --
    quotes removed, backslash escapes resolved, the same errors for an unclosed quote
    or a trailing backslash -- except that an UNQUOTED run of ( ) ; < > | & ` comes
    out as its own _Op token. A quoted one stays inside its word, as in bash, so
    `bash -c "cd /tmp && rm -rf /"` keeps its script whole and `rm -rf '&' ~` keeps
    `&` as an argument.
    """
    words, buf, has_word, state, ansi_cut = _Words(), [], False, "", False
    i, n = 0, len(s)
    opens_quoted = value_quoted = False
    words.expanding = set()
    dollar, dq_bs = False, -2   # see push(); dq_bs: where a lone backslash sat in a "..."

    def word():
        text = "".join(buf)
        return (_QuotedWord(text) if opens_quoted
                else _QuotedValueWord(text) if value_quoted else text)

    def push():
        if dollar:
            words.expanding.add(len(words))
        words.append(word())

    while i < n:
        c = s[i]
        if state == "$'":                            # bash ANSI-C string: \ escapes, ' ends
            if c == "\\" and i + 1 < n:
                text, i = _ansi_escape(s, i)         # \x2f, \57, \u2f, \n ... decoded
            elif c == "'":
                state = ""
                i += 1
                continue
            else:
                text, i = c, i + 1
            # bash ends the string at its first NUL: `$'--hard\x00x'` is `--hard`.
            if not ansi_cut:
                if "\x00" in text:
                    text, ansi_cut = text.split("\x00", 1)[0], True
                buf.append(text)
            continue
        elif state == "'":
            if c == "'":
                state = ""
            else:
                buf.append(c)
        elif state == '"':
            if c == '"':
                state = ""
            elif c == "\\" and i + 1 >= n:
                raise ValueError("No escaped character")
            elif c == "\\" and s[i + 1] in '"\\':
                buf.append(s[i + 1])
                i += 1
            else:
                if c == "`" or (c == "$" and s[i + 1:i + 2] == "("):
                    words.subst = True               # a substitution bash runs in "..."
                if c == "$" and dq_bs != i - 1:
                    dollar = True                    # unless a lone backslash escapes it
                elif c == "\\":
                    dq_bs = i
                buf.append(c)
        elif c == "\\":
            if i + 1 >= n:
                raise ValueError("No escaped character")
            buf.append(s[i + 1])
            i += 1
        elif c == "$" and s[i + 1:i + 2] == "$":
            buf.append("$$")                         # $$ (the PID): the 2nd $ opens nothing
            dollar = True
            i += 2
            continue
        elif c == "$" and s[i + 1:i + 2] == "'":
            state, has_word, ansi_cut = "$'", True, False
            i += 2
            continue
        elif c in "'\"":
            if not (buf or has_word):
                opens_quoted = True
            elif (buf[-1:] == ["="] and not value_quoted
                  and _PS_VALUE_PREFIX_RE.fullmatch("".join(buf))):
                value_quoted = True
            state, has_word = c, True
        elif c in " \t\r\n":                         # shlex's default whitespace
            if buf or has_word:
                push()
            buf, has_word, opens_quoted, value_quoted = [], False, False, False
            dollar = False
        elif c in _OP_CHARS:
            if c == "`" or (c == "(" and buf and buf[-1] == "$"):
                words.subst = True
            glued = bool(buf or has_word)
            if glued:
                push()
            buf, has_word, opens_quoted, value_quoted = [], False, False, False
            dollar = False
            j = i
            while j < n and s[j] in _OP_CHARS:
                j += 1
            op = _Op(s[i:j])
            op.glued = glued
            words.append(op)
            i = j
            continue
        else:
            dollar = dollar or c == "$"
            buf.append(c)
        i += 1
    if state:
        raise ValueError("No closing quotation")
    if buf or has_word:
        push()
    return words


class _QuotedWord(str):
    """A word _shell_words read as opening with a ' or " quote."""


class _QuotedValueWord(str):
    """A word holding an assignment whose value opens with a quote: `$x='a b'`, `key="v"`."""


class _Seg(list):
    """A segment's tokens.

    piped: something other than a terminal or a named file feeds its stdin (a | or
    |&, or a process substitution). redirs: the redirect targets dropped from the
    tokens, kept so extraPatterns can still match them. ps_script: the segment is part of
    a script handed to pwsh/powershell (see _runner_scripts). xargs_fed: the segment is
    part of an inline script that xargs runs (`xargs sh -c '...'`), so its arguments
    include xargs' items. ps_tool: the segment is the PowerShell tool's own payload, not
    a script nested in it. ps_call: it follows a call operator, starts a group in argument
    position, is or holds a method call's object, or comes at or after a group that is
    called or passed to a program runner. ps_foreach: it is a foreach header. ps_quoted,
    ps_quoted_value: the indexes of the words that open with a quote, and of those whose
    assignment's value does. (The last five: see _ps_statement_tail.) expanding: the
    indexes of the words that hold a `$` the shell expands (see expanding on _Words), or
    a `$` at all when the words were read quote-blind; a PowerShell script in such a word
    is not the text pwsh gets: its segments are marked ps_outer, and a $ word in them is
    no expression (see _rules_at). heredoc: a `<<` heredoc redirect is on the segment;
    herestr_fed: a `<<<` here-string is; heredoc_wide: one of them is on a group or
    compound command that ends here, so it feeds every command in it (see
    _heredoc_check). cmd_script: the segment is part of a script handed to cmd (see
    _cmd_prefix_variants); scripts nested inside it are not. empties: the indexes before
    which the shell's words held an empty word (`""`, `''`), which the segment drops: a
    program gets each one as an argument, and cmd reads it as a word (see _runner_rests).
    """
    heredoc = heredoc_wide = herestr_fed = False
    cmd_script = False
    empties = ()
    piped = False
    redirs = ()
    ps_script = False
    xargs_fed = False
    ps_tool = False
    ps_call = False
    ps_foreach = False
    ps_quoted = ps_quoted_value = frozenset()
    expanding = frozenset()
    ps_outer = False


def _new_seg(toks, piped, redirs=()):
    seg = _Seg(toks)
    seg.piped = piped
    seg.redirs = list(redirs)
    return seg


def _xargs_fed_copy(seg):
    """A copy of seg marked xargs_fed. A copy, because seg may be shared: segments
    _runner_segments returns are memoized and must not change after the call."""
    out = _Seg(seg)
    out.__dict__.update(vars(seg))         # ps_call, ps_outer, expanding, ... as they are
    out.redirs = list(seg.redirs)
    out.xargs_fed = True
    return out


def _cmd_start_targets(toks, i):
    """Indexes where the command after cmd's `start` at toks[i] may begin: past its
    switches (any word opening with /, glued ones too: `/b/wait`), the value a switch may
    take (`/d <dir>`, `/node 1`, `/machine x`) and at most one title word among them (a
    quoted title may come first or between switches). No table of the switches that take
    a value: every word after a switch is read both as its value and as the command, as
    _git_candidates reads git's options, so a switch missing from a table costs a false
    positive, never a miss. Linear: each (index, title taken, after a switch) state is
    visited once."""
    out, n = set(), len(toks)
    work, seen = [(i + 1, False, False)], set()
    while work:
        state = work.pop()
        if state in seen:
            continue
        seen.add(state)
        j, titled, after = state
        if j >= n:
            continue
        if toks[j].startswith("/"):
            work.append((j + 1, titled, True))
            continue
        out.add(j)
        if after:
            work.append((j + 1, titled, False))      # the word was the switch's value
        if not titled:
            work.append((j + 1, True, False))        # the word was the title
    return out


def _cmd_if_targets(toks, i):
    """Indexes where the command after cmd's `if` at toks[i] may begin: past `/i` and
    `not`, the word two or three words on. A condition is two or three words (`exist x`,
    `defined v`, `errorlevel n`, `a== b`; `a == b`, `a equ b`), or one, `a==b`, which every
    cmd script is also read as two words (`=` is one of _CMD_DELIMS): every count is
    read, so no table of condition forms can be wrong."""
    j, n = i + 1, len(toks)
    while j < n and toks[j] in ("/i", "not"):
        j += 1
    return {k for k in (j + 2, j + 3) if k < n}


def _seg_suffix(seg, i, first):
    """A copy of seg from toks[i] on, its first word replaced by first (unless None), its
    attributes kept and its expanding indexes shifted to the suffix. (ps_quoted and
    ps_quoted_value are read on the PowerShell tool's own segments only, never on a
    cmd script's.)"""
    out = _Seg([seg[i] if first is None else first] + list(seg[i + 1:]))
    out.__dict__.update(vars(seg))
    out.redirs = list(getattr(seg, "redirs", ()))
    out.expanding = _suffix_expanding(seg, out)
    out.empties = tuple(e - i for e in getattr(seg, "empties", ()) if e > i)
    return out


def _cmd_prefix_variants(seg):
    """For a segment of a cmd script: a copy of it from each command position cmd's
    command-position prefixes lead to, the prefixes dropped, so that the command they run
    is judged as any other. cmd strips `@` from a command (`@git ...`), and runs the word
    after `call`, after `start`'s switches and title, and after an `if` condition. The
    walk also steps over wrappers and keywords as _shell_index does (cmd's `do` and
    `else` among them), so an `@` after `do` is reached. Tokens are already lowercased
    (see _words_to_segments). Only a
    position reached through one of cmd's prefixes gives a copy: the segment itself
    covers the rest. Each state is visited once, so the walk is linear in the words; the
    copies' words are charged to the runner budget (see _runner_segments), so a long run
    of prefixes that would multiply them is refused rather than slow."""
    out, seen, n = [], set(), len(seg)
    work = [(0, None, False)]         # (index, its word with the @s removed, prefix read)
    while work:
        state = work.pop()
        if state in seen:
            continue
        seen.add(state)
        i, word, read = state
        if i >= n:
            continue
        t = seg[i] if word is None else word
        base = _cmd_word(t)
        if t.startswith("@"):                      # `@@x`: the state is visited again
            rest = t[1:]
            work.append((i, rest, True) if rest else (i + 1, None, True))
        elif base == "start" or t.startswith("start/"):     # glued: `start/b/wait x`
            work += [(k, None, True) for k in _cmd_start_targets(seg, i)]
        elif base in _WRAPPERS:
            work += [(_skip_wrapper_args(base, seg, i + 1, c), None, read)
                     for c in _READINGS]
            if base == "if":
                work += [(k, None, True) for k in _cmd_if_targets(seg, i)]
        elif base == "call":
            work.append((i + 1, None, True))
        elif read:
            copy = _seg_suffix(seg, i, word)
            _RunnerBudget.charge(sum(len(w) + 1 for w in copy))
            out.append(copy)
    return out


def _cmd_expansion_word(word: str) -> bool:
    r"""Does a cmd variable expansion decide which program this command word names? cmd
    expands `%x%` (`%x:~0,3%`, `%COMSPEC%`) as text before it parses the line, `!x!` when
    delayed expansion is on (`/v:on`, or the registry's DelayedExpansion, which the
    command does not show) and a for-variable (`%i`, `%~i`) in its loop's body: the
    program is the value, which is not in the payload. Anywhere in the word: a value
    holding a space or a quote moves the word's end (`"%x%\node.exe"`, `%x%/node.exe`
    run the program x names), so even a literal last path component names nothing. (In
    PowerShell text, `cmd /c --% ...` hands cmd no `--%` word: see _runner_rests.) Not a
    URL `start` opens (`https://x/?q=a%20b`): an expansion there names no other program,
    short of one whose value adds an `&` (cmd `%VAR%` indirection, in README's limits)."""
    return ("%" in word or "!" in word) and not _URL_SCHEME_RE.match(word)


# Only these: a one-letter scheme is a drive (`c://%x%`), and others may name a program.
_URL_SCHEME_RE = re.compile(r"https?://")


def _cmd_command_index(seg) -> int:
    """The index of cmd's command word in a segment of a cmd script: the first word, past
    cmd's `do` and `else`. A command behind `@`, `call`, `start` or an `if` condition is
    the first word of a copy _cmd_prefix_variants makes. `if` is not stepped over as the
    bash finders step over it: the word after it is the condition."""
    i = 0
    while i < len(seg) - 1 and seg[i] in ("do", "else"):
        i += 1
    return i


def _ps_command_mode(cur, quoted):
    """Has a command name started the statement these words begin? Past an expression
    chain (`$x =`, `$a -eq`, `$f in`, `$x=`), a word that is not a variable, a number or a
    quoted string names a command (`$x = git ...`), and after it every word is an
    argument, `-is`, `in` and `--repo=` included. quoted: indexes of quoted words."""
    i = 1 if len(cur) > 1 and cur[0].lower() in _PS_STATEMENT_PREFIX else 0
    while i < len(cur):
        word = cur[i]
        glued = _PS_GLUED_ASSIGN_RE.fullmatch(word)
        if glued:
            word = glued[3]
            if not word:
                i += 1
                continue
        elif (_PS_VAR_WORD_RE.fullmatch(word) and i + 1 < len(cur)
              and (cur[i + 1].lower() in _PS_TOOL_EXPR_NEXT or cur[i + 1].lower() == "in")):
            i += 2
            continue
        if i in quoted or word[:1] in "$@'\"" or _PS_NUMBER_RE.fullmatch(word):
            return False
        if word[:1] == "-":     # `-foo (` calls -foo; `-1 (` and `- (` are values
            return bool(_PS_DASH_NAME_RE.fullmatch(word))
        return True
    return False


def _ps_argument_group(values, cur, quoted):
    """Does a `(` after these words open a group in a command's argument position?
    Not a keyword's header (`if (`, `} else { if (`). After a command name, yes
    (`git push --repo=(...)`, `curl -is (...)`); in an expression, not where a value goes
    (`$x = (`, `$a -eq @(`, `$x=(`). values: see close() in _words_to_segments."""
    words = [v.lower() for v in (values[:-1] if values[-1:] in (["@"], ["$"]) else values)]
    if not words:
        return False
    if words[-1] in _PS_HEADER_KEYWORDS and _PS_BLOCK_WORDS.issuperset(words[:-1]):
        return False
    if _ps_command_mode(cur, quoted):
        return True
    return bool(words[-1]) and words[-1] not in _PS_TOOL_EXPR_NEXT and words[-1] != "in"


class _Latch(list):
    """The state _words_to_segments shares across the lines of one text: non-empty once a
    called or runner-argument group has opened; last, the latest segment; closer, the
    operator that ended the words before the current ones; orphan_heredoc, a heredoc was
    on a group closer with no segment before it to mark (see _heredoc_check)."""
    last = None
    closer = None
    orphan_heredoc = False


def _words_to_segments(words, split_words: bool = True, latch=None):
    """Operator pieces end a segment; group/negation punctuation is stripped.

    A run of operators (`;>`, `(>`) is split into single operators. A redirection
    is part of its command, not the end of it: the operator, its target and an fd
    glued to it (the 2 of 2>, the {x} of {x}>) are dropped and the segment
    continues, so `>/dev/null rm -rf /` is judged as rm. A here-string's target is
    appended as `-c <target>`, so `bash <<< 'script'` -- in either order -- reads
    like `bash -c`. A pipe marks the next segment piped, through a `( ... )` group
    but not `||`; `<( ... )` marks the command it feeds, `>( ... )` its own body.
    Tokens are lowercased, except short-flag bundles (-P, -Rf): wrapper options are
    case-sensitive (xargs -P takes a value, -p does not). latch: shared by the lines of one
    text, since a group can span lines (see _Latch, ps_call on _Seg and close() below).
    """
    segments, cur, redirs, herestr = [], [], [], []
    here_exp = []                          # per herestr target: see expanding on _Seg
    piped, pending = False, None           # pending: redirect awaiting its target
    heredoc_here = False                   # a `<<` target was taken for this segment
    call_next = arg_next = foreach_next = False   # see ps_call and ps_foreach on _Seg
    quoted, quoted_value = set(), set()
    exp = set()                            # see expanding on _Seg
    empties = []                           # see empties on _Seg
    expanding = getattr(words, "expanding", None)   # None: quote-blind words
    latch = _Latch() if latch is None else latch

    def close(next_piped, fed=False, op=None, glued_op=False, real_op=False):
        nonlocal cur, redirs, herestr, piped, pending, call_next, arg_next, foreach_next
        nonlocal quoted, quoted_value, exp, here_exp, heredoc_here, empties
        toks = cur + [w for target in herestr for w in ("-c", target)]
        # Each word's value: `$x=.` and `$x=sudo` hold a `.` and a `sudo`.
        values = [w.rsplit("=", 1)[-1] for w in cur]
        calls = op in ("&", "`") or (op == "(" and (
            values[-1:] in (["."], [".@"], [".$"])
            or (values[-1:] in (["@"], ["$"]) and values[-2:-1] == ["."])))
        held, held_arg = call_next, arg_next
        # A method call's `(`, glued to its name: `$w.Run(`, `$w. Run(`, and `($w).Run(`,
        # `($w)[0].Run(`, `($w)::Run(`, `($w)?.Run(`, whose object is the segment before,
        # perhaps on an earlier line (latch.last).
        method = bool(op == "(" and glued_op and cur and (
            _PS_CALLED_WORD_RE.search(cur[-1])
            or (cur[-2:-1] and cur[-2].endswith(".") and "$" in cur[-2])))
        if (op == "(" and glued_op and cur and latch.closer == ")"
                and cur[0].startswith((".", "[", "::", "?.")) and latch.last is not None):
            latch.last.ps_call = True
        latch.closer = op
        # A heredoc or here-string on a group closer (`{ ...; } <<EOF`, `( ... ) <<< x`)
        # feeds every command in the group: the segment before it is marked, or with none
        # before it in these words, the text (see _heredoc_check).
        if (heredoc_here or herestr) and not cur:
            if latch.last is not None:
                latch.last.heredoc_wide = True
            else:
                latch.orphan_heredoc = True
        if toks:
            # A here-string feeds stdin too: `bash - <<< '...'` reads it as its script.
            seg = _new_seg(toks, piped or fed or bool(herestr), redirs)
            seg.ps_call = held or held_arg or bool(latch) or method
            seg.ps_foreach = foreach_next
            seg.ps_quoted, seg.ps_quoted_value = frozenset(quoted), frozenset(quoted_value)
            seg.empties = tuple(empties)
            # A here-string target follows its `-c` at the end of toks (see above).
            seg.expanding = frozenset(exp) | {len(cur) + 2 * j + 1
                                              for j, e in enumerate(here_exp) if e}
            # One on `done`, `fi` or `esac` feeds the whole compound command, and one on
            # an exec with no command every later one. (A here-string on the runner
            # itself is a piped one, refused as such.)
            seg.heredoc, seg.herestr_fed = heredoc_here, bool(herestr)
            seg.heredoc_wide = (bool(heredoc_here or herestr)
                                and (cur[:1] in (["done"], ["fi"], ["esac"])
                                     or _exec_only(cur)))
            segments.append(seg)
            latch.last = seg
            piped = next_piped
        else:
            piped = piped or next_piped        # `| (bash)`: the group keeps the pipe
        call_next = calls
        # The first statement of a group in argument position: `git push ($x) --force`.
        # real_op: a `(` the quote-blind pass found may be inside a string.
        arg_next = op == "(" and real_op and (_ps_argument_group(values, cur, quoted | quoted_value)
                                              or (held_arg and not toks))
        # `& @(1; $y)` calls what the group yields; `sudo @(1; $c)` passes it to a program
        # that runs it, so a variable in it is no more ordinary than `sudo $c` is. A latch,
        # not a depth count: this reader counts a `)` that PowerShell may not (`# )`, `--% )`).
        if op == "(" and (held or calls or any(_cmd_word(v) in _PS_PROGRAM_RUNNERS for v in values)):
            latch.append(True)
        foreach_next = op == "(" and cur[-1:] == ["foreach"]
        cur, redirs, herestr, pending = [], [], [], None
        here_exp, heredoc_here = [], False
        quoted, quoted_value = set(), set()
        exp = set()
        empties = []

    for k, word in enumerate(words):
        is_op = isinstance(word, _Op)
        if is_op:                          # from _shell_words: an unquoted operator run
            pieces, glued = [word], word.glued
        elif split_words:                  # quote-blind words: split them on operators
            pieces, glued = _SEP_SPLIT_RE.split(word), False
        else:                              # a word from _shell_words: whole, as bash has it
            pieces, glued = [word], False
        prev_op = None                     # glued: the op touches cur[-1]'s word
        for piece in pieces:
            if not piece:
                if not (is_op or split_words or pending):
                    empties.append(len(cur))       # an empty word ("", ''): see empties
                continue
            if is_op or (split_words and _SEP_ONLY_RE.match(piece)):
                for op in _OP_RE.findall(piece):
                    if _REDIR_RE.match(op):
                        if glued and cur and (cur[-1].isdigit() or _NAMED_FD_RE.match(cur[-1])):
                            cur.pop()
                            quoted.discard(len(cur))
                            exp.discard(len(cur))
                            quoted_value.discard(len(cur))
                        pending = op
                    elif op == "(" and prev_op == "<":
                        close(False, fed=True)     # <(...): its output feeds this command
                    elif op == "(" and prev_op == ">":
                        close(True)                # >(...): this command feeds its body
                    else:
                        close(op in ("|", "|&"), op=op, glued_op=glued, real_op=is_op)
                    glued, prev_op = False, op
                continue
            prev_op = None
            # `function f { ...; }` and `coproc NAME { ...; }`: the body's first command
            # starts after the `{`, as it does after `f() {` (whose `(` already ends the
            # segment).
            if piece == "{" and len(cur) == 2 and cur[0] in ("function", "coproc"):
                close(False)
                continue
            piece = piece.lstrip(_LEAD_GROUP_CHARS)
            if not piece or piece == "}":   # `{ ... ; }` closer: no command meaning
                continue
            if not _SHORT_FLAG_RE.match(piece):
                piece = piece.lower()
            if pending:
                if pending == "<<<":
                    herestr.append(piece)
                    here_exp.append((k in expanding) if expanding is not None else ("$" in piece))
                else:
                    redirs.append(piece)
                    heredoc_here = heredoc_here or pending == "<<"
                pending = None
                continue
            if isinstance(word, _QuotedWord):
                quoted.add(len(cur))
            elif isinstance(word, _QuotedValueWord):
                quoted_value.add(len(cur))
            if (k in expanding) if expanding is not None else ("$" in piece):
                exp.add(len(cur))
            cur.append(piece)
            glued = True
    close(False)
    return segments


def _lenient_words(line: str):
    """One physical line with escapes resolved and every quote character deleted.

    Used only as a second pass over the lines of a multi-line logical line. Deleting
    the quotes makes every separator on the line visible, so a command that bash would
    run is inspected even where the quote scanner took it for part of a string -- the
    scanner does not model comments, the fresh quoting context inside "$(...)", or
    heredoc bodies, and a divergence there must not become a bypass.

    Returns a list of word lists, one per reading. str.split() separates words on every
    one of _PS_SPACES but U+180E, which Python no longer counts as a space; a line with
    U+180E is ALSO read with it a separator, as a pwsh script the line may run reads
    it on Windows PowerShell 5.1 with an older .NET. The reading that keeps it inside
    its word stays (pwsh 7 does that), so `x<U+180E>$CMD` is still one command word.
    """
    bare = re.sub(r"\\(.)", r"\1", line).replace("'", "").replace('"', "")
    out = [bare.split()]
    spaced = bare.translate(_PS_AS_SPACE).split()
    if spaced != out[0]:
        out.append(spaced)
    return out


# Characters str.splitlines() treats as line breaks but bash reads as part of a word:
# `rm -rf <VT> ~` is two harmless lines to splitlines() and deletes ~ in bash. Text
# containing any of them is split in two readings, and the segments of both are
# judged: each character as a line break (what splitlines() did, and how a line-based
# shell may read it) and as a space (closest to bash, where it only glues onto a
# word). CRLF stays one line break in both; backslash-CR-LF is not a continuation in
# bash, and the line reading keeps that. _segments() applies this to every text it
# splits, so an inline script whose $'...' decodes to one (`bash -c $'rm -rf \v ~'`)
# is covered too.
_WORD_BREAKS = "\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"
_AS_LINE_BREAK = str.maketrans(dict.fromkeys(_WORD_BREAKS, "\n"))
_AS_SPACE = str.maketrans(dict.fromkeys(_WORD_BREAKS, " "))
# A third reading keeps each character INSIDE its word, as bash does, under a stand-in
# that is neither a separator nor anything a rule allows: `http://localhost<U+2028>-x@
# evil.example/` is one word to curl, and must be one word here too. Readings only add
# segments, so this can only add blocks.
_AS_IN_WORD = str.maketrans(dict.fromkeys(_WORD_BREAKS, "\x01"))

# Characters PowerShell separates words on and the readings take for part of a word.
# Beyond tab, VT, FF and space, PowerShell's whitespace is NBSP, NEL and every
# character .NET's char.IsSeparator() accepts (CharTraits.cs, IsWhitespace); VT, FF,
# NEL, U+2028 and U+2029 are _WORD_BREAKS already, whose space reading covers them.
# U+180E was a space separator before Unicode 6.3, and .NET Framework 4 to 4.5.2,
# which Windows PowerShell 5.1 can run on, classify characters with Unicode 5.0.
# A PowerShell payload holding any of them is also judged with each one a space (see
# _powershell_segments); bash reads them as part of a word, so a Bash payload is not,
# but a pwsh/powershell script inside it is (see _runner_scripts and _lenient_words),
# and so is a cmd script (see _CMD_DELIMS).
# The mapping covers the whole text, quoted strings and inline bash -c scripts too:
# a quoted string stays one word, and the extra splitting there only adds segments.
# The readings that keep one inside its word stay, so a command word glued by one to
# a $ word (Write-Output, NBSP, $env:PATH) is still blocked as an expansion in command
# position. The one exception is the quote-blind pass (_lenient_words): str.split()
# has always split there on every one of them but U+180E, which keeps both readings.
_PS_SPACES = "".join(map(chr, (0xA0, 0x1680, 0x180E, *range(0x2000, 0x200B),
                               0x202F, 0x205F, 0x3000)))
_PS_AS_SPACE = str.maketrans(dict.fromkeys(_PS_SPACES, " "))

# cmd's own reading of its line: , and = separate words as a space does (so does ;, which
# the bash reading already ends a segment at), and so does every one of _PS_SPACES (cmd
# separates words on all Unicode whitespace, U+180E included; tab, VT, FF, NEL, U+2028
# and U+2029 are bash's or _WORD_BREAKS' already); a ' is an ordinary character (deleted
# here, so the bash tokenizer does not read it as a quote); and a backslash escapes
# nothing (read as /, so `"a\"` closes its string as it does for cmd).
_CMD_DELIMS = str.maketrans({",": " ", "=": " ", "'": None, chr(92): "/",
                             **dict.fromkeys(_PS_SPACES, " ")})

# Characters after which a `#` starts a bash comment (it must start a word).
_COMMENT_AFTER = set(" \t\n;&|()<>")
# Reserved words that open (and close) a compound command: a pipe before one feeds every
# command inside it (see _bash_substitutions). `case` and `esac` are read on their own.
_BASH_OPEN_WORDS = {"{", "if", "while", "until", "for", "select"}
_BASH_CLOSE_WORDS = {"}", "fi", "done"}
# Reserved words a command follows, so a reserved word may come next (`! case ...`).
_BASH_LEAD_WORDS = {"{", "if", "while", "until", "then", "do", "else", "elif", "!", "time",
                    "coproc"}
_BASH_WORD_RE = re.compile(r"[^\s;&|()<>'\"`$\\]+")
# The readings of _bash_substitutions (all four) and _ps_subexpressions (the first
# three); callers judge the bodies of every one.
_SCAN_READINGS = ("strict", "open", "hash", "eager")


def _word_span_end(text: str, j: int) -> int:
    """End (exclusive) of the `$(...)`, `${...}` or backtick span at text[j] inside a
    heredoc word. Quotes and backslashes are skipped while counting parens or braces,
    and the span never crosses a line break, so a wrong count costs only the rest of
    its line: the lines after it are still read. A `case` inside the span is not
    modelled (its pattern's `)` ends the span): the scanner's delimiter then matches no
    line and its heredoc runs on to the end of the text, which over-reads."""
    n, tick = len(text), text[j] == "`"
    opener = "" if tick else text[j + 1]
    closer = "`" if tick else ")" if opener == "(" else "}"
    k, depth = j + 1, 0
    while k < n and text[k] != "\n":
        ch = text[k]
        if ch == "\\" and text[k + 1:k + 2] not in ("", "\n"):
            k += 2
            continue
        if not tick and ch == "$" and text[k + 1:k + 2] == "'":
            e = k + 2                                  # `$'...'`: a backslash escapes
            while e < n and text[e] not in ("'", "\n"):
                e += 2 if text[e] == "\\" and text[e + 1:e + 2] not in ("", "\n") else 1
            if e >= n or text[e] == "\n":
                return min(e, n)
            k = e + 1
            continue
        if not tick and ch in "'\"":
            e = k + 1
            while e < n and text[e] not in (ch, "\n"):
                escaped = ch == '"' and text[e] == "\\" and text[e + 1:e + 2] not in ("", "\n")
                e += 2 if escaped else 1
            if e >= n or text[e] == "\n":
                return min(e, n)
            k = e + 1
            continue
        if tick and ch == "`":
            return k + 1
        if not tick:
            depth += (ch == opener) - (ch == closer)
            if not depth:
                return k + 1
        k += 1
    return k


def _heredoc_word(text: str, j: int):
    """(delimiter, quoted, end) for the heredoc word at text[j], as bash reads it: the
    word ends at an unquoted blank or operator character, quotes and backslashes are
    removed (`E\\ O`, `'E O'`, `"E\\"F"`; `$'...'` decoded), and any of them makes the
    body literal; `$(...)`, `${...}` and backticks are kept whole, blanks and all
    (`<<a$(b c)`, and inside "..." too: `<<"a$(: "'")"`). A quoted part stops at a line
    break (bash's delimiter would then span lines and match none, so its heredoc runs
    to the end of the text, as the scanner's does). An empty quoted word (`<<''`) ends
    at an empty line."""
    n, out, quoted = len(text), [], False
    while j < n and text[j] not in " \t\n;&|()<>":
        c = text[j]
        if c == "\\":
            quoted = True
            out.append(text[j + 1:j + 2])
            j += 2
        elif c in "'\"" or (c == "$" and text[j + 1:j + 2] in ("'", '"')):
            quoted, ansi = True, c == "$" and text[j + 1] == "'"
            if c == "$":
                j += 1
                c = text[j]
            j += 1
            while j < n and text[j] not in (c, "\n"):     # a quoted part stays on its line
                if c == '"' and (text[j] == "`" or (text[j] == "$"
                                                    and text[j + 1:j + 2] in ("(", "{"))):
                    k = _word_span_end(text, j)        # a substitution in "...": whole
                    out.append(text[j:k])
                    j = k
                    continue
                if text[j] == "\\" and j + 1 < n and ansi:
                    s, j = _ansi_escape(text, j)
                    out.append(s)
                    continue
                if text[j] == "\\" and j + 1 < n and c == '"' and text[j + 1] in '$`"\\\n':
                    j += 1
                out.append(text[j])
                j += 1
            j += text[j:j + 1] == c                    # its closing quote, if on the line
        elif c == "`" or (c == "$" and text[j + 1:j + 2] in ("(", "{")):
            k = _word_span_end(text, j)                # `$(...)` `${...}` `...`: one span
            out.append(text[j:k])
            j = k
        else:
            out.append(c)
            j += 1
    return "".join(out), quoted, min(j, n)


def _bash_substitutions(text: str, reading: str = "strict"):
    """(bodies, uncommented) for bash text: (body, fed) for every command substitution
    bash runs in it (`$(...)`, backticks, `<(...)` / `>(...)`), at every nesting level,
    and the text with its `#` comments removed (None when it has none).

    One pass that follows bash's own reading, which the quote-blind pass does not: a
    `$(` body starts a fresh quoting context (`"$(pwsh -c 'pwsh -c ''x''')"`), a word
    starting with `#` is a comment to the line's end (`C:\\x\\' ; ... #'`; not right after
    a substitution or `${...}`, which the word goes on past), and a heredoc's lines are
    its body (literal for a quoted delimiter, read with its quoting: see _heredoc_word;
    for a bare one, only `\\`, `$(`, `${` and backticks count). Inside `${...}` only
    quotes, `\\`, `$(`, `${`, backticks, braces and process substitutions count
    (and `$'...'` quoting when the `${` is unquoted); inside arithmetic (`((...))`,
    `$((...))`, `$[...]`) there is no comment, heredoc or reserved
    word, and a '...' only hides the end, not a substitution. A reserved word counts only
    where a command starts (after `;` `&` `|` a line break `(` `)` or one of
    _BASH_LEAD_WORDS, or a `function` name): `case` opens a case, whose `|` between
    patterns is no pipe and whose pattern's `)` ends neither a body nor a subshell, and
    `esac` closes it there or as a pattern's first word.
    A backtick body runs to the next unescaped backtick, with `\\$` `` \\` `` and `\\\\`
    (and `\\"` inside "...") unescaped, as bash reads it; its own substitutions are found
    when it is judged. Each `$(` body comes back with its direct substitutions replaced
    by `$(:)` (a backtick one by `` `:` ``), which tokenizes as the original does: each is
    judged on its own, so the work stays linear in the text. An unterminated body (bash
    refuses the line) runs to the end of the text, or of the heredoc body it opened in.

    fed: the substitution is expanded for a command after a `|` in its pipeline (or
    inside such a body), whose stdin is the pipe. `;` `&` `&&` `||` and a line break end
    the pipeline, but not right after the `|` (blank lines and comments may follow it),
    nor inside a group, subshell or compound command the pipe feeds (`x | { a; b "$(c)";
    }`, `x | while ...; do ...; done`).

    reading: callers judge the bodies of every reading (see _bash_bodies). "strict" is
    bash's. Three of its decisions are also read the other way: where a comment starts
    ("open" skips none, so none is returned; "hash" starts one at every `#` outside a
    word's quotes and arithmetic), how a heredoc is read ("open" reads every body as a
    bare delimiter's, and its delimiter word as code too), and where a case opens
    ("open" reads no `case`, so any unmatched `)` ends a body; "eager" opens one at any
    word `case`, where a command starts or not). The rest (a case pattern's parens,
    where a delimiter line is, arithmetic, the pipe) follow bash alone."""
    bodies, comments = [], []
    open_, hash_, eager = (reading == r for r in _SCAN_READINGS[1:])

    def frame(kind, start, parent, **extra):
        f = {"kind": kind, "start": start, "quote": "", "depth": 0, "kw": 0, "cases": [],
             "children": [], "pipe": False, "pipe_nest": 0, "wait": False, "cmd": True,
             "lead": "", "fed": bool(parent) and (parent["fed"] or parent["pipe"])}
        f.update(extra)
        return f

    def pop(end, after=None):
        """Close the innermost frame: its body ends at end, its text at after (past its
        `)`; end when it has none). A substitution's body is kept and the frame becomes
        its parent's child; any other frame hands its children up."""
        f = stack.pop()
        if f["kind"] == "$(":
            bodies.append((_subst_body(text, f, end), f["fed"]))
            stack[-1]["children"].append((f["open"], end if after is None else after,
                                          text[f["open"]:f["open"] + 2]))
        else:
            stack[-1]["children"].extend(f["children"])

    stack, heres, pending = [frame("top", 0, None)], [], []
    i, n, closed_at = 0, len(text), -1       # closed_at: just after a substitution's end
    while i < n:
        if heres and i >= stack[heres[-1]]["end"]:
            k = heres.pop()
            end, after = stack[k]["end"], stack[k]["after"]
            while len(stack) > k:               # unterminated frames end with the body
                pop(end)
            i = after
            continue
        f = stack[-1]
        kind, q, c = f["kind"], f["quote"], text[i]
        if kind == "H" and f["literal"]:               # a quoted delimiter's body
            i = f["end"]
            continue
        if q == "'":
            if c == "'":
                f["quote"] = ""
            i += 1
            continue
        if q == "$'":
            if c == "'":
                f["quote"] = ""
            i += 2 if c == "\\" else 1
            continue
        if f["wait"] and c not in " \t\n#" and not text.startswith("\\\n", i):
            f["wait"] = False                          # the command after a `|` starts
        if c == "\\":
            f["cmd"] = f["cmd"] and text.startswith("\\\n", i)
            i += 2
            continue
        if c == "`":
            j = i + 1
            while j < n and text[j] != "`":
                j += 2 if text[j] == "\\" else 1
            esc = r"\\([$`\\\"])" if q == '"' else r"\\([$`\\])"
            bodies.append((re.sub(esc, r"\1", text[i + 1:min(j, n)]), f["fed"] or f["pipe"]))
            f["children"].append((i, min(j + 1, n), "`"))
            f["cmd"] = False
            i = closed_at = j + 1
            continue
        if c == "$" and text[i + 1:i + 2] in ("(", "[", "{"):
            f["cmd"] = False
            if text[i + 1] == "(":
                stack.append(frame("$(", i + 2, f, open=i, arith=text.startswith("((", i + 1)))
            elif text[i + 1] == "[":
                stack.append(frame("$[", i + 2, f))      # arithmetic, as $((...))
            else:
                stack.append(frame("${", i + 2, f, indq=q in ('"', "a'") or kind == "H"))
            i += 2
            continue
        if q in ('"', "a'"):                   # "a'": a '...' in arithmetic hides no $(
            if c == q[-1]:
                f["quote"] = ""
            i += 1
            continue
        if kind == "H":                                # only \ $( ${ ` count in a body
            i += 1
            continue
        if kind == "${":
            if c == "$" and text.startswith("'", i + 1) and not f["indq"]:
                f["quote"] = "$'"                      # `${x:-$'\''}`: ANSI-C quoting
                i += 2
                continue
            if c == '"' or (c == "'" and not f["indq"]):
                f["quote"] = c
            elif c in "<>" and text.startswith("(", i + 1) and not f["indq"]:
                stack.append(frame("$(", i + 2, f, open=i))   # process substitution
                i += 2
                continue
            elif c == "{":
                f["depth"] += 1
            elif c == "}":
                if f["depth"]:
                    f["depth"] -= 1
                else:
                    pop(i)
                    closed_at = i + 1
            i += 1
            continue
        if c in " \t":
            i += 1
            continue
        arith = f.get("arith", False) or kind in ("((", "$[")
        word_start = (i == f["start"] or text[i - 1] in _COMMENT_AFTER) and i != closed_at
        nest = f["depth"] + f["kw"]
        cmd = f["cmd"]
        case = f["cases"][-1] if f["cases"] and f["cases"][-1][0] == f["depth"] else None
        if c in "'\"":
            f["quote"] = "a'" if arith and c == "'" else c
            f["cmd"] = False
            if case:
                case[2] = False
        elif c == "$" and text.startswith("'", i + 1):
            f["quote"], f["cmd"] = "a'" if arith else "$'", False
            if case:
                case[2] = False
            i += 1
        elif c == "#" and not arith and not open_ and (hash_ or word_start):
            j = text.find("\n", i)
            j = n if j < 0 else j
            comments.append((i, j))
            i = j
            continue
        elif arith:                     # no comment, heredoc, pipe or reserved word inside
            if c == ("[" if kind == "$[" else "("):
                f["depth"] += 1
            elif c == ("]" if kind == "$[" else ")"):
                if f["depth"]:
                    f["depth"] -= 1
                elif kind == "$[":
                    pop(i)
                    closed_at = i + 1
                elif kind in ("$(", "(("):
                    pop(i, i + 1)
                    if kind == "((" and text.startswith(")", i + 1):
                        i += 1                         # `((...))` ends a word: `#` may follow
                    else:
                        closed_at = i + 1
        elif case and case[1] == "pattern":            # `case w in` until a pattern's `)`
            if c == ")" and case[3]:
                case[3] -= 1                           # an extglob group's end
            elif c == ")":
                case[1] = "body"
                f["cmd"] = True
            elif c == "(":
                case[3] += not case[2]                 # `@(a|b)`; first: the optional `(`
                case[2] = False
            elif c not in "|;\n":                      # `|` between patterns: no pipe
                m = _BASH_WORD_RE.match(text, i) if word_start else None
                if (m and case[2] and m.group() == "esac"
                        and (m.end() == n or text[m.end()] in _COMMENT_AFTER)):
                    f["cases"].pop()
                    f["kw"] = max(f["kw"] - 1, 0)
                    f["cmd"] = False
                case[2] = False
                if m:
                    i = m.end()
                    continue
        elif c in "<>" and text.startswith("(", i + 1):
            f["cmd"] = False
            stack.append(frame("$(", i + 2, f, open=i))   # process substitution
            i += 2
            continue
        elif c == "(" and word_start and text.startswith("((", i):
            stack.append(frame("((", i + 2, f))          # an arithmetic command
            i += 2
            continue
        elif c == "(":
            f["depth"] += 1
            f["cmd"] = True
        elif c == ")":
            f["cmd"] = True                            # `f() case ...`
            if f["depth"]:
                f["depth"] -= 1
            elif kind == "$(":
                pop(i, i + 1)
                closed_at = i + 1
        elif c == "|" and not text.startswith("||", i):  # `|` or `|&`: a pipe
            f["pipe"], f["pipe_nest"], f["wait"], f["cmd"] = True, nest, True, True
            i += 2 if text.startswith("|&", i) else 1
            continue
        elif (c in ";|" or (c == "&" and text[i - 1:i] not in ("<", ">")
                             and text[i + 1:i + 2] != ">")
              or (c == "\n" and not pending)):         # the pipeline ends (not `>&`, `&>`)
            f["cmd"] = True
            if c == "\n" and f["wait"]:                # a `|` goes on past a line break
                i += 1
                continue
            if nest <= f["pipe_nest"]:
                f["pipe"] = False
            if c == ";" and case and case[1] == "body" and text.startswith((";;", ";&"), i):
                case[1:] = "pattern", True, 0          # `;;` `;&` `;;&`: the next pattern
                i += 3 if text.startswith(";;&", i) else 2
                continue
            i += 2 if text.startswith(("&&", "||", ";;"), i) else 1
            continue
        elif text.startswith("<<<", i):                # a here-string: an ordinary word follows
            f["cmd"] = False
            i += 3
            continue
        elif text.startswith("<<", i):
            j = i + 2
            strip = text.startswith("-", j)
            j += strip
            while j < n and text[j] in " \t":
                j += 1
            delim, quoted, j = _heredoc_word(text, j)
            if delim or quoted:
                pending.append((delim, strip, quoted and not open_))
            f["cmd"] = False
            i = i + 2 + strip if open_ else j          # open: the word is read as code too
            continue
        elif c == "\n" and pending:
            j, spans = i + 1, []
            for delim, strip, quoted in pending:
                start = j
                while j < n:
                    e = text.find("\n", j)
                    e = n if e < 0 else e
                    line = text[j:e]
                    if (line.lstrip("\t") if strip else line) == delim:
                        spans.append((start, j, min(e + 1, n), quoted))
                        j = min(e + 1, n)
                        break
                    j = e + 1
                else:
                    spans.append((start, n, n, quoted))
            pending = []
            for start, end, after, quoted in reversed(spans):
                heres.append(len(stack))
                stack.append(frame("H", start, stack[-1], end=end, after=after,
                                   literal=quoted))
            if nest <= f["pipe_nest"] and not f["wait"]:
                f["pipe"] = False
            f["cmd"] = True
            i += 1
            continue
        elif word_start and _BASH_WORD_RE.match(text, i):
            end = _BASH_WORD_RE.match(text, i).end()
            if hash_ and "#" in text[i:end]:
                end = text.index("#", i)               # the comment starts inside the word
            w = text[i:end] if end == n or text[end] in _COMMENT_AFTER else ""
            # A command (so a reserved word) may follow `time [-p] [--]`, and a reserved
            # word the name after `function` or `coproc`.
            timed = f["lead"] == "time" and w in ("-p", "--")
            lead, f["lead"] = f["lead"], ("time" if timed else w if cmd and w in (
                "time", "function", "coproc") else "")
            if case and case[1] == "subject":
                if w == "in":
                    case[1], case[2] = "pattern", True
            elif (cmd or eager) and w == "case" and not open_:
                f["cases"].append([f["depth"], "subject", False, 0])
                f["kw"] += 1
            elif cmd and w == "esac" and case:
                f["cases"].pop()
                f["kw"] = max(f["kw"] - 1, 0)
            elif cmd and w in _BASH_OPEN_WORDS:
                f["kw"] += 1
            elif cmd and w in _BASH_CLOSE_WORDS:
                f["kw"] = max(f["kw"] - 1, 0)
            f["cmd"] = ((cmd and (w in _BASH_LEAD_WORDS or timed))
                        or (lead in ("function", "coproc") and w != "case"))
            i = end
            continue
        else:
            f["cmd"] = False
        i += 1
    while len(stack) > 1:                              # unterminated: to the text's end
        pop(n)
    uncommented = None
    if comments:
        out, pos = [], 0
        for a, b in comments:
            out.append(text[pos:a])
            pos = b
        uncommented = "".join(out) + text[pos:]
    return bodies, uncommented


def _bash_bodies(text: str):
    """(bodies, uncommented): the substitution bodies of every reading of
    _bash_substitutions, each once, and the strict reading's uncommented text. A body
    the strict reading also gives keeps its fed (a case-blind reading reads a `|`
    between patterns as a pipe)."""
    bodies, uncommented = _bash_substitutions(text)
    strict = {body for body, _ in bodies}
    for reading in _SCAN_READINGS[1:]:
        bodies += [b for b in _bash_substitutions(text, reading)[0] if b[0] not in strict]
    return list(dict.fromkeys(bodies)), uncommented


def _ps_bodies(text: str):
    """The subexpression bodies of every reading of _ps_subexpressions, each once."""
    return list(dict.fromkeys(
        b for r in _SCAN_READINGS[:3] for b in _ps_subexpressions(text, r)))


def _subst_body(text: str, f, end: int) -> str:
    """The body of substitution frame f, which ends at end, with each of its direct
    substitutions replaced by one of the same kind that runs nothing (`$(:)`, `<(:)`,
    `` `:` ``; see _bash_substitutions). ck: the child's opener."""
    out, pos = [], f["start"]
    for cs, ce, ck in f["children"]:
        out += [text[pos:cs], "`:`" if ck == "`" else ck + ":)"]
        pos = ce
    out.append(text[pos:end])
    return "".join(out)


def _ps_subexpressions(text: str, reading: str = "strict"):
    """The body of every $( ) subexpression PowerShell runs in text, at every nesting
    level: in code, in a "..." string and in an @"..."@ here-string, not in a '...' one
    or a comment. One pass that follows PowerShell's quoting, which no reading does
    inside a string: a doubled quote character is one literal character, a backtick
    escapes the next character (`` `$( `` is literal text), a "..." string ends at any
    of _PS_DQ, a here-string (`@` and any of _PS_SQ or _PS_DQ ending its line, after
    anything but a word character: `$x=@'`) at a line starting with any of the same
    kind's and `@`, ${...} is one variable, a # starting a word (or <# #>) is a
    comment, and after a `--%` word the line is verbatim up to a `|`, `&&` or line
    break (CR or LF). Each body comes
    back as _bash_substitutions gives one: its direct subexpressions replaced by
    `$(:)`, so the work stays linear; an unterminated one runs to the end of the text.
    reading (see _bash_substitutions): "open" opens a here-string after any character,
    skips no comment and reads past a `--%` as code; "hash" starts a comment at every #
    (and <#) outside a string."""
    open_, hash_ = reading == "open", reading == "hash"
    bodies = []
    stack = [{"kind": "top", "start": 0, "quote": "", "depth": 0, "children": []}]
    i, n = 0, len(text)
    while i < n:
        f = stack[-1]
        kind, q, c = f["kind"], f["quote"], text[i]
        if (q in ("@'", '@"') and (i == 0 or text[i - 1] == "\n")
                and c in (_PS_SQ if q == "@'" else _PS_DQ) and text.startswith("@", i + 1)):
            f["quote"] = ""                            # a here-string's closer
            i += 2
            continue
        if q == "@'":
            i += 1
            continue
        if q == "'":
            if c in _PS_SQ:
                if i + 1 < n and text[i + 1] in _PS_SQ:
                    i += 2
                    continue
                f["quote"] = ""
            i += 1
            continue
        if c == "`":
            i += 2
            continue
        if c == "$" and text.startswith("(", i + 1):
            stack.append({"kind": "$(", "start": i + 2, "open": i, "quote": "",
                          "depth": 0, "children": []})
            i += 2
            continue
        if q == '"':
            if c in _PS_DQ:
                if i + 1 < n and text[i + 1] in _PS_DQ:
                    i += 2
                    continue
                f["quote"] = ""
            i += 1
            continue
        if q == '@"':
            i += 1
            continue
        word_start = i == f["start"] or text[i - 1] in " \t\r\n;|&(){}"
        opener = open_ or i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")
        if c == "@" and opener and (text[i + 1:i + 2] in _PS_SQ or text[i + 1:i + 2] in _PS_DQ):
            eol = text.find("\n", i)
            if eol != -1 and not text[i + 2:eol].strip():
                f["quote"] = "@'" if text[i + 1] in _PS_SQ else '@"'
                i = eol + 1
                continue
        if c in _PS_SQ:
            f["quote"] = "'"
        elif c in _PS_DQ:
            f["quote"] = '"'
        elif c == "$" and text.startswith("{", i + 1):  # ${...}: one variable
            j = i + 2
            while j < n and text[j] != "}":
                j += 2 if text[j] == "`" else 1
            i = j + 1
            continue
        elif c == "<" and text.startswith("<#", i) and not open_ and (hash_ or word_start):
            j = text.find("#>", i + 2)
            i = n if j < 0 else j + 2
            continue
        elif c == "#" and not open_ and (hash_ or word_start):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        elif (c == "-" and word_start and not open_ and text.startswith("--%", i)
              and text[i + 3:i + 4] in ("", " ", "\t", "\r", "\n")):
            j = i + 3                          # stop-parsing: verbatim to | && CR or LF
            while j < n and text[j] not in "|\r\n" and not text.startswith("&&", j):
                j += 1
            i = j
            continue
        elif kind == "$(" and c == "(":
            f["depth"] += 1
        elif kind == "$(" and c == ")":
            if f["depth"]:
                f["depth"] -= 1
            else:
                stack.pop()
                bodies.append(_subst_body(text, f, i))
                stack[-1]["children"].append((f["open"], i + 1, "$("))
        i += 1
    while len(stack) > 1:                              # unterminated: to the text's end
        f = stack.pop()
        bodies.append(_subst_body(text, f, n))
        stack[-1]["children"].append((f["open"], n, "$("))
    return bodies


def _segments(raw: str, _depth: int = 0, shell: str = "bash", ps_slashes: bool = True,
              piped: bool = False, lenient_on_error: bool = False,
              windows_paths: bool = True, ps_script: bool = False,
              ps_tool: bool = False, outer_expanded: bool = False,
              heredoc: bool = False, cmd_script: bool = False, scan: bool = True):
    """Tokenize into independent sub-commands. Raises ValueError if unparseable.

    Returns a list of token lists. The text is split on unquoted newlines (see
    _logical_lines), each logical line is really tokenized (shlex, posix), then
    operator tokens end a segment. A logical line that spans several physical lines
    is ALSO inspected line by line, leniently (see _lenient_words). Text holding a
    drive-letter or UNC path is also read without the path rewrite (windows_paths
    False; see the end of this function). ps_script: raw is a script a Windows
    runner hands to pwsh/powershell; its own segments are marked so (scripts nested
    inside it are not). ps_tool: raw is the PowerShell tool's own payload; its segments
    are marked so, and what their statements run is added (see _ps_statement_tails).
    heredoc: raw is the script of a command a heredoc feeds (see _heredoc_check).
    cmd_script: raw is a script a Windows runner hands to cmd; its own segments are
    marked so, and also judged with cmd's command prefixes read away (see
    _cmd_prefix_variants). scan: bash text is also read as bash reads its command
    substitutions and comments (see _bash_substitutions); False for a reading that came
    from one.
    """
    if any(c in raw for c in _WORD_BREAKS):
        lf = raw.replace("\r\n", "\n")
        kw = dict(shell=shell, ps_slashes=ps_slashes, piped=piped,
                  lenient_on_error=lenient_on_error, windows_paths=windows_paths,
                  ps_script=ps_script, ps_tool=ps_tool, outer_expanded=outer_expanded,
                  heredoc=heredoc, cmd_script=cmd_script, scan=scan)
        return (_segments(lf.translate(_AS_LINE_BREAK), _depth, **kw)
                + _segments(lf.translate(_AS_SPACE), _depth, **kw)
                + _segments(lf.translate(_AS_IN_WORD), _depth, **kw))
    segments, lenient, lenient_runs, latch = [], [], [], _Latch()
    lenient_fed, orphan = [], False    # see _heredoc_check
    fed_in = heredoc
    slashed = _slashify_windows_paths(raw) if windows_paths else raw
    text = _expand_ifs(slashed)
    # Bash text, read as bash reads it: only where no drive-path rewrite changed it (that
    # text gets its bash reading below, windows_paths False).
    bash_read = (scan and shell == "bash" and not ps_script and not cmd_script
                 and slashed == raw)
    if shell == "powershell" and ps_slashes:
        # PowerShell's escape is the backtick; a backslash is a path separator, so
        # `rm -r -Force ..\..` must not tokenize to `....`.
        text = text.replace("\\", "/")
    for logical, physical in _logical_lines(text, shell):
        if not logical.strip():
            continue
        # ValueError (unbalanced quoting) -> caller blocks
        try:
            words = _shell_words(logical)
        except ValueError:
            if not lenient_on_error:
                raise                    # unbalanced quoting -> caller blocks
            words = None                 # judged piecewise only, below
        if words is not None:
            segments.extend(_words_to_segments(words, split_words=False, latch=latch))
        # The piecewise pass: for a multi-line logical line, and for any line with a
        # command substitution, whose body (`echo "$(git reset --hard)"`) sits inside
        # a word and gets a fresh quoting context in bash.
        if words is None or len(physical) > 1 or words.subst:
            # Physical lines, plus every continuation chain regardless of quote
            # state: a desync that leaves the scanner inside a quote also stops it
            # joining `git push \` + newline + `--force`, which bash still joins.
            for line in dict.fromkeys(physical + _cont_chains(physical)):
                first, first_run = len(lenient), len(lenient_runs)
                for words in _lenient_words(line):
                    line_latch = _Latch()      # one per call, as before; read back below
                    segs = list(_words_to_segments(words, latch=line_latch))
                    for toks in segs:
                        toks.ps_tool, toks.cmd_script = ps_tool, cmd_script
                    # Quote-blind words split a cmd runner's script at its & | && || as
                    # if they were the shell's: when the line holds a cmd runner (or Git
                    # Bash's start), each of its segments may be one of that script's
                    # commands, so each also gets cmd's prefix readings, plain and with
                    # cmd's delimiters (`echo "$(cmd //c 'echo a & call,x')"`).
                    cmd_line = cmd_script or any(
                        kind == "cmd" for t in segs for kind, _, _ in _runner_rests(t))
                    for toks in segs:
                        extra = []
                        if cmd_line:
                            delims = _Seg(" ".join(toks).translate(_CMD_DELIMS).split())
                            delims.__dict__.update(vars(toks))
                            delims.redirs = list(getattr(toks, "redirs", ()))
                            delims.empties = ()
                            # Re-split words: the quote-blind rule (any $ word expands)
                            # applies to them anew.
                            delims.expanding = frozenset(
                                i for i, w in enumerate(delims) if "$" in w)
                            # Both: the delimiter reading also re-splits the arguments
                            # the rules judge (`call git -c a=b push --force`), which cmd
                            # hands a program as they are.
                            extra = _cmd_prefix_variants(toks) + _cmd_prefix_variants(delims)
                        for seg in [toks] + extra:
                            lenient.append(seg)
                            lenient.extend(_lenient_inline(seg))
                            lenient_runs.extend(_lenient_runner(seg, outer_expanded))
                    orphan = orphan or line_latch.orphan_heredoc
                # Quote-blind words do not model groups: a heredoc on the line feeds
                # every command the line's readings found.
                if any(getattr(s, "heredoc", False) for s in lenient[first:]):
                    lenient_fed += lenient[first:] + lenient_runs[first_run:]
                # The quote-blind pass resolves backslashes and splits on spaces,
                # which shreds a quoted Windows path ("C:\Program Files\Git\bin\
                # bash.exe" -c ...). Also read the line on its own with quotes kept
                # and backslashes as /, through the main pipeline (inline sh -c
                # recursion included). A line that does not tokenize alone adds
                # nothing; the passes above still cover it.
                try:
                    segments.extend(_words_to_segments(
                        _shell_words(line.replace("\\", "/")), split_words=False))
                except ValueError:
                    pass
    if cmd_script:
        # Before the heredoc check, the depth limit and the expansion below, so a command
        # behind cmd's prefixes (`call pwsh <<EOF`, `start /b cmd /c ...`) is read by
        # them as any other.
        for seg in segments:
            seg.cmd_script = True
        segments += [v for seg in list(segments) for v in _cmd_prefix_variants(seg)]
    # Every command substitution's body, judged as the script it is (with its own
    # expansions; at this depth, as it runs in this shell; see _bash_substitutions). Its
    # segments come back expanded, so they join the others after the expansion below, but
    # the heredoc check sees them first: a here-string on a call, in a body, of a function
    # this text defines feeds the function's commands here. A body's stdin is that of the
    # command it is expanded for: piped after a `|` in its pipeline (see
    # _bash_substitutions), or when this whole text is.
    subst, uncommented = [], None
    if bash_read and ("$(" in text or "`" in text or "#" in text):
        bodies, uncommented = _bash_bodies(text)
        for body, fed in bodies:
            if body.strip() not in ("", ":"):
                _RunnerBudget.charge(len(body))
                subst += _segments(body, _depth, piped=piped or fed,
                                   lenient_on_error=True, outer_expanded=outer_expanded,
                                   heredoc=fed_in)
    # A pwsh script's subexpressions likewise, each read as a pwsh script is.
    if scan and ps_script and "$(" in raw:
        for body in _ps_bodies(raw):
            if body.strip() not in ("", ":"):
                for t in _ps_script_texts(body):
                    subst += _runner_segments(t, _depth, piped, True, outer_expanded, fed_in)
    heredoc = _heredoc_check(text, segments, lenient + lenient_runs + subst, lenient_fed,
                             orphan or latch.orphan_heredoc, heredoc)
    if piped:                      # this is the inline script of a piped segment
        for seg in segments + lenient + lenient_runs:
            if isinstance(seg, _Seg):
                seg.piped = True
    if ps_script:                  # not lenient_runs: a runner's command is not PowerShell
        for seg in segments + lenient:
            if isinstance(seg, _Seg):
                seg.ps_script, seg.ps_outer = True, outer_expanded
    if ps_tool:                    # not _lenient_inline's segments: those are bash text
        for seg in segments:
            seg.ps_tool = True
        segments += _ps_statement_tails(
            segments + [s for s in lenient if isinstance(s, _Seg) and s.ps_tool])
    # Re-tokenize inline `sh -c` scripts. Depth-bounded so a nested
    # `sh -c 'sh -c "..."'` chain cannot recurse without limit. At the limit a segment
    # that still holds an inline script or a Windows runner's command would run text
    # no reading has expanded, so the command is refused as uninspectable (a block).
    if _depth >= _MAX_INLINE_DEPTH:
        for toks in segments:
            inline = _split_inline_script(toks)[1]
            scripts = inline if isinstance(inline, tuple) else (inline,)
            if (any(s and s.strip() for s in scripts)
                    or any(" ".join(w).strip() for _, w, _ in _runner_rests(toks))):
                raise _Uninspectable(
                    f"inline scripts nested too deep to inspect (> {_MAX_INLINE_DEPTH} "
                    "levels)")
    else:
        expanded, reached = _expand_scripts(segments, _depth, outer_expanded, heredoc, text)
        if reached and not heredoc:
            # A heredoc reaches a shell that one of the expanded scripts starts (`bash -c
            # bash <<EOF`), or an eval's exec redirects this shell's stdin: every command
            # of this text is fed after all. Check them, and expand their scripts again
            # as fed ones.
            heredoc = _heredoc_check(text, segments, lenient + lenient_runs + subst,
                                     lenient_fed, False, True)
            expanded = _expand_scripts(segments, _depth, outer_expanded, True, text)[0]
        segments = expanded
    # Lenient segments skip the inline split: with the quotes deleted, the script
    # of `bash -c "rm -rf ~"` is already bare tokens. Splitting would take only its
    # first word as the script and strand the arguments; _lenient_inline judges
    # every word after the -c instead, and _lenient_runner a Windows runner's words.
    segments += lenient + lenient_runs + subst
    # The text without its comments (see _bash_substitutions): an added reading.
    if uncommented is not None and uncommented.strip():
        segments += _segments(uncommented, _depth, piped=piped, lenient_on_error=True,
                              windows_paths=windows_paths, outer_expanded=outer_expanded,
                              heredoc=fed_in, scan=False)
    # PowerShell text (the tool's payload or a pwsh script): what a `--%` hands cmd.
    if ps_tool or ps_script:
        for script, fed in _ps_stop_parsing_cmd_scripts(raw):
            segments += _runner_segments(script, _depth + 1, piped or fed, False, False,
                                         False, True)
    # The drive-letter/UNC rewrite above reads `C:\dir\x` as a path; a POSIX shell
    # reads those backslashes as it reads any other. So when the rewrite changed the
    # text, ALSO judge the text as the shell itself reads it and add those segments:
    # a command is judged by both readings, so this only adds blocks. The extra
    # reading is lenient about quoting, because a path such as "C:\dir\" that the
    # rewrite balances is often unbalanced read that way; such a line is then judged
    # piecewise rather than refused. It is not lenient about _Uninspectable: a run of
    # lines that each end in a backslash is a continuation chain read that way, and a
    # chain too long to inspect still blocks. PowerShell's own reading (ps_slashes)
    # turns every backslash into a separator anyway, so it has no second reading; an
    # inline `bash -c` script in it is covered by the POSIX readings of the same text
    # (see _powershell_segments). Cost: only text with a drive or UNC path pays; the
    # work doubles per nesting level of inline scripts.
    if slashed != raw and not (shell == "powershell" and ps_slashes):
        segments += _segments(raw, _depth, shell=shell, ps_slashes=ps_slashes,
                              piped=piped, lenient_on_error=True, windows_paths=False,
                              ps_script=ps_script, ps_tool=ps_tool,
                              outer_expanded=outer_expanded, heredoc=heredoc,
                              cmd_script=cmd_script, scan=scan)
    return segments


def _expand_scripts(segments, _depth: int, outer_expanded: bool, heredoc: bool, text: str):
    """The segments of _segments() below its depth limit, each followed by what its inline
    scripts and Windows runner's command run, tokenized one level down. Returns them, and
    whether a heredoc reaches every command of the text through them (see
    _heredoc_check): one on a segment reaches a shell reading its script from stdin among
    them, or an eval's script holds a heredoc_wide segment (it runs in this shell).
    heredoc: every segment is fed by a heredoc. text: the text the segments are from."""
    expanded, reached = [], False
    for toks in segments:
        start = len(expanded)
        # A script an outer shell expands first (`bash -c "pwsh -c '$CMD'"`, `pwsh -c
        # "$CMD"`) is not the text it runs: a pwsh script in it is marked ps_outer.
        # Its words from the shell's on count, the shell's own included (`watch "..."`).
        starts = [j for j in (_shell_index(toks, c) for c in _READINGS) if j is not None]
        first = min(starts) if starts else -1
        words = {_cmd_word(toks[j]) for j in starts}
        # An alias's value runs wherever it is called, in this text or (defined in an
        # eval) the command around it: what feeds a call is not known, so a heredoc, or a
        # pipe or redirect, anywhere in either feeds it.
        aliasing = "alias" in words
        whole = text + "\n" + _Command.raw if aliasing else ""
        alias_here = aliasing and "<<" in whole
        alias_piped = aliasing and ("|" in whole or "<" in whole)
        outer = outer_expanded or any(e >= first for e in getattr(toks, "expanding", ()))
        head, inline = _split_inline_script(toks)
        if head:
            expanded.append(head)
            start = len(expanded)
        # `xargs sh -c 'rm -rf "$@"' _`: xargs' items reach the script's commands (as
        # "$@", or substituted for -I's string), so they are marked too.
        fed = getattr(toks, "xargs_fed", False) or any(
            _effective_cmd_index(toks, c)[1] for c in _READINGS)
        # A heredoc on the segment (or on the text, see _heredoc_check) feeds the
        # commands its script runs: `bash -c pwsh <<EOF`, `cmd /c pwsh <<EOF`.
        here = heredoc or getattr(toks, "heredoc", False) or alias_here
        for script in (inline if isinstance(inline, tuple) else (inline,)):
            if not (script and script.strip()):
                continue
            # `echo ... | bash -c "true; sh"`: the pipe reaches every command of
            # the script, so the script's segments start out piped.
            subs = _segments(script, _depth + 1,
                             piped=getattr(toks, "piped", False) or alias_piped,
                             outer_expanded=outer, heredoc=here)
            expanded.extend(_xargs_fed_copy(s) if fed and isinstance(s, _Seg) else s
                            for s in subs)
        # A Windows runner's command (`cmd /c`, `pwsh -Command`, `wsl`), judged in
        # addition to the inline split above, from the segment's own tokens. Lenient:
        # a runner's command line re-split on spaces can leave an odd quote
        # (`cmd /c git commit -m "don't"`); such a line is judged piecewise.
        for script, kind, outer_run in _runner_scripts(toks):
            outer_run = outer_expanded or outer_run
            expanded.extend(_runner_segments(script, _depth + 1,
                                             getattr(toks, "piped", False),
                                             kind == "ps", outer_run, here,
                                             kind == "cmd"))
        # The scripts' segments come back flattened from every depth below.
        subs = expanded[start:]
        reached = (reached
                   or (getattr(toks, "heredoc", False)
                       and any(_shell_reads_stdin(s) for s in subs))
                   or (bool(words & {"eval", "alias"})
                       and any(getattr(s, "heredoc_wide", False) for s in subs)))
    return expanded, reached


class _RunnerBudget:
    """Characters of runner script tokenized in this evaluate() call (see below)."""
    used = 0

    @staticmethod
    def charge(chars: int) -> None:
        """Add chars to the budget; past _MAX_RUNNER_CHARS, refuse the command."""
        _RunnerBudget.used += chars
        if _RunnerBudget.used > _MAX_RUNNER_CHARS:
            raise _Uninspectable(
                f"Windows runner scripts too long to inspect (> {_MAX_RUNNER_CHARS} chars)")


class _Command:
    """The whole payload of this evaluate() call: what an alias defined anywhere in it may
    be fed by (see _expand_scripts)."""
    raw = ""


@functools.lru_cache(maxsize=4096)
def _runner_segments(script: str, depth: int, piped: bool, ps: bool, outer: bool = False,
                     heredoc: bool = False, cmd: bool = False):
    """_segments() of a Windows runner's script (see _runner_scripts), memoized: the
    PowerShell readings and nested runners hand the same script text down many times.
    The arguments are all the result depends on (with _Command.raw, fixed for one
    evaluation), and no segment is changed after the call that made it returns, so
    sharing the result is safe. evaluate() clears the cache and the budget on entry.

    Budgeted: the readings multiply per nesting level, so a 4 KB chain of nested
    runners can hand down thousands of distinct long scripts (~3 MB). Past
    _MAX_RUNNER_CHARS tokenized in one evaluation the command is refused as
    uninspectable (a block), like an over-long continuation chain, rather than run
    toward the hook timeout. A pwsh level can more than double the texts (its grouping,
    block and quoting readings), so the use compounds with depth: a 4 KB PowerShell
    payload of three nested `pwsh -c` levels with quoted paths uses about 92 KB (a test
    keeps that one under half of the cap). A dense multi-level payload that also holds
    groups, escapes, Unicode spaces or VT/FF breaks can reach the cap and is refused."""
    _RunnerBudget.charge(len(script))
    return tuple(_segments(script, depth, piped=piped, lenient_on_error=True,
                           ps_script=ps, outer_expanded=outer, heredoc=heredoc,
                           cmd_script=cmd))


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
                f"continued lines too long to inspect (> {_MAX_CHAIN_CHARS} chars joined)"
                f"{_FILE_HINT}")
        out.append(chain)
    return out


def _is_c_bundle(tok: str) -> bool:
    """A short-flag bundle containing c (-c, -lc, -xc), not a --long option."""
    return tok.startswith("-") and not tok.startswith("--") and "c" in tok[1:]



# PowerShell's escape character is the backtick. Inside a "..." string, an @"..."@
# here-string body or a bareword, `t `v `n `r `f `a `b `e `0 and `u{hex} become
# characters and a backtick before any other character makes it literal; in '...',
# @'...'@ and comments a backtick is an ordinary character. PowerShell also accepts
# typographic quotes as quote marks. It does all this BEFORE it starts a native
# program, so `bash -c "rm -rf `t ~"` hands bash a real TAB and bash deletes ~. The
# matcher's other readings take the backtick for bash command substitution and
# misparse the line, so a PowerShell payload that contains a backtick or a
# typographic quote is also judged as the text PowerShell produces (see evaluate()).
# `0 is NUL. A native program's argument ends at a NUL, so the program receives only
# the text before it; `0 is decoded as a line break, which judges that text on its
# own (the text after it is judged too, which only adds). `e and `u{} exist from
# PowerShell 6 on: Windows PowerShell 5.1 reads them as the letters e and u, so the
# 5.1 values are judged in a reading of their own (see _ps_escape's legacy).
_PS_ESCAPES = {"0": "\n", "a": "\a", "b": "\b", "e": "\x1b", "f": "\f", "n": "\n",
               "r": "\r", "t": "\t", "v": "\v"}
_PS_UNICODE_RE = re.compile(r"u\{([0-9A-Fa-f]{1,6})\}")
_PS_DQ = {'"', chr(0x201C), chr(0x201D), chr(0x201E)}
_PS_SQ = {"'", chr(0x2018), chr(0x2019), chr(0x201A), chr(0x201B)}
_PS_TYPOGRAPHIC_QUOTES = (_PS_DQ | _PS_SQ) - {'"', "'"}
_POSIX_BARE_SPECIAL = set(" \t\n\\'\"$`;&|<>()*?[]{}#~=!")


def _ps_escape(text: str, i: int, legacy: bool = False):
    """Value of the PowerShell escape whose letter is text[i] (just after a backtick).
    Returns (value, index after the escape). legacy: Windows PowerShell 5.1, which
    has no `e or `u{} escape and reads both as the plain letter."""
    c = text[i]
    if legacy and c in "eu":
        return c, i + 1
    if c in _PS_ESCAPES:
        return _PS_ESCAPES[c], i + 1
    if c == "u":
        m = _PS_UNICODE_RE.match(text, i)
        if m and int(m.group(1), 16) <= 0x10FFFF:
            return chr(int(m.group(1), 16)), m.end()
    return c, i + 1


def _ps_decode(text: str, legacy: bool = False) -> str:
    """text with every backtick escape decoded, as in a "..." string."""
    out, i, n = [], 0, len(text)
    while i < n:
        if text[i] == "`" and i + 1 < n:
            v, i = _ps_escape(text, i + 1, legacy)
            out.append(v)
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def _ps_quoted(text: str, i: int, legacy: bool):
    """The PowerShell "..." or '...' string opening at text[i]: (its value, index after
    it), or None if it is unterminated. Escapes are decoded in "..." only; inside
    either, a doubled quote character is one literal character (the second one)."""
    quotes = _PS_DQ if text[i] in _PS_DQ else _PS_SQ
    expandable = quotes is _PS_DQ
    j, val, n = i + 1, [], len(text)
    while j < n:
        d = text[j]
        if expandable and d == "`" and j + 1 < n:
            v, j = _ps_escape(text, j + 1, legacy)
            val.append(v)
        elif d in quotes:
            if j + 1 < n and text[j + 1] in quotes:
                val.append(text[j + 1])
                j += 2
            else:
                return "".join(val), j + 1
        else:
            val.append(d)
            j += 1
    return None


def _ps_here_string_end(text: str, j: int, close: str) -> int:
    """Index of the first line, from index j on, that starts with close ('@ or "@);
    -1 if there is none."""
    while not text.startswith(close, j):
        j = text.find("\n", j) + 1
        if j == 0:
            return -1
    return j


def _posix_literal(value: str) -> str:
    """value as POSIX single-quoted text. A backslash is quoted on its own and an
    apostrophe is written '"'"', so neither _shell_words nor _slashify_windows_paths
    (which runs before tokenizing and would read a backslash pair as a UNC path) can
    change the value."""
    out, run = [], []
    for ch in value:
        if ch in "\\'":
            if run:
                out.append("'" + "".join(run) + "'")
                run = []
            out.append("'\\'" if ch == "\\" else "\"'\"")
        else:
            run.append(ch)
    if run or not out:
        out.append("'" + "".join(run) + "'")
    return "".join(out)


def _posix_dq(value: str) -> str:
    """value as a POSIX "..." word in which $ and the backtick stay live, so $var and
    $( ) still read as expansion. A double quote or a backslash is emitted outside
    the quotes (see _posix_literal): _shell_words honours only those two escapes
    inside "...", and _slashify_windows_paths would rewrite a backslash in a path."""
    out = ['"']
    for ch in value:
        out.append('"' + _posix_literal(ch) + '"' if ch in '"\\' else ch)
    out.append('"')
    return "".join(out)


def _append_posix(out: list, s: str) -> None:
    """Append the quoted POSIX text s to out. After a bare $, a leading ' would open a
    POSIX $'...' (ANSI-C) string (\\\\srv\\c$\\dir), so an empty "" separates them."""
    if s.startswith("'") and out and out[-1].endswith("$"):
        out.append('""')
    out.append(s)


def _ps_unescape(text: str, legacy: bool = False) -> str:
    """Rewrite a PowerShell command as POSIX text whose words carry PowerShell's values.

    "..." becomes a POSIX "..." holding the decoded string (see _posix_dq); '...'
    becomes the POSIX literal of its value; ${...} stays one braced variable word; a
    bareword keeps its characters, with each backtick escape decoded (quoted when it
    would split or quote a POSIX word), backtick-newline a line continuation and a
    literal backslash quoted. An @"..."@ here-string keeps its delimiters with the
    body decoded; @'...'@ and # comments are copied as they are, and a closed <# #>
    comment becomes a space. Unterminated text is copied. legacy: decode as Windows
    PowerShell 5.1 does (see _ps_escape).
    """
    out, i, n = [], 0, len(text)
    at_word_start = True
    unclosed = set()          # here-string kinds with no closer left: skip re-scanning
    braced_closes = True      # False once a ${ found no closing brace: skip re-scanning
    while i < n:
        c = text[i]
        # here-string opener: @" or @' starting a word, with nothing but blanks after
        # it on its line (x@' is the word x@ and an ordinary string)
        if (c == "@" and at_word_start and i + 1 < n and text[i + 1] in "\"'"
                and text[i + 1] not in unclosed):
            eol = text.find("\n", i)
            if eol != -1 and not text[i + 2:eol].strip():
                close = text[i + 1] + "@"
                end = _ps_here_string_end(text, eol + 1, close)
                if end == -1:
                    unclosed.add(text[i + 1])
                else:
                    body = text[eol + 1:end]
                    if text[i + 1] == '"':
                        body = _ps_decode(body, legacy)
                    out.append(text[i:eol + 1] + body + close)
                    i = end + 2
                    at_word_start = False
                    continue
        if c == "#" and at_word_start:                     # line comment
            eol = text.find("\n", i)
            eol = n if eol == -1 else eol
            out.append(text[i:eol])
            i = eol
            continue
        if c == "<" and at_word_start and text.startswith("<#", i):   # block comment
            # PowerShell reads a closed one as blank space (bash would read `<#` as a
            # redirect taking the next word); an unclosed one is copied
            end = text.find("#>", i + 2)
            if end == -1:
                out.append(text[i:])
                break
            out.append(" ")
            i = end + 2
            continue
        if c in _PS_DQ or c in _PS_SQ:
            quoted = _ps_quoted(text, i, legacy)
            if quoted is None:                             # unterminated: copy the rest
                out.append(text[i:])
                break
            value, i = quoted
            _append_posix(out, _posix_dq(value) if c in _PS_DQ else _posix_literal(value))
            at_word_start = False
            continue
        if c == "$" and braced_closes and text.startswith("{", i + 1):
            # ${...} is one variable whatever its name holds (spaces, #, quotes); a
            # backtick makes the next character part of the name
            j, name = i + 2, []
            while j < n and text[j] != "}":
                if text[j] == "`" and j + 1 < n:
                    j += 1
                name.append(text[j])
                j += 1
            if j < n:
                out.append(_posix_dq("${" + "".join(name) + "}"))
                i = j + 1
                at_word_start = False
                continue
            braced_closes = False
        if c == "`":
            if i + 1 >= n:
                i += 1
                continue
            if text[i + 1] in "\r\n":                      # continuation: LF, CRLF or CR
                out.append(" ")
                i += 3 if text.startswith("\r\n", i + 1) else 2
                at_word_start = True
                continue
            # PowerShell decodes the same escapes in a bareword (`echo a`tb` is the
            # one argument a<TAB>b). A decoded character that would split or quote
            # a POSIX word is quoted so the word keeps its value.
            v, i = _ps_escape(text, i + 1, legacy)
            for ch in v:
                if ch in _POSIX_BARE_SPECIAL or ch < " " or ch in _WORD_BREAKS:
                    _append_posix(out, _posix_literal(ch))
                else:
                    out.append(ch)
            at_word_start = False
            continue
        if c == "\\":
            _append_posix(out, _posix_literal(c))
            i += 1
            at_word_start = False
            continue
        out.append(c)
        # ${...} is a variable, not a script block: a # inside it starts no comment
        at_word_start = c in " \t\r\n;|&(" or (c == "{" and (i == 0 or text[i - 1] != "$"))
        i += 1
    return "".join(out)


def _ps_unescape_everywhere(text: str, legacy: bool = False) -> str:
    """Every backtick escape decoded, whatever quoting or comment _ps_unescape()
    believes it is in, and backtick-newline read as a continuation: a backstop
    reading, so a scanner mistake about context cannot leave a real escape undecoded
    (see evaluate()). legacy: as in _ps_escape."""
    out, i, n = [], 0, len(text)
    while i < n:
        if text[i] == "`" and i + 1 < n:
            if text[i + 1] in "\r\n":                      # continuation: LF, CRLF or CR
                out.append(" ")
                i += 3 if text.startswith("\r\n", i + 1) else 2
            else:
                v, i = _ps_escape(text, i + 1, legacy)
                out.append(v)
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def _ps_stop_parsing_cmd_scripts(raw: str):
    """(script text, piped) for what may follow PowerShell's stop-parsing token `--%` in
    PowerShell text that names cmd, each in every reading of _cmd_texts. After `--%`
    PowerShell hands the rest of the line to the program unparsed, `;` and `&` included,
    so cmd gets a script the PowerShell reading splits. An extra reading with few
    guesses, since it can only add blocks. A `--%` counts wherever it is (in a string
    too), and its tail is read whole as a cmd script (to the line's end: a `|` after it
    is judged there as well), and also from after a /c, /k or /r switch in it. The
    tails read: from the line's first `--%`, also with every `"` deleted, and from each
    `--%` to the next one (the last to the line's end). The windows partition the line,
    so the work stays linear in it; a window stands alone, and with the quotes deleted
    no quote a decoy `--%` leaves open (in a string PowerShell closes with a typographic
    quote), or a `--%` inside cmd's own string starts, can glue the real script into one
    word. The other readings of the text are judged too: PowerShell's escapes decoded
    (`` c`md ``), word breaks as spaces (see _segments), and a cmd runner named by its
    word, with its switch, read from the words around the `--%`. piped: a `|` comes
    before the tail's `--%` on its line."""
    if "--%" not in raw or "cmd" not in raw.lower():
        return []
    out = []
    for line in raw.split("\n"):
        k = line.find("--%")
        if k < 0:
            continue
        ks = [j for j in range(len(line)) if line.startswith("--%", j)]
        tails = [(line[k + 3:], "|" in line[:k]), (line[k + 3:].replace('"', ""), "|" in line[:k])]
        tails += [(line[a + 3:b], "|" in line[:a]) for a, b in zip(ks, ks[1:] + [len(line)])]
        for tail, fed in dict.fromkeys(tails):
            words = tail.lower().split()
            readings = [words]
            # Also from after a /c, /k or /r switch: when cmd is named by a computed
            # call (`& (Get-Command cmd) --% /c call x`) no other reading finds the
            # runner, and the whole tail would take the switch for the command.
            sw = _cmd_run_switch(words)
            if sw is not None:
                j, glued = sw
                readings.append(([glued] if glued else []) + words[j + 1:])
            for ws in readings:
                out += [(t, fed) for t in _cmd_texts(ws)]
    return list(dict.fromkeys(out))


def _powershell_segments(raw: str):
    """Every segment evaluate() judges for a PowerShell payload: the readings below of
    the raw text and, when it holds one of _PS_SPACES, the same readings of the text
    with each of them a space, as PowerShell reads them outside a string; and the same
    again with PowerShell's grouping read away (_ps_ungroup: `git reset ("--hard")`,
    `& ('git') ...`, `& {...}`), so a grouped value is judged as the argument or command
    word it becomes. The raw readings stay, so this only adds segments. Raises as
    _segments() does."""
    segments = []
    # Each $( ) subexpression's body, judged as a payload of its own (see
    # _ps_subexpressions): inside a "..." string no other reading sees it as code.
    if "$(" in raw:
        for body in _ps_bodies(raw):
            if body.strip() not in ("", ":"):
                _RunnerBudget.charge(len(body))
                segments += _powershell_segments(body)
    texts = [raw, raw.translate(_PS_AS_SPACE)]
    if "(" in raw or "{" in raw:
        texts += [_ps_ungroup(t, keep_variables=True) for t in texts]
    if "{" in raw or "}" in raw:
        texts += [_ps_block_statements(t) for t in texts[:2]]
    if ".'" in raw or '."' in raw:
        texts += [_PS_DOT_QUOTE_RE.sub(r"\1. ", t) for t in texts]
    # A <# #> comment reads as two redirects, whose targets take the words beside it. An
    # added reading, and lenient: a `<#` in a string can leave an odd quote behind.
    if "<#" in raw:
        for text in dict.fromkeys(texts):
            segments += _segments(_PS_BLOCK_COMMENT_RE.sub(" ", text), shell="powershell",
                                  lenient_on_error=True, ps_tool=True)
    for text in dict.fromkeys(texts):
        segments += _segments(text, shell="powershell", ps_tool=True)
        # PowerShell reads `\` as a path separator, but a script it hands to bash
        # (`bash -c "git push \` + newline + `--force"`) reads it as an escape or a
        # line continuation. Judge the POSIX reading too and add its segments; a line
        # of it that does not tokenize is judged piecewise (quote-blind) instead of
        # being dropped.
        segments += _segments(text, shell="powershell", ps_slashes=False,
                              lenient_on_error=True, ps_tool=True)
        # ...and the words as PowerShell's own quoting gives them, which is the text an
        # inline script for a native program such as bash is built from: _ps_unescape()
        # follows PowerShell's quoting, escapes and typographic quotes. It is always
        # taken, since the two quotings disagree even with no escape in the text (`\"`
        # is a backslash and then a string in PowerShell, an escaped quote in bash; a '
        # inside "..." quotes nothing in PowerShell). With a backtick or a typographic
        # quote, _ps_unescape_everywhere() also decodes every escape whatever the
        # context, so a scanner mistake about quoting cannot leave an escape undecoded;
        # with a `e or `u, both are also read with Windows PowerShell 5.1's escapes. A
        # reading identical to the text, already judged above with the same arguments,
        # or to another reading adds nothing and is skipped. An escape's value is a
        # literal character, so a _PS_SPACES character it produces stays part of its word.
        readings = [_ps_unescape(text)]
        if "`" in text or any(q in text for q in _PS_TYPOGRAPHIC_QUOTES):
            readings += [_ps_unescape_everywhere(text)]
            if "`e" in text or "`u" in text:
                readings += [_ps_unescape(text, legacy=True),
                             _ps_unescape_everywhere(text, legacy=True)]
        for reading in dict.fromkeys(readings):
            if reading != text:
                segments += _segments(reading, shell="powershell", ps_slashes=False,
                                      lenient_on_error=True, ps_tool=True)
    return segments


def evaluate(raw: str, extra_patterns=(), shell: str = "bash"):
    """Return the list of block reasons for a raw command string (+ optional query).
    Pure function -- no I/O -- so it is directly unit-testable. shell is "bash" or
    "powershell" (the payload's tool_name); "powershell" adds here-string handling
    and the PowerShell readings (see _powershell_segments)."""
    if raw is None:
        return []
    if len(raw) > _MAX_INSPECT_LEN:
        # Do NOT parse it. A guard that can be made slow can be made to hit the
        # hook timeout. A timed-out guard blocks under onFailure:block (2.1.295+)
        # and fails OPEN below it, so the cap still matters.
        return ["command too large to inspect safely "
                f"({len(raw)} chars > {_MAX_INSPECT_LEN}){_FILE_HINT}"]
    if not raw.strip():
        return []

    _runner_segments.cache_clear()
    _RunnerBudget.used = 0
    _Command.raw = raw
    try:
        segments = (_powershell_segments(raw) if shell == "powershell"
                    else _segments(raw, shell=shell))
    except _Uninspectable as exc:
        return [f"uninspectable command ({exc})"]
    except ValueError as exc:
        # Unbalanced quoting: the real command words cannot be recovered, so this
        # must not be waved through. Fail closed, like the hook's other
        # "CONTROL COULD NOT RUN" paths.
        return [f"uninspectable command (unbalanced quoting: {exc})"]
    finally:
        _Command.raw = ""                  # no later direct _segments() call reads it

    # The readings overlap heavily; judge each distinct segment once. The key holds
    # everything a rule reads, ps_script included, so an exempt copy of a segment
    # never stands in for one that is not. (extraPatterns below still see every
    # segment in order: a pattern may span two of them.)
    seen, unique = set(), []
    for toks in segments:
        key = (tuple(toks), getattr(toks, "piped", False),
               tuple(getattr(toks, "redirs", ())), getattr(toks, "ps_script", False),
               getattr(toks, "ps_tool", False), getattr(toks, "ps_call", False),
               getattr(toks, "ps_foreach", False), getattr(toks, "xargs_fed", False),
               getattr(toks, "ps_outer", False), getattr(toks, "cmd_script", False))
        if key not in seen:
            seen.add(key)
            unique.append(toks)

    reasons = []
    for toks in unique:
        for r in _reasons_for(toks):
            if r not in reasons:
                reasons.append(r)

    # extraPatterns are documented as case-insensitive SUBSTRING matches. Test them
    # against both the tokenized form (quotes removed, so an ${IFS}-spliced pattern
    # is visible) and the collapsed raw form (so a pattern that spans a shell
    # operator still hits).
    # Short-flag bundles keep their case in the tokens (xargs -P is not -p), so this
    # joined copy is lowercased for the case-insensitive match.
    tok_norm = " ; ".join(" ".join(list(t) + list(getattr(t, "redirs", ())))
                          for t in segments).lower()
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

    # A missing config means "no extraPatterns". One that exists but cannot be read as a
    # JSON object (bytes in, so a BOM or UTF-16 is fine) is a control that cannot run:
    # report it, so the hook fails closed instead of silently dropping the patterns.
    # Below the top level, a wrong shape reads as "none", as the hooks' own reader
    # (bcl_prime in common.sh) reads it.
    extra = []
    if cfg_path and os.path.isfile(cfg_path):
        try:
            with open(cfg_path, "rb") as fh:
                cfg = json.loads(fh.read())
        except json.JSONDecodeError as exc:
            reason = f"line {exc.lineno} column {exc.colno}: {exc.msg}"
            cfg = None
        except Exception as exc:
            reason = type(exc).__name__
            cfg = None
        else:
            reason = "" if isinstance(cfg, dict) else "the top level is not a JSON object"
        if reason:
            print(f"__MATCHER_ERROR__ {cfg_path} cannot be read ({reason}); repo "
                  f"extraPatterns could not be applied.")
            return 0
        guard = cfg.get("guardrails")
        guard = guard.get("commandGuard") if isinstance(guard, dict) else None
        extra = (guard.get("extraPatterns") if isinstance(guard, dict) else None) or []

    reasons = evaluate(raw, extra, shell=shell)
    if reasons:
        print("; ".join(reasons))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
