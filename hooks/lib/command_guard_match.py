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
    shredded into extra tokens by a blind quote-to-space substitution. Inside "..."
    bash also decodes a backslash before $ or ` and a backslash-newline, which shlex
    keeps: each line is read that way too, so a script a double-quoted word hands to
    a runner is judged as the runner gets it (see _shell_words, bash_dq).
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
    heredoc (`pwsh <<EOF`; see _heredoc_check), and so is bash text holding a heredoc
    whose body bash decodes before its reader runs it (an unquoted delimiter and a
    backslash escape after it; see _heredoc_escapes), whoever reads it. An `rm -rf` fed by xargs, directly or
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
separates words on read as spaces, with the dashes it reads as `-` (U+2013, U+2014,
U+2015) read as `-`, all of them or only one before `=`, and with a ( ) / $( ) / @( )
group around one word and every { } read away, so
`git reset ("--hard")` and `& {...}` are judged as the words they become (see
_ps_unescape, _PS_SPACES, _ps_dash_readings, _ps_ungroup and _powershell_segments); a
pipeline continued after a `|` that ends a line, and a literal list's group (`('a','~')`),
are each also read as one line / without the group (_PS_PIPE_EOL_RE, _PS_LIST_GROUP_RE);
more than one dash before `=` is refused. Each of these readings also runs on the text one
PowerShell lexer normalizes it to (_ps_lex, _ps_normalized_texts: comments read away and
here-strings read as one-line strings exactly where pwsh's tokenizer opens them, a "..." string
read with its $( ) whole, the words after --% (stop-parsing) as literal strings, split as the
UCRT and, in a second text, as Git's MSYS2 runtime splits the command line a program receives;
two texts again when it holds U+180E, which Windows PowerShell on .NET Framework 4 to 4.5.2 reads
as a space and pwsh 7 as part of a word; again with a bare word glued to a comment opener ending
before it, an identifier position not modelled; and, for a non-ASCII text, with its non-ASCII
characters outside names, inside them as .NET's letters only, and as those with unknown
characters too, as .NET's letters differ from Python's and between .NET versions; a text whose
readings together pass 24 K in one evaluation is refused), so an older scanner's own rule for where a comment or a
string opens cannot hide a command. The raw readings stay: they also judge the text after --%
decoded, and give what the program receives there (for cmd, the text after it is also read as the
script cmd gets: _ps_stop_parsing_cmd_scripts). Limits: a --% tail holding a single-quoted script
for an MSYS2 program (`bash --% -c 'echo hi'`) is refused (the UCRT split leaves the script's quote
unbalanced); MSYS2's globbing, brace and ~ expansion of a tail's words and an @file argument's
contents are not modelled (the words are read literally); PowerShell cmdlets are matched by the deny-list only, except Remove-Item and its aliases, read as
PowerShell binds their parameters (see _ps_remove_item; a target it computes, such as
`(Resolve-Path ~)` or `$x`, and a call through a new alias are not read), and code run
from a string: Invoke-Expression's (`iex`) Command, bound as PowerShell binds it, and the
literal of a [scriptblock]::Create / .InvokeScript / .NewScriptBlock / .AddScript call
are read as a pwsh script; a computed one, an iex fed from the pipe, and any other
code-from-string route are refused (see _ps_iex_command and _ps_code_strings; a command,
type or member reached without its name is not read). The context-free reading
decodes escapes inside '...' too, so a single-quoted commit message holding `n
followed by a blocked command at the start of the next line is blocked, the cost the
multi-line pass already accepts for a real newline; a "..." message whose decoded
line starts with one is blocked the same way.
"""
from __future__ import annotations

import bisect
import functools
import json
import os
import re
import shlex
import sys
import unicodedata

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
# Wrappers that read NAME=VALUE operands before their command, with any NAME (see
# _wrapper_assignment): env takes every operand holding `=`, after `--` too; sudo takes one
# not led by `/` or `=` (sudo-rs: one whose NAME is alphanumeric or `_`), interleaved with
# its options, up to `--`.
_WRAPPER_ASSIGNS = {"env", "sudo"}
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
_PS_EVAL_RE = re.compile(r"\biex\b|invoke-expression|(?<!-)scriptblock\b|newscriptblock"
                         r"|invokescript|addscript|expandstring|getscriptblock|createpipeline"
                         r"|createnestedpipeline|function:|addcommand"
                         r"|add-type\b[^;|]*-typedefinition",
                         re.IGNORECASE)
# The characters PowerShell reads as `-` wherever its own syntax takes a dash (its
# tokenizer's IsDash): U+2013 (en dash), U+2014 (em dash) and U+2015 (horizontal bar). Not
# U+2212, U+2010 to U+2012, U+FE63 or U+FF0D. A native program gets them as they are. See
# _ps_dash_readings.
_PS_DASHES = "".join(map(chr, (0x2013, 0x2014, 0x2015)))
# Characters pwsh's command-line parser accepts as a switch prefix: -, /, and the dashes.
_PS_SWITCH_CHARS = "-/" + _PS_DASHES
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
_PS_VAR_NAME = r"\$(?:\{[^{}$:]+\}|(?:(?:env|global|script|local|private|using):)?\w+|\?)"
_PS_VAR = _PS_VAR_NAME + r"(?:\.\w+|\[[^\]()]*\])*"
_PS_VAR_NAME_RE = re.compile(_PS_VAR_NAME, re.I)
_PS_VAR_RE = re.compile(_PS_VAR, re.I)
_PS_VAR_WORD_RE = re.compile(_PS_VAR + r"(?:\+\+|--)?\}*", re.I)
# A member step after an index, or one a variable names: `$b[ 0].c=cmd`, `$b.$c=cmd` (see
# _ps_index_target).
_PS_MEMBER_RE = re.compile(r"\.(?:\w+|\$\w+|\$\{[^{}]+\})")
# Text glued after a target's steps that no operator, comma or end starts: a word, a
# variable, a bracket, a quote, a space a quoted member name left (`$b[ 0].'c d'=cmd`)
# or a static member's `::` (see _ps_index_target).
_PS_STEP_JUNK_RE = re.compile(r"[\w$\[\]'\"`\s:]")
# `$x=value`, one word: variable, operator, value.
_PS_GLUED_ASSIGN_RE = re.compile("(" + _PS_VAR + r")((?:[-+*/%]|\?\?)?=)(.*)", re.I | re.S)
# `key=value` in a hashtable; the value runs as a pipeline.
_PS_GLUED_KEY_RE = re.compile(r"[^=]*=(.+)", re.S)
# A word up to a value's opening quote: `$x=`, `$a=$b=`, `key=`, after any `{` or `!`.
_PS_VALUE_PREFIX_RE = re.compile(
    "[{!]*(?:(?:" + _PS_VAR + r"(?:[-+*/%]|\?\?)?=)+|\w*=)", re.I | re.S)
# Words that may stand before a statement's variable (_effective_cmd_index skips them).
_PS_STATEMENT_PREFIX = {"-not", "do", "else"}
# Statements whose operand is a pipeline: the words after one run (see _ps_statement_tail).
_PS_FLOW_PIPELINE = {"return", "throw", "exit"}
# A word of type literals (`[string]`, `[string[]]`, `[int][string]`), perhaps after the
# `]` an attribute's parentheses leave (`[ValidateNotNull()]` splits at them). The class
# holds the brackets, so one group spans several literals; a repeated group would make a
# failing match try every split (exponential in the brackets).
_PS_TYPE_WORD_RE = re.compile(r"\]?(?:\[[\w.\[\],`]*\])?")
# An assignment operator at the start of a word: `=`, `+=`, `??=`, glued or alone.
_PS_ASSIGN_LEAD_RE = re.compile(r"(?:[-+*/%]|\?\?)?=")
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
_ASCII_CAPITAL_RE = re.compile(r"[A-Z]")   # a word the second reading keeps the case of (_words_to_segments)
_NAMED_FD_RE = re.compile(r"^[a-z_][a-z0-9_]*\}$")     # {x}> after the { is stripped
_REDIR_RE = re.compile(r"^(?:&>>?|[<>]&|>>|>\||<<<|<<|<>|<|>)$")
# Catastrophic delete targets beyond _DANGER_ROOTS: a drive root (C:, Git Bash /c,
# WSL /mnt/c, Cygwin /cygdrive/c) and a path made only of `..` steps.
_DRIVE_ROOT_RE = re.compile(r"^(?:[a-z]:|/[a-z]|/mnt/[a-z]|/cygdrive/[a-z])$")
_PARENT_ONLY_RE = re.compile(r"^\.\.(?:/\.\.)*$")
# PowerShell's Remove-Item and its aliases (PowerShell 7 and Windows PowerShell 5.1 alike),
# read as PowerShell binds their parameters (see _ps_remove_item). `ri` and `rm` only in a
# PowerShell text: bash's ri is Ruby's viewer, and bash's rm has its own rule. The others
# everywhere: no bash meaning of them takes -r or a PowerShell parameter.
_PS_REMOVE_ITEM = frozenset({"remove-item", "ri", "rm", "del", "erase", "rd", "rmdir"})
_PS_REMOVE_ITEM_GATED = frozenset({"ri", "rm"})
# cmd's own deletes (see _cmd_delete): rd/rmdir /s remove a directory tree, del/erase /s delete
# what a pattern matches in its directory and in every one below it. cmd ends an internal
# command's name at the first character that is not a letter, digit, `_` or `-` (`rd/s/q x`,
# `rd.\x`, `rd\x`, `rd,x`, `rd:` and `rd(` all run rd; `rd"x"`, `rd1`, `rd_` and `rd-` do
# not), and the rest of the word is its first argument.
_CMD_DELETE_RE = re.compile(r"(rd|rmdir|del|erase)(?![0-9a-z_-])")
# The text between the `/`s of a switch word, as each command accepts it; cmd refuses the whole
# command for any other (`/sq`, `/s:x`, an empty one). del's /a takes the attribute letters cmd
# accepts (measured: a d h i l o r s v x and -), glued or after a `:` (`/as` is the attribute,
# not /s; `/assets` is refused).
_CMD_RD_SWITCH_RE = re.compile(r"[sq]")
_CMD_DEL_SWITCH_RE = re.compile(r"[pfsq]|a:?[-adhilorsvx]*")
# cmd's variables naming the home, the system drive or the current directory, at the start of a
# word: `%x%`, or `!x!` under delayed expansion (the tokenizer drops a word-leading `!`, leaving
# `x!`), with an optional `:~n,m` / `:a=b` modifier, which can cut the value to a root
# (`%USERPROFILE:~0,3%` is `C:\`). Each is read as the root PowerShell's spelling of it is (see
# _PS_HOME_RE and its neighbours). %__CD__% ends in a `\`, so a word may go on right after it.
_CMD_VAR = "(?:%{0}(?::[^%]*)?%|!?{0}(?::[^!]*)?!)"
_CMD_DRIVE_VAR = _CMD_VAR.format("(?:systemdrive|homedrive)")
# The home: also a drive letter before HOMEPATH (`C:%HOMEPATH%`), a profile folder named by
# USERNAME (`C:\Users\%USERNAME%`, PowerShell's `$env:USERNAME`), and the spellings bash or
# PowerShell leave for cmd unexpanded or expand themselves (Git Bash inherits USERPROFILE).
_CMD_USERNAME = "(?:" + _CMD_VAR.format("username") + "|[$]env:username|[$][{]env:username[}]|[$]username)"
_CMD_HOMEPATH = ("(?:" + _CMD_VAR.format("homepath")
                 + "|[$]env:homepath|[$][{]env:homepath[}]|[$]homepath)")
_CMD_HOME_RE = re.compile(
    "^(?:(?:" + _CMD_DRIVE_VAR + "|[a-z]:)?" + _CMD_HOMEPATH + "|"
    + _CMD_VAR.format("(?:userprofile|home)") + "|(?:" + _CMD_DRIVE_VAR + "|[a-z]:)?/users/"
    + _CMD_USERNAME + "|[$]userprofile|[$][{]userprofile(?:[:?#%/=+-][^}]*)?[}]"
    "|[$]homedrive[$]homepath)(?=/|$)")
# Not only before a `/`: `%SystemDrive%*` is drive-relative (see _cmd_root_target).
_CMD_SYSTEM_DRIVE_RE = re.compile("^(?:" + _CMD_DRIVE_VAR
                                  + "|[$](?:systemdrive|homedrive)(?![0-9a-z_]))")
# The current directory: %CD%, and %=C:%, the current directory cmd keeps per drive.
_CMD_CWD_RE = re.compile("^" + _CMD_VAR.format("(?:cd|=[a-z]:)") + "(?=/|$)")
_CMD_CWD_SLASH_RE = re.compile("^" + _CMD_VAR.format("__cd__"))
# Any other variable with cmd's modifier (`:~n,m`, `:a=b`), anywhere in the word: a value cut or
# rewritten to anything (`%TEMP:~0,3%` is `C:\`, `C:%TEMP:~2,1%` is `C:\`). A `!` form may lead
# the word without its first `!` (the tokenizer drops it). The name may be `=C:` (the hidden
# per-drive current directory, see _CMD_CWD_RE).
_CMD_MODIFIED_VAR_RE = re.compile("%(?:=[a-z]:|[^%:/]+)(?::~[^%]*|:[^%=]*=[^%]*)%"
                                  "|(?:^|!)(?:=[a-z]:|[^!:/%]+)(?::~[^!]*|:[^!=]*=[^!]*)!")
# A `(` glued to the name: cmd runs the command (measured: `rd( /s /q t` deletes t), where the
# bash reading ends the segment at it.
_CMD_NAME_PAREN_RE = re.compile("(?i)(^|[ " + chr(9) + "&|;,=@(])(rd|rmdir|del|erase)[(]")
# A last component made only of * ? and . with a wildcard: an all-files pattern, read as `*`
# (measured: `?*.*`, `*.*.*`, `*.?*`, `????????.???` each delete every file; `*.` and `?.?`
# fewer, an accepted cost).
_CMD_ALL_FILES_RE = re.compile(r"(^|/)(?=[.]*[*?])[*?.]+$")
# A path name led by `$` or `~` (see _cmd_root_target).
_CMD_SIGIL_NAME_RE = re.compile("(^|/)[$~]")
# Remove-Item's parameter names and aliases (7.6 and 5.1, the common parameters included),
# each mapped to its parameter. A parameter word binds every parameter it is a prefix of;
# PowerShell refuses an ambiguous or unknown one, so nothing runs.
_PS_REMOVE_ITEM_PARAMS = {
    "path": "path", "literalpath": "literalpath", "pspath": "literalpath", "lp": "literalpath",
    "filter": "filter", "include": "include", "exclude": "exclude", "recurse": "recurse",
    "force": "force", "credential": "credential", "stream": "stream",
    "usetransaction": "usetransaction", "usetx": "usetransaction",
    "verbose": "verbose", "vb": "verbose", "debug": "debug", "db": "debug",
    "erroraction": "erroraction", "ea": "erroraction",
    "warningaction": "warningaction", "wa": "warningaction",
    "informationaction": "informationaction", "infa": "informationaction",
    "progressaction": "progressaction", "proga": "progressaction",
    "errorvariable": "errorvariable", "ev": "errorvariable",
    "warningvariable": "warningvariable", "wv": "warningvariable",
    "informationvariable": "informationvariable", "iv": "informationvariable",
    "outvariable": "outvariable", "ov": "outvariable", "outbuffer": "outbuffer",
    "ob": "outbuffer", "pipelinevariable": "pipelinevariable", "pv": "pipelinevariable",
    "whatif": "whatif", "wi": "whatif", "confirm": "confirm", "cf": "confirm",
}
_PS_REMOVE_ITEM_SWITCHES = frozenset({"recurse", "force", "usetransaction", "verbose", "debug",
                                      "whatif", "confirm"})
_PS_REMOVE_ITEM_PATHS = frozenset({"path", "literalpath"})
# A delete target as PowerShell spells a root: a FileSystem provider prefix, removed; the
# variables naming the home, the system drive or the current location, each read as the
# bash root it names (after `\` has become `/`); a PSDrive name (`C:`, `HKCU:`, `Env:`) read
# as the root `/`, so `HKCU:\*` and `Env:*` are roots as `/*` is.
_PS_PROVIDER_RE = re.compile(r"^(?:microsoft\.powershell\.core\\)?filesystem::")
_PS_HOME_RE = re.compile(
    r"^(?:(?:\$env:homedrive|\$\{env:homedrive\})(?:\$env:homepath|\$\{env:homepath\})"
    r"|\$env:(?:userprofile|home|homepath)|\$\{env:(?:userprofile|home|homepath)\})(?=/|$)")
_PS_SYSTEM_DRIVE_RE = re.compile(r"^(?:\$env:(?:systemdrive|homedrive)"
                                 r"|\$\{env:(?:systemdrive|homedrive)\})(?=/|$)")
_PS_CWD_RE = re.compile(
    r"^(?:\$pwd(?:\.path|\.providerpath)?"
    r"|\$\(\s*(?:get-location|gl|pwd)\s*\)(?:\.path|\.providerpath)?"
    r"|\(get-location\)\.(?:path|providerpath)|get-location|gl|pwd)(?=/|$)")
_PS_DRIVE_RE = re.compile(r"^[a-z][\w.-]*:(?!:)")
# A Win32 device or long-path prefix (`\\?\C:\`, `\\.\C:\`), removed, and `\\?\UNC\`
# read as `\\`; a drive's admin share (`\\host\c$`), read as that drive.
_PS_LONG_PATH_RE = re.compile(r"^//[?.]/(unc/)?")
_PS_ADMIN_SHARE_RE = re.compile(r"^//[^/]+/([a-z])\$(?=/|$)")
# A variable's scope or drive qualifier (`$global:HOME`, `${variable:PWD}`): the same variable.
_PS_SCOPE_RE = re.compile(r"^\$(\{?)(?:global|local|script|private|using|variable):")
# A payload that can reach $PSDefaultParameterValues without spelling it whole: through the
# variable cmdlets (and their aliases), the variable: drive, or the session state's PSVariable.
_PS_DEFAULTS_RE = re.compile(
    r"psdefault|parametervalues|psvariable|variable:"
    r"|(?<![\w-])(?:get|set|new)-variable(?![\w-])"
    r"|(?:^|(?<=[\s(;|&{=,]))(?:gv|sv|nv)(?=[\s)]|$)")
# A literal list in a group (`('./build','~')`, `@("a", "b")`): two or more quoted strings or
# bare words, comma-separated, and nothing else, opening a word (a method call's arguments
# do not). Read without its parentheses, it is the list a command gets as one argument (a
# group that runs a command is not a literal list). Each
# item's alternatives start with a different character, so the match is linear.
_PS_LIST_GROUP_RE = re.compile(
    r"(?<!\S)@?\(\s*((?:'[^']*'|\"[^\"]*\"|[^\s'\"(),]+)"
    r"(?:\s*,\s*(?:'[^']*'|\"[^\"]*\"|[^\s'\"(),]+))+)\s*\)")
# A `|` that ends a line, with any blank lines after it: PowerShell continues the pipeline on
# the next command line (see _ps_joined_pipes). Each repetition takes a newline, so the
# match is linear. A comment starts at a `#` that begins a word; its matches run to the end
# of a line and never overlap, and a failed position costs one character, so it is linear.
_PS_PIPE_EOL_RE = re.compile(r"\|(?:[ \t]*\r?\n)+")
_PS_COMMENT_RE = re.compile(r"(?:^|(?<=[\s;|&({]))#[^\r\n]*", re.M)
# The variables a script block bound per piped item reads it through (`{ $_.PSPath }`).
_PS_PIPED_ITEM_RE = re.compile(r"\$(?:_|\{_\}|psitem|\{psitem\}|input)(?!\w)")
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


def _ps_joined_pipes(text: str) -> list:
    """text with each `|` that ends a line (blank lines after it included) joined to the next
    command line: as it is, and without its comments (a `#` that begins a word, so `| # c`
    still joins); the ones that join anything. Added, lenient readings: a `#` the comment
    pattern takes inside a string (`' #'`) only stops the second one joining, and the first
    still does. Both miss a quoted ` #` followed by a real comment after the `|`."""
    out = []
    for t in (text, _PS_COMMENT_RE.sub("", text)):
        if _PS_PIPE_EOL_RE.search(t):
            joined = _PS_PIPE_EOL_RE.sub("| ", t)
            if joined not in out:
                out.append(joined)
    return out


def _ps_list_items(m) -> str:
    """_PS_LIST_GROUP_RE's replacement: the list's items on one line (a list may break after a
    comma, and the newline would end the statement)."""
    return m.group(1).replace("\r", " ").replace("\n", " ")


def _ps_long_path(m) -> str:
    """_PS_LONG_PATH_RE's replacement: `//?/unc/host/...` is `//host/...`, `//?/c:/` is `c:/`."""
    return "//" if m.group(1) else ""


def _ps_tilde_names(path: str) -> str:
    """path with each `~`-led component other than a leading `~` alone spelled as a plain
    name: PowerShell reads `~` as the home only as the whole first component, so `~foo` is a
    name in the current location (and `~foo/..` that location), not bash's ~name home,
    which _is_danger_target and _collapse_parents read it as (a POSIX reading of `~\\foo`
    gives `~foo`)."""
    comps = path.split("/")
    return "/".join(c if (i == 0 and c == "~") or not c.startswith("~") else "_" + c[1:]
                    for i, c in enumerate(comps))


def _ps_root_target(word: str) -> bool:
    """A Remove-Item target word that names a root, the home or the current location: each
    comma-separated item, as it is and in its PowerShell spellings (see _PS_HOME_RE and its
    neighbours), with `\\` read as the path separator it is."""
    for item in word.lower().split(","):
        item = item.strip()
        # An item of a literal list keeps the list's parentheses (`('./build','~')`).
        if item.count("(") > item.count(")"):
            item = item[2:] if item.startswith("@(") else item[1:] if item[:1] == "(" else item
        if item.count(")") > item.count("(") and item.endswith(")"):
            item = item[:-1]
        item = _PS_SCOPE_RE.sub(r"$\1", item.strip(), count=1)
        if not item:
            continue
        plain = item.replace("\\", "/")
        t = _PS_PROVIDER_RE.sub("", item).replace("\\", "/")
        t = _PS_ADMIN_SHARE_RE.sub(r"\1:", _PS_LONG_PATH_RE.sub(_ps_long_path, t, count=1), count=1)
        t = _PS_HOME_RE.sub("$home", t, count=1)
        t = _PS_SYSTEM_DRIVE_RE.sub("c:", t, count=1)
        t = _PS_CWD_RE.sub("$pwd", t, count=1)
        drive = _PS_DRIVE_RE.match(t)
        cands = (plain, t) + (("/" + t[drive.end():],) if drive else ())
        if any(_is_danger_target(_ps_tilde_names(x)) for x in cands):
            return True
    return False


def _ps_style_parameter(arg: str) -> bool:
    """A parameter only PowerShell spells so (`-rec`, `-Recurse`, `-x:y`): POSIX rm refuses
    it, so an `rm` holding one is Remove-Item in any text (see _PS_REMOVE_ITEM_GATED)."""
    w = arg.lower()
    return (len(w) > 1 and w[0] in "-" + _PS_DASHES
            and (":" in w or (len(w) > 2 and "recurse".startswith(w[1:]))))


def _ps_remove_item(args, piped: bool, defaults: bool = False):
    """(root, unknown) for Remove-Item's arguments, bound as PowerShell binds them. root:
    it recurses into a target that names a root, the home or the current location (see
    _ps_root_target). unknown: it recurses into what a pipe feeds it, with no path of its
    own (`Get-Item ~ | Remove-Item -Recurse`, the xargs case). Recursion is a parameter that
    binds Recurse, whatever its value, or a splat (`@p`), or, with defaults, any call: the
    payload names $PSDefaultParameterValues, which can turn it on. A path of its own is a
    non-empty positional word, or the value of a parameter that binds only Path or
    LiteralPath; none counts when any word holds a piped item's variable (_PS_PIPED_ITEM_RE:
    a script block bound per piped item). A word after a parameter is that parameter's value
    unless the parameter binds only switches and has no bare `:`; one that binds nothing
    (`--`, an unknown name, which PowerShell refuses) also takes it, so a parameter missing
    from _PS_REMOVE_ITEM_PARAMS can only lose a path. Every misreading can only lose a path
    of its own, so it adds a block, never an allow."""
    recursive, targets, paths = defaults, [], []
    takes = None            # the parameters the last word binds, when the next is its value
    for a in args:
        w = a.lower()
        if len(w) > 1 and w[0] in "-" + _PS_DASHES:
            name, colon, value = w[1:].partition(":")
            binds = {p for n, p in _PS_REMOVE_ITEM_PARAMS.items() if name and n.startswith(name)}
            recursive = recursive or "recurse" in binds
            takes = None
            if colon and value:
                targets.append(value)
                if binds and binds <= _PS_REMOVE_ITEM_PATHS:
                    paths.append(value)
            elif colon or not binds or not binds <= _PS_REMOVE_ITEM_SWITCHES:
                takes = binds or {""}
            continue
        if len(w) > 1 and w[0] == "@" and w[1] not in "({":
            recursive = True
        else:
            targets.append(w)
            if takes is None or takes <= _PS_REMOVE_ITEM_PATHS:
                paths.append(w)
        takes = None
    root = recursive and any(_ps_root_target(t) for t in targets)
    own = (any(p.strip() for p in paths)
           and not any(_PS_PIPED_ITEM_RE.search(a.lower()) for a in args))
    return root, recursive and piped and not own


def _cmd_root_target(word: str) -> bool:
    """A target word of cmd's rd or del that names a root, the home or the current directory:
    cmd's variable spellings of them (_CMD_HOME_RE and its neighbours) read as PowerShell's
    are, any other variable with a modifier refused (its value can be any part of a path), a
    drive with no `\\` after it read on that drive's current directory and on its root, an
    all-files pattern as `*`, then a
    drive path as _is_danger_target reads it, and any other word as _ps_root_target reads a
    Remove-Item target (`\\`, `.`, `..`, `*`, `~`, long-path prefixes, admin shares, and what
    bash or PowerShell put there before cmd ran: `$HOME`, `$env:USERPROFILE`). A word led by
    one `/` is a path from the current drive's root (a `\\` read as `/`: cmd takes a real `/`
    for a switch), so it is read on a drive, not as Git Bash's drive `/x` (`\\x` is no root,
    `\\` is). Also read with its trailing dots and spaces removed: Windows drops them from the
    last name (measured: `rd /s /q t.` deletes t)."""
    # Any variable with a modifier, a known one too, anywhere: its value is cut or rewritten to
    # anything, alone or with another (`%A:~0,2%%B:~2,1%` and `%HOMEDRIVE:~0,1%:\` are `C:\`).
    # Fail closed. (A known variable with a modifier names a root, the home or the cwd anyway.)
    if _CMD_MODIFIED_VAR_RE.search(word):
        return True
    # Also without a long-path or device prefix and with an admin share read as its drive,
    # before cmd's variables are read (`\\?\%CD%` names the current directory: measured,
    # `\\?\%CD%\t` deletes t; `\\host\c$%HOMEPATH%` is the home).
    plain = _CMD_ADMIN_SHARE_RE.sub(r"\1:", _PS_LONG_PATH_RE.sub(_ps_long_path, word, count=1),
                                    count=1)
    for w in dict.fromkeys(v for x in (word, plain) for v in (x, x.rstrip(". ") or x)):
        t = "c:" + w if w.startswith("/") and not w.startswith("//") else w
        t = _CMD_HOME_RE.sub("$home", t, count=1)
        t = _CMD_SYSTEM_DRIVE_RE.sub("c:", t, count=1)
        t = _CMD_CWD_RE.sub("$pwd", t, count=1)
        t = _CMD_CWD_SLASH_RE.sub("$pwd/", t, count=1)
        # A drive with no `\` after it is relative to that drive's current directory: the
        # current one (`C:*`, `C:.\*`), or the drive's root when none was set (`D:*`).
        cands = [t]
        if t[1:2] == ":" and t[:1].isalpha() and t[2:3] not in ("", "/"):
            cands += [t[2:], t[:2] + "/" + t[2:]]
        for c in cands:
            if _cmd_root_target_read(_CMD_ALL_FILES_RE.sub(r"\1*", c, count=1)):
                return True
    return False


def _cmd_root_target_read(t: str) -> bool:
    """_cmd_root_target's test of one reading t (cmd's variables already read)."""
    # Also with every `$`- or `~`-led name a plain one: for cmd they are ordinary characters,
    # and Windows resolves `..` as text (`C:\$x\..` is `C:\`, whether $x exists or not),
    # where _collapse_parents keeps such a name (its value is unknown to bash).
    # The first name is kept in one reading: it may be the root a variable was read as
    # (`%USERPROFILE%\$x\..` is `$home/$x/..`), or a drive; after it, a `:` is an ordinary
    # character too (measured: `t\x:\..` is t).
    head, sep, rest = t.partition("/")
    plain = head + sep + _CMD_SIGIL_NAME_RE.sub(r"\1_", rest).replace(":", "_")
    for c in dict.fromkeys((t, plain, _CMD_SIGIL_NAME_RE.sub(r"\1_", t))):
        # A drive path is judged as it is: cmd has no PSDrives, whose reading (`HKCU:\x` as
        # `/x`) would take `C:\x` for Git Bash's drive x:.
        if (_is_danger_target(c) if c[1:2] == ":" and c[:1].isalpha()
                else _ps_root_target(c)):
            return True
    return False


def _cmd_delete(name: str, words) -> bool:
    """Does cmd's rd/rmdir or del/erase (name) with these argument words recurse (a /s switch)
    into a root, the home or the current directory (_cmd_root_target)? Read as cmd reads them:
    a `/` opens a switch anywhere in a word, so `t/s` is the target t and /s, and `/s/q` two
    switches; cmd runs the command only when every piece after that `/` is a switch it accepts,
    so only a run of such pieces ending the word is read as switches, and the text before each
    of its `/`s as a target (`c:/users/s`: `c:/users` and /s). A word's `/` may be a `\\` (the
    segments read it so), so every word is also a target as it is, but for one made only of
    switches in either reading (`/s/q`, Git Bash's `//s`), which gives no target at all: its
    `/x` would be read as Git Bash's drive x:, so every switch word would name a root. But
    `\\/s` (the current drive's root, then /s) reads as Git Bash's `//s`: when the payload
    holds a `\\` right before a `/` (_Command.backslash_switch), the text before such a word's
    switches is a target too (`/`). Each word is also read with
    its runs of `/` collapsed: Git Bash hands cmd `//s` as `/s`. /q is not needed: with it
    absent, a `y` piped in answers the prompt. del deletes what its target matches in the
    target's directory and in every one below it: all files for a directory or an all-files
    pattern (`C:\\`, `%CD%`, `C:\\*`, `*.*`), which are refused; a narrower pattern
    (`%USERPROFILE%\\*.log`, `*.pyc`) is a targeted delete, as the rm rule reads `rm -rf
    ~/*.log`. Every misreading adds a target or a switch, so it can only add a block."""
    valid = _CMD_RD_SWITCH_RE if name in ("rd", "rmdir") else _CMD_DEL_SWITCH_RE
    recursive, targets = False, []
    subs = []
    for w in words:
        w = w.replace("^", "").lower()
        # Also each part between cmd's delimiters, read here and not only in the delimiter
        # reading of the whole text: that one also cuts a variable's modifier (`/s,/q
        # %USERPROFILE:~0,3%`: cmd expands the variable first, then splits).
        subs += [w] + (re.split("[,;=]", w) if any(c in w for c in ",;=") else [])
    for w in dict.fromkeys(subs):
        readings = list(dict.fromkeys((w, re.sub("/+", "/", w))))
        found, switch_word = [], False
        for r in readings:
            # The `/` that opens the switches is the first of a run of valid switches ending
            # the word, or a later one (the earlier ones may be `\`: `../../s` is `..\..`
            # and /s). The target is the text before it: the shortest is judged, as a later
            # `/` only adds a one-letter name to it, which makes no root of a non-root (and
            # judging every one would be quadratic in the word).
            pieces = r.split("/")
            # Any /s is a recursion, valid run or not: a switch the tables miss costs a block,
            # never the /s (`rd /s/x C:\`, which cmd refuses, is blocked).
            recursive = recursive or "s" in pieces[1:]
            j = len(pieces)
            while j > 1 and valid.fullmatch(pieces[j - 1]):
                j -= 1
            if j < len(pieces):
                switch_word = switch_word or (j == 1 and not pieces[0])
                found.append("/".join(pieces[:j]))
        if not switch_word:
            targets += readings + found
        elif _Command.backslash_switch:
            targets += found          # `\/s`: the `\` (now `/`) before the switches
        if _Command.backslash_switch:
            # `\$null/s` (PowerShell), `\!x!/s` with x unset (cmd): the text expands to
            # nothing before the delete runs.
            targets += [_CMD_EXPANDED_TEXT_RE.sub("", f) for f in found if "$" in f or "!" in f]
    return recursive and any(_cmd_root_target(t) for t in targets if t)


def _wrapper_assignment(base: str, t: str, consume=True) -> bool:
    """t is a NAME=VALUE operand that wrapper base reads before its command. The NAME can
    be anything (`a-b=1`, `'a b=1'`, `=1`): the callers' VAR=val skip is bash's own prefix
    assignment, identifier-only, so it would take such an operand for the command word.

    env (GNU, BSD, busybox) reads every such operand as an assignment. sudo does not
    always: upstream sudo runs one led by `/` or `=` as the command, sudo-rs takes one only
    when its NAME is alphanumeric or `_`, and Windows sudo.exe takes none. An operand
    without a path separator is skipped in every reading: read as the command it keeps its
    `=`, so it names no program a rule knows. One holding a separator may be a path to the
    program, so it is skipped only in the wide reading and read as the command in the
    others; one led by `/` is the command under every sudo. For sudo the wide reading takes
    the same option values as the table (no _WRAPPER_VALUE_*_WIDE entry): one added there
    would need a reading of its own."""
    if base not in _WRAPPER_ASSIGNS or "=" not in t or t.startswith("-"):
        return False
    if base == "env":
        return True
    if "/" not in t and "\\" not in t:
        return True
    return consume == _WIDE and not t.startswith("/")


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
    while i < n:
        t = toks[i]
        if _wrapper_assignment(base, t, consume):
            i += 1
            continue
        if not t.startswith("-") or (t == "-" and base != "env"):
            break                                    # env: a lone `-` is -i
        i += 1
        if t == "--":
            if base == "env":                        # env reads assignments after -- too
                while i < n and "=" in toks[i]:
                    i += 1
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
        # A PowerShell statement whose walk stopped at a target it could not read (see
        # _ps_index_target): what the statement runs after it is not known. Fail closed.
        if getattr(seg, "ps_unread", False):
            r = "uninspectable command word (shell expansion in command position)"
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


def _ps_statement_tail(toks, script=False):
    """For an ordinary statement of a PowerShell tool payload whose first word is a
    variable (`$x = 1`, `if ($LASTEXITCODE -ne 0)`, `foreach ($f in $l)`), or a flow or
    type word (below), the words it goes on to run, as a list (empty when nothing is left
    to judge); None for any other segment. The tool's payload has no outer shell, so the
    variable is no expansion. Not after a call operator (`& $x`, `. ($x)`), not a method
    call (`$x.Run(...)`, or one as a later word), not fed by a pipe, and not `$x <word>`.

    The words are what follows an `=`, an operator or a foreach header's `in` (its
    collection is a pipeline), past a chain `$a = $b = cmd`, with a glued `$x=value` read
    as the same three words. A value that opens with a quote is a string, not a command.

    `return`, `throw` and `exit` take a pipeline: the words after one run (`return git
    push`), unless an `=` follows (a hashtable key so named), and an operand that opens
    with a `$` word or a comma is an expression (`return $a, $b`, `exit $LASTEXITCODE`),
    unless it is walked as an assignment. Type literals and attributes may stand before a
    target (`[string] $x = cmd`, `[ValidateNotNull()] $x = cmd`, where the attribute's
    parentheses leave a `]`), and after an `=` (`$x = [string] $y = cmd`, `$x=[string] $y
    = cmd`). After a flow or type word, a word that opens with `[`, or in a script, any `$`
    word is a target, and so is a list of them (an item may have types before it, see
    _ps_list_item; an item that is a glued target ends the list, and an operator glued
    to its value may follow the list: `$a, [int] $b=cmd`, `$a, $b =cmd`); and when that
    walk stops at a type it cannot read or short of a command in a statement led by a `$`
    or `[` word, a flow word or a type run, it resumes after the next assignment operator
    (see _ps_assignment_operator): `[int] $a, [int] $b
    = cmd`, `[int] $x =cmd`, `return $a , $b = cmd`. Every value starts as the statement
    does, past a flow word and a type run (see _ps_value_start): `$x = return cmd`,
    `$x=return [int] $y = cmd`, `[int] $a =return cmd`. In a script an outer shell
    expanded (ps_outer), a variable left alone as an assignment's value is the tail, which
    _rules_at refuses there (`\\$x = $CMD` is refused already).

    script: also read a statement of a script a runner hands to pwsh/powershell
    (ps_script), piped or not, for words to judge in addition (see _ps_statement_tails).
    That reading only adds segments: _rules_at still judges the script's statement
    itself as before (it calls this without script). Its early return needs a `$` first
    word, which the type and flow words and a `[` word without one are not, and the list
    walk is only open after them: so for the tool's own `$a, $b = ...`, this is None as
    before.

    A target whose steps the walk cannot read (see _ps_index_target) ends it: the tail is
    that target's word and the words after it, as a _PsUnreadTail, whose segment is
    refused."""
    try:
        return _ps_statement_walk(toks, script)
    except _PsUnreadTarget as stop:
        return _PsUnreadTail([stop.word] + list(toks[stop.index + 1:]))


def _ps_statement_walk(toks, script):
    """The walk of _ps_statement_tail (see there); raises _PsUnreadTarget."""
    if script and getattr(toks, "ps_script", False):
        if toks.ps_call:
            return None
    elif not getattr(toks, "ps_tool", False) or toks.ps_call or toks.piped:
        return None
    start = _ps_statement_start(toks)
    # A flow word (not a hashtable key so named, `@{ return = cmd }`: see
    # _ps_statement_tails) or a type run may lead the statement, as any value.
    i, word, value_of_glue, flow, typed = _ps_value_start(toks, start, toks[start], False,
                                                          first=True)
    walked, resumed = flow, -1
    loose = script or flow or typed or (toks[start][:1] == "[" and "$" not in toks[start])
    # A statement a resume may read: led by a `$` or `[` word, a flow word or a type run,
    # not a command's arguments (`Write-Host x = y`) nor a hashtable entry (`a = return
    # cmd`, which _ps_statement_tails reads as one).
    led = flow or typed or "$" in toks[start] or toks[start][:1] == "["
    # In a script an outer shell expanded (ps_outer), the words it expanded: what one holds
    # is not known (`[int] $CMD = 1` from bash), so the walk never steps past one as a
    # target; it is the tail, which _rules_at refuses there.
    ext = toks.expanding if script and getattr(toks, "ps_outer", False) else ()
    while True:
        # `[int] $b[ 0]=cmd`, `return $b[$c[0]]=cmd`, `return [int]$b[ 0], $c=cmd`: a
        # target whose steps _PS_VAR cannot read in one word (see _ps_index_target; one it
        # cannot read at all is refused), read as its name and what follows its steps (a
        # type glued before it goes: it reads nothing). Not the tool's statement's own first
        # word, whose reading _rules_at's early return depends on (the tool's `$b[ 0]=cmd`
        # stays an uninspectable command word); a script's is read (`$b[$i, 0]=cmd`, whose
        # comma _rules_at takes for a list's: the reading with script only adds segments).
        # Not past a word an outer shell expanded (see ext). The text read is no word of
        # the payload: whether one opens with a quote says nothing of it (value_of_glue
        # None).
        lead = _PS_TYPE_WORD_RE.match(word).end() if word[:1] and word[:1] in "[]" else 0
        indexed = (_ps_index_target(toks, i, word[lead:]) if (walked or i != start or script)
                   and word[lead:lead + 1] == "$" else None)
        if indexed:
            if any(t in ext for t in range(i, indexed[0] + 1)):
                return _ps_outer_tail(toks, i, word, ext)
            i, word = indexed
            value_of_glue = None
        glued = _PS_GLUED_ASSIGN_RE.fullmatch(word)
        if glued:
            if i in ext:
                return _ps_outer_tail(toks, i, word, ext)
            walked, word, value_of_glue = True, glued[3], True
            if not word:
                i += 1                 # `$x= 1`: the value is the next word
                if i >= len(toks):
                    return []
                word, value_of_glue = toks[i], False
            # `$x=[string] $y = cmd`, `$x=return cmd`
            i, word, value_of_glue, flow, typed = _ps_value_start(toks, i, word, value_of_glue)
            loose = loose or flow or typed
            continue
        step = None
        # `[Dictionary[string,` `int]]$c, $y = cmd`: a first item a type a space split leads.
        first = (_ps_list_item(toks, i, word) if (loose or walked) and "$" not in word
                 and word[:1] in "[]" else None)
        if first or loose and "$" in word and (
                not _PS_VAR_WORD_RE.fullmatch(word)
                or toks[i + 1:i + 2] and toks[i + 1].startswith(",")):
            # Other assignment targets, as _rules_at reads a script's (a typed `[int]$x`,
            # `$x,$y`), and a list of them (`$a, $b = cmd`, `$a, [int] $b = cmd`, `$a , $b
            # = cmd`): see _ps_list_scan.
            j, last = _ps_list_scan(toks, i, word, first[1] if first else i)
            op = _PS_ASSIGN_LEAD_RE.match(toks[j + 1]) if j + 1 < len(toks) else None
            if op and toks[j + 1] in _PS_ASSIGN:
                step = j + 2
            elif last:
                # The list's last item is a glued target: walk on in it, as in a glued
                # word (not past an expanded item, see ext).
                if any(t in ext for t in range(i, last[0] + 1)):
                    return _ps_outer_tail(toks, i, word, ext)
                i, word, value_of_glue, walked = last[0], last[1], True, True
                continue
            elif op:
                # `$a, $b =cmd`, `$x = $a, [int] $b +=cmd`: the operator glued to its value
                # (not past an expanded item, see ext).
                if any(t in ext for t in range(i, j + 1)):
                    return _ps_outer_tail(toks, i, word, ext)
                walked = True
                i, word, value_of_glue, flow, typed = _ps_value_start(
                    toks, j + 1, toks[j + 1][op.end():], True)
                loose = loose or flow or typed
                continue
        if step is None and _PS_VAR_WORD_RE.fullmatch(word):
            nxt = toks[i + 1].lower() if i + 1 < len(toks) else None
            if nxt is None:
                outer = walked and not flow and script and getattr(toks, "ps_outer", False)
                return [word] if outer else []
            if nxt in _PS_TOOL_EXPR_NEXT or (nxt == "in" and toks.ps_foreach):
                step = i + 2
        if step is not None:
            if toks[step - 1] in _PS_ASSIGN and any(t in ext for t in range(i, step - 1)):
                return _ps_outer_tail(toks, i, word, ext)
            walked = True
            if step >= len(toks):
                return []
            # `$x = [string] $y = cmd`, `$x = return cmd`, `$x = return [int] $y = cmd`
            i, word, value_of_glue, flow, typed = _ps_value_start(toks, step, toks[step],
                                                                  False)
            loose = loose or flow or typed
            continue
        # After a flow word or a type run, a `$` word is a value or a target, no command.
        # A word that opens a type it does not close and holds no `$` is a type literal the
        # walk could not read (`[x, Get-Date ...`): no command either.
        unread = word[:1] == "[" and "$" not in word and word.count("[") > word.count("]")
        stuck = (not walked or ((flow or typed) and ("$" in word or word.startswith(",")))
                 or unread)
        if stuck and (loose or unread) and led:
            # The walk did not reach a command: resume it after the next assignment
            # operator, if there is one (see _ps_assignment_operator), past the last one
            # resumed after (`[int] $a, [int] $b = return [int] $c, $d = cmd`); past an
            # unread type, at the glued target that ends it too. The searches never
            # overlap, so this stays linear.
            found = _ps_assignment_operator(toks, max(i, resumed + 1), unread)
            if found is not None and any(t in ext for t in range(i, max(found[0], i + 1))):
                # Not past a word an outer shell expanded (see ext). With no operator
                # after it, it stays a flow word's value (`exit $LASTEXITCODE`: the
                # documented `$VAR` limit).
                return _ps_outer_tail(toks, i, word, ext)
            if found is None and unread and any(t in ext for t in range(i, len(toks))):
                # An unread type that holds or precedes a word an outer shell expanded
                # (`[Dictionary[string, $T]]$a, ...`): what it reads as is not known.
                return _ps_outer_tail(toks, i, word, ext)
            if found is not None:
                k, rest = found
                walked, resumed = True, k
                if rest:
                    word, value_of_glue = rest, True       # `[int] $a =return cmd`
                elif k + 1 >= len(toks):
                    return []
                else:
                    k, word, value_of_glue = k + 1, toks[k + 1], False
                i, word, value_of_glue, flow, typed = _ps_value_start(toks, k, word,
                                                                      value_of_glue)
                continue
        if not walked:
            return None
        if flow and ("$" in word or word.startswith(",")):
            return []          # `return $a, $b`, `return ,$x`, `exit $LASTEXITCODE`: a value
        if value_of_glue is not None and i in (toks.ps_quoted_value if value_of_glue
                                               else toks.ps_quoted):
            return []
        return [word] + list(toks[i + 1:])


def _ps_list_scan(toks, i, word, j):
    """The items of a list target from toks[j] on (see _ps_statement_tail), word being the
    text read for toks[i] (the walk's word) and j the last word of the first item. Each
    item is read by _ps_list_item. A separator: a comma inside the word that starts an item
    in it (`$a,$b=cmd`, `$a,[int] $b=cmd`; read once per word, see _ps_comma_item), a
    comma that ends an item (`$a, $b`), a word of commas (`$a , $b`), or one that leads the
    next item (`$a ,$b`, read without it). An item that is a glued target ends the list,
    whatever its value holds (`$a, $b=cmd`, `$a, [int] $b= cmd`, `$a, [Dictionary[string,`
    `int]]$b=cmd`; `$b=[Dictionary[string,` ends in its value's comma). (The index of the
    last word read, (its index, the glued target and its value as one text) for that item
    or None.)"""
    last, inner, cur = None, -1, (word if j == i else toks[j])
    while True:
        piece = _ps_comma_item(cur) if inner < j else None
        nxt, head = (toks[j + 1] if j + 1 < len(toks) else None), None
        if piece:
            s, head, inner = j, piece, j
        elif nxt is None:
            break
        elif not nxt.strip(","):
            s = j + 2
        elif nxt.startswith(","):
            s, head = j + 1, nxt.lstrip(",")
        elif toks[j].endswith(","):
            s = j + 1
        else:
            break
        item = _ps_list_item(toks, s, head) if s < len(toks) else None
        if item is None:
            break
        k, j, kword = item
        # An item whose index a space split is read as one text (see _ps_list_item), and so
        # is the rest of its last word (`$a, $b[ 0],$c=cmd`).
        joined = j > k and kword[:1] == "$"
        text = kword if j == k or joined else toks[j]
        cur = text if joined else toks[j]
        last = ((j, text) if _PS_GLUED_ASSIGN_RE.fullmatch(text)
                else _ps_typed_glued_target(toks, k, kword))
        if last:
            break
    return j, last


def _ps_comma_item(text):
    """The list item a comma inside a word starts (`$a,$b=cmd`, `$a,[int]$b=cmd`, `$a,[int]`
    before ` $b=cmd`), as the text to read for that word (see _ps_list_item): the first
    item after such a comma that is a glued target, perhaps typed, with the rest of the
    word (its value may hold commas: `$a,$b=1,2`), else the last item; None when there is
    none. A comma inside brackets, parentheses or braces is not the list's. Each item is
    read once, within its own text, as soon as it ends: the scan stops at the first glued
    one, so a chain of them in one word (`$a,$b=$c,$d=$e,...`, one per walk step) is read
    in linear time."""
    depth, start, last, n, size = 0, None, None, 0, len(text)
    while n <= size:
        c = text[n] if n < size else ","
        # start is None until the first top-level comma: before it, only the word's start.
        if c == "[" and not depth and n in (0, start):
            # A type that leads an item (or the word) ends at the first `]` that closes
            # it there, as _ps_split_target reads one (`[x,[int]$b,$c=cmd`): its commas
            # and brackets are not the list's.
            end = _PS_TYPE_WORD_RE.match(text, n).end()
            if end > n:
                n = end
                continue
        if c in "[({":
            depth += 1
        elif c in "])}":
            depth = max(depth - 1, 0)
        elif c == "," and (not depth or n == size):
            if start is not None and start < n:
                lead = _PS_TYPE_WORD_RE.match(text, start, n).end()
                if _PS_GLUED_ASSIGN_RE.fullmatch(text, lead, n):
                    return text[start:]
                last = (start, n)
            start = n + 1
        n += 1
    return text[last[0]:last[1]] if last else None


def _ps_outer_tail(toks, i, word, ext):
    """What a walk hands back when it stops before a word an outer shell expanded (ext,
    see _ps_statement_tail): from its word when that holds a `$` (_rules_at refuses such a
    command word there), else from the first expanded word after i (`[Dictionary[string,`
    `int]]$T, ...`: a word with no `$` would be judged as a command)."""
    if "$" in word:
        return [word] + list(toks[i + 1:])
    return list(toks[min((t for t in ext if t >= i), default=i):])


def _ps_flow_word(toks, i, word):
    """word (toks[i], or the value glued to an `=` in it) is `return`, `throw` or `exit`
    with an operand, toks[i + 1] (not an assignment operator, which would make it a
    hashtable key so named)."""
    nxt = toks[i + 1] if i + 1 < len(toks) else ""
    return (word.lower() in _PS_FLOW_PIPELINE and bool(nxt) and nxt not in _PS_ASSIGN
            and not nxt.startswith("="))


def _ps_value_start(toks, i, word, glue, first=False):
    """Where a value's own words begin (see _ps_statement_tail), from word: toks[i], or
    with glue the value glued to an `=` in toks[i] (`$x=return`). Past a flow word with an
    operand (`return cmd`), a unary comma, alone or glued (`, $y = cmd`, `,[int] $y =
    cmd`), and a run of type literals (`[int] $y = cmd`), hopped until none applies, so a
    statement's start, a value after an operator, a glued value and a resumed one all
    read alike: `$x=return [int] $y = cmd`. PowerShell takes at most a flow word, then the
    types; other orders are read the same way, which only adds words to judge. Each hop
    moves i on or shortens word, so this stays linear. Returns (i, word, glue, flow,
    typed): flow when a flow word was hopped, typed when a comma or a type run was. first:
    word is the statement's first word."""
    flow = typed = False
    while True:
        if _ps_flow_word(toks, i, word):
            i, word, glue, flow = i + 1, toks[i + 1], False, True
            continue
        if word.endswith(",") and _ps_flow_word(toks, i, word.rstrip(",")):
            # `return, $b = cmd`: a flow word glued to a unary comma; what follows is the
            # comma's operand, a value or a target as after a type.
            i, word, glue, flow, typed = i + 1, toks[i + 1], False, True, True
            continue
        if word and not word.strip(",") and i + 1 < len(toks):
            # `$x = , $y = cmd`: a unary comma; what follows is its operand, a value or a
            # target as after a type.
            i, word, glue, typed = i + 1, toks[i + 1], False, True
            continue
        commas = len(word) - len(word.lstrip(","))
        if 0 < commas < len(word) and (flow or typed or not first or "$" not in word):
            # `$x = ,[int] $y = cmd`: a unary comma glued to its operand, read as glued
            # text. Not a statement's first word holding a `$` (see the glued target
            # below); a word a hop reached is no first word (`return ,$y=cmd`).
            word, glue, typed = word[commas:], True, True
            continue
        k = _ps_type_words_end(toks, i, word if glue else None)   # `$x=[string] $y = cmd`
        if k == i:
            # `return [int]$y=cmd`: a type glued to a glued target. Not from a statement's
            # first word holding a `$`, whose reading _rules_at's early return depends on.
            found = (_ps_typed_glued_target(toks, i, word)
                     if flow or typed or not first or "$" not in word else None)
            if found:
                return found[0], found[1], True, flow, True
            return i, word, glue, flow, typed
        i, word, glue, typed = k, toks[k], False, True


def _ps_typed_glued_target(toks, i, word):
    """A type glued to a glued target from word (toks[i], or the value glued to an `=` in
    it): `[int]$y=cmd`, the type perhaps split by a space (`[Dictionary[string,`
    `int]]$y=cmd`), joined as _ps_split_target joins one. The word alone is read first:
    an open `[` may be its value's (`[int]$y=[Dictionary[string,`). (The index of the last
    word read, the target and its value as one text), or None. `$y[ 0]=cmd`: a target a
    space splits is read too."""
    return _ps_split_target(toks, i, word, True)


def _ps_split_target(toks, i, word, glued):
    """A type literal from word (toks[i], or the value glued to an `=` in it) and the
    target after it, the two perhaps split by spaces: word joined with the words after it
    one at a time while it opens a `[` it has not closed, up to 8 words. The first text
    that reads as a type, then a target (glued: a glued assignment, `$y=cmd`; else a word
    holding a `$`) is the one: PowerShell's type ends at the first `]` that closes it there
    (`[x, [int]$y=cmd` types `$y` as `[x, [int]`, and `cmd` is its value, not part of a
    longer type). (The index of the last word read, the text after the type), or None."""
    joined, j, tried = word, i, False
    while True:
        lead = _PS_TYPE_WORD_RE.match(joined).end()
        if lead and (_PS_GLUED_ASSIGN_RE.fullmatch(joined, lead) if glued
                     else "$" in joined[lead:]):
            return j, joined[lead:]
        if glued and lead and not tried and joined[lead:lead + 1] == "$":
            # `[int]$b[$c[0]]=cmd`: a target whose index _PS_VAR cannot read in one word
            # (see _ps_index_target), tried once, where the type first ends at a `$`.
            tried = True
            indexed = _ps_index_target(toks, j, joined[lead:])
            if indexed and _PS_GLUED_ASSIGN_RE.fullmatch(indexed[1]):
                return indexed
        if not (joined[:1] in "[]" and joined.count("[") > joined.count("]")
                and j + 1 < len(toks) and j - i < 7):
            return None
        j += 1
        joined += toks[j]


class _PsUnreadTarget(Exception):
    """Raised by _ps_index_target for a target whose steps it cannot read: the statement
    walk refuses the target's word and the words after it (see _ps_statement_tail)."""

    def __init__(self, index, word):
        super().__init__(word)
        self.index, self.word = index, word


class _PsUnreadTail(list):
    """A statement tail that starts at a target the walk could not read: its segment is
    refused (ps_unread, see _ps_statement_tails and _reasons_for)."""


def _ps_index_target(toks, i, word):
    """A variable target from word (toks[i], or the text a walk reads for it) with steps
    _PS_VAR cannot read in one word: an index a space splits (`$b[ 0]=cmd`, `$b[$i,`
    `0]=cmd`), or one holding a nested index or a parenthesis (`$b[$c[0]]=cmd`,
    `$b[(0)]=cmd`), or a member a variable names (`$b.$c=cmd`, `$b.${c}=cmd`). Its steps,
    member names and indexes, are read from the variable's name on, an index ending at
    the `]` that balances its `[`, across the words after it joined one at a time. (The
    index of the last word read, the name with the text after the steps: `$b=cmd`, `$b`,
    `$b, ...`), or None when _PS_VAR reads the word's steps (a word that is no such
    target).

    Raises _PsUnreadTarget, which the walk refuses, for such a target it cannot read: an
    index still open at the end of the statement or before a word that opens with an
    assignment operator; text glued after the steps that no operator, comma or end
    starts (`$b[0]]=cmd`); and when toks[i] or a word after it held a bracket inside
    quotes, or the segment has no record of that (ps_qbracket on _Seg is None: the words
    were read quote-blind). The words have lost their quotes, so where such an index
    ends is not known (`$h[ 'x]' ]=cmd`), and nor is the reading of a later target that
    holds one. Not refused, but not read either (None, as before), in a quote-blind
    segment of a line the strict pass also tokenized whole on one physical line
    (ps_quote_covered on _Seg): the strict segment holds the same words with their
    record, and is read or refused there. There is no cap on the words joined: a read
    moves the walk past them and a refusal ends it, so each word is scanned once and
    this stays linear.

    Also refused: a word that ends in a member's `.` (`$b. c=cmd`, `$b[ 0]. c=cmd`:
    PowerShell reads the name after the space), and steps _PS_VAR reads whole that may
    hold a quoted bracket (`$h["x]" ]=cmd`: toks[i] held one, or there is no record of
    that outside a covered segment), whose index may go on past the word."""
    m = _PS_VAR_RE.match(word)
    if not m:
        return None
    stop = word[m.end():m.end() + 1]
    qb = getattr(toks, "ps_qbracket", None)
    covered = qb is None and getattr(toks, "ps_quote_covered", False)
    name = _PS_VAR_NAME_RE.match(word).end()
    if word[m.end():] == ".":
        raise _PsUnreadTarget(i, word)
    if not (stop in ("[", "]") or stop == "." and _PS_MEMBER_RE.match(word, m.end())):
        if "[" in word[name:m.end()] and not covered and (
                qb is None or _ps_qbracket_holds(qb, i)):
            raise _PsUnreadTarget(i, word)
        return None
    if covered:
        return None
    if qb is None or (qb and qb[-1] >= i):
        raise _PsUnreadTarget(i, word)
    joined, j, n, depth = word, i, name, 0
    while True:
        size = len(joined)
        while n < size:
            c = joined[n]
            if c == "[":
                depth += 1
            elif depth:
                if c == "]":
                    depth -= 1
            else:
                member = _PS_MEMBER_RE.match(joined, n) if c == "." else None
                if not member:
                    break
                n = member.end()
                continue
            n += 1
        if not depth:
            rest = joined[n:]
            if _PS_STEP_JUNK_RE.match(rest) or rest == ".":
                raise _PsUnreadTarget(i, word)
            return j, word[:name] + rest
        if j + 1 >= len(toks) or _PS_ASSIGN_LEAD_RE.match(toks[j + 1]):
            raise _PsUnreadTarget(i, word)
        j += 1
        joined += toks[j]


def _ps_qbracket_holds(qb, i):
    """Whether the ps_qbracket indexes qb (ascending, see _Seg) hold i."""
    k = bisect.bisect_left(qb, i)
    return k < len(qb) and qb[k] == i


def _ps_list_item(toks, s, head=None):
    """An item of a list target from toks[s] (see _ps_statement_tail): a word holding a
    `$`, perhaps after a run of type literals (`[int] $b`, see _ps_type_words_end), or a
    type a space split glued to its variable (`[Dictionary[string,` `int]]$b`, see
    _ps_split_target). head: the text to read for toks[s] (without the comma that leads
    it). (The index where its type run ends, the index of its last word, the text read
    for the word at the run's end), or None. Not when a word from the run's end opens with
    an assignment operator: a resume reads that word, so a list scan stops there and never
    rescans it (`=,$b, =,$b, ...` stays linear; type words hold no `=`)."""
    k = _ps_type_words_end(toks, s, head)
    kword = head if k == s and head is not None else toks[k]
    e = k
    if "$" not in kword:
        found = _ps_split_target(toks, k, kword, False)
        if found is None:
            return None
        e = found[0]
    else:
        # `$a, $b[ 0]=cmd`, `$a, [int]$b[ 0], $c=cmd`: steps _PS_VAR cannot read in one
        # word (see _ps_index_target), read as the item's name and what follows its steps
        # (a type glued before it goes).
        lead = (_PS_TYPE_WORD_RE.match(kword).end()
                if kword[:1] and kword[:1] in "[]" else 0)
        indexed = (_ps_index_target(toks, k, kword[lead:])
                   if kword[lead:lead + 1] == "$" else None)
        if indexed:
            e, kword = indexed
    if _PS_ASSIGN_LEAD_RE.match(kword) or any(_PS_ASSIGN_LEAD_RE.match(toks[t])
                                              for t in range(k + 1, e + 1)):
        return None
    return k, e, kword


def _ps_assignment_operator(toks, i, target=False):
    """The first assignment operator from toks[i] on, as a word (`=`, `+=`) or leading one
    (`=cmd`): (its index, the rest of its word), or None (see _ps_statement_tail). target:
    also a word that holds a glued target right after a `]` (`Get-Date]$b=cmd`, the end
    of a type literal the walk could not read): (its index, the target and its value)."""
    for k in range(i, len(toks)):
        op = _PS_ASSIGN_LEAD_RE.match(toks[k])
        if op:
            return k, toks[k][op.end():]
        d = toks[k].find("]$") if target else -1
        if d >= 0 and _PS_GLUED_ASSIGN_RE.fullmatch(toks[k], d + 1):
            return k, toks[k][d + 1:]
    return None


def _ps_type_words_end(toks, i, head=None):
    """The index past a run of type-literal words from toks[i] (see _PS_TYPE_WORD_RE), a
    literal a space split (`[Dictionary[string, int]]`) read as one, up to 8 words (so the
    walk stays linear); i when there is none. Never the last word's index plus one: a
    target must follow. head: the text to read for toks[i] (a value glued to an `=` in
    it, `$x=[string]`)."""
    k = i
    while k + 1 < len(toks):
        word, j = (head if k == i and head is not None else toks[k]), k
        while (word[:1] in "[]" and word.count("[") > word.count("]")
               and j + 2 < len(toks) and j - k < 7):
            j += 1
            word += toks[j]
        if not (word and _PS_TYPE_WORD_RE.fullmatch(word)):
            break
        k = j + 1
    return k


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


def _ps_tail_segment(words, called=False, piped=False, expanding=frozenset(), src=None,
                     qbracket=None):
    """words as a segment of the tool's payload. `. cmd` dot-invokes cmd, so the words
    are judged without the dot, and `. $y` is a call of $y, not an ordinary statement.
    A leading number goes too: in `$x=2>&1 rm -rf /` the 2 was a redirect's.
    called, piped: the source segment's ps_call and pipe, for words taken from one that
    is not an ordinary statement (`'x' | . bash` feeds bash). expanding: the indexes of
    the words that hold a `$` the shell expands (see expanding on _Seg). src: a segment
    of a runner's pwsh script the words come from: the new segment is one of that
    script's (ps_script, with its ps_outer and pipe), not of the tool's payload.
    qbracket: the ps_qbracket indexes of words (see _Seg), or None."""
    dot = words[0] == "." and len(words) > 1
    drop = dot or (words[0].isdigit() and len(words) > 1)
    seg = _new_seg(words[1:] if drop else words, piped or getattr(src, "piped", False))
    seg.ps_call = called or (dot and "$" in words[1])
    if src is None:
        seg.ps_tool = True
    else:
        seg.ps_script, seg.ps_outer = True, src.ps_outer
    seg.expanding = frozenset(e - drop for e in expanding if e >= drop)
    seg.ps_qbracket = (None if qbracket is None
                       else tuple(e - drop for e in qbracket if e >= drop))
    return seg


def _suffix_qbracket(src, words):
    """The ps_qbracket indexes of src (see _Seg) for words, which end as src does; None
    when src has none."""
    got = getattr(src, "ps_qbracket", None)
    if got is None:
        return None
    k = len(src) - len(words)
    return tuple(e - k for e in got if e >= k)


def _suffix_expanding(src, words):
    """The expanding indexes of src (see _Seg) for words, which end as src does."""
    k = len(src) - len(words)
    return frozenset(e - k for e in getattr(src, "expanding", ()) if e >= k)


def _ps_statement_tails(segments, script=False):
    """What the ordinary statements of a PowerShell tool payload go on to run, as segments
    of their own, so the caller tokenizes inline scripts in them and judges them like any
    other segment: see _ps_statement_tail and _ps_hash_value. `$x = $(cmd)`: the body is
    its own segment. Each input yields at most three segments, so this stays linear.

    A statement that opens with a flow or type word gets the dot and hashtable readings
    too: those words also name a hashtable key (`@{ return = cmd }`), so their reading
    adds to the others and never replaces them.

    script: the segments are a runner's pwsh script's (ps_script), read the same way, so a
    runner after an `=` (`pwsh -c '$x = cmd /c ...'`) is expanded like one the script
    starts. _rules_at judges an assignment's right-hand side there by the rules only, and
    nested runners are expanded only from segments, so these are added for that."""
    out = []
    for toks in segments:
        if not getattr(toks, "ps_script" if script else "ps_tool", False):
            continue
        own = toks if script else None
        tail = _ps_statement_tail(toks, script)
        tails = [] if tail is None else [(tail, toks)]
        start = _ps_statement_start(toks)
        if (tail is None or toks[start].lower() in _PS_FLOW_PIPELINE
                or _ps_type_words_end(toks, start) > start):
            value = (list(toks[1:]) if toks[0] == "." and len(toks) > 1 and "$" not in toks[1]
                     else _ps_hash_value(toks))   # `. cmd args`: cmd is the command
            if value and value != ["$"]:
                seg = _ps_tail_segment(value, toks.ps_call, toks.piped,
                                       _suffix_expanding(toks, value), own,
                                       _suffix_qbracket(toks, value))
                # `@{ a = $y = cmd }`: one more step
                out.append(seg)
                tails.append((_ps_statement_tail(seg, script), seg))
        for tail, src in tails:
            if tail and tail != ["$"]:
                seg = _ps_tail_segment(tail, expanding=_suffix_expanding(src, tail),
                                       src=src if script else None,
                                       qbracket=_suffix_qbracket(src, tail))
                # A target the walk could not read: refused (see _reasons_for).
                seg.ps_unread = isinstance(tail, _PsUnreadTail)
                out.append(seg)
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
            _ps_rhs_records(toks, rhs)
            rest.append(rhs)
        elif toks[idx].endswith(",") and rest is not None:
            # `$a, $b = cmd`: a list target; the command after its `=` (the script's tail
            # segments also read it, see _ps_statement_tails; this is the backstop).
            k = next((k for k in range(idx + 1, len(toks)) if toks[k] in _PS_ASSIGN), None)
            if k is not None and k + 1 < len(toks):
                rhs = _new_seg(toks[k + 1:], getattr(toks, "piped", False))
                rhs.ps_script = True
                _ps_rhs_records(toks, rhs)
                rest.append(rhs)
            # `$a, $b =cmd`: also the value glued to the first word an assignment operator
            # opens (in addition: the reading above stays).
            g = next((g for g in range(idx + 1, len(toks))
                      if _PS_ASSIGN_LEAD_RE.match(toks[g])), None)
            if g is not None and toks[g] not in _PS_ASSIGN:
                rhs = _new_seg([toks[g][_PS_ASSIGN_LEAD_RE.match(toks[g]).end():]]
                               + list(toks[g + 1:]), getattr(toks, "piped", False))
                rhs.ps_script = True
                _ps_rhs_records(toks, rhs)
                rest.append(rhs)
        return out

    # PowerShell's Remove-Item (and its aliases), read as PowerShell binds it; an `rm` in a
    # PowerShell text is judged by the rule below as well (see _PS_REMOVE_ITEM).
    name = cmd.lower()
    if name in _PS_REMOVE_ITEM and (name not in _PS_REMOVE_ITEM_GATED
                                    or getattr(toks, "ps_tool", False)
                                    or getattr(toks, "ps_script", False)
                                    or (name == "rm" and any(map(_ps_style_parameter, args)))):
        root, unknown = _ps_remove_item(args, getattr(toks, "piped", False),
                                        _Command.ps_defaults)
        if root:
            out.append("recursive delete of a root/cwd/home target (Remove-Item -Recurse)")
        if unknown:
            out.append("recursive delete with targets piped in "
                       "(Remove-Item -Recurse, unknown scope)")

    # cmd's rd /s and del /s, read as cmd reads them (see _cmd_delete), in every text: no
    # other shell has these commands, and PowerShell's binds /s as a path, never a recursion.
    word = toks[idx].replace("^", "").lower().lstrip("@")
    m = _CMD_DELETE_RE.match(word)
    if m and _cmd_delete(m.group(1), ([word[m.end():]] if m.end() < len(word) else [])
                         + list(args)):
        if m.group(1) in ("rd", "rmdir"):
            out.append("recursive delete of a root/cwd/home target (cmd rd /s)")
        else:
            out.append("recursive delete of a root/cwd/home target (cmd del /s)")

    # Invoke-Expression runs its Command as code: a literal one is read (see _runner_rests);
    # one fed from the pipe, or computed, cannot be read (the `| sh` and `eval $x` cases).
    if _ps_is_iex(name) and (getattr(toks, "ps_tool", False)
                             or getattr(toks, "ps_script", False)):
        state = _ps_iex_command(toks, idx)[0]
        if state == "none" and getattr(toks, "piped", False):
            out.append("shell reading its commands from a pipe (uninspectable)")
        elif state in ("none", "computed", "blind"):
            out.append("uninspectable command (PowerShell code from a computed string)")

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


def _runner_rests(toks, ps=None):
    """(kind, words, outer) for each command a Windows runner at the command position would
    run: `cmd /c|/r|/k ...`, `pwsh|powershell -Command ...` (and 5.1's positional command),
    and `wsl ...`. Both readings of wrapper options are tried. Empty commands are dropped.
    outer: a word after the runner holds a `$` the shell expands (see expanding on _Seg),
    so the words are not the text the runner gets. In PowerShell text, also Invoke-Expression
    (`iex`) with a literal Command, read as a pwsh script (see _ps_iex_command), with its own
    outer. ps: whether toks are PowerShell text; None reads ps_tool / ps_script (a quote-blind
    segment of a pwsh script is marked ps_script only after its runners are read, so
    _segments passes it)."""
    out, iex = [], []
    if ps is None:
        ps = getattr(toks, "ps_tool", False) or getattr(toks, "ps_script", False)
    for consume in _READINGS:
        i = _shell_index(toks, consume)
        if i is not None and ps:
            # `try { pwsh -c '...' }`: the block's first statement follows the word in the
            # readings that keep its words whole; the block reading, which splits it off,
            # also splits a brace inside a string (`"i`u{65}x"`).
            k = _ps_skip_block_words(toks, i)
            if k != i:
                j = _shell_index(toks[k:], consume)
                i = None if j is None else k + j
        if i is None:
            continue
        base, args = _cmd_word(toks[i]), list(toks[i + 1:])
        if getattr(toks, "ps_script", False):
            # A runner in a pwsh script: PowerShell's quoting is not the one `expanding`
            # follows (`\"` opens a string there), so any $ word after it counts.
            outer = "$" in "".join(toks[i + 1:])
        else:
            outer = any(e > i for e in getattr(toks, "expanding", ()))
        found = len(out)
        if base == "cmd":
            # Git Bash (and pwsh in its Standard mode) hands cmd an empty argument as `""`
            # (`cmd //c if "" equ "" x`), a word to it; Windows PowerShell, and pwsh's Windows
            # mode for cmd.exe, drop it. Both are read: these words with it, and the cmd text
            # re-tokenized without it. (A trailing one lands after a here-string's `-c`
            # words: only their order differs.)
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
        elif ps and _ps_is_iex(base):
            state, readings, outer_iex = _ps_iex_command(toks, i)
            if state in ("literal", "blind"):
                iex += [("ps", words, outer_iex) for words in readings]
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
    out += iex
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
    `call,git ...`, `echo ' & x & '`, `call<NBSP>git ...`); and each of those holding a ;
    with it a space too (_CMD_SEMI_AS_SPACE: `rd;/s /q x`)."""
    texts = [" ".join(words)]
    if any(not w or any(c.isspace() for c in w) for w in words[1:]):
        texts.append(" ".join(words[:1] + ['"' + w + '"' if not w or any(
            c.isspace() for c in w) else w for w in words[1:]]))
    # An empty "" or '' is a word to cmd (an `if` operand: `if "" equ "" x`), where the
    # bash reading leaves no word at all: also read with each one a word of its own.
    texts += [t.replace('""', '"_"').replace("''", "_") for t in texts
              if '""' in t or "''" in t]
    texts += [t.replace("^", "") for t in texts]
    texts += [p for p in (_CMD_NAME_PAREN_RE.sub(r"\1\2 ", t) for t in texts) if p not in texts]
    delims = [t.translate(_CMD_DELIMS) for t in texts]
    return texts + delims + [t.translate(_CMD_SEMI_AS_SPACE) for t in delims if ";" in t]


def _runner_scripts(toks):
    """(script text, kind, outer) for every command a Windows runner in the segment would run.

    A runner's words are joined with spaces, as a runner that hands a command LINE to a
    parser sees them (cmd /c, pwsh -Command, wsl's default shell): `cmd /c "git reset
    --hard"` is `git reset --hard`. (A quoted script for a shell later in the words,
    `wsl -e bash -c '...'`, is still found whole by _split_inline_script.) cmd's text is
    also read as _cmd_texts gives it. A pwsh/powershell script is also read with each
    of _PS_SPACES a space, as PowerShell separates words on them, and with its dashes as
    `-` (_ps_dash_readings); then each of those in its grouping and block readings
    (_ps_ungroup, _ps_block_statements), and all of those with PowerShell's own quoting
    (_ps_unescape; see _powershell_segments) and with its backtick escapes decoded. The
    spaces are read before the escapes, so a space an escape produces stays inside its
    word. Both decoders read the same base texts, never
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


@functools.lru_cache(maxsize=4096)
def _ps_script_texts(text: str, nest: int = 0) -> tuple:
    """The texts a pwsh/powershell script is read as (see _runner_scripts), and those of
    the code each canonical literal call in it runs from a string (_ps_code_strings), nest
    levels deep at most _MAX_INLINE_DEPTH. Memoized (evaluate() clears it): a script's text
    comes down once per reading of each level above it."""
    texts = _ps_dash_readings(text)
    # ...and of each text one lexer reads it as (see _ps_normalized_texts), when it differs.
    for norm in _ps_normalized_texts(text):
        if norm != text:
            texts += [t for t in _ps_dash_readings(norm) if t not in texts]
    plain = list(texts)
    texts += [_ps_ungroup(t) for t in plain]
    texts += [_ps_block_statements(t) for t in plain if "{" in t or "}" in t]
    texts += [b for b in (_ps_code_braces(t) for t in plain if "{" in t or "}" in t)
              if b not in texts]
    base = list(texts)
    texts += [_ps_unescape(t) for t in base]
    texts += [_ps_unescape_everywhere(t) for t in base if "`" in t]
    # A pipeline continued after a `|` that ends a line, read as one line (the runner's
    # segments are lenient, so a here-string this cuts cannot refuse the script).
    texts += [j for t in plain for j in _ps_joined_pipes(t)]
    # A literal list's group read away (see _PS_LIST_GROUP_RE), likewise lenient.
    texts += [_PS_LIST_GROUP_RE.sub(_ps_list_items, t) for t in plain
              if _PS_LIST_GROUP_RE.search(t)]
    # After the decoders, so a body is not decoded twice: its own readings decode it.
    for t in plain:
        for body in _ps_code_strings(t):
            if nest >= _MAX_INLINE_DEPTH:
                raise _Uninspectable(f"inline scripts nested too deep to inspect (> "
                                     f"{_MAX_INLINE_DEPTH} levels)")
            texts += _ps_script_texts(body, nest + 1)
    return tuple(texts)


# PowerShell words that open a block whose first statement follows them in a segment
# (`try { ... }`, `catch [T] { ... }`, a script block's named blocks), see _runner_rests.
# Not _PS_BLOCK_WORDS (_ps_argument_group's own set).
_PS_BLOCK_OPENERS = frozenset({"try", "catch", "finally", "trap", "begin", "process", "end",
                               "clean", "dynamicparam", "else", "do"})


def _ps_skip_block_words(toks, i):
    """The index after any run of _PS_BLOCK_OPENERS at toks[i] (with a catch or trap's type
    words: `catch [IOException], [Exception]`), and after a dot-source `.` there (`try { .
    iex '...' }`: the dot runs the next word, as _effective_cmd_index reads it), keeping at
    least one word after it."""
    n = len(toks)
    while i < n - 1 and toks[i].lower() in _PS_BLOCK_OPENERS:
        i += 1
        while i < n - 1 and (toks[i].startswith("[") or toks[i] == ","):
            i += 1
        if i < n - 1 and toks[i] == ".":
            i += 1
    return i


def _lenient_level_extras(r):
    """The statement tails of a pwsh command a quote-blind level found (see _lenient_reads):
    what its statements run after a dot-source, a flow word or an `=` (`. pwsh -c ...`,
    `return pwsh -c ...`, `$x = pwsh -c ...`), as the strict pass reads a pwsh script's
    statements (_ps_statement_tails), so a runner there is read at the next level."""
    if not getattr(r, "ps_script", False):
        return []
    out = []
    for t in _ps_statement_tails([r], script=True):
        t.ps_script, t.ps_outer = True, getattr(r, "ps_outer", False)
        t.piped = t.piped or getattr(r, "piped", False)
        out.append(t)
    return out


def _lenient_suffix(words, piped):
    """A shell -c suffix of quote-blind words as a segment to read for runners, with the
    quote-blind expansion record (any $ word counts as one the shell expands, see expanding
    on _Seg), so a runner in it whose words hold a $ is outer-expanded (`bash -c 'pwsh
    --command $CMD'`), as the strict pass reads the same script."""
    seg = _new_seg(words, piped)
    seg.expanding = frozenset(k for k, w in enumerate(seg) if "$" in w)
    return seg


def _lenient_reads(toks, outer_expanded=False, ps=None):
    """In a quote-blind segment: (_lenient_inline's segments, the segments of every Windows
    runner's command and of the runners and shell -c scripts nested in those). Quote-blind
    words are flat, so a runner's command holds a nested runner's words in place (`pwsh -c
    pwsh -c git ...`, `bash -c cmd //c ...`, `wsl bash -c ...`): each level's segments are
    read again (_lenient_runner, _lenient_inline, and a pwsh command's statement tails,
    _lenient_level_extras, for runners), as the strict pass expands a runner's script, at most
    _MAX_INLINE_DEPTH runner levels deep counted from this line; a level past that which
    still finds a runner's command refuses (as _segments does at its limit). ps: see
    _runner_rests, for toks only; a shell -c script is not PowerShell text, and a runner's
    command is PowerShell text when its runner is pwsh/powershell (its ps_script).

    Bounded: a runner's command is most often a tail of the words it was read from, and a
    tail's shell -c suffixes are among theirs (a shell word before a -c in the tail is before
    it in the whole), so a tail of words already split (with the same outer) is not split
    again; each other (words, outer) is split once; and every reading this keeps (all but
    toks's own runner's, which main read too) is charged to _RunnerBudget as it is found, so
    a line of many runner starts is refused at the cap instead of read in quadratic time;
    so is each of toks's own shell -c suffixes, which this reads for runners (main judged
    them only)."""
    piped = getattr(toks, "piped", False)
    inline = _lenient_inline(toks)
    tails = {(tuple(s), outer_expanded) for s in inline}
    for s in inline:                # read for runners below: main did not (see above)
        _RunnerBudget.charge(len(" ".join(s)))
    # (segment, outer, ps, covered): covered when its suffixes were all read already.
    todo = [(toks, outer_expanded, ps, True)] + [(_lenient_suffix(s, piped), outer_expanded, False,
                                                 True) for s in inline]
    runs, seen = [], set()
    for level in range(1, _MAX_INLINE_DEPTH + 2):
        found = []
        for seg, outer, is_ps, covered in todo:
            for r in _lenient_runner(seg, outer, is_ps):
                key = (tuple(r), r.ps_script, r.cmd_script, r.ps_outer, getattr(r, "piped", False))
                if key in seen:
                    continue
                seen.add(key)
                if level > 1 or seg is not toks:
                    # A reading main did not take (main read toks's own runner only):
                    # charged as found (see above).
                    _RunnerBudget.charge(len(" ".join(r)))
                found.append((r, covered and r.ps_outer == outer
                              and list(seg[len(seg) - len(r):]) == list(r)))
        if not found:
            break
        if level > _MAX_INLINE_DEPTH:
            raise _Uninspectable(f"inline scripts nested too deep to inspect (> "
                                 f"{_MAX_INLINE_DEPTH} levels)")
        runs += [r for r, _ in found]
        todo = []

        def split(x, outer):
            """x's shell -c suffixes: judged, and read for runners at the next level."""
            for s in _lenient_inline(x):
                if (tuple(s), outer) not in tails:
                    tails.add((tuple(s), outer))
                    _RunnerBudget.charge(len(" ".join(s)))
                    s = _lenient_suffix(s, getattr(x, "piped", False))
                    runs.append(s)
                    todo.append((s, outer, False, True))

        for r, covered in found:
            todo.append((r, r.ps_outer, r.ps_script, True))
            if not covered:
                split(r, r.ps_outer)
            # Its statement tails are read for runners at the next level, not judged: on a
            # quote-blind line a statement's expression is no command (main judges none).
            for t in _lenient_level_extras(r):
                key = (tuple(t), "tail", t.ps_outer, getattr(t, "piped", False))
                if key in seen:
                    continue
                seen.add(key)
                _RunnerBudget.charge(len(" ".join(t)))
                if list(r[len(r) - len(t):]) != list(t) or t.ps_outer != r.ps_outer:
                    split(t, t.ps_outer)
                todo.append((t, t.ps_outer, True, True))
    return inline, runs


def _lenient_runner(toks, outer_expanded=False, ps=None):
    """In a quote-blind segment, the command words of each Windows runner, one segment
    each (the counterpart of _lenient_inline): `echo "$(wsl rm -rf ~)"` is judged as
    `rm -rf ~`. ps: see _runner_rests. A pwsh script here that names a code-from-string
    call is refused (_ps_code_strings: its quotes are gone, so no literal is covered),
    unless the strict pass read the same line (ps_quote_covered on _Seg)."""
    out = []
    for kind, words, outer in _runner_rests(toks, ps):
        if kind == "ps" and not getattr(toks, "ps_quote_covered", False):
            _ps_code_strings(" ".join(words))
        variants = [words]
        if kind == "cmd":
            variants.append([w.replace("^", "") for w in words])
            # A `(` glued to a delete's name (see _CMD_NAME_PAREN_RE).
            variants += [_CMD_NAME_PAREN_RE.sub(r"\1\2 ", " ".join(v)).split() for v in list(variants)
                         if "(" in " ".join(v)]
            # cmd's , = ' and Unicode spaces (see _CMD_DELIMS), as _runner_scripts reads them.
            delims = [" ".join(v).translate(_CMD_DELIMS) for v in list(variants)]
            variants += [d.split() for d in delims]
            variants += [d.translate(_CMD_SEMI_AS_SPACE).split() for d in delims if ";" in d]
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


_PS_VAR_BRACE_RE = re.compile(r"\$\{[^{}]*\}")
# Blanks to the end of the line, the line break included (a here-string opener's rest).
_PS_BLANK_TO_EOL_RE = re.compile(r"[^\S\n]*\n")
def _ps_code_braces(text: str) -> str:
    """The block reading (_ps_block_statements) of the braces PowerShell reads as code only:
    one inside a "..." or '...' string (a "..." string's $( ) followed as code to its `)`, so
    a string in it does not end the outer one), a here-string (its `@'` or `@"` after any
    non-word character: `$h=@'`), a ${...} variable, a <# #> or # comment or a backtick
    escape (`` `u{74} ``, in a string or a bareword) stays as it is, so the string or escape
    keeps its value: `Invoke-Command { pwsh -c '& "gi`u{74}" ...' }` reads as the runner and
    its whole script. An added reading (a scanner mistake here only loses this reading); no
    quote character changes."""
    out, i, n = [], 0, len(text)
    stack = []                 # inside a "..." string: ["dq"], and ["sub", depth] for its $( )
    at_word_start = True
    while i < n:
        c = text[i]
        if stack and stack[-1][0] == "dq":
            if c == "`":
                j = min(n, i + 2)
            elif c == "$" and text.startswith("(", i + 1):
                stack.append(["sub", 0])
                j = i + 2
            elif c in _PS_DQ:
                if i + 1 < n and text[i + 1] in _PS_DQ:
                    j = i + 2
                else:
                    stack.pop()
                    j = i + 1
            else:
                j = i + 1
            out.append(text[i:j])
            i, at_word_start = j, False
            continue
        if (c == "@" and i + 1 < n and text[i + 1] in "\"'"
                and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_"))):
            blank = _PS_BLANK_TO_EOL_RE.match(text, i + 2)
            if blank:
                end = _ps_here_string_end(text, blank.end(), text[i + 1] + "@")
                j = n if end == -1 else end + 2
                out.append(text[i:j])
                i, at_word_start = j, False
                continue
        if c == "<" and text.startswith("<#", i):
            end = text.find("#>", i + 2)
            j = n if end == -1 else end + 2
            out.append(text[i:j])
            i = j
            continue
        if c == "#" and at_word_start:
            eol = text.find("\n", i)
            j = n if eol == -1 else eol
            out.append(text[i:j])
            i = j
            continue
        if c in _PS_SQ:
            quoted = _ps_quoted(text, i, False)
            j = n if quoted is None else quoted[1]
            out.append(text[i:j])
            i, at_word_start = j, False
            continue
        if c in _PS_DQ:
            stack.append(["dq"])
            out.append(c)
            i, at_word_start = i + 1, False
            continue
        if c == "$":
            m = _PS_VAR_BRACE_RE.match(text, i)
            if m:
                out.append(m.group(0))
                i, at_word_start = m.end(), False
                continue
        if c == "`":
            j = min(n, i + 2) if i + 1 >= n or text[i + 1] in "\r\n" else _ps_escape(text, i + 1)[1]
            out.append(text[i:j])
            i, at_word_start = j, False
            continue
        if stack:                                        # code in a string's $( )
            if c == "(":
                stack[-1][1] += 1
            elif c == ")":
                if stack[-1][1]:
                    stack[-1][1] -= 1
                else:
                    stack.pop()
            out.append(c)
        else:
            out.append(" ; " if c in "{}" else c)
        at_word_start = c in " \t\r\n;|&(){}"
        i += 1
    return "".join(out)


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


# A heredoc operator (`<<`, `<<-`; not the here-string's `<<<`) with its delimiter word, and the
# escapes bash decodes in an unquoted heredoc's body.
_HEREDOC_OP_RE = re.compile(r"(?<!<)<<-?(?!<)[ \t]*([^\s;|&<>()]*)")
_HEREDOC_ESC_RE = re.compile(r"\\[\\$`\n]")


def _heredoc_escapes(text: str) -> bool:
    """Whether bash text holds a heredoc whose body bash decodes into other text: one whose
    delimiter word is unquoted (no quote or backslash in it) with a backslash before a
    backslash, $, ` or a newline after its operator. The operator and its word are read with
    backslash-newlines joined, as bash joins them before it reads an operator or a word
    (`<<E`, a backslash-newline, `OF` is `<<EOF`); the escapes are searched in the text itself, from where the
    word ends. An over-approximation: the search runs to the text's end (the delimiter line
    and later commands too), and an operator inside quotes counts."""
    kept, at, i, n = [], [], 0, len(text)
    while i < n:
        if text[i] == "\\" and text[i + 1:i + 2] == "\n":
            i += 2
            continue
        kept.append(text[i])
        at.append(i)
        i += 1
    joined = "".join(kept)
    for m in _HEREDOC_OP_RE.finditer(joined):
        if any(q in m.group(1) for q in "'\"\\"):
            continue
        if _HEREDOC_ESC_RE.search(text, at[m.end() - 1] + 1):
            return True
    return False


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


def _shell_words(s: str, bash_dq: bool = False):
    """Words of a logical line, exactly as shlex.split(s, posix=True) reads them --
    quotes removed, backslash escapes resolved, the same errors for an unclosed quote
    or a trailing backslash -- except that an UNQUOTED run of ( ) ; < > | & ` comes
    out as its own _Op token. A quoted one stays inside its word, as in bash, so
    `bash -c "cd /tmp && rm -rf /"` keeps its script whole and `rm -rf '&' ~` keeps
    `&` as an argument. bash_dq: inside "..." also decode the escapes bash decodes
    there and shlex keeps: a backslash before $ or ` is dropped, a backslash-newline
    is nothing (see the second reading in _segments).
    """
    words, buf, has_word, state, ansi_cut = _Words(), [], False, "", False
    i, n = 0, len(s)
    opens_quoted = value_quoted = qbracket = False
    words.expanding = set()
    words.qbracket = set()     # the words holding a `[` or `]` inside quotes
    dollar, dq_bs = False, -2   # see push(); dq_bs: where a lone backslash sat in a "..."

    def word():
        text = "".join(buf)
        return (_QuotedWord(text) if opens_quoted
                else _QuotedValueWord(text) if value_quoted else text)

    def push():
        if dollar:
            words.expanding.add(len(words))
        if qbracket:
            words.qbracket.add(len(words))
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
                qbracket = qbracket or "[" in text or "]" in text
            continue
        elif state == "'":
            if c == "'":
                state = ""
            else:
                buf.append(c)
                qbracket = qbracket or c in "[]"
        elif state == '"':
            if c == '"':
                state = ""
            elif c == "\\" and i + 1 >= n:
                raise ValueError("No escaped character")
            elif c == "\\" and s[i + 1] in '"\\':
                buf.append(s[i + 1])
                i += 1
            elif bash_dq and c == "\\" and s[i + 1] in "$`\n":
                if s[i + 1] != "\n":
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
                qbracket = qbracket or c in "[]"
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
            qbracket = False
            dollar = False
        elif c in _OP_CHARS:
            if c == "`" or (c == "(" and buf and buf[-1] == "$"):
                words.subst = True
            glued = bool(buf or has_word)
            if glued:
                push()
            buf, has_word, opens_quoted, value_quoted = [], False, False, False
            qbracket = False
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
    assignment's value does. (The last five: see _ps_statement_tail.) ps_qbracket: the
    indexes of the words that held a `[` or `]` inside quotes, or None when the words
    were read quote-blind or the segment was made without them (see
    _ps_index_target), in ascending order. ps_quote_covered: a quote-blind segment of a
    line the strict pass tokenized whole on one physical line (see _ps_index_target).
    ps_unread: a statement tail the walk refused (see _ps_statement_tails). expanding: the
    indexes of the words that hold a `$` the shell expands (see expanding on _Words), or
    a `$` at all when the words were read quote-blind; a PowerShell script in such a word
    is not the text pwsh gets: its segments are marked ps_outer, and a $ word in them is
    no expression (see _rules_at). heredoc: a `<<` heredoc redirect is on the segment;
    herestr_fed: a `<<<` here-string is; heredoc_wide: one of them is on a group or
    compound command that ends here, so it feeds every command in it (see
    _heredoc_check). cmd_script: the segment is part of a script handed to cmd (see
    _cmd_prefix_variants); scripts nested inside it are not. empties: the indexes before
    which the shell's words held an empty word (`""`, `''`), which the segment drops: Git
    Bash hands a program each one as an argument, and cmd reads it as a word (see
    _runner_rests).
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
    ps_qbracket = None
    ps_unread = False
    ps_quote_covered = False
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
    out.ps_qbracket = _suffix_qbracket(seg, out)
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
    qbracket = getattr(words, "qbracket", None)     # see ps_qbracket on _Seg
    qb = set()
    latch = _Latch() if latch is None else latch

    def close(next_piped, fed=False, op=None, glued_op=False, real_op=False):
        nonlocal cur, redirs, herestr, piped, pending, call_next, arg_next, foreach_next
        nonlocal quoted, quoted_value, exp, here_exp, heredoc_here, empties, qb
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
            seg.ps_qbracket = None if qbracket is None else tuple(sorted(qb))
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
        qb = set()
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
                            qb.discard(len(cur))
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
                # Two kinds of word lower() misreads, each noted for the second reading (see
                # evaluate()). One where lower() changes a non-ASCII character (the Kelvin sign folds
                # into k, U+0130 splits in two, U+1C90 becomes a letter Unicode 3.2 had): the second
                # reading lowercases its ASCII only, the Kelvin sign and U+0130 spelled U+0138 (a letter
                # lower() keeps). And one holding an ASCII capital and a backtick or a `$'` string:
                # pwsh's escapes are lowercase only (`U{27} is a U and a { token, `u{27} one escape;
                # `T a T, `t a tab), and a quote a reading removes (gi``"T") or bash's $'...' decode
                # (gi\x60T) can join the capital to a backtick one level down, so the second reading
                # keeps that word's case whole.
                folds = not piece.isascii() and any(ord(c) > 127 and c.lower() != c for c in piece)
                capital = (("`" in piece or "$'" in piece)
                           and _ASCII_CAPITAL_RE.search(piece) is not None)
                if folds or capital:
                    _Command.kelvin_seen = True
                if (folds or capital) and _Command.kelvin_alt:
                    piece = piece.replace(chr(0x212A), chr(0x138)).replace(chr(0x130), chr(0x138))
                    if not capital:
                        piece = "".join(c.lower() if ord(c) < 128 else c for c in piece)
                else:
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
            if qbracket is not None and k in qbracket:
                qb.add(len(cur))
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
# PowerShell reads each of _PS_DASHES as `-` in its own syntax: an operator (`$b -= cmd`
# spelled with U+2013), a unary minus, `--`, a parameter name (`rm`, Remove-Item's alias,
# binds -Recurse -Force from U+2013 r U+2013 fo). A native program gets the character as
# it is: git rejects U+2013 followed by `-force`, and curl.exe reads U+2013 `o` as a URL
# and goes on to fetch the next one. So a PowerShell text is also read with every dash as
# `-`, and with only a dash right before `=` as `-` (the operator read as PowerShell reads
# it, a program's arguments as the program gets them): see _ps_dash_readings.
_PS_AS_DASH = str.maketrans(dict.fromkeys(_PS_DASHES, "-"))
_PS_DASH_ASSIGN_RE = re.compile("[" + _PS_DASHES + "]=")


def _ps_dash_readings(text: str) -> list:
    """The base texts a PowerShell text is read as: the text and the text with each of
    _PS_SPACES a space, each of them as it is, with every one of _PS_DASHES as `-`, and
    with only a dash right before `=` as `-`; the text first, then the spaced text,
    duplicates dropped. Readings only add segments, so the extra ones can only add
    blocks; a text without a dash gets the same texts as before (main's raw and spaced
    readings, one when they are equal).

    A text holding more than one dash right before `=` is refused as uninspectable: the
    text alone cannot tell PowerShell's `-=` from a program's argument (`$b <D>= curl.exe
    <D>=x URL` hands curl.exe `<D>=x`, which it reads as a URL), so no single reading has
    each operator ASCII and each argument as it is. With one, the reading with it ASCII is
    that reading. No command in the recorded corpus holds even one; a string holding two
    (`Write-Output 'a <D>= b <D>= c'`) is refused too, an accepted cost."""
    if len(_PS_DASH_ASSIGN_RE.findall(text)) > 1:
        raise _Uninspectable("more than one PowerShell `-=` spelled with a dash")
    out = []
    for t in (text, text.translate(_PS_AS_SPACE)):
        out += [t, t.translate(_PS_AS_DASH), _PS_DASH_ASSIGN_RE.sub("-=", t)]
    return list(dict.fromkeys(out))


# cmd's own reading of its line: , and = separate words as a space does (so does ;, which
# the bash reading already ends a segment at), and so does every one of _PS_SPACES (cmd
# separates words on all Unicode whitespace, U+180E included; tab, VT, FF, NEL, U+2028
# and U+2029 are bash's or _WORD_BREAKS' already); a ' is an ordinary character (deleted
# here, so the bash tokenizer does not read it as a quote); and a backslash escapes
# nothing (read as /, so `"a\"` closes its string as it does for cmd).
_CMD_DELIMS = str.maketrans({",": " ", "=": " ", "'": None, chr(92): "/",
                             **dict.fromkeys(_PS_SPACES, " ")})
# That reading again with ; a space as well: the segment the bash reading ends at a ; loses
# the words after it, which cmd hands the command (`rd;/s /q x` is rd's /s, see _cmd_delete).
# Added to the reading above, never in its place: that one's segments stay judged.
_CMD_SEMI_AS_SPACE = str.maketrans({";": " "})
# What _Command.backslash_switch reads the payload without: cmd's caret, and the quotes a shell
# or cmd removes before the delete runs.
_CMD_GATE_DROP = str.maketrans(dict.fromkeys("^'`" + chr(34)))
# A `\` and then a `/` in one word, whatever stands between them (`\$null/s`, `\$('')/s`:
# PowerShell expands it to nothing). No match runs past the next `\`, so the scan is linear.
_CMD_GATE_RE = re.compile(re.escape(chr(92)) + "[^ " + "".join(map(chr, range(9, 14)))
                          + re.escape(chr(92)) + "/]*/")
# A bash ANSI-C string ($'...') whose escapes could spell a backslash: `\\`, `\x5c`, `\134`,
# `\u005c`, `\U0000005c`, a control escape. Text escapes (`\n`, `\t`) cannot.
_ANSI_C_RE = re.compile("[$]'(?:[^'" + re.escape(chr(92)) + "]|" + re.escape(chr(92)) + ".)*'")
# Text a shell or cmd may expand to nothing in a cmd argument: a `$` and the rest of its path
# name (PowerShell), an unset `!x!` (cmd's delayed expansion); see _cmd_delete.
_CMD_EXPANDED_TEXT_RE = re.compile("[$][^/]*|![^!/]*!")
# A drive's admin share leading a word, whatever follows the `$` (`c$%HOMEPATH%`).
_CMD_ADMIN_SHARE_RE = re.compile("^//[^/]+/([a-z])[$]")
_ANSI_C_BACKSLASH_RE = re.compile(re.escape(chr(92)) + "(?:" + re.escape(chr(92)) + "|[xuUc0-7])")

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


def _ps_walk_flags(seg):
    """The flags of a segment a statement walk reads that the words do not show (the others,
    ps_tool, ps_script, ps_outer, are the same for every segment of one _segments call)."""
    return (getattr(seg, "piped", False), getattr(seg, "ps_call", False),
            getattr(seg, "ps_foreach", False))


def _ps_strict_prefixes(strict):
    """Every prefix of the strict segments of a logical line that holds no word with a
    record (one that opens with a quote, whose value does, that held a bracket inside
    quotes, or before which an empty word was dropped: the quote-blind words have none of
    that), keyed by (its length, a hash of its words built word by word, the segment's walk
    flags), each with a segment and the length it is a prefix of. Built in one pass over
    the words, so linear (see _ps_strict_prefix)."""
    out = {}
    for seg in strict:
        recorded = (set(getattr(seg, "ps_quoted", ()))
                    | set(getattr(seg, "ps_quoted_value", ()))
                    | set(getattr(seg, "ps_qbracket", None) or ())
                    | set(getattr(seg, "empties", ())))
        flags, h = _ps_walk_flags(seg), 0
        for n, word in enumerate(seg, 1):
            if n - 1 in recorded:
                break
            h = hash((h, word))
            out.setdefault((n, h, flags), (seg, n))
    return out


def _ps_strict_prefix(prefixes, toks):
    """Whether the words of toks begin a strict segment with the same walk flags, read with
    no record (see _ps_strict_prefixes): that segment's walk reads those words as toks's
    would, with their quote record, and is judged; words after them only lengthen what it
    judges. Looked up by length, hash and flags, then compared word for word (one
    comparison per segment)."""
    if not prefixes or not toks:
        return False
    h = 0
    for word in toks:
        h = hash((h, word))
    found = prefixes.get((len(toks), h, _ps_walk_flags(toks)))
    return found is not None and list(found[0][:found[1]]) == list(toks)


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
    # Bash decodes an unquoted heredoc's body (see _heredoc_escapes) before whatever reads it
    # runs it, so the lines judged here would not be the ones it runs: refused, whoever reads
    # the heredoc (a shell, a group, a script file on its fd, a function, data).
    if (shell == "bash" and not (ps_script or ps_tool or cmd_script) and "<" in raw
            and "\\" in raw and _heredoc_escapes(raw)):
        raise _Uninspectable("unquoted heredoc whose body bash decodes (a backslash escape)")
    segments, lenient, lenient_runs, latch = [], [], [], _Latch()
    lenient_fed, orphan = [], False    # see _heredoc_check
    fed_in = heredoc
    slashed = _slashify_windows_paths(raw) if windows_paths else raw
    text = _expand_ifs(slashed)
    # Bash text, read as bash reads it: only where no drive-path rewrite changed it (that
    # text gets its bash reading below, windows_paths False).
    bash_read = (scan and shell == "bash" and not ps_script and not cmd_script
                 and slashed == raw)
    # Bash text (not a script pwsh or cmd reads): its "..." escapes, see below.
    bash_dq_read = shell == "bash" and not (ps_script or ps_tool or cmd_script)
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
        strict = ()
        if words is not None:
            strict = list(_words_to_segments(words, split_words=False, latch=latch))
            segments.extend(strict)
            # Bash's own escapes in "..." (\$ \` and a backslash-newline), which
            # shlex keeps: the line is also read with them decoded, as the program a word
            # is handed gets it (`pwsh -c "echo \$x.y#'..."` runs `echo $x.y#'...`).
            # An added reading: the one above is unchanged.
            if bash_dq_read and "\\" in logical:
                try:
                    decoded = _shell_words(logical, bash_dq=True)
                except ValueError:
                    decoded = None
                if decoded is not None and list(decoded) != list(words):
                    segments.extend(_words_to_segments(decoded, split_words=False))
        # The piecewise pass: for a multi-line logical line, and for any line with a
        # command substitution, whose body (`echo "$(git reset --hard)"`) sits inside
        # a word and gets a fresh quoting context in bash.
        if words is None or len(physical) > 1 or words.subst:
            # Only where the strict pass read this line whole, on one physical line (the
            # piecewise pass is here for a substitution), are these words also in a
            # segment with a record of quoted brackets (see ps_quote_covered on _Seg). A
            # line the strict pass could not tokenize, or one over several physical
            # lines, is read here alone (a quote the strict pass took for a string's may
            # be a comment's, or an escaped one: `"a`" b"`), but for a segment whose
            # words begin a strict segment of the line (`"a` LF `b"; return $x[0]`,
            # `$y = $x[0] -join "` LF `"`): that one holds them, at the same places,
            # with their record (see _ps_strict_prefixes).
            covered = words is not None and len(physical) == 1
            prefixes = _ps_strict_prefixes(strict) if not covered else {}
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
                        toks.ps_quote_covered = covered or _ps_strict_prefix(prefixes, toks)
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
                            inline, runs = _lenient_reads(seg, outer_expanded,
                                                          ps_script or ps_tool)
                            lenient.extend(inline)
                            lenient_runs.extend(runs)
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
        # What its statements run after an `=` (or a dot, or in a hashtable): segments of
        # their own, so the expansion below reaches a runner there.
        segments += _ps_statement_tails(
            segments + [s for s in lenient if isinstance(s, _Seg)], script=True)
    if ps_tool:                   # not _lenient_inline's segments: those are bash text
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
    be fed by (see _expand_scripts). ps_defaults: the payload names
    $PSDefaultParameterValues, which can give Remove-Item -Recurse without the word (set by
    evaluate() while it judges, see _ps_remove_item). backslash_switch: the payload holds a
    `\\` right before a `/` (carets read away), which cmd reads as a path's `\\` and then a
    switch (`rd /q \\/s` is the drive's root and /s); a segment reads it as Git Bash's `//s`
    (see _cmd_delete)."""
    raw = ""
    ps_defaults = False
    backslash_switch = False
    kelvin_seen = False             # a lowercased word lower() misreads (see evaluate(), _words_to_segments)
    kelvin_alt = False              # ...and this reading keeps such words' case (non-ASCII, or all of it)


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

# PowerShell code run from a string (follow-up 8at). Invoke-Expression's names (_cmd_word
# reads its module qualifier away); its common parameters that are switches.
_PS_IEX = frozenset({"iex", "invoke-expression"})
_PS_COMMON_SWITCHES = ("verbose", "debug")
# A parameter's name: the characters after its dash up to the first one no name holds
# (`-c@p` is -c and the splat @p, `-c:x` is -c and x).
_PS_PARAM_NAME_RE = re.compile(r"[\w?]*")
# The members that run a string as code, as words: a gap, comment, quote or type spelling
# around one cannot hide the word. `create` counts in a text that also holds `::` and
# `scriptblock` or `gettype` (`{}.GetType()::Create(...)`), and after a computed receiver's
# `::` (`$t::Create(`, `(...)::Create(`: _ps_computed_receiver), see _ps_code_strings; a
# named type's Create (`[Security.Cryptography.SHA256]::Create()`) stays unread. The
# function: drive (`Set-Item function:f '...'`, `${function:f} = '...'`) turns a string into
# a command, and AddCommand builds one from strings: both refused whenever named.
_PS_CODE_TRIGGER_RE = re.compile(
    r"(?<![\w-])(?:(invokescript|newscriptblock|addscript|expandstring|createpipeline"
    r"|createnestedpipeline|getscriptblock|addcommand|create)(?![\w-])|function:)", re.I)

_PS_SQ_CLASS = "".join(sorted(_PS_SQ))
_PS_DQ_CLASS = "".join(sorted(_PS_DQ))
# One string literal: single-quoted (its quotes doubled inside), or double-quoted with no `$`
# or backtick. Each stops at the next quote, which every call brings, so a run of calls
# scans linearly. Not a here-string: with no terminator in the text, each call's scan
# would run to its end (quadratic); a here-string argument is refused (an accepted cost).
_PS_CODE_LIT = (
    "(?:[{s}](?:[^{s}]|[{s}][{s}])*[{s}]"
    "|[{d}](?:[^{d}$`]|[{d}][{d}])*[{d}])"
).format(s=_PS_SQ_CLASS, d=_PS_DQ_CLASS)
# A bare argument: no quote, `$`, `@`, bracket, brace, paren, comma or backtick, so nothing
# PowerShell computes (numbers, operators and words; a word there does not parse at the top
# level). It is what a reading that lost a literal's quotes leaves (`pwsh -c '...''x''...'`
# read with bash's quoting): read as the literal it was.
_PS_CODE_BARE_CHARS = r"$@()\[\]{}`," + _PS_SQ_CLASS + _PS_DQ_CLASS
_PS_CODE_BARE = r"[^{x}\s](?:[^{x}\s]|[ \t]+(?=[^{x}\s]))*".format(
    x=_PS_CODE_BARE_CHARS)
# The canonical calls whose literal is read: [scriptblock]::Create('...') (the type with or
# without its namespace) and .InvokeScript / .NewScriptBlock / .AddScript('...'[, ...]).
_PS_CODE_CALL_RE = re.compile(
    r"(?:\[[ \t]*(?:system\.)?(?:management\.automation\.)?scriptblock[ \t]*\]::[ \t]*create"
    r"|\.[ \t]*(?:invokescript|newscriptblock|addscript))"
    r"(?:\([ \t]*(" + _PS_CODE_LIT + "|" + _PS_CODE_BARE + r")[ \t]*[,)]"
    # The grouping reading (_ps_ungroup) reads a one-word argument's parens away: `Create
    # 'x' `. Without them the call does not parse at the top level, so this form only ever
    # stands for a canonical call.
    r"|[ \t]+(" + _PS_CODE_LIT + r"|[^{x}\s]+))".format(x=_PS_CODE_BARE_CHARS),
    re.I | re.S)
_PS_SQ_PAIR_RE = re.compile("[{s}][{s}]".format(s=_PS_SQ_CLASS))
_PS_DQ_PAIR_RE = re.compile("[{d}][{d}]".format(d=_PS_DQ_CLASS))


def _ps_computed_receiver(form: str, start: int) -> bool:
    """Whether the `create` at form[start] follows `::` on any receiver but a named type
    literal: `$t::Create(`, `$o.T::Create(`, `$o['T']::Create(`, `({ })::Create(`, `{ }::Create(`,
    across any whitespace and a quote before the name (a comment between them is gone in the
    comment-stripped forms _ps_code_strings also counts). A named type is a `[` ... `]` (the
    `]`'s own `[`, nested brackets of a generic type included: `[Tuple[int, string]]`) holding
    only name characters, that no word, `$`, closing bracket or quote stands before (that would
    make it an index: `$o[0]`). Each walk back stops at the name's own gap and reads at most 200
    characters before it, so a run of them stays linear."""
    k = start
    while k > 0 and (form[k - 1].isspace() or form[k - 1] in _PS_SQ or form[k - 1] in _PS_DQ):
        k -= 1
    if form[k - 2:k] != "::":
        return False
    k -= 2
    while k > 0 and form[k - 1].isspace():
        k -= 1
    if k == 0 or form[k - 1] != "]":
        return True
    j, depth, stop = k - 1, 0, max(0, k - 200)
    while j >= stop:
        c = form[j]
        if c == "]":
            depth += 1
        elif c == "[":
            depth -= 1
            if not depth:
                break
        elif not (c.isalnum() or c in "._, `" or c == chr(9)):
            return True
        j -= 1
    if j < stop:
        return True
    before = form[j - 1] if j > 0 else " "
    return before.isalnum() or before in "_$)]}" or before in _PS_SQ or before in _PS_DQ


# An Invoke-Expression word in a text (backticks removed): see _ps_iex_operand.
_PS_IEX_WORD_RE = re.compile(r"(?<![\w$.-])(?:iex|invoke-expression)(?![\w-])", re.I)
# A quote directly followed by a member, index or static-member operator: a literal used as an
# expression's operand (`'x'.Replace('a','b')`, `'x'[0]`, `'x'::Join`; pwsh 7's null-conditional
# `?.` and `?[`), or an opening quote so followed (`'.git'`, a false positive this accepts).
# After `.` or `::` anything but a space, a tab, a path's `\` or `/` or another `.` counts: a
# name, a quoted or dynamic name (`.$m(`), a block (`.{Replace}(`), and the line break a
# continuation or a line comment leaves (`.`LF`Replace(`, `.#c`LF`Replace(`); `'.\x'`,
# `'./x'` and `'..\x'` (paths) stay out.
_PS_QUOTE_MEMBER_RE = re.compile(
    "[" + "".join(sorted(_PS_SQ | _PS_DQ)) + r"]\??(?:(?:\.|::)[^ \t\\/.]|\[)")
# Cmdlets that write a drive's items: with them, a bare `function:` (the drive's root, its
# item named by -Name) is a write to the function drive.
_PS_ITEM_WRITER_RE = re.compile(
    r"(?<![\w-])(?:new-item|ni|set-item|si|set-content|sc|add-content|ac|copy-item|cpi|copy|cp"
    r"|move-item|mi|move|mv|rename-item|rni|ren)(?![\w-])", re.I)


def _ps_iex_operand(forms) -> bool:
    """Whether a text (its forms: as written, escape-decoded, comments deleted; backticks
    removed here) names Invoke-Expression and holds a quote directly followed by `.`, `[` or
    `::`: iex's Command may be a literal used as an expression's operand (`iex
    'x'.Replace(...)` runs the method's result, not the literal; a block comment between them
    changes nothing, so its deleted form is tested too). Any such quote in the text counts,
    since where a literal ends is not tracked: a false positive this accepts. Also true for
    any `u{} escape in such a text (see below). forms[0] is the text as written."""
    raw = forms[0]
    forms = [f.replace("`", "") for f in forms]
    if not any(_PS_IEX_WORD_RE.search(f) for f in forms):
        return False
    # A `u{...} escape (a name spelled by code point): the brace reading that exposes a
    # script block argument's statements (`1 | % { iex '& "i`u{65}x" ...' }`) splits its
    # braces, so where iex is named such a text is refused rather than misread.
    return "`u{" in raw or any(_PS_QUOTE_MEMBER_RE.search(f) for f in forms)


def _ps_strip_block_comments(text: str, repl: str = " ") -> str:
    """text with each `<#` ... `#>` block comment read as a space (an unclosed one to the end).
    A linear scan, not a lazy regex (a run of unclosed `<#` would make that quadratic). An
    added form only: a `<#` inside a string loses text, which only lowers this form's count."""
    out, i = [], 0
    while True:
        a = text.find("<#", i)
        if a < 0:
            out.append(text[i:])
            return "".join(out)
        out.append(text[i:a])
        b = text.find("#>", a + 2)
        if b < 0:
            return "".join(out)
        out.append(repl)
        i = b + 2


# A line comment right after a member operator (`{ }::#c` LF `Create(`, `.#c` LF `Run(`): pwsh
# 7.6 and 5.1 read the name on the next line. _PS_COMMENT_RE takes a `#` only after a space
# or an operator such as `;`, so this form reads these away too. Linear.
_PS_MEMBER_COMMENT_RE = re.compile(r"((?:::|\.)[ \t]*)#[^\r\n]*")


def _ps_code_body(lit: str) -> str:
    """The value of a _PS_CODE_LIT literal: the string's text with its doubled quotes read
    as one; a bare argument as it is."""
    if lit[0] in _PS_SQ:
        return _PS_SQ_PAIR_RE.sub("'", lit[1:-1])
    if lit[0] in _PS_DQ:
        return _PS_DQ_PAIR_RE.sub('"', lit[1:-1])
    return lit                                       # a bare argument (_PS_CODE_BARE)


@functools.lru_cache(maxsize=4096)
def _ps_code_strings(text: str) -> tuple:
    """The code PowerShell text runs from string literals: the value of each canonical call's
    literal (_PS_CODE_CALL_RE). Raises _Uninspectable when the text names more code-from-string
    members (_PS_CODE_TRIGGER_RE; in the text with backticks removed, and in its escape-decoded
    readings, which spell out a quoted member name's escapes, and with its comments read
    away) than it has canonical calls:
    a computed argument, a gap, comment or unusual spelling in a call, ExpandString or a
    pipeline or ParseInput route, the function: drive, or a trigger word in a string or
    comment (a false positive this accepts). Memoized; evaluate() clears it."""
    forms = [text]
    if "`" in text:
        forms.append(_ps_unescape_everywhere(text))
        if "`e" in text or "`u" in text:
            forms.append(_ps_unescape_everywhere(text, legacy=True))
    # Comments read away, so a computed receiver's Create is seen across one (`{ }::<#c#>Create(`,
    # `$t::#c` LF `Create(`): counted forms only, never the ones calls are covered in.
    # Both the block-stripped forms and those with line comments also gone: a `#` inside a
    # string reads as a comment's start and would hide the rest of its line.
    if "#" in text:
        blocks = list(dict.fromkeys(_ps_strip_block_comments(f) for f in forms))
        forms += blocks + [_PS_COMMENT_RE.sub("", _PS_MEMBER_COMMENT_RE.sub(r"\1", f))
                           for f in blocks]
    if _ps_iex_operand(forms + ([_ps_strip_block_comments(f, "") for f in forms]
                                if "<#" in text else [])):
        raise _Uninspectable("PowerShell code from a computed string")
    triggers = 0
    for form in forms:
        form = form.replace("`", "")
        low = form.lower()
        creates = ("scriptblock" in low or "gettype" in low) and "::" in form
        writes = bool(_PS_ITEM_WRITER_RE.search(form))
        n = sum(1 for m in _PS_CODE_TRIGGER_RE.finditer(form)
                if _ps_trigger_counts(m, form, creates, writes))
        triggers = max(triggers, n)
    if not triggers:
        return ()
    calls = {m.start(): _ps_code_body(m.group(1) or m.group(2))
             for m in _PS_CODE_CALL_RE.finditer(text)}
    if triggers > len(calls):
        raise _Uninspectable("PowerShell code from a computed string")
    return tuple(calls.values())


def _ps_trigger_counts(m, form: str, creates: bool, writes: bool) -> bool:
    """Whether a _PS_CODE_TRIGGER_RE match in form counts: a member name always; `create` in a
    text naming scriptblock or gettype with a `::`, or after a receiver no named type is
    (_ps_computed_receiver); `function:` naming an item (`function:f`), or the drive's root
    when the text holds a cmdlet that writes items (`New-Item -Path function: -Name f`), not
    a bare `function:` in prose (`extract helper function: parse`)."""
    name = m.group(1)
    if name is None:
        nxt = form[m.end():m.end() + 1]
        return writes or not (nxt == "" or nxt.isspace() or nxt in "|;)")
    if name.lower() == "create":
        return creates or _ps_computed_receiver(form, m.start())
    return True


def _ps_rhs_records(src, rhs):
    """Give rhs, a suffix of src's words that _rules_at builds (an assignment's right-hand
    side), src's quote records for its words: expanding, ps_qbracket and ps_quote_covered,
    which the Invoke-Expression rule reads (_ps_iex_command). Without them rhs would read as
    quote-blind, and an expanded word as a literal."""
    rhs.expanding = _suffix_expanding(src, rhs)
    rhs.ps_qbracket = _suffix_qbracket(src, rhs)
    rhs.ps_quote_covered = getattr(src, "ps_quote_covered", False)


def _ps_is_iex(base: str) -> bool:
    """Whether a command word's basename (_cmd_word) is Invoke-Expression: `iex`, or a name
    ending in `invoke-expression` (the quote-blind pass resolves the module qualifier's
    backslash away: `microsoft.powershell.utilityinvoke-expression`)."""
    base = base.lower()
    return base in _PS_IEX or base.endswith("invoke-expression")


def _ps_is_parameter(word: str) -> bool:
    """A PowerShell parameter word: a dash (`-` or one of _PS_DASHES) and a name."""
    return len(word) > 1 and word[0] in "-" + _PS_DASHES


def _ps_iex_command(toks, i):
    """(state, readings, outer) for Invoke-Expression at toks[i]: its Command bound as
    PowerShell binds it (measured, pwsh 7.6 and 5.1): -Command by any prefix (`-c`), with a
    glued value (`-c:x`, `-c@p`: a name ends at its first character no name holds) or the next
    word (`-c x`, `-c: x`); a bare `-Name:` takes the next word for any parameter, switches
    included (`-Verbose: 1`); a switch common parameter with no colon (-Verbose, -Debug, by
    prefix) takes none; any other parameter takes the next word; `--` ends the parameters;
    else the first other word. state: "none" (no Command; a `--%` too), "computed" (the word
    holds a `$` the shell expands, starts with `@`, a splat or a group, or holds a `,`, an
    array that $OFS joins), or "literal". readings: the word lists to read as the script
    ([[the text]] when strict).

    A quote-blind segment (no ps_qbracket record), whose words have lost their quotes so
    neither the parameters nor the Command can be told apart, nor a group the segment ended
    at (`iex -ea 0 (Get-Content f)`): "covered" when the strict pass read the same line
    (ps_quote_covered: that segment decides); "none" when piped; else "blind", refused like
    a computed one (8ai: quote-blind coverage fails closed), with its readings: each suffix
    of the words after the head (to a `#` that starts a comment, a glued value split off,
    typographic quotes trimmed) that starts at a word no dash starts (the _lenient_inline
    approach), read as scripts so their own reasons are reported too."""
    words = list(toks[i + 1:])
    if getattr(toks, "ps_qbracket", None) is None:
        if getattr(toks, "ps_quote_covered", False):
            return "covered", [], False
        if getattr(toks, "piped", False):
            return "none", [], False
        cut = next((k for k, w in enumerate(words) if w.startswith("#")), len(words))
        split = []
        for w in words[:cut]:
            name = _PS_PARAM_NAME_RE.match(w, 1).group(0) if _ps_is_parameter(w) else None
            if name and len(w) > 1 + len(name):
                split += [w[:1 + len(name)], w[1 + len(name):].lstrip(":")]
            else:
                split.append(w)
        words = [w.strip("".join(_PS_TYPOGRAPHIC_QUOTES)) for w in split]
        words = [w for w in words if w]
        readings = [words[k:] for k in range(len(words)) if not _ps_is_parameter(words[k])]
        return "blind", readings, any("$" in w for w in words)
    expanding = getattr(toks, "expanding", frozenset())
    j, n = 0, len(words)
    while j < n:
        w = words[j]
        if w == "--":
            j += 1
            break
        if w == "--%" or not _ps_is_parameter(w):
            break
        name = _PS_PARAM_NAME_RE.match(w, 1).group(0)
        rest = w[1 + len(name):]
        colon, value = rest.startswith(":"), rest[1:] if rest.startswith(":") else rest
        name = name.lower()
        if name and "command".startswith(name):
            if value:
                return _ps_iex_word(value, i + 1 + j in expanding, words[j + 1:])
            j += 1
            break
        if colon and not value:
            j += 2
        elif value or (name and any(s.startswith(name) for s in _PS_COMMON_SWITCHES)
                       or name in ("vb", "db")):
            j += 1
        else:
            j += 2
    if j >= n or words[j] == "--%":
        return "none", [], False
    return _ps_iex_word(words[j], i + 1 + j in expanding, words[j + 1:])


def _ps_iex_word(word: str, expands: bool, after=()):
    """_ps_iex_command's state for the Command word. A literal's reading is the word alone
    when only parameters follow it (up to a comment); with a positional word among them,
    PowerShell refuses the command (nothing runs), and the words are the literal's own only
    in a reading whose quotes an outer reading lost (`iex -vb: 0 git push --force`): the
    word joined with them."""
    if expands or word.startswith("@") or "," in word:
        return "computed", [[word]], True
    after = list(after)
    after = after[:next((k for k, w in enumerate(after) if w.startswith("#")), len(after))]
    return "literal", [[word] + after] if _ps_positional_after(after) else [[word]], False


def _ps_positional_after(after) -> bool:
    """Whether Invoke-Expression's words after its Command hold a positional word, walking
    its parameters as _ps_iex_command does."""
    j, n = 0, len(after)
    while j < n:
        w = after[j]
        if not _ps_is_parameter(w) or w == "--%":
            return True
        if w == "--":
            return j + 1 < n
        name = _PS_PARAM_NAME_RE.match(w, 1).group(0)
        rest = w[1 + len(name):]
        colon, value = rest.startswith(":"), rest[1:] if rest.startswith(":") else rest
        name = name.lower()
        if colon and not value:
            j += 2
        elif value or (name and any(s.startswith(name) for s in _PS_COMMON_SWITCHES)
                       or name in ("vb", "db")):
            j += 1
        else:
            j += 2
    return False
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


# Follow-up 8bk: one PowerShell lexer (_ps_lex) and the text it normalizes to
# (_ps_normalize), read as an added reading of every PowerShell payload and script. The older
# scanners (_ps_unescape, _ps_code_braces, _ps_subexpressions) each decide by their own rule
# where a comment, a block comment or a here-string opens, and a text that one of them reads
# differently from pwsh shifts every quote after it. pwsh opens one only where a new token
# starts, which depends on the token before it and on the mode: a bareword runs on through
# `@'`, `<#` and `#` (`a=@'` is one word, `x<#` too), while after a blank, `;,|&(){}`, a whole
# string, a `-name:` parameter, a member access, a number (comments only) or an operator in
# an expression a new token starts (`$h=@'`, `(1)#c`, `-p:<#c#>`, `1#c`). A command name's
# $( ) is literal text to its matching parenthesis; a backtick-newline inside a word is an
# escaped newline, not a line continuation; an argument that is exactly --% makes the rest of
# its line verbatim (to a | or && outside a "..." span). Measured against pwsh 7's tokenizer
# over the recorded commands and generated texts (guard-lab examples/8bk, lexdiff.py).

_PS_LEX_WS = frozenset(" \t\x0b\x0c\x85\u2028\u2029" + _PS_SPACES)
_PS_LEX_QUOTES = frozenset(_PS_SQ | _PS_DQ)
_PS_LEX_DASH = frozenset("-" + _PS_DASHES)
_PS_LEX_EOL_RE = re.compile("[\r\n]")
_PS_LEX_KEY_RE = re.compile(r"\w+")                # a hashtable's bare key: letters, digits, _
_PS_LEX_DIGITS = frozenset("0123456789")   # only ASCII digits start a number (`<U+0663>`: a word character)
_PS_LEX_MVS = chr(0x180E)          # U+180E: a space to the older .NET, a word character to pwsh 7
_PS_LEX_MVS_INERT = chr(0x200B)    # what U+180E as a word character is lexed as (see _ps_normalize)
# a here-string opener's rest: any blank pwsh accepts there (NBSP, NEL, VT, ... measured), then a line break
_PS_LEX_BLANK_EOL_RE = re.compile("[" + re.escape("".join(sorted(_PS_LEX_WS))) + "]*(?:\r\n|\n|\r)")
# a bare word glued to a comment opener at a statement start (the start, after `{`, `(`, `;` or a
# line break, blanks between): in an identifier position the lexer does not model it ends before the
# opener (see _ps_lex_copies)
_PS_LEX_IDENT_RE = re.compile(r"(?:^|(?<=[{(;\r\n]))[^\S\r\n]*\w+(?=<#|#)")
# a DSC configuration's keyword (refused in code wherever a name can follow it: its body's shape depends on the
# resources loaded when pwsh parses it; any position, an over-approximation: a position test missed blanks the
# lexer knows)
_PS_LEX_DSC_WORD_RE = re.compile(r"(?<![\w$.\-:\\/@`])" + "`?".join("configuration")
                              + r"(?![\w\-.:\\/=`])", re.I | re.A)
_PS_LEX_WORD_CH_RE = re.compile(r"\w")
_PS_LEX_NARROW = chr(0xA7)         # a non-name, non-blank character: a non-ASCII word character, narrowly

_PS_LEX_MAX_DEPTH = 32
_PS_LEX_MAX_OUT = 2 * _MAX_INSPECT_LEN      # the normalized text's length cap (2 x the inspected input)
_PS_LEX_MAX_READ = 3 * _PS_LEX_MAX_OUT   # the normalized texts' total length when copies add readings (24 K)
# over one evaluate() when "on" (the matcher sets it; used counts every call's texts), else per call
_PS_LEX_READ = {"used": 0, "on": False}
_PS_LEX_KEYWORDS = frozenset((
    "if elseif else while for foreach switch do until try catch finally trap function filter "
    "workflow param begin process end clean dynamicparam return throw exit break continue data "
    "class enum using configuration hidden static").split())
_PS_LEX_KEYWORDS_51 = _PS_LEX_KEYWORDS - {"clean"}     # `clean` is a keyword to pwsh 7.3+ only
_PS_LEX_UNARY = frozenset("not bnot split join isplit csplit".split())
_PS_LEX_VAR_RE = re.compile(r"\$(?:::?(?:[\w?]|:(?!:))*|\w(?:[\w?]|:(?!:))*|[?^$])")   # `$x::y`: x; `$::x`: ::x; `$x?.y`: x?
_PS_LEX_NUM_RE = re.compile(r"(?:0x[0-9a-f]*|0b[01]+|(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:e[+-]?[0-9]+)?)"
                         r"(?:ul|us|uy|un|[dlnusy])?(?:kb|mb|gb|tb|pb)?", re.I | re.A)   # ASCII only
_PS_LEX_NUM_END = frozenset(";|&,(){}]#<>=+-*/%!.\r\n" + _PS_DASHES) | _PS_LEX_WS
_PS_LEX_WORD_RE = re.compile(r"[\w\-.\\/:~" + _PS_DASHES + r"]*")
_PS_LEX_PARAM_RE = re.compile(r"[-" + _PS_DASHES + r"][\w?]*:?")
_PS_LEX_REDIR_RE = re.compile(r"[0-9*]?>>?(?:&[12])?")
_PS_LEX_MEMBER_RE_51 = re.compile(r"(?:\.|::)\w+")
_PS_LEX_MEMBER_RE = re.compile(r"(?:\?\.|\.|::)\w+")   # pwsh 7.1+: `?.y` too


def _ps_lex_escape_end(t, i):
    """Index after the backtick escape at t[i] (a backtick)."""
    if i + 1 < len(t) and t[i + 1] == "u":
        m = _PS_UNICODE_RE.match(t, i + 1)
        if m:
            return m.end()
    return min(len(t), i + 2)


# Windows PowerShell 5.1's number literals (measured, logs/lexdiff51_*_num.log): no 0b, no n / u / ul /
# y / uy / s / us suffix, and 0x needs a digit; such a word is a bareword there (`1n<#`: no comment).
_PS_LEX_NUM_RE_51 = re.compile(r"(?:0x[0-9a-f]+|(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:e[+-]?[0-9]+)?)"
                            r"(?:[dl])?(?:kb|mb|gb|tb|pb)?", re.I | re.A)
# Syntax only pwsh 7 has (see _ps_normalized_texts): a `u{...} escape (5.1 reads `u as u and starts a
# script block at the {), the keyword clean, or a number pwsh 7 reads that 5.1 reads to another end.
_PS_LEX_V7_WORDS = re.compile(r"`u\{|clean|\?\.|\?\[", re.I | re.A)


def _ps_lex_v7_syntax(text):
    """Whether the text may read differently to Windows PowerShell 5.1 (a superset: every
    number-like run is compared, at a token start or not)."""
    if _PS_LEX_V7_WORDS.search(text):
        return True
    for m in _PS_LEX_NUM_RE.finditer(text):
        m51 = _PS_LEX_NUM_RE_51.match(text, m.start())
        if m51 is None or m51.end() != m.end():
            return True
    return False


def _ps_lex_number_end(t, i, n, v51=False):
    """End of the number literal at t[i], or -1 when pwsh reads the text there as a bareword
    (a number runs into anything but a terminator: `1a`, `1$x`, `1'x'`, `` 1`a ``). v51:
    Windows PowerShell 5.1's literals."""
    m = (_PS_LEX_NUM_RE_51 if v51 else _PS_LEX_NUM_RE).match(t, i, n)
    if m and (m.end() >= n or t[m.end()] in _PS_LEX_NUM_END):
        return m.end()
    return -1


def _ps_lex_param_end(t, i, n):
    """(end, colon) of the parameter token at t[i] (a dash): it runs like a bareword to a
    blank, line break, ;,|&(){}, a `.` or `[` or quote (`-p.x#y`: a parameter, then the
    bareword `.x#y`), and a `:` ends it (`-a=<#c#>` is one token, `-p:`
    ends one). A backtick escapes one character (`-p`u{74}`: `{` starts a new token); before a
    blank, a line break, a quote or ;,|&(){} it ends the parameter after the backtick (`-p`` #c`:
    a comment; `-p`'x'`: a string; `-p`(1)`: a group): (end, colon, True) then."""
    j = i + 1
    while j < n:
        d = t[j]
        if d in _PS_LEX_WS or d in "\r\n;,|&(){}.[" or d in _PS_LEX_QUOTES:
            return j, False, False
        if d == ":":
            return j + 1, True, False
        if d == "`":
            if j + 1 < n and (t[j + 1] in "\r\n;,|&(){}.[" or t[j + 1] in _PS_LEX_WS
                                  or t[j + 1] in _PS_LEX_QUOTES):
                return j + 1, False, True
            j += 2
            continue
        j += 1
    return n, False, False


def _ps_lex_here_end(t, j, closers, n):
    """(body end, string end) of a here-string whose body starts at j: the first line
    starting with one of closers followed by @; (-1, -1) if none before n."""
    while j < n:
        if t[j] in closers and t.startswith("@", j + 1) and j + 2 <= n:
            body_end = j - 1 if j > 0 and t[j - 1] in "\r\n" else j   # a lone CR ends a line too
            if t[j - 1:j] == "\n" and body_end > 0 and t[body_end - 1] == "\r":
                body_end -= 1
            return body_end, j + 2
        m = _PS_LEX_EOL_RE.search(t, j, n)
        k = m.start() if m else -1
        if k < 0:
            break
        j = k + 1
    return -1, -1


def _ps_lex_here_dq(t, i, n, depth, v51=False):
    """(children, body end, string end) of an @"..."@ body from i, or None if unterminated:
    a line starting with a double-quote character and @ ends it, but only outside the body's
    $( ) bodies, which pwsh reads first (a '...' string in one can hold such a line)."""
    children, seg, j, line = [], i, i, True
    while j < n:
        if line and t[j] in _PS_DQ and t.startswith("@", j + 1):
            body_end = j - 1 if j > 0 and t[j - 1] in "\r\n" else j   # a lone CR ends a line too
            if t[j - 1:j] == "\n" and body_end > 0 and t[body_end - 1] == "\r":
                body_end -= 1
            if seg < body_end:
                children.append(("text", seg, body_end))
            return children, body_end, j + 2
        d = t[j]
        if d == "`":
            # an escaped line break: the next line does not start a line (no terminator there)
            j = min(n, j + 3 if t.startswith("\r\n", j + 1) else _ps_lex_escape_end(t, j))
            line = False
            continue
        line = d in "\r\n"
        if d == "$" and t[j + 1:j + 2] in ("$", "?", "^"):
            j += 2
            continue
        if d == "$" and t.startswith("{", j + 1):
            k = _ps_lex_braced_end(t, j, n)
            if seg < j:
                children.append(("text", seg, j))
            children.append(("var", j, k))
            j = seg = k
            continue
        if d == "$" and t.startswith("(", j + 1):
            if seg < j:
                children.append(("text", seg, j))
            nodes, k = _ps_lex_code(t, j + 2, ")", depth + 1, n, v51)
            close = k + 1 if k < n else n
            children.append(("sub", j, close, nodes))
            j = seg = close
            line = False
            continue
        j += 1
    return None


def _ps_lex_braced_end(t, j, n):
    """Index after the ${...} variable at t[j] (a backtick escapes the next character)."""
    k = j + 2
    while k < n and t[k] != "}":
        k += 2 if t[k] == "`" else 1
    return min(n, k + 1)


def _ps_lex_dq_parts(t, i, bound, string, depth, literal=False, v51=False):
    """Children of a "..." string's content from i (string=True: a lone quote ends it) or of a
    @"..."@ body (to bound): ("text", a, b) and ("sub", a, b, nodes). Returns (children, index
    of the closing quote, or bound)."""
    children, seg, j = [], i, i
    while j < bound:
        d = t[j]
        if d == "`":
            j = min(bound, _ps_lex_escape_end(t, j))
            continue
        if string and d in _PS_DQ:
            if j + 1 < bound and t[j + 1] in _PS_DQ:
                j += 2
                continue
            break
        if d == "$" and t[j + 1:j + 2] in ("$", "?", "^"):
            j += 2                                # $$ $? $^: a variable, then text
            continue
        if d == "$" and t.startswith("{", j + 1):
            # ${...} is one variable: a quote in its name does not end the string
            k = _ps_lex_braced_end(t, j, bound)
            if seg < j:
                children.append(("text", seg, j))
            children.append(("var", j, k))
            j = seg = k
            continue
        if d == "$" and t.startswith("(", j + 1) and literal:
            k, depth_p = j + 2, 1               # in a command name: literal to its matching paren
            while k < bound and depth_p:
                depth_p += {"(": 1, ")": -1}.get(t[k], 0)
                k += 1
            j = k
            continue
        if d == "$" and t.startswith("(", j + 1):
            if seg < j:
                children.append(("text", seg, j))
            nodes, k = _ps_lex_code(t, j + 2, ")", depth + 1, bound, v51)
            close = k + 1 if k < bound else bound
            children.append(("sub", j, close, nodes))
            j = seg = close
            continue
        j += 1
    if seg < j:
        children.append(("text", seg, j))
    return children, j


def _ps_lex_code(t, i, closer, depth, n=None, v51=False):
    """Nodes of PowerShell code from i up to an unmatched closer (")" for a $( ) body, None at
    the top) or n. Returns (nodes, index of the closer or n)."""
    if depth > _PS_LEX_MAX_DEPTH:
        raise _Uninspectable(f"PowerShell text nested too deep to read (> {_PS_LEX_MAX_DEPTH} levels)")
    n = len(t) if n is None else n
    nodes = []
    code = [i]                      # start of the pending code span

    def put(kind, a, b, *extra):
        if code[0] < a:
            nodes.append(("code", code[0], a))
        nodes.append((kind, a, b) + extra)
        code[0] = b

    stack = []                      # open groups: [closer, mode to restore, boundary after, hashtable]
    mode = None                     # None statement start, "cmd" in a command, "expr"
    bnd = True                      # an opener here starts a new token
    num = False                     # just after a number (no here-string)
    name = False                    # inside a command name's bareword (its $( ) is literal)
    pcolon = False                  # just after a `-name:` parameter
    rtarget = False                 # just after a redirection: its target comes next
    inv = False                     # just after a first `&` or `.`: no command element yet
    post = False                    # an argument's group or variable just ended: `.` is member access
    post_nocc = False               # ...a braced variable: `.` only, not `::` (`${x}::y` is one word)
    comma = False                   # just after a `,`: a --% next is an array element, a word
    ident_next = False              # just after `class` / `enum` / `data`: its name is an identifier
    body = None                     # (stack depth, flag) for the next `{`: a class's / an enum's body ("i")
    type_lb = -1                    # the last `[` read as an index / a type literal / an attribute
    attr_end = False                # just after an attribute's `)`
    pipe_at, pipe_next = -1, False  # look-ahead cache: does the line after a break start with `|`?
    while i < n:
        c = t[i]
        if bnd:
            name = False
        pc, pcolon = pcolon, False
        rt, rtarget = rtarget, False
        iv, inv = inv, False
        po, post = post, False
        pnocc, post_nocc = post_nocc, False
        cm, comma = comma, False
        ae, attr_end = attr_end, False
        if stack and stack[-1][3] == "v=" and not (
                c in _PS_LEX_WS or c in "\r\n|&," or (c == "`" and (t[i + 1:i + 2] in ("\r", "\n")
                                                     or t[i + 1:i + 2] in _PS_LEX_WS))
                or (bnd and (c == "#" or t.startswith("<#", i)))):
            stack[-1][3] = "v"                                   # the value's first token
        # (not after a comma, blanks, comments or a line break between: `echo a, --% ;x` runs x)
        if not cm and ((mode == "cmd" and bnd and not pc and not rt and (
                c == "-" or (c == "`" and t.startswith("-", i + 1)))) or (
                mode is None and bnd and c == "`" and t.startswith("-", i + 1))):
            # the stop-parsing token: an argument that is exactly --% (escapes read away)
            j, val = i, []
            while j < n and t[j] not in _PS_LEX_WS and t[j] not in "\r\n;,|&(){}":
                if t[j] == "`" and j + 1 < n:
                    j += 1
                val.append(t[j])
                j += 1
                if len(val) > 3 or "--%"[len(val) - 1] != val[-1]:
                    break                        # no --%: stop (a glued `-a.''-a.''...` stays linear)
            if "".join(val) == "--%" and (j >= n or t[j] in _PS_LEX_WS or t[j] in "\r\n;,|&(){}"):
                k, quoted = j, False             # | and && end it outside a "..." span
                while k < n and t[k] not in "\r\n" and (quoted or (
                        t[k] != "|" and not t.startswith("&&", k))):
                    quoted ^= t[k] in _PS_DQ
                    k += 1
                put("verb", j, k)
                i = k
                continue
        if c in _PS_LEX_WS:
            i, bnd, num, pcolon, rtarget, inv = i + 1, True, False, pc, rt, iv   # `-p: --%`: the value
            comma = cm
            continue
        if c in "\r\n":
            i, bnd, num, mode, comma = i + 1, True, False, None, cm   # `a,<LF>`: the array goes on
            if stack and stack[-1][3] == "v" and not v51:
                if i > pipe_at:                                  # pwsh 7: `a=x<LF>| y` goes on
                    pipe_at = i
                    while pipe_at < n:                   # blanks, comments, line continuations
                        ch = t[pipe_at]
                        if ch in _PS_LEX_WS or ch in "\r\n":
                            pipe_at += 1
                        elif t.startswith("<#", pipe_at):
                            k = t.find("#>", pipe_at + 2, n)
                            pipe_at = n if k < 0 else k + 2
                        elif ch == "#":
                            m = _PS_LEX_EOL_RE.search(t, pipe_at, n)
                            pipe_at = m.start() if m else n
                        elif ch == "`" and t[pipe_at + 1:pipe_at + 2] in ("\r", "\n"):
                            pipe_at += 2
                        else:
                            break
                    pipe_next = t.startswith(("|", "&&"), pipe_at)   # `|`, `||`, `&&` first
                if pipe_next:
                    continue
            if stack and stack[-1][3] in (True, "v"):
                stack[-1][3] = True                              # a hashtable's next key (`a=<LF>b`: the value)
            continue
        if c == "`":
            if bnd and i + 1 < n and t[i + 1] in "\r\n":
                i += 3 if t.startswith("\r\n", i + 1) else 2
                pcolon, rtarget, inv, comma = pc, rt, iv, cm
                continue                   # a line continuation (mid-word: an escaped newline)
            if bnd and i + 1 < n and t[i + 1] in _PS_LEX_WS:
                i += 2                     # an escaped blank at a token start: a blank
                pcolon, rtarget, inv, comma = pc, rt, iv, cm
                continue
            # 5.1 has no `u{...} escape: `u is a u, and the { after it starts a script block
            i = min(n, i + 2 if v51 else _ps_lex_escape_end(t, i))
            if mode is None:
                mode, name = "cmd", True
            bnd = num = False
            continue
        if bnd and c == "#":
            j = i
            while j < n and t[j] not in "\r\n":
                j += 1
            put("lc", i, j)
            i, comma = j, cm               # a comment is a blank to what precedes it:
            pcolon, rtarget, inv = pc, rt, iv
            continue
        if bnd and t.startswith("<#", i):
            j = t.find("#>", i + 2, n)
            if j < 0:
                put("open", i, n)
                i = n
                continue
            put("bc", i, j + 2)
            i, comma = j + 2, cm           # `echo x > <#c#> --%`: the file name; `& <#c#> > --%`: no file
            pcolon, rtarget, inv = pc, rt, iv
            continue
        if c == "@" and bnd and not num and i + 1 < n and t[i + 1] in _PS_LEX_QUOTES:
            m = _PS_LEX_BLANK_EOL_RE.match(t, i + 2, n)
            if m:
                body_a = m.end()
                if t[i + 1] in _PS_SQ:
                    body_b, end = _ps_lex_here_end(t, body_a, _PS_SQ, n)
                    here = None if end < 0 else ("hsq", i, end, body_a, body_b)
                else:
                    r = _ps_lex_here_dq(t, body_a, n, depth, v51)
                    here = None if r is None else ("hdq", i, r[2], body_a, r[1], r[0])
                if here is None:
                    put("open", i, n)
                    i = n
                    continue
                put(*here)
                end = here[2]
                i, bnd, num = end, True, False
                if mode is None:
                    mode = "expr"
                post = mode == "cmd"
                continue
        if c in _PS_SQ:
            j = i + 1
            while j < n:
                if t[j] in _PS_SQ:
                    if j + 1 < n and t[j + 1] in _PS_SQ:
                        j += 2
                        continue
                    break
                j += 1
            if j >= n:
                put("open", i, n)
                i = n
                continue
            put("sq", i, j + 1)
            if mode is None:
                mode = "expr"
            i, num = j + 1, False          # bnd kept: a string at a token start ends one
            post = mode == "cmd" and bnd   # ...and a `.` after it is member access (`'a'.b#c`)
            continue
        if c in _PS_DQ:
            children, j = _ps_lex_dq_parts(t, i + 1, n, True, depth, name and not bnd, v51)
            if j >= n:
                put("open", i, n)
                i = n
                continue
            put("dq", i, j + 1, children)
            if mode is None:
                mode = "expr"
            i, num = j + 1, False
            post = mode == "cmd" and bnd
            continue
        if c == "$" and t.startswith("(", i + 1) and name:
            # a command name's $( ) is literal text to its matching paren (nothing else counts)
            j, depth_p = i + 2, 1
            while j < n and depth_p:
                depth_p += {"(": 1, ")": -1}.get(t[j], 0)
                j += 1
            i = j
            continue
        if c == "$" and t.startswith("(", i + 1):
            # mid-bareword (`a$(1)<#c#>`) the bareword goes on after it
            stack.append([")", mode if mode is not None else "expr", bnd, False])
            i, mode, bnd, num = i + 2, None, True, False
            continue
        if c == "$" and (t.startswith("{", i + 1) or _PS_LEX_VAR_RE.match(t, i, n)):
            at, braced = bnd, t.startswith("{", i + 1)
            if braced:
                j = i + 2
                while j < n and t[j] != "}":
                    j += 2 if t[j] == "`" else 1
                if "`" in t[i + 2:j]:
                    put("bvar", i, min(n, j + 1), j < n)   # an escaped brace in its name (see _ps_lex_emit)
                i = min(n, j + 1)
            else:
                i = _PS_LEX_VAR_RE.match(t, i, n).end()
            if mode is None:
                mode = "expr"
            num = False
            if mode != "cmd":
                bnd = True
                continue
            # an argument: `$x` and `${x}` run on as a bareword; a member access, an index
            # or a method call at a token start makes it an expression ending a token
            chain = False
            if at:
                while True:
                    m = (_PS_LEX_MEMBER_RE_51 if v51 else _PS_LEX_MEMBER_RE).match(t, i, n)
                    if not m or (braced and not chain and not t.startswith(".", i)):
                        break
                    i, chain = m.end(), True
                nc = not v51 and t.startswith("?[", i) and (chain or not braced)   # pwsh 7.1+: `$x.y?[0]`
                if nc or t.startswith("[", i) or (chain and t.startswith("(", i)):
                    stack.append(["]" if nc or t[i] == "[" else ")", mode, True, False])
                    i, mode, bnd = i + (2 if nc else 1), None, True
                    continue
            bnd, post, post_nocc = chain, at, braced and not chain
            continue
        if c == "@" and t[i + 1:i + 2] in ("(", "{"):
            stack.append([")" if t[i + 1] == "(" else "}", mode if mode is not None else "expr",
                          True, t[i + 1] == "{"])
            i, mode, bnd, num = i + 2, None, True, False
            continue
        if c in "({":
            flag = False
            if c == "{" and body is not None and body[0] == len(stack):
                flag, body = body[1], None               # a class's / an enum's body
            elif c == "(" and type_lb >= 0:
                if _ps_lex_attribute_open(t, i, type_lb):
                    flag = "i"                           # an attribute's arguments (`[Parameter(Mandatory)]`)
                type_lb = -1                             # each `[` checked once (linear)
            stack.append([")" if c == "(" else "}", mode if mode is not None else "expr", True, flag])
            i, mode, bnd, num, ident_next = i + 1, None, True, False, False
            continue
        if c == "[" and mode != "cmd":
            type_lb = i                                  # an attribute's `(` may follow its name
            i, mode, bnd, num = i + 1, "expr", True, False      # an index or a type literal
            continue
        if c in ")}]":
            if stack and stack[-1][0] == c:
                _, mode, bnd, fl = stack.pop()
                attr_end = fl == "i" and c == ")"         # `[Flags()]`: its `]` comes next
                post = mode == "cmd" and bnd
                i, num = i + 1, False
                continue
            if c == closer and not stack:
                break
            i, num = i + 1, False
            if c == "]" and ae:
                mode, bnd = None, True                   # an attribute's end: its statement goes on
                continue
            if c == "]" and mode is None:
                mode, bnd = "cmd", True                  # `]` first: arguments follow
                continue
            bnd = bnd or mode == "expr"
            continue
        if c == ";":
            if stack and stack[-1][3] in (True, "v", "v="):
                stack[-1][3] = True                              # a hashtable's next key
            i, mode, bnd, num, ident_next, body = i + 1, None, True, False, False, None
            continue
        if c == "|":
            i += 2 if t.startswith("||", i) else 1
            mode, bnd, num = None, True, False
            if stack and stack[-1][3] in ("v", "v="):
                stack[-1][3] = "v="                              # the pipeline goes on past a line break
            continue
        if c == "&":
            if t.startswith("&&", i):
                i, mode = i + 2, None
                if stack and stack[-1][3] in ("v", "v="):
                    stack[-1][3] = "v="
            elif mode is None:
                i, mode, inv = i + 1, "cmd", True
            else:
                i, mode = i + 1, None
            bnd, num = True, False
            continue
        if c == ",":
            i, bnd, num, comma = i + 1, True, False, True
            if stack and stack[-1][3] in ("v", "v="):
                stack[-1][3] = "v="                              # the array goes on past a line break
            continue
        if stack and stack[-1][3] is True and c == "=":       # a value's own `b=x` is one bareword
            stack[-1][3] = "v="                                  # the value comes next
            i, mode, bnd, num = i + 1, None, True, False         # a hashtable's key = value
            continue
        if mode != "cmd" and (c == ">" or (c in "0123456789*" and t[i + 1:i + 2] == ">")):
            m = _PS_LEX_REDIR_RE.match(t, i, n)             # a redirection first: `>x cmd`
            j = max(m.end() if m else 0, i + 1)
            # `echo > --%`, `2> --%`: --% is the file's name; a bare `>`, `>>`, `*>` first in a
            # command takes no --% (`> --% x`: x is a stop-parsing tail)
            rtarget = "&" not in t[i:j] and not (mode is None and c in ">*")
            i, mode, bnd, num = j, "cmd", True, False
            continue
        if mode is None:
            if c == "!" and (t[i + 1:i + 2].isalpha() or t[i + 1:i + 2] in ("_", ".", ":", "\\", "/", "~", "=")):
                mode, bnd, num, name = "cmd", False, False, True    # `!a`: a bareword
                i += 1
                continue
            if c in _PS_LEX_DIGITS or (c == "." and t[i + 1:i + 2] in _PS_LEX_DIGITS):
                j = _ps_lex_number_end(t, i, n, v51)
                if j < 0:
                    mode, bnd, num, name = "cmd", False, False, True   # a bareword: read on below
                    continue
                i, mode, bnd, num = j, "expr", True, True
                continue
            if c in _PS_LEX_DASH or c in "+!":
                nx = t[i + 1:i + 2]
                if nx in _PS_LEX_DIGITS or (nx == "." and t[i + 2:i + 3] in _PS_LEX_DIGITS):
                    j = _ps_lex_number_end(t, i + 1, n, v51)
                    if j >= 0:
                        i, mode, bnd, num = (i + 1 if c == "!" else j), "expr", True, c != "!"
                    else:                                       # `+1$x`: a bareword
                        mode, bnd, num, name = "cmd", False, False, True
                    continue
                if nx == "=":                                   # `+=x`: a bareword
                    mode, bnd, num, name = "cmd", False, False, True
                    continue
                # `+.x`, `-.'y'`: the number scan fails and pwsh reads one bareword, its quotes
                # embedded and its `#`, `<#` opening nothing (measured; `+.;` splits)
                if nx == "." and t[i + 2:i + 3] and t[i + 2] not in _PS_LEX_NUM_END:
                    mode, bnd, num, name = "cmd", False, False, True
                    continue
            if c in "+!":
                i, mode, bnd, num = i + 1, "expr", True, False
                continue
            if c in _PS_LEX_DASH:
                m = _PS_LEX_PARAM_RE.match(t, i, n)
                name = m.group(0)[1:].rstrip(":")
                name = name.lower() if name.isascii() else name   # lower() folds the Kelvin sign into k
                if len(m.group(0)) == 1 or name in _PS_LEX_UNARY:
                    i, mode, bnd, num = m.end(), "expr", True, False
                    continue
                # a parameter first: what follows is read as arguments
                # (a leading `-p:` takes no value: a --% after it stops parsing)
                i, colon, tick = _ps_lex_param_end(t, i, n)
                if tick:
                    put("pbt", i - 1, i)
                mode, bnd, num = "cmd", colon or t[i:i + 1] in (".", "["), False   # `-p.'x'`
                continue
            # `.` then an ASCII quote: dot-sourcing (before a typographic quote: one bareword)
            if c == "." and (i + 1 >= n or t[i + 1] in _PS_LEX_WS or t[i + 1] in "$({&"
                             or t[i + 1] in ("'", '"')):
                i, mode, bnd, inv = i + 1, "cmd", True, True
                continue
            j = max(_PS_LEX_WORD_RE.match(t, i, n).end(), i + 1)
            word = t[i:j].lower() if t[i:j].isascii() else ""   # `brea<U+212A>`: no keyword to pwsh
            key = ((ident_next or (stack and stack[-1][3] in (True, "i"))) and mode is None and bnd
                   and _PS_LEX_KEY_RE.fullmatch(t, i, j) is not None)
            owner, ident_next = ident_next, False
            i, num = j, False
            if key:
                # a hashtable's bare key (`@{a<#c#>=1}`), a class's / an enum's name or member, an
                # attribute's argument name: a token ends after it (measured)
                mode, bnd = "expr", True
                if owner in ("class", "enum"):
                    body = (len(stack), "i")             # its body comes next
                continue
            # a keyword only before a blank, a line break, the end or &(),;{|} (measured, pwsh 7 and
            # 5.1): `return#c`, `if'x'`, `if$x` are one bareword each, their # or quote opens nothing
            if word in (_PS_LEX_KEYWORDS_51 if v51 else _PS_LEX_KEYWORDS) and (
                    j >= n or t[j] in _PS_LEX_WS or t[j] in "\r\n&(),;{|}"):
                mode, bnd = None, True
                if word in ("class", "enum", "data"):
                    ident_next = word                    # `class C<#c#>{}`: the name is an identifier
            else:
                mode, bnd, name = "cmd", False, True
            continue
        if mode == "expr":
            if (c == "=" or (c in "+-*/%" + _PS_DASHES and t[i + 1:i + 2] == "=")
                    or t.startswith("??=", i)):
                i += 3 if t.startswith("??=", i) else (1 if c == "=" else 2)
                mode, bnd, num = None, True, False
                if stack and stack[-1][3] in ("v", "v="):
                    stack[-1][3] = "v="                          # `@{a=$x=<LF>b}`: b is the right side
                continue
            if c in _PS_LEX_DIGITS:
                j = _ps_lex_number_end(t, i, n, v51)
                if j >= 0:
                    i, bnd, num = j, True, True
                    continue
            if c.isalnum() or c == "_":
                while i < n and (t[i].isalnum() or t[i] == "_"):
                    i += 1
            else:
                i += 1
            bnd, num = True, False
            continue
        # mode == "cmd": an argument
        if po and (c == "[" or (not v51 and not pnocc and t.startswith("?[", i))):   # `${x}?[0]`: one word
            # an index after a member name (`'a'.b[0]#c`, pwsh 7.1+ `(1)?[0]#c`): a group, a token
            # starts after it
            stack.append(["]", mode, True, False])
            i, mode, bnd, num = i + (1 if c == "[" else 2), None, True, False
            continue
        if bnd and not po and c == "." and (t[i + 1:i + 2] in ("'", '"') or t.startswith("$(", i + 1)):
            # a `.` first in an argument before an ASCII quote or $( is a token of its own (`echo
            # .'x'-p<BT> #c`: a string, then a parameter; before a typographic quote: one bareword)
            i += 1
            continue
        if po and ((c == "." and not t.startswith("..", i)) or (
                not pnocc and (t.startswith("::", i) or (not v51 and t.startswith("?.", i))))):
            # member access after a group or a variable (`(1).y#c`, `$x.'y'#c`, `(1).@'`): the
            # member name is its own token, so what follows it starts one (measured)
            i += 2 if c in ":?" else 1
            j = i
            while j < n and (t[j].isalnum() or t[j] == "_"):
                j += 1
            i, bnd, num, post = j, True, False, j > i
            continue
        if bnd and c in _PS_LEX_DASH and (t[i + 1:i + 2].isalpha() or t[i + 1:i + 2] in ("_", "?")):
            i, pc_end, tick = _ps_lex_param_end(t, i, n)
            if tick:
                put("pbt", i - 1, i)
            num = False
            pcolon, bnd = pc_end, pc_end or t[i:i + 1] in (".", "[")   # `-p.'x'`: a token starts
            continue
        if bnd and (c == ">" or (c in "0123456789*" and t[i + 1:i + 2] == ">")):
            m = _PS_LEX_REDIR_RE.match(t, i, n)
            j = m.end() if m and m.end() > i else i + 1
            rtarget = "&" not in t[i:j] and not iv       # `& 2> --%`: no file, as first
            i, bnd, num = j, True, False                 # a token starts after a redirection
            continue
        i, bnd, num = i + 1, False, False
    if code[0] < i:
        nodes.append(("code", code[0], i))
    return nodes, i


def _ps_lex_skip_fwd(t, j, end):
    # over blanks, <#...#> comments and line continuations, not past end
    while j < end:
        if t[j] in _PS_LEX_WS:
            j += 1
        elif t.startswith("<#", j):
            k = t.find("#>", j + 2, end)
            if k < 0:
                return j
            j = k + 2
        elif t[j] == "`" and t[j + 1:j + 2] in ("\r", "\n"):
            j += 3 if t.startswith("\r\n", j + 1) else 2
        else:
            break
    return j


def _ps_lex_attribute_open(t, i, lb):
    # a `(` after a type-position `[` (at lb) and a type name, blanks, block comments and line
    # continuations between allowed (measured: `[ CmdletBinding(`, `[<#c#>CmdletBinding(`): an
    # attribute's arguments follow
    j = _ps_lex_skip_fwd(t, lb + 1, i)
    k = j
    while k < i and (t[k].isalnum() or t[k] in "_."):
        k += 1
    return k > j and _ps_lex_skip_fwd(t, k, i) == i


def _ps_lex(text, v51=False):
    return _ps_lex_code(text, 0, None, 0, None, v51)[0]


def _ps_lex_esc(s):
    """Text of a $( ) body as it sits inside a "..." string for an older scanner: each
    backtick and each double-quote character doubled, so the string's decoded value is s."""
    return "".join(ch * 2 if ch == "`" or ch in _PS_DQ else ch for ch in s)


def _ps_lex_emit_code(t, a, b, out):
    """Code as it is, but for a mid-word opener (a token start is never code here): an `@`
    before a quote gets an empty string of the other quote kind after it (`a=@""'...'`), and a
    `<` before `#` an empty '' string (`x<''#`). pwsh reads an empty string inside a word as
    nothing (`a''b` is `ab`), POSIX too, and no scanner then opens a here-string or block
    comment there: _ps_code_braces and _ps_subexpressions open them after any non-word
    character, the POSIX reading opens `@'` anywhere. (A backtick escape there made POSIX
    read substitutions: measured FPs.)
    A mid-word `#` is left: the scanners open it at a word
    start (one of _ps_subexpressions' three readings anywhere; their bodies are unioned)."""
    i = a
    while i < b:
        ch = t[i]
        if ch == "`":
            j = min(b, _ps_lex_escape_end(t, i))
            out.append(t[i:j])
            i = j
            continue
        out.append(ch)
        if ch == "@" and i + 1 < len(t) and t[i + 1] in _PS_LEX_QUOTES:
            out.append('""' if t[i + 1] in _PS_SQ else "''")
        elif ch == "<" and t.startswith("#", i + 1):
            out.append("''")
        i += 1


def _ps_lex_ucrt_words(text):
    """The words the UCRT (a Windows program's startup code) makes of text: blanks (space, tab)
    separate outside a "..." span, a double quote toggles a span and is dropped, a "" inside one is
    a literal quote, and backslashes before a double quote halve (an odd one makes it literal)."""
    bs, dq = chr(92), chr(34)
    words, i, n = [], 0, len(text)
    while i < n:
        while i < n and text[i] in " \t":
            i += 1
        if i >= n:
            break
        cur, inq = [], False
        while i < n and (inq or text[i] not in " \t"):
            c = text[i]
            if c == bs:
                j = i
                while j < n and text[j] == bs:
                    j += 1
                if j < n and text[j] == dq:
                    cur.append(bs * ((j - i) // 2))
                    if (j - i) % 2:
                        cur.append(dq)
                        i = j + 1
                    else:
                        i = j
                    continue
                cur.append(text[i:j])
                i = j
                continue
            if c == dq:
                if inq and i + 1 < n and text[i + 1] == dq:
                    cur.append(dq)
                    i += 2
                    continue
                inq = not inq
                i += 1
                continue
            cur.append(c)
            i += 1
        words.append("".join(cur))
    return words


def _ps_lex_msys2_span(buf, i, plain):
    """MSYS2's quoted(): the index after the quoted span at buf[i]. plain (a word starting with @):
    the two quotes are deleted from buf. Otherwise '...' runs to the next ', "..." to the next
    unescaped " (a backslash skips the next character; a "" becomes a backslash and a quote)."""
    bs, dq, sq = chr(92), chr(34), chr(39)
    q, n = buf[i], len(buf)
    if plain:
        del buf[i]
        k = next((k for k in range(i, len(buf)) if buf[k] == q), len(buf))
        if k < len(buf):
            del buf[k]
        return k
    stops = (sq,) if q == sq else (bs, dq)
    cmd = i
    while cmd < n and cmd + 1 < n:
        cmd += 1
        k = next((k for k in range(cmd, n) if buf[k] in stops), None)
        if k is None:
            return n
        if buf[k] == bs:
            cmd = k + 1
            continue
        if q == dq and k + 1 < n and buf[k + 1] == dq:
            buf[k] = bs
            cmd = k + 1
            continue
        return k + 1
    return min(cmd + 1, n) if cmd < n else n


def _ps_lex_msys2_glob(word):
    """MSYS2's globify(): the characters of each quoted span protected, a backslash before the span's
    quote or a backslash inside it dropped, then glob's quoting read away (no file is matched, braces
    and ~ are not expanded: a limit). A DOS path keeps its backslashes outside spans."""
    bs, dq, sq = chr(92), chr(34), chr(39)
    if not word.startswith("~") and not any(c in "?*[(){}" or c in (dq, sq) for c in word):
        return word

    def dos(w):
        return ((len(w) >= 2 and w[0].isascii() and w[0].isalpha() and w[1] == ":")
                or (len(w) >= 3 and w[0] == bs and w[1] == bs and w[2].isascii() and w[2].isalpha()
                    and bs in w[3:]))
    dos_spec = dos(word) or (word[:1] in (dq, sq) and len(word) >= 3 and dos(word[1:]))
    pat, k, n = [], 0, len(word)
    while k < n:
        c = word[k]
        if c not in (dq, sq):
            if dos_spec and c == bs:
                pat.append(bs)
            pat.append(c)
            k += 1
            continue
        k += 1
        while k < n and word[k] != c:
            if word[k] == bs and k + 1 < n and word[k + 1] in (c, bs):
                k += 1
            pat += [bs, word[k]]
            k += 1
        if k >= n:
            break
        k += 1
    out, k, n = [], 0, len(pat)
    while k < n:
        if pat[k] == bs and k + 1 < n:
            out.append(pat[k + 1])
            k += 2
        else:
            out.append(pat[k])
            k += 1
    return "".join(out)


def _ps_lex_msys2_words(text):
    """The words Git's MSYS2 runtime (bash.exe, sh.exe and the other usr/bin programs) makes of a
    command line from a Windows parent: build_argv(), quoted() and globify() of winsup/cygwin/dcrt0.cc
    (msys2-runtime 3.6), after the program's name."""
    buf, words, i = list(text), [], 0
    while i < len(buf):
        if buf[i] in " \t\r\n":
            i += 1
            continue
        start, plain = i, buf[i] == "@"
        while i < len(buf):
            if buf[i] in (chr(34), chr(39)):
                i = _ps_lex_msys2_span(buf, i, plain)
            else:
                i += 1
            if i < len(buf) and buf[i] in " \t\r\n":
                break
        words.append(_ps_lex_msys2_glob("".join(buf[start:i])))
        i += 1
    return words


# The --% tail's deliveries read (pwsh 7.6 measured): Legacy mode and Windows PowerShell 5.1 pass the
# tail verbatim, and the program's runtime splits it: the UCRT, or MSYS2 for Git's usr/bin programs.
# Windows mode (7.6's default) splits it on spaces with every quote literal; a reading of that adds
# refusals (`bash --% -c "echo hi"` reaches bash as `"echo` and `hi"`) and closed no gap the tail fuzz
# found (two seeds, 1,400 tails, the raw readings cover it), so it is not read.
_PS_LEX_SPLITS = ("ucrt", "msys2")


def _ps_lex_argv(text, split="ucrt"):
    """The words a program receives from a --% tail, by delivery (see _PS_LEX_SPLITS)."""
    return _ps_lex_msys2_words(text) if split == "msys2" else _ps_lex_ucrt_words(text)


def _ps_lex_has_verb(nodes):
    # whether the nodes hold a --% tail, in a string's $( ) too
    for nd in nodes:
        if nd[0] == "verb":
            return True
        for ch in (nd[3] if nd[0] == "dq" else nd[5] if nd[0] == "hdq" else ()):
            if ch[0] == "sub" and _ps_lex_has_verb(ch[3]):
                return True
    return False


def _ps_lex_emit_dq(t, children, out, here, split="ucrt"):
    for ch in children:
        if ch[0] == "var":
            # ${...}: its double quotes doubled, so an older scanner keeps the string open
            out.append("".join(c * 2 if c in _PS_DQ else c for c in t[ch[1]:ch[2]]))
            continue
        if ch[0] == "text":
            if here:
                i = ch[1]
                while i < ch[2]:
                    if t[i] == "`":
                        j = min(ch[2], _ps_lex_escape_end(t, i))
                        out.append(t[i:j])
                        i = j
                        continue
                    out.append(t[i] * 2 if t[i] in _PS_DQ else t[i])
                    i += 1
            else:
                out.append(t[ch[1]:ch[2]])
        else:
            inner = []
            _ps_lex_emit(t, ch[3], inner, split)
            esc = _ps_lex_esc("".join(inner))
            if len(esc) > _PS_LEX_MAX_OUT:
                # each nesting level doubles its quotes and backticks: refuse, never grow
                raise _Uninspectable("PowerShell text nested too deep to read (its quotes "
                                    "double at each level)")
            out.append("$(" + esc + (")" if t[ch[2] - 1:ch[2]] == ")" else ""))


def _ps_lex_emit(t, nodes, out, split="ucrt"):
    for node in nodes:
        k = node[0]
        if k == "code":
            _ps_lex_emit_code(t, node[1], node[2], out)
        elif k in ("lc", "bc"):
            out.append(" ")
        elif k == "sq":
            # ASCII delimiters (pwsh closes one at a typographic quote, POSIX does not)
            out.append("'" + t[node[1] + 1:node[2] - 1] + "'")
        elif k == "dq":
            out.append('"')
            _ps_lex_emit_dq(t, node[3], out, False, split)
            out.append('"')
        elif k == "hsq":
            body = t[node[3]:node[4]]
            out.append(" '" + "".join(c * 2 if c in _PS_SQ else c for c in body) + "'")
        elif k == "hdq":
            out.append(' "')
            _ps_lex_emit_dq(t, node[5], out, True, split)
            out.append('"')
        elif k == "bvar":
            # a ${...} variable whose name holds a backtick escape: an older scanner ends it at
            # an escaped brace and opens a comment after it (`echo ${a<BT>}b}#'x' ; cmd`). Its
            # escapes read away, every character but a word character or `:` as `_` (the name
            # is only a variable's to a reader; `${a<BT>}b}` is `${a_b}`)
            closed = node[3]
            body, name, j = t[node[1] + 2:node[2] - (1 if closed else 0)], [], 0
            while j < len(body):
                if body[j] == "`" and j + 1 < len(body):
                    j += 1
                name.append(body[j] if body[j].isalnum() or body[j] in "_:" else "_")
                j += 1
            out.append("${" + "".join(name) + ("}" if closed else ""))
        elif k == "pbt":
            # a parameter's last backtick (before a blank, a line break, a quote or a
            # terminator) escapes nothing: doubled, so no older scanner escapes what follows
            out.append("``")
        elif k == "verb":
            # verbatim text (pwsh passes it to the program as it is): each word the program's
            # command-line parser makes of it (_ps_lex_argv) as a '...' string of its exact
            # characters, so no reader expands, escapes or opens anything in it
            out.append(" " + " ".join("'" + "".join(c * 2 if c in _PS_SQ else c for c in w) + "'"
                                      for w in _ps_lex_argv(t[node[1]:node[2]], split)))
        else:                                            # "open": as it is
            out.append(t[node[1]:node[2]])


def _ps_normalize(text, mvs_word=False, split="ucrt", v51=False):
    # mvs_word: U+180E read as a word character, lexed as an inert character of the same
    # length in its place (no lexer rule names either), emitted from the text itself;
    # split: how a --% tail's words are delivered (see _PS_LEX_SPLITS); v51: Windows PowerShell
    # 5.1's number literals
    nodes = _ps_lex(text.replace(_PS_LEX_MVS, _PS_LEX_MVS_INERT) if mvs_word else text, v51)
    return _ps_lex_emit_capped(text, nodes, split)


def _ps_lex_emit_capped(text, nodes, split):
    out = []
    _ps_lex_emit(text, nodes, out, split)
    norm = "".join(out)
    if len(norm) > _PS_LEX_MAX_OUT:
        # many sibling $( ) chains, each under the cap: the whole text is capped too
        raise _Uninspectable("PowerShell text nested too deep to read (its quotes double at "
                            "each level)")
    return norm


def _ps_normalized_texts(text):
    """The texts _ps_normalize() gives for each reading a pwsh and the program it runs may make:
    U+180E a space (Windows PowerShell 5.1 on .NET Framework 4 to 4.5.2, Unicode 5.0: modelled)
    and, when the text holds one, a word character (pwsh 7, and 5.1 on a later .NET: measured);
    and, when the text has a --% tail, each delivery of its words (see _PS_LEX_SPLITS), with each
    U+180E reading. Neither U+180E reading alone is safe: as a space, `a<U+180E><#` opens a
    comment pwsh 7 runs past; as a word character, `a<U+180E>#'` opens a string the older one
    runs past. No split is either: MSYS2 groups '...' (`bash --% -c 'x'`), the UCRT does not.
    And, when the text may hold syntax only pwsh 7 has (a literal `1n`, `0b1`, `0x`; a `<BT>u{...}`
    escape), each read as Windows PowerShell 5.1 reads it too: there `1n<#` is one bareword, to
    pwsh 7 a number and a comment. Each of these for each copy of the text _ps_lex_copies() gives (a
    bare word glued to a comment opener ending before it, at a statement start; a non-ASCII text's
    name characters as Python and .NET read them). A DSC configuration, and a name character whose
    letter class differs between Unicode versions, are refused (see _ps_lex_refusal)."""
    texts = []
    copies = _ps_lex_copies(text)
    for copy in copies:
        for v51 in ((False, True) if _ps_lex_v7_syntax(text) else (False,)):
            for mvs in ((False, True) if _PS_LEX_MVS in text else (False,)):
                nodes = _ps_lex(copy.replace(_PS_LEX_MVS, _PS_LEX_MVS_INERT) if mvs else copy, v51)
                _ps_lex_refusal(text, nodes)
                for split in (_PS_LEX_SPLITS if _ps_lex_has_verb(nodes) else _PS_LEX_SPLITS[:1]):
                    texts.append(_ps_lex_emit_capped(text, nodes, split))
    texts = list(dict.fromkeys(texts))          # the same text twice is judged once
    total = sum(map(len, texts)) if len(copies) > 1 else 0
    if _PS_LEX_READ["on"]:
        _PS_LEX_READ["used"] += total
        total = _PS_LEX_READ["used"]
    if total > _PS_LEX_MAX_READ:
        # every reading at once (non-ASCII names, a glued word, pwsh 7-only syntax, U+180E, a --%
        # tail) multiplies the texts each reading then reads: past the bound, refuse (a block)
        raise _Uninspectable("PowerShell text with too many readings to inspect")
    return texts


def _ps_lex_code_spans(nodes):
    # (a, b) of each code node, a $( ) in a string's included
    for node in nodes:
        if node[0] == "code":
            yield node[1], node[2]
        elif node[0] in ("dq", "hdq"):
            for child in node[-1]:
                if child[0] == "sub":
                    yield from _ps_lex_code_spans(child[3])


def _ps_lex_name_class(db, ch):
    # a letter or a decimal digit in Unicode database db (a name character to .NET)
    k = db.category(ch)
    return k[0] == "L" or k == "Nd"


def _ps_lex_dsc_nameless(t, e):
    # whether no DSC name can follow the keyword ending at e: blanks, then `=` `,` `)` `}` `;` `|` or the text's
    # end (`@{ Configuration = 'Release' }`; `configuration =c{` and `configuration ,c{` are parse errors to pwsh
    # 7.6 and 5.1: measured)
    while e < len(t) and t[e] in _PS_LEX_WS:
        e += 1
    return e == len(t) or t[e] in "=,)};|"


def _ps_lex_refusal(t, nodes):
    # raise Uninspectable when a lexer reading's code cannot be read faithfully (see _ps_normalized_texts). A
    # character Unicode 3.2 did not assign, or classed otherwise than Python's Unicode does, is a name
    # character to some of .NET 8 / 10, .NET Framework 4.8 and Python and not to others (measured over
    # the BMP: U+1885 and U+1886 are letters to .NET Framework 4.8 only)
    for a, b in _ps_lex_code_spans(nodes):
        for i in range(a, b):
            ch = t[i]
            if ord(ch) > 127 and (unicodedata.ucd_3_2_0.category(ch) == "Cn"
                                  or _ps_lex_name_class(unicodedata.ucd_3_2_0, ch) != _ps_lex_name_class(unicodedata, ch)):
                raise _Uninspectable("a PowerShell name character whose letter class differs between Unicode versions")
        for m in _PS_LEX_DSC_WORD_RE.finditer(t, a, b):
            if not _ps_lex_dsc_nameless(t, m.end()):
                raise _Uninspectable("a PowerShell DSC configuration (its body's reading depends on the resources loaded)")


def _ps_lex_net(ch):
    # .NET: letters and decimal digits name characters (one UTF-16 unit each); Python's other word
    # characters (No, Nl, astral letters) are not
    return (_PS_LEX_NARROW if ord(ch) > 127 and _PS_LEX_WORD_CH_RE.match(ch)
            and not ((ch.isalpha() or ch.isdecimal()) and ord(ch) <= 0xFFFF) else ch)


def _ps_lex_copies(text):
    """The copies of text the lexer reads, each of the text's length (emitted from the text itself):
    the text; when a bare word is glued to `#` / `<#`, the text with each such word ending before
    it, at a statement start (an identifier position the lexer does not model); and, when it is not
    ASCII, each with .NET's letters and decimal digits only as name characters (measured:
    `$x.y<U+00B2>#'` ends the name to pwsh 7 and 5.1). Python, .NET 8 / 10 and .NET Framework 4.8
    disagree only on characters Unicode 3.2 did not assign or classed otherwise (`$x.y<U+1C89>#'`
    does not end the name to pwsh 7, `$x.y<U+1C80>#'` and `$x.y<U+1885>#'` do to 5.1): a text with one
    in its code is refused instead (_ps_lex_refusal)."""
    copies = [text]
    if _PS_LEX_IDENT_RE.search(text):
        copies.append(_PS_LEX_IDENT_RE.sub(lambda m: m.group(0)[:-1] + " ", text))
    if not text.isascii():
        copies += ["".join(map(_ps_lex_net, c)) for c in list(copies)]
    return list(dict.fromkeys(copies))


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


def _powershell_segments(raw: str, normalized: bool = False):
    """Every segment evaluate() judges for a PowerShell payload: the readings below of
    the raw text and, when it holds one of _PS_SPACES, the same readings of the text
    with each of them a space, as PowerShell reads them outside a string; when it holds
    one of _PS_DASHES, the same readings of each of those with the dashes as `-`, all
    of them or only one before `=` (_ps_dash_readings); and the same
    again with PowerShell's grouping read away (_ps_ungroup: `git reset ("--hard")`,
    `& ('git') ...`, `& {...}`), so a grouped value is judged as the argument or command
    word it becomes. The raw readings stay, so this only adds segments. Unless normalized,
    the same readings again of each text _ps_normalized_texts() gives (comments and
    here-strings read as pwsh's tokenizer reads them), when it differs; such a text's own
    strict reading is lenient (a line it cannot tokenize is read piecewise: the raw text's
    stays strict and refuses). Raises as _segments() does."""
    segments = []
    if not normalized:
        for norm in _ps_normalized_texts(raw):
            if norm != raw:
                _RunnerBudget.charge(len(norm))
                segments += _powershell_segments(norm, normalized=True)
    # Each $( ) subexpression's body, judged as a payload of its own (see
    # _ps_subexpressions): inside a "..." string no other reading sees it as code.
    if "$(" in raw:
        for body in _ps_bodies(raw):
            if body.strip() not in ("", ":"):
                _RunnerBudget.charge(len(body))
                # a normalized text's bodies hold code the lexer emitted: read, not normalized
                # again (the raw text's own bodies are; every reading at once squared otherwise)
                segments += _powershell_segments(body, normalized=normalized)
    base = _ps_dash_readings(raw)
    # The code a canonical literal call runs from a string ([scriptblock]::Create('...'),
    # .InvokeScript('...'), ...), read as a pwsh script; any other such call is refused
    # (_ps_code_strings raises).
    for t in base:
        for body in _ps_code_strings(t):
            for s in _ps_script_texts(body, 1):
                segments += _runner_segments(s, 1, False, True)
    texts = list(base)
    if "(" in raw or "{" in raw:
        texts += [_ps_ungroup(t, keep_variables=True) for t in base]
    if "{" in raw or "}" in raw:
        texts += [_ps_block_statements(t) for t in base]
        # ...and with the braces in its strings and escapes kept (_ps_code_braces).
        texts += [b for b in map(_ps_code_braces, base) if b not in texts]
    if ".'" in raw or '."' in raw:
        texts += [_PS_DOT_QUOTE_RE.sub(r"\1. ", t) for t in texts]
    # A <# #> comment reads as two redirects, whose targets take the words beside it. An
    # added reading, and lenient: a `<#` in a string can leave an odd quote behind.
    # A pipeline continued after a `|` that ends a line, read as one line. An added reading,
    # and lenient: joining a line inside a here-string can cut its terminator.
    if "|" in raw:
        for joined in (j for t in base for j in _ps_joined_pipes(t)):
            segments += _segments(joined, shell="powershell", lenient_on_error=True,
                                  ps_tool=True)
    # A literal list's group read away (see _PS_LIST_GROUP_RE), likewise added and lenient.
    if "(" in raw:
        for text in base:
            listed = _PS_LIST_GROUP_RE.sub(_ps_list_items, text)
            if listed != text:
                segments += _segments(listed, shell="powershell", lenient_on_error=True,
                                      ps_tool=True)
    if "<#" in raw:
        for text in dict.fromkeys(texts):
            segments += _segments(_PS_BLOCK_COMMENT_RE.sub(" ", text), shell="powershell",
                                  lenient_on_error=True, ps_tool=True)
    for text in dict.fromkeys(texts):
        segments += _segments(text, shell="powershell", ps_tool=True,
                              lenient_on_error=normalized)
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
    _ps_script_texts.cache_clear()
    _ps_code_strings.cache_clear()
    _RunnerBudget.used = 0
    _Command.raw = raw
    _Command.kelvin_seen = _Command.kelvin_alt = False
    _PS_LEX_READ["used"], _PS_LEX_READ["on"] = 0, True     # the readings bound, over this evaluation
    try:
        segments = (_powershell_segments(raw) if shell == "powershell"
                    else _segments(raw, shell=shell))
        if _Command.kelvin_seen:
            # A word the readings lowercase held a non-ASCII character lower() changes: the Kelvin
            # sign folds into k, which neither bash nor pwsh does (`pwsh -c 'brea<U+212A> --% ...'`
            # holds no keyword); U+0130 splits into i and a combining dot that ends a name to the
            # lexer (`pwsh -c "echo (1).y<U+0130>#'..."`: to pwsh one letter); U+1C90 becomes U+10D0,
            # a letter to every reading, where 5.1 knows no U+1C90. Every reading again, with ASCII
            # only lowercased (the Kelvin sign and U+0130 spelled U+0138, a letter lower() keeps).
            # Or a word held an ASCII capital and a backtick or a `$'` string: pwsh's escapes are
            # lowercase only, so lowercasing `T (a T) makes `t (a tab) and `U{27} (a U, then a {
            # token) the escape `u{27}, in a runner's script the readings re-read as code; that word
            # keeps its case whole in this reading (see _words_to_segments).
            _runner_segments.cache_clear()
            _ps_script_texts.cache_clear()
            _ps_code_strings.cache_clear()
            _Command.kelvin_alt = True
            segments += (_powershell_segments(raw) if shell == "powershell"
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
        _Command.kelvin_alt = False
        _PS_LEX_READ["on"] = False

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
               getattr(toks, "ps_outer", False), getattr(toks, "cmd_script", False),
               getattr(toks, "ps_unread", False),
               # Read by the Invoke-Expression rule (_ps_iex_command): a quote-blind copy
               # of a strict segment, or one whose word is not expanded, stands for neither.
               getattr(toks, "ps_qbracket", None) is None,
               getattr(toks, "ps_quote_covered", False),
               frozenset(getattr(toks, "expanding", ())))
        if key not in seen:
            seen.add(key)
            unique.append(toks)

    reasons = []
    # A backtick inside a variable's braced name is an escape PowerShell reads away; either
    # half of the name, or any route to a variable by a computed name (see _PS_DEFAULTS_RE).
    _Command.ps_defaults = bool(_PS_DEFAULTS_RE.search(raw.lower().replace("`", "")))
    # The quotes the shells and cmd remove may stand between the two (`'\''/s`, `"\"/s`), and so
    # may text a shell expands to nothing (`\$null/s`); a bash ANSI-C string can spell the
    # backslash (`$'\x5c'/s`).
    _Command.backslash_switch = bool(
        _CMD_GATE_RE.search(raw.translate(_CMD_GATE_DROP))
        or ("$'" in raw and any(_ANSI_C_BACKSLASH_RE.search(m.group(0))
                                for m in _ANSI_C_RE.finditer(raw))))
    try:
        for toks in unique:
            for r in _reasons_for(toks):
                if r not in reasons:
                    reasons.append(r)
    finally:
        _Command.ps_defaults = False
        _Command.backslash_switch = False

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
