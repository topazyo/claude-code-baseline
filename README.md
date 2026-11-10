# claude-code-baseline

**English** · [עברית](README.he.md)

An org baseline for **Claude Code hooks + settings**, distributed as a single
bootstrap script. Run `install.sh` inside any repo and it gains a standard set
of safety defaults plus a menu of opt-in workflow modules — all driven by one
config file, with no hand-editing of `settings.json`.

It is the generalized, repo-agnostic form of a container-security hook set; the
worked policy that shipped with it survives as
[`examples/security-defaults.openclaw.json`](examples/security-defaults.openclaw.json).

**Read [What this does not protect against](#what-this-does-not-protect-against)
before you adopt it.** This is defense in depth for an agent that is mostly
cooperating — it is not a security boundary against one that is not.

---

## Model

Two tiers:

| Tier | Default | What it is |
|------|---------|------------|
| **Guardrails** | on, except `autoFormat` | Universal safety. Only `command-guard` ships enabled; `auto-format` is opt-in because it executes repo-supplied code. |
| **Modules** | opt-in (off) | Workflow-specific enforcement. Enable per repo. |

A single global **posture** decides what a violation does — but what "block"
*can* mean depends on the hook event, because Claude Code only lets a hook veto
a tool call **before** the tool runs:

| Event | Hooks | `"enforcement": "block"` means |
|-------|-------|-------------------------------|
| `PreToolUse` | command-guard, scopeGuard | The tool call **is refused**. Nothing ran. |
| `PostToolUse` | securityDefaults, fixTags, runTests, autoFormat, autoStage | **The write already happened.** The hook's stderr is reported back to Claude so it can correct course, and the dispatcher stops the rest of the chain — but nothing is undone or reverted. |
| `ConfigChange` | configGuard | Fires when a settings file changes mid-session. A detected tamper (or, under `failClosed`, a check that could not run) is refused for the session — **silently**: Claude Code shows no message to you or Claude and writes only a debug-log line. configGuard does not revert the file: revert the change yourself (re-running `install.sh` restores only the hook wiring and deny-list; it leaves `disableAllHooks`, `env` and `settings.local.json` as they are). If a settings edit seems to have no effect, check `claude --debug`. |
| `Stop` | trackerReminder | A reminder shown to you. Never blocks, never sends Claude back to work. |

`"enforcement": "warn"` downgrades every one of the above to a warning: the action
goes ahead, and the hook's report is shown to you and added to Claude's context.
(Claude Code ignores what a hook writes to stderr when it exits 0, so under `warn`
the PreToolUse hooks and the PostToolUse dispatcher also print the report as one
JSON object on stdout — `systemMessage` for you, `additionalContext` for Claude.)
The same applies to a control that could not run under `"failClosed": false`, and,
in any posture, to the dispatcher's note that a formatter or auto-stage step ran out
of time. Two exceptions: configGuard (Claude Code discards a ConfigChange hook's
messages in every posture: under `warn` its report reaches only the debug log,
`claude --debug`, and under `block` the change is refused without a message)
and trackerReminder, which is advisory in every posture: its reminder is shown to you
(`systemMessage`) but not passed to Claude, because context from a `Stop` hook keeps
the turn going.

There is also `"failClosed": true`: when a control *cannot run* (no Python, an
unparseable payload, a deleted or truncated matcher, a hook child that blew its
time budget), the hook says so loudly and — under `block` — refuses the call
rather than waving it through as clean. A `.claude/baseline.config.json` that
exists but cannot be read (invalid JSON, or not a JSON object) is one of these:
its own `enforcement` and `failClosed` are unknown, so every guard refuses every
call it watches until a human fixes or deletes the file (Claude's edit tools are denied it),
and tracker-reminder reports it. A byte order mark or UTF-16 text is read normally.
The post-write dispatcher treats its own read of the config and the payload running
past its time bound the same way: it cannot learn `enforcement` or `failClosed` in
time, so it reports the edit as unchecked with exit 2.

### Guardrails

- **command-guard** — `PreToolUse(Bash|PowerShell)`, **enabled by default**.
  Blocks a curated set of destructive / unapproved shell commands: `rm -rf /`
  and friends (including drive roots such as `C:/`, `/c` and `/mnt/c`, `../..`,
  the current directory as `~+` or `$PWD`, and a path that reaches a root through
  `..` or a glob such as `/**`), `git push --force` (including `+refspec` forms), `git push --mirror`
  and `--prune`, deleting a remote `main`, `master` or `HEAD`, `git reset
  --hard`, dangerous SQL (`drop/truncate table`, `delete from`), remote fetch
  via `curl`/`wget` (including scheme-less hosts, since both default to HTTP;
  an `http(s)://` URL to `localhost`, `127.x.x.x` or `[::1]` is not a remote fetch, though
  options that steer the connection elsewhere, such as `-x` or `--connect-to`, are not judged),
  and package installs (`npm/pnpm/yarn/pip install`, bare `yarn`,
  `python -m pip install`). The matcher is token-aware: it resolves quoting,
  `${IFS}`, wrapper paths (`/bin/rm`, `sh -c`, `xargs`), wrappers with options
  (`sudo -u root`, `nice -n 10`, `timeout 5`), `eval`, `env -S`, the Windows
  runners `cmd /c`, `pwsh -Command`/`powershell -Command` and `wsl`, redirections,
  `.exe` suffixes, newline-separated and compound commands, and blocks a shell
  or Windows runner reading its commands from a pipe (`... | sh`), `pwsh
  -EncodedCommand`, and anything it cannot parse --
  including `eval "$(...)"` and `source <(...)`, so a setup line such as
  `eval "$(ssh-agent -s)"` or `source <(kubectl completion bash)` is refused.
  A newline inside a quoted string (a
  multi-line commit message or PR body, a PowerShell here-string) or after a
  trailing `\` does not split the command; a line of such a string that starts
  with a blocked command, or names one in backticks, is still blocked. Extend per repo via
  `guardrails.commandGuard.extraPatterns`.
- **auto-format** — `PostToolUse(Write|Edit)`, **disabled by default**. Formats
  changed files with prettier/eslint, black, or `dotnet format`. It ships off
  because it *executes code the target repository supplies* —
  `./node_modules/.bin/*`, repo-controlled `prettier.config.js` /
  `eslint.config.js` and their plugins, and `dotnet format` builds the project.
  (The opt-in `runTests` module does too: it runs the repo's own tests.)
  Enabling it is a deliberate trade for a repo whose toolchain you trust; see
  [Configure](#configure).

### Shell coverage: Bash *and* PowerShell

The PowerShell tool is default-on on Windows, and on a Windows host **without**
Git Bash, Claude Code does not register the Bash tool at all. A hook matching
only `Bash` would never fire there, so the shell matchers are `Bash|PowerShell`
and the merged deny-list carries a PowerShell floor: `Remove-Item`/`rm`/`del`/
`rmdir`, `Invoke-WebRequest`/`iwr`/`Invoke-RestMethod`/`irm`/`curl`/`wget`
(plus the native `curl.exe`/`wget.exe`, which are *not* aliases under PowerShell 7),
`Invoke-Expression`/`iex`, and `git push … --force`.

Two limits, stated plainly:

1. **The hook command is `bash -p "…/command-guard.sh"`, so Git Bash is a
   requirement on Windows.** When Claude Code cannot find Git Bash, a hook with
   no `shell` runs in PowerShell, where `bash "…"` fails. The guards then fail
   **closed**: every shell command and every `Write`/`Edit` is refused (the
   guards carry `"onFailure": "block"`, and since 2.1.299 this happens even
   without it). Install Git for Windows, or point `CLAUDE_CODE_GIT_BASH_PATH` at
   its `bash.exe` in your user environment or `~/.claude/settings.json` (a
   repo's settings file that sets it is reported, see "What this does not
   protect against"); WSL's `bash` does not count for a Claude Code running
   natively on Windows. Below v2.1.295 `onFailure` is unsupported, and how
   those releases treat the key is unverified: most likely they ignore it and a
   guard that cannot start fails open, as before, leaving the `permissions.deny`
   rules (enforced by the CLI itself, no shell involved) as the only control.
   The worst case, also unverified, is a release that rejects the unknown key
   and does not load that `settings.json` at all, deny-list included. That is
   why `install.sh` warns below the pin. Note too that scope-guard is wired even
   while its module is off, so with `onFailure: "block"` a scope-guard that
   cannot start, or runs past its 10 s timeout, blocks every Write/Edit.
2. **command-guard's blocklist is POSIX command names.** It will inspect a
   PowerShell payload, but it does not know cmdlet verbs (`Remove-Item`,
   `Invoke-WebRequest`). Those are covered by the deny rules only, which is a
   coarser floor than the Bash side gets. "The hook fired" does not mean "the
   command was understood".

### Modules (opt-in)

| Module | Hook | Purpose |
|--------|------|---------|
| `securityDefaults` | PostToolUse | Verify immutable infra defaults haven't drifted, from a **declarative rules file** (see below). Reports to Claude after the write; cannot undo it. |
| `fixTags` | PostToolUse | Require a traceability tag (e.g. `# FIX: TICKET-123`) on every added line. Configurable marker, file types, and an optional env gate. Reports to Claude after the write; cannot undo it. |
| `scopeGuard` | PreToolUse | Refuse edits to files outside a declared task scope (`.claude/active-issue-scope.txt`). Genuinely blocking under `block` — the write never happens. Whether or not `scopeGuard` is enabled, `scope-guard.sh` also refuses **every** Write or Edit to a path only a human may write: subagent, skill and command definitions and hook scripts (`.claude/agents/`, `.claude/skills/`, `.claude/commands/`, `.claude/hooks/`, at any depth and in the user's config home), plugins (a skill folder's `.claude-plugin/`, `.claude/plugins/`, the plugin cache), user `settings.json` / `settings.local.json`, `.claude.json`, `.mcp.json` and `.claude/security-defaults.json`. That check has no switch and follows `enforcement`; see [Definitions are human-only](#what-this-does-not-protect-against). |
| `configGuard` | ConfigChange | Detect in-session tampering of `.claude/settings.json` (baseline hooks unwired or moved off the template's event or matcher, deny-list stripped, `disableAllHooks` or a risky environment value set) and of `.claude/settings.local.json` (`disableAllHooks`, a risky environment value, or a hook entry naming a baseline script, which the installer never writes there). **Off by default; under `block` it refuses the change for the session, silently (the report is in `claude --debug`), and does not revert the file; in-session only; watches those two files only** — never `baseline.config.json` and never the hook scripts. A deleted `settings.local.json` is normal; an unreadable one is treated as tampered. |
| `runTests` | PostToolUse | Run the right test/lint per file type (pytest, shellcheck/bats, yamllint/actionlint). Missing tools are skipped. Reports to Claude after the write; cannot undo it. A failing check's output is passed on verbatim but capped (the first 60 lines of a linter's report, the last 30 of pytest's, the last 20 of bats'); a passing one stays quiet. Anything a failing test prints — file contents, environment values — is therefore shown to Claude (and, under `warn`, to you). |
| `trackerReminder` | Stop | When Claude stops and commits whose subject contains `commitGrep` are among the last 20 (not only this session's), show you a reminder to update a tracking doc — once per session, then again only for a new matching commit (an amended or rebased commit counts as new). The session memory is kept in `.git/baseline/`; without a usable `session_id` in the Stop input, or when that memory cannot be used, it reminds at every stop. Not passed to Claude. Never blocks. |
| `autoStage` | PostToolUse | `git add` changed files after all gates pass. Never blocks. |

The `PostToolUse` hooks run through one **dispatcher** in a fixed safe order
(security → tags → tests → format → stage); a failing gate short-circuits the
chain, so nothing is formatted or staged after a violation. Formatting runs
*after* the gates deliberately: they must read the bytes Claude actually wrote,
and the unbounded step must not eat the shared hook timeout.

---

## What this does not protect against

This baseline raises the cost of a mistake. It is **not** a boundary against a
determined or prompt-injected agent. Everything below is a known, structural
limit — not a bug. Read it before you rely on any of the above.

- **The per-repo tier is self-disarming by design.** `.claude/hooks/baseline/**`
  and `.claude/baseline.config.json` are ordinary repo files. A developer — or
  the agent, through any subprocess the deny rules don't recognize — can edit or
  delete them. One config key (`commandGuard.enabled: false`, or
  `"enforcement": "warn"`) turns every blocking control in the product into an
  advisory warning for the rest of the session. **Only enterprise
  [managed settings](managed/README.md) are non-overridable.**
- **Deny rules bind tools, not the filesystem.** `Read()`/`Edit()` rules bind
  Claude's built-in file tools *and* the file commands Claude Code recognizes
  inside a shell command (`cat`, `head`, `tail`, `sed`, `grep`). They do **not**
  bind arbitrary subprocesses: `python -c "open('.env').read()"` or `node -e …`
  read or write the file with no rule consulted. The `Bash(*…*)` /
  `PowerShell(*…*)` path rules added to the template close the common shell
  shapes the `Edit()` rules miss (`>` redirection, `tee`, `cp`, `mv`, `rm`,
  `chmod`, `truncate`) — but they are a **text match on the command string**.
  `cd .claude && sed -i s/block/warn/ baseline.config.json`, or
  `sed -i … "$CFG"`, does not contain the literal path and is not caught.
- **command-guard is a blocklist, not an allowlist.** It matches command
  *names*. Base64 or other encoding, `$VAR` indirection, runtime aliases, and
  any binary that simply isn't on the list all pass uninspected. So do git
  settings made outside the command (`git config`, `GIT_CONFIG_*` variables),
  deleting a remote branch under any name other than `main`, `master` or `HEAD`
  (only server-side branch protection that binds admins stops that), cmd
  built-ins (`rd /s`, `del`), `wsl --unregister`, and a script file run by
  `pwsh -File` or `Start-Process`.
- **A mod can override a deny rule and a guard's block.** A Claude Code mod (on
  by default since v2.1.287) answers after the `PreToolUse` hooks, and — unless the
  machine has managed settings or the session's credential is a Team or Enterprise
  `/login` — it can approve a call that a deny rule refused or a guard blocked. A
  session on any other credential (for example an API key, Amazon Bedrock, Google
  Cloud, Microsoft Foundry or a long-lived `CLAUDE_CODE_OAUTH_TOKEN`) gets no such
  protection without managed settings. Managed
  adopters can stop users' own mods with `allowManagedModsOnly`
  (or `allowManagedHooksOnly`, which the strict profile sets); see
  [managed/README.md](managed/README.md).
- **Definitions are human-only, and that has a cost.** A subagent, skill or
  command definition can run commands no guard sees: `hooks` and `mcpServers` in
  its frontmatter, a skill's `allowed-tools` with `` !`cmd` `` lines that run when
  it loads, a `.claude-plugin/plugin.json` in a skill folder, or the scripts it
  calls. The same holds for hook scripts under `.claude/hooks/`, plugins, user
  settings, `.claude.json` and `.mcp.json`. So scope-guard judges the **path**,
  not the content, and refuses every Claude Write/Edit there: as written, in its
  canonical Windows form (`\\?\`, `\\.\`, `\??\`, `GLOBALROOT` and volume-GUID
  prefixes, trailing dots and spaces; NTFS streams such as `::$DATA` and
  drive-relative paths are refused outright), as it resolves (links, junctions,
  8.3 short names), under the real protected directories, and through hard links
  to a protected file. A UNC path to a loopback host or an address literal
  (`\\127.1\…`, `\\[::1]\…`, `\\10.0.0.5\…`) is not judged and fails closed.
  `permissions.deny` adds `Edit(//**/.claude/<dir>/**)`-style
  entries and path-text Bash/PowerShell entries as defense in depth. The project's
  `settings.json`, `settings.local.json` and `baseline.config.json` get the same
  floating form beside their cwd-anchored entries, which also covers a worktree's local
  settings (kept at the main checkout on macOS and Linux) and other checkouts' copies:
  in a session where these rules load, Claude's Edit tool is refused on every such file,
  wherever it sits. Edit these
  files yourself. What stops working: the bundled `/verify` recording its recipe
  in `.claude/skills/verify/`, `/run-skill-generator`, skill-creator-style skills
  writing `~/.claude/skills`, the `statusline-setup` agent and settings-editing
  skills (`update-config`, `fewer-permission-prompts`, plugin setup/HUD skills),
  Claude adding MCP servers to `.mcp.json`, and any Bash/PowerShell command whose
  *text* names one of these directories (a commit message, a `gh pr --body`, a
  `grep`). Residual gaps: shell spellings the path-text rules do not see (as for
  every deny rule here); a remote UNC share that holds this repo's definitions
  through a link, or the machine's own name under another DNS alias; a link to a
  remote UNC target made beforehand (it is followed while resolving); scripts a
  settings file names outside these directories (a `statusLine` command, a hook
  command pointing elsewhere); without Python, only the payload text is checked; a
  custom 8.3 name set with `fsutil` where the path cannot be resolved; a POSIX
  hard-link search that stops at 20 000 entries (a hard-linked file then fails
  closed); and resolving a `\\wsl$` path starts the WSL VM before the prompt. Repos that need no `` !`cmd` `` lines in skills can also set
  `disableSkillShellExecution: true`.
- **PostToolUse cannot undo a write.** `securityDefaults`, `fixTags` and
  `runTests` report a violation *after* the file has changed on disk. They give
  Claude a chance to fix it; they do not prevent it.
- **Whole tool families are unhooked.** Hooks cover the shell tools and
  `Write|Edit` only. `WebFetch`, `WebSearch` and every `mcp__*` tool have no
  hook and no deny rule here. `NotebookEdit` writes files but is not `Write` or
  `Edit`, so scope-guard and the post-write modules never see it; the `Edit(...)`
  deny rules do cover it. `curl`/`wget` are the two most common fetch
  binaries — any other runtime (`python -c "urllib.request.urlopen(…)"`,
  `nc`, a language SDK) reaches the network freely. **Egress control belongs to
  the OS sandbox, not to this baseline.**
- **The hooks trust the interpreter `PATH` gives them.** The baseline's own
  helpers run the first `python3` (else `python`) on `PATH`, skipping the Windows
  Store alias unless it is all there is, and always with `-I -S -X utf8`, so
  nothing in the project, on `PYTHONPATH` or in `site-packages` is imported. An
  interpreter that itself lives inside the project (an activated in-project
  virtualenv), in a directory the agent can write, or one a version-manager shim
  (pyenv, asdf, mise) picks from a project file such as `.python-version` is only
  as trustworthy as that directory. One that is found but does not run makes
  command-guard and the post-write checks fail closed; the opt-in scope-guard and
  config-guard go inert, as they do with no Python at all, except that scope-guard
  still refuses (fails closed on) a Write or Edit whose payload text names a
  human-only path; without Python it cannot resolve links or short names. On Windows
  the interpreter must be Python 3.8 or later: with an older one, scope-guard fails
  closed on every Write and Edit that names a file. It must also be a native Windows
  Python: the hooks never run their code on a Cygwin or MSYS one, which reads Windows
  paths as POSIX paths. With one first on `PATH`, command-guard and the post-write
  checks fail closed as they do without Python, and scope-guard fails closed on every
  Write and Edit. With no interpreter the config cannot be read, so even
  `failClosed: false` does not turn these into announcements. The opt-in `autoFormat`
  and `runTests` deliberately run the repo's own formatter and tests without this
  isolation.
- **The hook environment is trusted up to the shell that runs the hook.** Every
  baseline hook, and every child the dispatcher starts, runs as `bash -p`, and the
  hooks drop the bash values `-p` leaves alone as they load, so a `BASH_ENV` startup
  file, an exported function or `SHELLOPTS` in the hook's environment no longer acts
  before or inside a hook. The shell that runs the hook command string comes first
  and is Claude Code's (per the hooks documentation, `sh -c` on macOS and Linux,
  Git Bash on Windows, PowerShell when Git Bash is missing), so it may act on such
  values on any platform, and
  `PATH`, `LD_PRELOAD`/`DYLD_*` or `CLAUDE_CODE_SHELL_PREFIX` affect it too. A settings
  file's `env` block can set any of them. config-guard (opt-in) reports one in an
  in-session change to `.claude/settings.json` or `.claude/settings.local.json`,
  `install.sh` warns about one in the file it merges, and
  `tools/baseline-status.sh` reports one in `settings.json` or
  `settings.local.json` from outside Claude Code. None of them removes the value, and
  `~/.claude/settings.json` and the environment Claude Code is launched with are not
  checked: set values you need, such as `CLAUDE_CODE_GIT_BASH_PATH`, there.
- **The hooks' own git still runs a repository's filter driver.** fix-tags,
  auto-stage and tracker-reminder run git with `core.fsmonitor`, the
  `post-index-change` hook (from a hooks directory or a `hook.<name>` entry) and
  every fetch transport switched off, and fix-tags diffs with no external diff
  or textconv program, so a repository's git config cannot make those calls
  start a program in those ways (a `post-index-change` hook of your own does not
  run for them either). A filter driver (`filter.<name>.clean` or `.process` in
  `.git/config`, picked by `.gitattributes`) still runs inside auto-stage's
  `git add` and fix-tags' `git diff`, as it does in your own `git add`, and
  command-guard has no rule for `git config`, so the agent can set one. Keep
  `autoStage` and `fixTags` off in a repository whose git config you do not
  control. A settings `env` value for `HOME`, `XDG_CONFIG_HOME`, `USERPROFILE`,
  `HOMEDRIVE` or `HOMEPATH`, which moves the git config those calls read, is
  reported like the values above.
- **Below Claude Code v2.1.314, Monitor commands skip command-guard.** A shell
  command Claude starts with the Monitor tool reaches the `Bash`-matched guards only
  from 2.1.314; below it command-guard never sees the command. (The current tools
  reference says Monitor follows the same permission rules as Bash; that is not
  verified here for older releases.) A Monitor WebSocket watch reaches no
  `Bash`-matched hook, so no baseline guard, on any version.
- **Below Claude Code v2.1.295, a hook that cannot start most likely fails
  open.** From 2.1.295 the two guards' `"onFailure": "block"` refuses the call
  when the hook can't start, times out, or exits with anything but 0 or 2. Older
  releases do not support the key, and how they treat it is unverified: a guard
  that cannot start, or is killed at the Claude Code timeout, most likely lets
  the call proceed, as before. `failClosed` covers only the cases a hook *can*
  observe from inside itself. The `ConfigChange` config-guard deliberately has
  no `onFailure`: blocking on a broken config-guard would also block the
  settings edit that repairs it mid-session.
- **Config tampering by a human or an external process is largely uncovered.**
  `configGuard` is off by default, and even enabled it sees only in-session
  `.claude/settings.json` and `.claude/settings.local.json` changes, after they land,
  and its refusal under `block` is silent.
- **Nothing here addresses prompt injection itself.** This baseline constrains
  which *actions* are permitted. It does not make the model resistant to
  malicious instructions arriving in a file, a web page, or an MCP response.
- **Installing it is not verifying it.** `install.sh` writes files; it never
  confirms a hook fires. Verify one block by hand before you rely on it —
  `tests/` shows what a real check looks like.

---

## Install

From inside the target repo:

```bash
/path/to/claude-code-baseline/install.sh
```

Or point at a repo explicitly, and optionally seed the example security rules:

```bash
claude-code-baseline/install.sh --target ../some-repo --with-openclaw-rules
claude-code-baseline/install.sh --dry-run         # preview; writes nothing, but runs the
                                                  # settings merge in a temp file and exits 1
                                                  # if the real run would stop there
```

Every post-write module ships **off**, so on a default install writing a file
triggers no visible check. To see one fire, install into a fresh repo with the
example rules seeded and `securityDefaults` enabled in one step:

```bash
claude-code-baseline/install.sh --with-openclaw-rules --enable-security-defaults
```

Then have Claude write a `docker-compose.yml` containing `user: root`: the
post-write check reports the violation back to Claude after the write (it cannot
undo it). `--enable-security-defaults` refuses, writing nothing, unless a rules file
will exist, and it only enables a config it is creating. On an existing install,
set `modules.securityDefaults.enabled` to `true` yourself.

What it does (idempotent — safe to re-run):

1. Copies hooks to **`.claude/hooks/baseline/`** (namespaced — never collides
   with a repo's own `.claude/hooks/`). The whole `.claude/hooks/baseline/` tree
   is replaced on each run, so removed hooks don't linger and nothing planted
   there survives; each file the baseline does not ship is named before it goes.
2. Writes **`.claude/baseline.config.json`** *(only if absent — your toggles are
   never clobbered)* and refreshes the JSON schema next to it. A config that is a
   link to a file is kept and only read; a dangling link, or a link to a directory,
   is refused before anything is written. A link at the schema's path is replaced
   by the schema file, never written through.
3. **Merges** the baseline hook wiring + a security deny-list into
   **`.claude/settings.json`**. A `settings.json` that is a link, or not a regular
   file, is refused before anything is written: the merge would read the link's
   target into this repo and its backup. When the merge changes the file, the previous
   one is saved first as `settings.json.bak.<timestamp>` (`.1`, `.2`, … if that
   name is taken), and in a git work tree the backups are added to the repo's local
   `.git/info/exclude` unless git already ignores them; a re-install that changes
   nothing leaves the file and writes no backup. Old backups are never deleted. The merge replaces only baseline-managed
   hook entries, one by one, so a hook of yours that shares a matcher group with
   one stays. Under the events the template wires (`PreToolUse`, `PostToolUse`,
   `Stop`, `ConfigChange`), any hook whose command contains
   `/.claude/hooks/baseline/` counts as baseline-managed: it is removed and the
   template's entries are added back, so a baseline script you wired there by hand,
   under any matcher, is gone after the next install. A baseline script wired under
   any other event is left as it is and reported. It unions the deny-list; your
   `permissions.allow`, `model`, and everything else keep their values. Two
   changes of form: `//` comments are dropped (the installer says so, and the
   backup keeps them), and text is written as UTF-8 except the Unicode
   default-ignorable characters (zero-width, bidi controls, variation selectors,
   tags), non-ASCII spaces, controls, surrogates and private-use characters, which
   are written as `\uXXXX` escapes. A `disableAllHooks` it finds is kept and
   reported, since it turns every baseline hook off. If the
   existing file cannot be parsed, the merge **aborts** — it never treats an
   unreadable settings file as an empty one.

Requires `bash` and Python 3.7 or later (on Windows, a native Windows Python 3.8 or
later, not a Cygwin or MSYS one) as `python3` (or `python`). The installer
uses the interpreter the hooks will use (`python3` first, then `python`, skipping
the Windows Store app execution alias unless it is all there is), launches it once,
and stops before writing anything unless it runs, prints nothing else on stdout,
and is 3.7+ (3.8+ for a Windows Python, and never a Cygwin or MSYS one). The check sees the
installer's `PATH`; if Claude Code runs with a different one, whatever the hooks
resolve there must pass too. Designed to run under WSL, Git Bash, and macOS/Linux shells.
CI runs the full test suite on Linux and Windows, each with its oldest supported Python
and with the newest 3.x.
`.gitattributes` pins shipped shell scripts to LF so a contributor's `autocrlf`
cannot publish a CRLF hook, and value extraction inside the hooks strips `\r`
defensively.

It also runs an **advisory version check**: it compares your live `claude --version`
against `minClaudeCodeVersion` in `baseline.config.json` and prints a warning if
older. This never blocks the install. The floor is the documented minimum for
the behaviours this baseline depends on: shell commands started by the Monitor tool
reaching command-guard (Claude Code 2.1.314), which also covers
`"onFailure": "block"` on the guards (2.1.295) and a `PreToolUse` hook that returns
`"allow"` no longer bypassing a `deny` rule (fixed in 2.1.77). A mod is the
exception: see *What this does not protect against*. See [`RELEASING.md`](RELEASING.md) for the per-release
re-verification checklist behind the pin. On Git Bash/MSYS/Cygwin and WSL hosts
it also prints an advisory note about the Git Bash requirement above.

An existing install keeps its old `.claude/baseline.config.json` (the installer
never rewrites it), so `tools/baseline-status.sh` prints `ok=no` beside its
`minClaudeCodeVersion` (informational; `--strict` does not fail on it); set it
to `"2.1.314"` in that file to clear it. Re-running `install.sh`
does refresh `settings.json` and adds `onFailure` to the guards.

---

## Configure

Everything is toggled in `.claude/baseline.config.json` (validated by
`baseline.config.schema.json`). Enabling a module is a config change only — no
`settings.json` edits. Below is an annotated sketch of it, not the shipped file:
the shipped `baseline.config.json` has every module off, an empty
`extraPatterns`, empty `requireWhenEnv`, `commitGrep` and `tracker`, plus
`version`, `minClaudeCodeVersion`, `baselineVersion` and a `fileRegex` for
`fixTags`; the values here are examples. The comments mark the two keys worth
thinking about before you flip them.

```jsonc
{
  "enforcement": "block",                 // or "warn" — downgrades everything
  "failClosed": true,                     // a control that cannot run refuses the call
  "guardrails": {
    "commandGuard": { "enabled": true, "extraPatterns": ["terraform destroy"] },
    "autoFormat":   { "enabled": false }  // executes repo-supplied binaries — see below
  },
  "modules": {
    "securityDefaults": { "enabled": false, "rulesFile": ".claude/security-defaults.json" },
    "fixTags":          { "enabled": false, "tagMarker": "FIX:", "requireWhenEnv": "AUDIT_CYCLE" },
    "scopeGuard":       { "enabled": false, "scopeFile": ".claude/active-issue-scope.txt" },
    "configGuard":      { "enabled": false },
    "runTests":         { "enabled": false },
    "trackerReminder":  { "enabled": false, "commitGrep": "JIRA-", "tracker": "CHANGELOG.md" },
    "autoStage":        { "enabled": false }
  }
}
```

**`enforcement` and `failClosed` do not reach a guard that fails to run.** The
guards' `"onFailure": "block"` is static in `settings.json`: a guard that cannot
start, times out, or exits with anything but 0 or 2 blocks even under
`enforcement: "warn"` or `failClosed: false`. To let a failed guard through, set
its `onFailure` to `"continue"` in `.claude/settings.json`. `failClosed` still
governs the failures a hook observes from inside itself — no Python, an
unparseable payload, a deleted or truncated matcher, a child past its time budget —
except when the hook cannot read it: a malformed config, or the post-write
dispatcher's config read running past its time bound.

**Before enabling `autoFormat`:** it runs `./node_modules/.bin/prettier` and
`./node_modules/.bin/eslint` from the repo you are working in, honouring that
repo's `prettier.config.js` / `eslint.config.js` and their plugins, and
`dotnet format` builds the project. Cloning an untrusted repo and letting an
agent touch one file is then enough to run whatever that repo planted — the same
primitive (repo-defined content auto-executing without per-command approval) this
baseline exists to contain. Enable it for repos whose toolchain you trust. Only a
literal `true` in a readable config turns it on: a missing key, a missing config,
or an unreadable one keeps it off.

### Authoring `securityDefaults` rules

The checker is generic; the policy lives in a rules file. Each rule says *"when
the file content matches `appliesWhen`, it must (`mustMatch`) or must not
(`mustNotMatch`) contain X"*. Paths are filtered by `infraPattern` /
`skipPathPattern`. Regexes use Python `re` in multiline mode.

```json
{
  "infraPattern": "\\.(ya?ml)$|Dockerfile|docker-compose",
  "rules": [
    { "id": "no-root", "appliesWhen": "^\\s*user:\\s", "mustMatch": "1000:1000",
      "message": "Container user must be non-root (1000:1000)" }
  ]
}
```

See [`examples/security-defaults.openclaw.json`](examples/security-defaults.openclaw.json)
for a full immutable-defaults policy (gateway/MCP bind, cap_drop, read-only fs,
TLS 1.3, skills signing). Copy it to `.claude/security-defaults.json` and adapt —
yourself: scope-guard refuses Claude's edit tools on that path, and `permissions.deny`
refuses them and any shell command whose text names it, so the policy Claude is
checked against is not one Claude can rewrite. A repo
that points `rulesFile` elsewhere is not covered by those entries.

---

## Org rollout

- Keep this directory as the **single source of truth** (its own repo, or vendored
  here). Teams run `install.sh` against their repo; upgrades are a re-run.
- **Commit** `.claude/hooks/baseline/`, `.claude/baseline.config.json`, and the
  schema so the baseline travels with the repo and applies to every contributor.
- **Do not commit** `.claude/settings.local.json` (per-developer overrides) or the
  `settings.json.bak.*` backups (the installer adds those to the repo's local
  `.git/info/exclude` when git does not already ignore them).
- To roll across many repos, loop `install.sh --target <repo>` over a checkout list.

### Review the hooks like the executable content they are

Committing `.claude/hooks/baseline/**` plus the `settings.json` wiring means a
script in the repo **runs automatically on every collaborator's machine** once
they trust the folder, with no per-command approval. Accepting the trust prompt
allows exactly that (GHSA-ph6w-f82w-28w6: until 1.0.87 the prompt did not make it
clear; CVE-2025-59536, fixed in 1.0.111, was a related bug that ran a project's
code before the prompt was accepted). This is what the baseline exists to contain.
A one-line PR to `common.sh` executes on everyone who pulls it. In `claude -p` and
Agent SDK sessions there is no trust dialog at all: Claude Code treats the folder as
trusted, so committed hooks run at once — never point `claude -p` at an unreviewed
branch (a CI job on a pull request's head, say) without `--bare` or
`--settings '{"disableAllHooks": true}'`. So, in every repo that adopts the baseline:

- Add a `CODEOWNERS` entry requiring security review of `/.claude/**` (this repo
  ships [its own](.github/CODEOWNERS) as a model — it names this repo's
  maintainer, `@topazyo`; replace that handle with your security team's before use).
- Turn on branch protection: required review from those owners, and no direct
  pushes to the default branch.
- Treat any diff touching a hook, a permission rule, or the installer as a
  security change, reviewed for what it *executes*, not just what it *checks*.

### Non-overridable floor (managed settings)

For a floor individual devs can't disable, deploy the [`managed/`](managed/README.md)
profile via Claude Code **enterprise managed settings** (an org-admin action).
This `install.sh` template stays the customizable per-repo layer on top of it.
The managed hooks take their posture and every switch that could disarm them or run
repo code from an admin-owned `managed.config.json` beside them, never from the
repo's `.claude/baseline.config.json` (see
[Installing the guardrail scripts](managed/README.md#installing-the-guardrail-scripts-for-the-hooks-block)).

Two properties of that tier are documented by Claude Code and re-checked against
the docs each release (`RELEASING.md`), not run against a real managed deployment
here: a managed **deny** rule holds under `--dangerously-skip-permissions`, and
managed **hooks** survive a lower-tier `disableAllHooks` (the managed README's
acceptance steps run them on a real deploy). Managed hooks have *not* been verified to still
block under `--dangerously-skip-permissions` — don't assume command-guard
survives it until that acceptance step exists.

### Allowlist-primary posture

For an allowlist-primary posture (OWASP: grant only what's needed, deny the
rest), see [`managed/allowlist.example.json`](managed/allowlist.example.json) —
`defaultMode: "dontAsk"` (default-deny) + a minimal `allow` + the secrets `deny`
+ an OS-level `sandbox`. Three things to get right:

- A catch-all `deny(**)` plus a narrow `allow` does **not** work: deny always
  beats allow.
- `cat .env` **is** blocked by a `Read(.env*)` deny — `cat`/`head`/`tail`/`sed`
  are file commands Claude Code recognizes in a shell command. The real gap is
  the arbitrary subprocess (`python -c "open('.env').read()"`), and the answer to
  it is `sandbox.filesystem.denyRead`, which is enforced at the OS level for
  every child process.
- `sandbox.network.allowedDomains` alone **prompts**; blocking needs
  `strictAllowlist: true`, and that key is honored only from user, managed, or
  `--settings` scope. Shipped as a repo's `.claude/settings.json`, egress stays
  in prompt mode. `WebFetch` is not sandbox-governed at all.

### Common hardening add-ons

Not in the baseline (they're opinionated), but easy to add to your merged
`settings.json` `permissions.deny` or `commandGuard.extraPatterns`:

- `"WebFetch"` — the all-domains form (content rules take a `domain:` prefix, so
  `WebFetch(*)` matches nothing). Note the docs' own caveat: a `WebFetch` rule
  does not prevent network access. If Bash is allowed, `curl`, `wget` and any
  other runtime still reach the network.
- `"Edit(.github/workflows/deploy*.yml)"` — protect deploy pipelines.

---

## Operator tooling

[`tools/baseline-status.sh`](tools/README.md) reports, across many repos at once,
which have the baseline installed, at what `baselineVersion`, under what posture,
and which have drifted from this source tree:

```bash
tools/baseline-status.sh --drift ~/src/repo-a ~/src/repo-b
tools/baseline-status.sh --strict ~/src/*     # non-zero exit if any repo drifted
```

`--strict` is meant for an operator-run or org-level job. `baseline-ci.yml` does
not invoke it — a cross-repo drift check needs the consumer repos, which this
repo's CI does not have. Its only exerciser today is `tests/test_status.sh`.
Installation is detected from the presence of `.claude/hooks/baseline/`; beyond
that, the tool checks `settings.json` and `settings.local.json` for risky `env`
values, `disableAllHooks`, baseline hooks not launched or not wired as the template
wires them (including a guard without `onFailure: block`), a baseline hook entry in
`settings.local.json`, baseline deny-list entries missing from `settings.json`,
subagent, skill or command definitions naming the baseline hook directory, a `settings.json`
that is missing or cannot be read, and a `baseline.config.json` that cannot be read.
See
[`tools/README.md`](tools/README.md).

---

## Disable / uninstall

- Disable one hook: set its `enabled` to `false` in `baseline.config.json`.
- Disable everything fast: set `"enforcement": "warn"` (nothing blocks).
- Full removal: delete `.claude/hooks/baseline/`, remove the baseline hook
  groups from `.claude/settings.json` (or restore a `settings.json.bak.*`), and
  delete `.claude/baseline.config.json`. trackerReminder's session memory, if it
  ever ran, is in `.git/baseline/` (per worktree); delete that too.

---

## Testing

```bash
bash tests/run.sh   # bash -n + py_compile + matcher + merge fixtures + hook integration tests
```

Any change to what the baseline enforces — `hooks/`, `lib/`, `tools/`, `managed/`,
`examples/`, `tests/`, the installer, the config, its schema, the settings template,
`.gitattributes`, `.gitmodules` and the CI workflows (root-level docs and READMEs
aside) — must ship with an added or modified enforcement fixture file. `tests/policy-change-gate.sh`
fails the pull request otherwise; CI runs the **base branch's** copy of it, as a
required check. It is a tripwire for mistakes, not a boundary: a pull request can
edit the workflow that runs it, and only a reviewer reading that diff stops it.
See [`tests/README.md`](tests/README.md).

## Layout

```
claude-code-baseline/
├── install.sh                         # bootstrap (copy + merge, idempotent)
├── baseline.config.json               # default config (copied to target if absent)
├── baseline.config.schema.json        # schema for the config
├── settings.template.json             # hook wiring + deny-list merged into target
├── README.md                          # this file
├── README.he.md                       # Hebrew overview + "What this does not protect against"
├── ONBOARDING.md                      # how Claude Code hooks/permissions actually work
├── ONBOARDING.he.md                   # complete Hebrew translation of ONBOARDING.md
├── ROADMAP.md                         # enhancement roadmap (planned + deferred work)
├── RELEASING.md                       # per-release re-verification checklist
├── SECURITY.md                        # private vulnerability reporting + scope
├── LICENSE                            # Apache-2.0
├── .gitignore  .gitattributes         # junk exclusion; LF-pinned shell scripts
├── .github/
│   ├── CODEOWNERS                     # review routing (advisory with one maintainer)
│   └── workflows/
│       ├── baseline-ci.yml            # CI: test suite, both OSes
│       └── policy-gate.yml            # CI: policy-change release gate, on PRs
├── lib/
│   └── merge_settings.py              # install-time JSON merge
├── examples/
│   └── security-defaults.openclaw.json
├── managed/                           # enterprise non-overridable floor
│   ├── managed-settings.json          # deny-list + guardrails as managed settings
│   ├── managed-settings.strict.json   # + allowManaged*/strictPluginOnlyCustomization
│   ├── allowlist.example.json         # allowlist-primary profile (dontAsk + sandbox)
│   └── README.md                      # per-OS deploy + acceptance verification
├── tools/                             # operator tooling (see "Operator tooling")
│   ├── baseline-status.sh             # cross-repo posture + drift report
│   └── README.md
├── tests/                             # adversarial suite + release gate
│   ├── run.sh                         # aggregate runner (local + CI)
│   ├── test_command_guard.py          # matcher fixtures (originals + evasions + FPs)
│   ├── test_merge_settings.py         # settings-merge fixtures (per-hook ownership)
│   ├── test_hooks.sh                  # end-to-end hook integration tests
│   ├── test_managed.sh                # validates the managed/ enterprise profiles
│   ├── test_status.sh                 # exercises tools/baseline-status.sh
│   ├── policy-change-gate.sh          # fails policy changes lacking updated fixtures
│   ├── translation_sync.py            # Hebrew-docs drift check (+ stamp / mark-stale)
│   ├── test_translation_sync.py       # fixtures proving the drift check catches each defect
│   └── README.md
└── hooks/                             # copied to target .claude/hooks/baseline/
    ├── VERSION                        # baselineVersion stamp (a convention, not a checksum)
    ├── lib/
    │   ├── common.sh                  # shared payload/config helpers
    │   └── command_guard_match.py     # token-aware command matcher
    ├── guardrails/
    │   ├── command-guard.sh
    │   └── auto-format.sh
    ├── dispatcher/
    │   └── post-write.sh              # PostToolUse entry point
    └── modules/
        ├── security-defaults.sh
        ├── fix-tags.sh
        ├── scope-guard.sh
        ├── config-guard.sh            # ConfigChange tamper-detection
        ├── run-tests.sh
        ├── tracker-reminder.sh
        └── auto-stage.sh
```

---

## Security

Report vulnerabilities privately through GitHub's Private Vulnerability
Reporting — see [`SECURITY.md`](SECURITY.md), which also states what is in scope
(a control that silently fails to fire) and what is not (the documented limits in
[What this does not protect against](#what-this-does-not-protect-against)).

## License

[Apache-2.0](LICENSE). The hook scripts carry `SPDX-License-Identifier:
Apache-2.0` headers because `install.sh` copies them out of this repo and into
yours, where they are detached from this LICENSE file.
