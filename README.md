# claude-code-baseline

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
| `ConfigChange` | configGuard | Detection after the fact, within the session. |
| `Stop` | trackerReminder | Advisory text only. |

`"enforcement": "warn"` downgrades every one of the above to a printed message.

There is also `"failClosed": true`: when a control *cannot run* (no Python, an
unparseable payload, a deleted or truncated matcher, a hook child that blew its
time budget), the hook says so loudly and — under `block` — refuses the call
rather than waving it through as clean.

### Guardrails

- **command-guard** — `PreToolUse(Bash|PowerShell)`, **enabled by default**.
  Blocks a curated set of destructive / unapproved shell commands: `rm -rf /`
  and friends, `git push --force` (including `+refspec` forms), `git reset
  --hard`, dangerous SQL (`drop/truncate table`, `delete from`), remote fetch
  via `curl`/`wget` (including scheme-less hosts, since both default to HTTP),
  and package installs (`npm/pnpm/yarn/pip install`). The matcher is
  token-aware: it resolves quoting, `${IFS}`, wrapper paths (`/bin/rm`,
  `sh -c`, `xargs`), `.exe` suffixes, newline-separated and compound commands,
  and blocks anything it cannot parse. Extend per repo via
  `guardrails.commandGuard.extraPatterns`.
- **auto-format** — `PostToolUse(Write|Edit)`, **disabled by default**. Formats
  changed files with prettier/eslint, black, or `dotnet format`. It ships off
  because it is the one hook that *executes code the target repository
  supplies* — `./node_modules/.bin/*`, repo-controlled `prettier.config.js` /
  `eslint.config.js` and their plugins, and `dotnet format` builds the project.
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

1. **The hook command is `bash "…/command-guard.sh"`.** On a Windows host with
   no `bash` on `PATH` the hook cannot launch, and Claude Code treats a hook
   that never launches as fail-**open**. On such a host the `permissions.deny`
   rules — which the CLI enforces itself, with no shell involved — are the only
   control that actually runs.
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
| `scopeGuard` | PreToolUse | Refuse edits to files outside a declared task scope (`.claude/active-issue-scope.txt`). Genuinely blocking under `block` — the write never happens. |
| `configGuard` | ConfigChange | Detect in-session tampering of `.claude/settings.json` — baseline hooks unwired, deny-list stripped, or `disableAllHooks` set. **Off by default; detection after the change, not prevention; in-session only; watches `.claude/settings.json` only** — never `baseline.config.json` and never the hook scripts. A `local_settings` group for `.claude/settings.local.json` is wired in the template, but the handler is not implemented yet, so that source is currently inert. |
| `runTests` | PostToolUse | Run the right test/lint per file type (pytest, shellcheck/bats, yamllint/actionlint). Missing tools are skipped. Reports to Claude after the write; cannot undo it. |
| `trackerReminder` | Stop | Remind to update a tracking doc when matching commits exist this session. Never blocks. |
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
  `"enforcement": "warn"`) turns every blocking control in the product into a
  print statement for the rest of the session. **Only enterprise
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
  any binary that simply isn't on the list all pass uninspected.
- **PostToolUse cannot undo a write.** `securityDefaults`, `fixTags` and
  `runTests` report a violation *after* the file has changed on disk. They give
  Claude a chance to fix it; they do not prevent it.
- **Whole tool families are unhooked.** Hooks cover the shell tools and
  `Write|Edit` only. `WebFetch`, `WebSearch` and every `mcp__*` tool have no
  hook and no deny rule here. `curl`/`wget` are the two most common fetch
  binaries — any other runtime (`python -c "urllib.request.urlopen(…)"`,
  `nc`, a language SDK) reaches the network freely. **Egress control belongs to
  the OS sandbox, not to this baseline.**
- **A hook that cannot launch fails open.** That is Claude Code's behaviour, not
  a setting. `failClosed` covers the cases the hook *can* observe from inside
  itself; a host with no `bash`, or a hook killed at the Claude Code timeout,
  produces no exit code at all and the call proceeds.
- **Config tampering by a human or an external process is largely uncovered.**
  `configGuard` is off by default, and even enabled it sees only in-session
  `.claude/settings.json` changes, after they land.
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
claude-code-baseline/install.sh --dry-run         # preview, change nothing
```

What it does (idempotent — safe to re-run):

1. Copies hooks to **`.claude/hooks/baseline/`** (namespaced — never collides
   with a repo's own `.claude/hooks/`). The baseline subtree is replaced wholesale
   on each run so removed hooks don't linger.
2. Writes **`.claude/baseline.config.json`** *(only if absent — your toggles are
   never clobbered)* and refreshes the JSON schema next to it.
3. **Merges** the baseline hook wiring + a security deny-list into
   **`.claude/settings.json`**, backing up the previous file to
   `settings.json.bak.<timestamp>` first. The merge replaces only baseline-managed
   entries (matched by their `/.claude/hooks/baseline/` command path) and unions
   the deny-list; your `permissions.allow`, `model`, and everything else are left
   untouched. If the existing file cannot be parsed, the merge **aborts** — it
   never treats an unreadable settings file as an empty one.

Requires `bash` and `python3` (or `python`). Designed to run under WSL, Git Bash,
and macOS/Linux shells. `.gitattributes` pins shipped shell scripts to LF so a
contributor's `autocrlf` cannot publish a CRLF hook, and value extraction inside
the hooks strips `\r` defensively.

It also runs an **advisory version check**: it compares your live `claude --version`
against `minClaudeCodeVersion` in `baseline.config.json` and prints a warning if
older. This never blocks the install. The floor exists for one behaviour this
baseline depends on — a `deny` rule being enforced unconditionally, including
against a `PreToolUse` hook that returns `"allow"` (fixed in Claude Code 2.1.77).
See [`RELEASING.md`](RELEASING.md) for the per-release re-verification checklist
behind the pin.

---

## Configure

Everything is toggled in `.claude/baseline.config.json` (validated by
`baseline.config.schema.json`). Enabling a module is a config change only — no
`settings.json` edits. Below is what ships; the comments mark the two keys worth
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
TLS 1.3, skills signing). Copy it to `.claude/security-defaults.json` and adapt.

---

## Org rollout

- Keep this directory as the **single source of truth** (its own repo, or vendored
  here). Teams run `install.sh` against their repo; upgrades are a re-run.
- **Commit** `.claude/hooks/baseline/`, `.claude/baseline.config.json`, and the
  schema so the baseline travels with the repo and applies to every contributor.
- **Do not commit** `.claude/settings.local.json` (per-developer overrides) or the
  `settings.json.bak.*` backups.
- To roll across many repos, loop `install.sh --target <repo>` over a checkout list.

### Review the hooks like the executable content they are

Committing `.claude/hooks/baseline/**` plus the `settings.json` wiring means a
script in the repo **runs automatically on every collaborator's machine**, with
no per-command approval — the CVE-2025-59536 pattern this baseline exists to
contain. A one-line PR to `common.sh` executes on everyone who pulls it. So, in
every repo that adopts the baseline:

- Add a `CODEOWNERS` entry requiring security review of `/.claude/**` (this repo
  ships [its own](.github/CODEOWNERS) as a model — replace `@OWNER` before use).
- Turn on branch protection: required review from those owners, and no direct
  pushes to the default branch.
- Treat any diff touching a hook, a permission rule, or the installer as a
  security change, reviewed for what it *executes*, not just what it *checks*.

### Non-overridable floor (managed settings)

For a floor individual devs can't disable, deploy the [`managed/`](managed/README.md)
profile via Claude Code **enterprise managed settings** (an org-admin action).
This `install.sh` template stays the customizable per-repo layer on top of it.

Two properties of that tier are actually verified here: a managed **deny** rule
holds under `--dangerously-skip-permissions`, and managed **hooks** survive a
lower-tier `disableAllHooks`. Managed hooks have *not* been verified to still
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
repo's CI does not have. Its only exerciser today is `tests/test_status.sh`. Note
also that installation is detected from the presence of `.claude/hooks/baseline/`;
the tool does not currently verify the `settings.json` wiring. See
[`tools/README.md`](tools/README.md).

---

## Disable / uninstall

- Disable one hook: set its `enabled` to `false` in `baseline.config.json`.
- Disable everything fast: set `"enforcement": "warn"` (nothing blocks).
- Full removal: delete `.claude/hooks/baseline/`, remove the baseline hook
  groups from `.claude/settings.json` (or restore a `settings.json.bak.*`), and
  delete `.claude/baseline.config.json`.

---

## Testing

```bash
bash tests/run.sh   # bash -n + py_compile + matcher fixtures + hook integration tests
```

Any change to the matcher, the deny-list, or a guard hook must ship with a
fixture — `tests/policy-change-gate.sh` (run in CI on PRs) fails a policy change
that lacks updated tests. See [`tests/README.md`](tests/README.md).

## Layout

```
claude-code-baseline/
├── install.sh                         # bootstrap (copy + merge, idempotent)
├── baseline.config.json               # default config (copied to target if absent)
├── baseline.config.schema.json        # schema for the config
├── settings.template.json             # hook wiring + deny-list merged into target
├── README.md                          # this file
├── ONBOARDING.md                      # how Claude Code hooks/permissions actually work
├── ROADMAP.md                         # enhancement roadmap (planned + deferred work)
├── RELEASING.md                       # per-release re-verification checklist
├── SECURITY.md                        # private vulnerability reporting + scope
├── LICENSE                            # Apache-2.0
├── .gitignore  .gitattributes         # junk exclusion; LF-pinned shell scripts
├── .github/
│   ├── CODEOWNERS                     # security review on hooks/permissions/installer
│   └── workflows/baseline-ci.yml      # CI: test suite + policy-change gate
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
│   ├── test_hooks.sh                  # end-to-end hook integration tests
│   ├── test_managed.sh                # validates the managed/ enterprise profiles
│   ├── test_status.sh                 # exercises tools/baseline-status.sh
│   ├── policy-change-gate.sh          # fails policy changes lacking updated fixtures
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
