# claude-code-baseline — managed (enterprise floor)

> The **non-overridable** org floor (ROADMAP **R6**). The bootstrap `install.sh`
> ships a *copyable, per-repo* baseline that a developer can disable. This profile
> promotes the load-bearing parts — the secrets/tamper **deny-list** and the
> always-on **guardrail hooks** — into Claude Code **managed settings**, the
> highest-precedence tier. Two properties are documented, and they are different
> properties: a managed **`deny` rule** cannot be overridden by user, project, or
> local settings, by `--allowedTools`, or by `--dangerously-skip-permissions`; a
> managed **hook** cannot be turned off by a `disableAllHooks` set anywhere below the
> managed tier. Neither statement is "managed hooks run under bypass mode" — see
> the acceptance test, which now checks that separately instead of assuming it.
>
> Deploying this is an **org-admin action** (MDM / golden image / config
> management), not a per-repo `install.sh` run. Like everything else here it sends
> **no telemetry** — these are config files and local scripts; nothing phones home.
>
> All facts below were verified against the official Claude Code docs, most recently
> on 2026-10-30 for the managed-source ranking and drop-ins, `/status`, the WSL path,
> and the sandbox (path forms, wildcard limits, the `Read`-rule merge, the unsandboxed
> retry and auto-allow), and on 2026-08-12 for the rest (see Sources). Re-confirm per release via
> [`../RELEASING.md`](../RELEASING.md). Several statements in the 2026-05-31 revision
> of this file were **wrong in the direction of over-claiming**; each is called out
> inline where it was, rather than quietly deleted, because an operator who read the
> old text made deployment decisions on it.

---

## Why a managed floor

The per-repo baseline and even the [`configGuard`](../hooks/modules/config-guard.sh)
tamper hook only govern what they can see: the agent's tools, and one repo's
`.claude/settings.json`. A developer (or a prompt-injected agent that finds a gap)
can still edit their own user settings, pass `--dangerously-skip-permissions`, or
simply not install the baseline. **Managed settings are the only tier that closes
those gaps**, because:

- **A managed `deny` is non-overridable.** *"Rules are evaluated in order: deny →
  ask → allow"*, *"Managed settings have the highest precedence and cannot be
  overridden … including command line arguments"*, and *"if a deny rule matches,
  the tool is blocked, even in bypassPermissions mode."* So the secrets deny-list
  here holds even under `--dangerously-skip-permissions`.
- **Managed hooks can't be turned off from below.** *"disableAllHooks set in user,
  project, or local settings cannot disable … managed hooks. Only disableAllHooks
  set at the managed settings level can disable managed hooks."*
- **Optional total lockdown.** `allowManagedHooksOnly`, `allowManagedPermissionRulesOnly`,
  and `strictPluginOnlyCustomization` make managed settings the *only* source of
  hooks / permission rules / customization (see the strict profile).

This is also where the deliberate **R5 residual** is narrowed the furthest: a managed
`deny` on `.claude/baseline.config.json`, `.claude/settings.json`,
`.claude/settings.local.json`, and `.claude/hooks/baseline/**` blocks the agent from
tampering with the baseline *non-overridably and in every repo* — not just the one repo
`configGuard` watches.

> **Read "blocks the agent from tampering" precisely.** Until 2026-08 those were
> `Edit()` rules only, which bind Claude's Edit tool — so `sed -i` or `echo {} >` on the
> same path went through untouched, and one shell write turned every blocking control in
> the baseline into a print statement. The profiles now also carry verb-agnostic
> **path-text** rules — `Bash(*.claude/baseline.config.json*)` and PowerShell forward- and
> backslash variants — which do cover the shell path. Understand what a text rule can and
> cannot do: it matches the **command string**, so `cd .claude && sed -i … settings.json`
> and `sed -i … "$CFG"` are *not* matched, and command-guard's own tamper rule is the
> other half of that coverage. And it is still a **permission** control, not a filesystem
> one: it governs what Claude Code will run, not what a human at a terminal, a Makefile,
> or a CI job can write. A deliberate side effect worth knowing before you deploy:
> read-only shell access to those paths (`cat .claude/settings.json`,
> `git add .claude/settings.json`) is refused too.

---

## Where managed settings live (highest precedence)

Deploy the chosen profile (renamed to **`managed-settings.json`**) to the
OS-specific path:

| OS | Path |
|----|------|
| macOS | `/Library/Application Support/ClaudeCode/managed-settings.json` |
| Linux / WSL | `/etc/claude-code/managed-settings.json` |
| Windows | `C:\Program Files\ClaudeCode\managed-settings.json` |

> Windows note: Claude Code does not read the legacy
> `C:\ProgramData\ClaudeCode\managed-settings.json` path (deprecated in v2.1.75) — use
> `C:\Program Files\ClaudeCode\`.

**Precedence (high → low):** managed settings → CLI args (`--settings`) → local
project (`.claude/settings.local.json`) → project (`.claude/settings.json`) → user
(`~/.claude/settings.json`). The managed tier wins outright — that is the property
the floor depends on, and it is the core verified fact here.

> **⚠️ Within the managed tier only one source applies by default, and that can drop
> this whole floor.** Claude Code checks the managed sources in this order, highest
> first: remote settings (server-managed, from the claude.ai admin console or a
> gateway); an MDM or OS policy (a macOS plist, or Windows
> `HKLM\SOFTWARE\Policies\ClaudeCode`); the file-based `managed-settings.json`, with
> every `managed-settings.d/*.json` merged after it in alphabetical order; and last the
> user-writable `HKCU\SOFTWARE\Policies\ClaudeCode`. Under the default
> `managedSourcesBehavior: "first-wins"`, the highest-ranked source that delivers any
> policy key is used and the others are **ignored, with no warning** — apart from a
> short list of keys read from every admin source (sandbox locks, MCP server lists,
> `env`, `sandbox.network.strictAllowlist` and a few more; `permissions` and `hooks`
> are not among them). So an organization that already delivers an MDM/HKLM policy
> never applies this file: not its deny-list, not its hooks. Remote settings count only
> in a session that authenticates to Anthropic's API directly with an eligible
> credential, signs in to a Claude apps gateway with `/login`, or runs in Claude
> Desktop's Code tab behind a gateway that serves settings; otherwise (another provider,
> or `ANTHROPIC_BASE_URL` pointing elsewhere) the check starts at the next source, so
> one machine can apply this file in one session and skip it in another. A shadowed
> [allowlist profile](#allowlist-primary-profile-r7) still contributes its cross-source
> `strictAllowlist: true`, but none of its `allowedDomains` unless an admin source turns
> on `allowManagedDomainsOnly`.
>
> - After deploying, run `/status` and read **Setting sources** (the source in use) and
>   **Skipped sources** (v2.1.242+, within the 2.1.295 pin), which names a source that
>   a higher one overrode.
> - To combine sources, set `managedSourcesBehavior: "merge"` (v2.1.242+) in the
>   highest-ranked source you deploy — not in this file: `managed-settings.json` is the
>   lowest-ranked admin source, so `"merge"` set there has nothing below it to combine
>   with, and a machine that never receives server-managed settings needs the key in its
>   MDM profile too. Lists such as `permissions` rules and `hooks` then combine from
>   every admin source, lower ones included, so turn it on only when every source below
>   the highest is under an administrator's control. `permissions.defaultMode` is still
>   read only from the highest-ranked source that carries a policy key, even when that
>   source sets no mode, so the allowlist profile's `dontAsk` applies only from that
>   source. Otherwise deliver this file's contents through the source you already use.
> - **Drop-ins can override the floor.** `managed-settings.d/*.json` files merge after
>   `managed-settings.json`; lists such as `permissions.deny` and `hooks` combine, but
>   for a single value the later file wins, so a drop-in can set `disableAllHooks: true`
>   or turn the strict profile's `allowManagedHooksOnly` /
>   `allowManagedPermissionRulesOnly` back off. Sorting last protects only the single
>   values a file sets (for this floor, the strict profile's two locks), so audit every
>   other drop-in for `disableAllHooks: true` whatever its name, and give the floor a
>   name that sorts after every other drop-in. Drop-ins are also the way to deploy the
>   allowlist profile next to this floor.
>
> *(Verified against the managed-settings and settings-reference docs on 2026-10-30.)*

Because these directories are root/admin-owned, a normal developer cannot edit the
floor — distribute the file via MDM, a golden image, or config management. **Except on
WSL:** there `/etc/claude-code` is user-writable, so a floor deployed only there can be
edited by the developer. Deploy the floor itself through the Windows policy chain
instead — in `HKLM\SOFTWARE\Policies\ClaudeCode` or in `C:\Program Files\ClaudeCode\`
(`managed-settings.json` or a drop-in there) — together with
`wslInheritsWindowsSettings: true` (v2.1.282+, within the pin). WSL sessions then read
the Windows policy, and `/etc/claude-code` only when no Windows admin document is
present. A Windows source that holds only that key is not a policy source, so
`/etc/claude-code` would still supply the policy. One more catch, unverified because
the docs say nothing about translating hook paths for a Windows-sourced policy in WSL:
the floor's hook commands use one absolute `<BASELINE_PREFIX>`, and the same document
then serves both Windows and WSL sessions. No path resolves in both (`C:/…` in Git
Bash, `/mnt/c/…` in WSL), so with `onFailure: "block"` one of them may refuse every
shell command. On such machines, deploy the config-only floor (no `hooks` block)
through the Windows chain, or run floor steps 0 and 3 in both a Windows and a WSL
session before rollout, and in each confirm that a harmless command such as `ls` runs
(a guard that cannot start refuses every command, so step 3 alone passes either way).

---

## The two profiles

Pick one, **rename it to `managed-settings.json`**, and deploy:

| File | What it enforces | Disruption |
|------|------------------|------------|
| [`managed-settings.json`](managed-settings.json) | Non-overridable **deny-list** (secrets + baseline self-protection) **+** the always-on **guardrail hooks** (command-guard, post-write dispatcher) as *managed* hooks. User/project hooks still run *in addition*. | Low — teams keep their own hooks and permission rules. |
| [`managed-settings.strict.json`](managed-settings.strict.json) | Everything above **plus** `allowManagedPermissionRulesOnly`, `allowManagedHooksOnly`, and `strictPluginOnlyCustomization: ["skills","hooks","agents","mcp"]`. **Only** managed (and force-enabled-plugin) hooks/rules/customization apply. | **High** — disables per-repo hooks, permission rules, and user/project skills/agents/MCP. Deploy only if that lockdown is your intent. |

> **Config-only floor (no scripts).** If you want only the non-overridable
> deny-list and not the managed hooks, delete the `"hooks"` block from the profile
> before deploying. The deny-list needs nothing installed and is the highest-value,
> zero-dependency win.

**Deny-list notes (read before deploying):**

- **The managed deny is now identical to the per-repo template's deny.** It used to
  diverge by one entry — `Edit(.claude/settings.local.json)` — on the reasoning that a
  per-repo control can't usefully own a file the developer is meant to own locally. That
  reasoning was wrong about the threat: `settings.local.json` is an *overlay that
  outranks* `settings.json`, so `{"disableAllHooks": true}` written there turned off
  every baseline hook, in a file nobody was watching and no rule covered. The per-repo
  template now denies it too. Keep the two lists equal; `tests/test_managed.sh` asserts
  the managed floor is never weaker than the template.
- **Shell coverage: `Bash|PowerShell`.** Both profiles' hook matchers are
  `"Bash|PowerShell"`, not `"Bash"`. On Windows without Git Bash, Claude Code doesn't
  register the Bash tool at all, so a `Bash`-only matcher never fired there — the floor
  looked deployed and inspected nothing. The deny list carries a PowerShell command floor
  to match (`Remove-Item`/`rm`/`del`/`rmdir`, `Invoke-WebRequest`/`iwr`/`Invoke-RestMethod`/`irm`/
  `curl`/`wget`, `Invoke-Expression`/`iex`, forced push). The `.exe` and alias entries are
  not padding: under PowerShell 7 `curl` and `wget` are the native `curl.exe`/`wget.exe`
  rather than aliases, so alias resolution never reaches them. `Remove-Item` is denied
  outright rather than in a `-Recurse -Force` form, because PowerShell parameter
  abbreviation and free flag order make a targeted text pattern a rule that only *appears*
  to work.
  > **What a missing Git Bash does.** The managed `hooks` commands are `bash "<PREFIX>/…"`.
  > When Claude Code cannot find Git Bash, a hook with no `shell` runs in PowerShell, where
  > `bash "…"` fails. Both profiles set `"onFailure": "block"` on command-guard, so on
  > v2.1.295+ that fails **closed**: every shell command is refused (since 2.1.299 even
  > without `onFailure`). Git for Windows (or `CLAUDE_CODE_GIT_BASH_PATH` pointing at its
  > `bash.exe`) is therefore a requirement on Windows fleets; WSL's `bash` does not count
  > for a Claude Code running natively on Windows. Below v2.1.295 `onFailure` is
  > unsupported and a hook that cannot start most likely fails open, as before
  > (unverified). There, the deny rules are the entire floor — which is a real argument
  > for deploying the config-only subset below to such fleets rather than assuming the
  > hooks cover them.
- **Over-blocking is non-overridable here.** `Read(.env*)` matches non-secret files like
  `.env.example` / `.env.sample`, and `**/secrets/**` matches any `secrets/` dir
  (including non-sensitive fixtures). At the per-repo tier a team can override this; at the
  managed tier they **cannot** — if a team has a legitimate read need, it must be carved
  out at the managed level (the only tier that can), or tighten the glob there. This is the
  right enterprise tradeoff, but it is a real, org-wide, non-overridable block.
- **`strict` disables user/project MCP servers — and until 2026-08 it silently did not.**
  The key's valid surface names are `skills` / `agents` / `hooks` / **`mcp`**, and an
  unrecognized name is *silently ignored* — no error, no warning. This profile shipped
  `mcpServers`, so the MCP third of the lockdown was inert while this README asserted it
  as fact twice. It now lists `mcp`. If you deployed the earlier profile believing MCP was
  locked down, it was not: re-deploy and confirm with the acceptance step below that a
  project `.mcp.json` server does not load. The same silent-ignore behavior is why
  `../RELEASING.md` re-checks the surface names every release.

### Installing the guardrail scripts (for the `hooks` block)

The managed `hooks` commands reference `<BASELINE_PREFIX>` — **replace it** with
the absolute path where you deploy a copy of this repo's `hooks/` tree on every
machine, e.g. `/opt/claude-code-baseline/hooks` (POSIX) or
`C:\Program Files\ClaudeCode\baseline-hooks` (Windows). Steps:

1. Copy `claude-code-baseline/hooks/` to that fixed path on the golden image / via
   config management (it must be present for the managed hooks to run).
2. Substitute `<BASELINE_PREFIX>` in the deployed `managed-settings.json` with that
   absolute path (forward slashes work on all platforms).
3. The scripts read per-repo `.claude/baseline.config.json` when present and fall
   back to safe defaults (`block` posture, `failClosed: true`, guardrails on) when
   a repo has no config — so the floor works even in repos that never ran `install.sh`.

> Repos that *also* ran `install.sh` will have their own per-repo command-guard in
> addition; the duplicate run is harmless (both block the same things). For a single
> source of truth, prefer the managed hooks and skip per-repo wiring (or use the
> strict profile, which blocks the per-repo hooks anyway).

---

## Scale-out distribution: a force-enabled marketplace plugin (advanced)

Instead of copying scripts to a fixed path, an org can package the hooks as a
**marketplace plugin** and force-enable it via managed settings:

- Add the plugin to `enabledPlugins` in managed settings (force-enabled — users
  cannot disable it). A force-enabled plugin's hooks are **exempt** from
  `allowManagedHooksOnly`, so they keep running under the strict profile.
- Point Claude Code at your internal marketplace via the documented marketplace
  keys, then list the plugin in `enabledPlugins`.

This avoids the per-machine script copy and gives versioned distribution, but it
requires hosting a marketplace and packaging the hooks as a plugin. **Before
publishing, verify the current plugin *hooks* manifest schema against the live
plugins docs** — this repo ships the managed-hooks form (verified) and documents the
plugin path at the level confirmed here (the `enabledPlugins` force-enable + the
`allowManagedHooksOnly` exemption), without a fabricated plugin manifest.

---

## Allowlist-primary profile (R7)

OWASP's posture is **allowlist-primary** — grant only what's needed and deny the
rest — with denylists as defense-in-depth *secondary*. The baseline so far is
denylist-centric (block secrets / destructive commands). [`allowlist.example.json`](allowlist.example.json)
is a starter profile for the inverse posture: **only explicitly-allowed actions run.**

**The naive approach does NOT work.** A catch-all `deny` plus narrow `allow`
(`deny: ["Read(**)"]` + `allow: ["Read(src/**)"]`) is a dead end — Claude Code
evaluates **deny → ask → allow** categorically and **deny always wins**, so the
catch-all deny would block the allowlisted paths too. (Verified against the
permissions docs.) The supported allowlist-primary mechanism is instead:

- **`permissions.defaultMode: "dontAsk"`** — default-deny. *"dontAsk mode auto-denies
  every tool call that would otherwise prompt. Only actions matching your
  `permissions.allow` rules and read-only Bash commands can execute."* So you list the
  tools/paths the agent may use in `allow`, and everything else is auto-declined (no
  prompt). It does **not** auto-approve — it is the opposite of `bypassPermissions`.
- **`permissions.allow`** — the allowlist itself. Keep it minimal and **grant narrow,
  never broad-then-subtract** (see the deny-reliability caveat below). The example
  allows repo-relative file access (`Read/Edit/Write(./**)`) and a small set of safe
  Bash commands — **adapt this list to your repo's real workflow.**
- **The secrets/tamper `deny` is retained as a backstop.** Because deny beats allow, a
  `.env` matching the broad `Read(./**)` allow **and** the `Read(.env*)` deny → **deny
  wins → the read is blocked.** That covers Claude's own file tools *and* the file
  commands Claude Code recognizes inside a shell command (`cat`, `head`, `tail`, `sed`,
  `grep`). What it does not cover is a subprocess that opens the file itself — see the
  secrets-read boundary below.
- **`sandbox`** (filesystem + network) — OS-level isolation on **macOS, Linux, and
  WSL2** (native Windows is **not** supported — run inside WSL2). The sandbox is enforced
  by the OS against **every sandboxed command and its child processes**, which is what
  makes it, and not the permission checks, the answer to the subprocess-read case. Its
  read block comes from two places, which Claude Code merges into one sandbox
  configuration: `filesystem.denyRead`, and the `Read` deny rules. The example's
  `denyRead` holds the credential dirs only (`~/.aws`, `~/.ssh`, `~/.gnupg`, …),
  because the file is meant for managed settings, where a project-relative `./` path
  has no documented meaning. The repo's secrets are meant to be covered by its
  `Read(.env*)` and `Read(**/secrets/**)` denies: a bare-filename rule matches at any
  depth at or under the working directory. The docs do not spell out how such a rule
  becomes a sandbox path, so the allowlist profile's Verify step 3 checks it (for
  `.env`; check a `secrets/` file the same way). To list them explicitly as well, use
  `./.env`, `./.env.*` and `./secrets` in a repo's `.claude/settings.json` (`./` is
  relative to the project root there), and in managed settings home-anchored patterns
  such as `~/**/.env`, `~/**/.env.*` (this one also blocks `.env.example`) and
  `~/**/secrets`. These cover checkouts under the home directory only; add one entry
  per other top-level directory you check out into (for example `/srv/**/.env`). They
  work on Linux and WSL2 as well, because the wildcard comes after the first directory
  name of the full path. The example sets `allowUnsandboxedCommands: false`,
  `failIfUnavailable: true` and `autoAllowBashIfSandboxed: false` (see the boundary
  note below), and also
  **allowlists outbound network domains** — the control that limits *exfiltration* of
  whatever the agent manages to read, provided you read the scope caveat on
  `strictAllowlist` below.

> **⚠️ Secrets-read boundary — this section was wrong until 2026-08-12.** It previously
> read *"no permission or sandbox setting reliably stops a Bash subprocess from reading a
> local file… `cat .env` returns the secret,"* and the acceptance test below instructed
> operators to confirm exactly that. Both halves were backwards, and an operator who
> believed them would have skipped the control that actually works. The real boundary:
> 1. **`permissions.deny Read(.env*)` covers more than the Read tool.** It binds Claude's
>    own file tools **and the file commands Claude Code recognizes inside a shell command**
>    — `cat`, `head`, `tail`, `sed`, `grep`. So `cat .env` **is refused**, including under
>    `dontAsk`, where read-only Bash otherwise runs without an `allow` entry.
> 2. **The real gap is an arbitrary subprocess**, which Claude Code cannot inspect ahead of
>    time: `python -c "print(open('.env').read())"`, `node -e …`, an interpreter invoked
>    from a build script. No permission check sees inside those before they run.
> 3. **The sandbox closes that gap, in strict sandbox mode.** The OS blocks the read for
>    every child process of a sandboxed command, on the paths in `filesystem.denyRead`
>    and on those of the `Read` deny rules, which Claude Code merges into the sandbox
>    configuration (see the sandbox bullet above for the path forms per deployment).
>    Limits, and what the example does about them:
>    - A command the sandbox blocked can be **retried outside it**. An `allow` rule that
>      matches the command approves that retry with no prompt in any mode, and
>      `bypassPermissions` approves any retry; `dontAsk` denies only a retry that no
>      allow rule matches. So the example sets `sandbox.allowUnsandboxedCommands: false`
>      (strict sandbox mode): Claude Code ignores the `dangerouslyDisableSandbox`
>      parameter, so a retry runs inside the sandbox again. Set in managed settings, it
>      also makes the sandbox admin-required. Keep it if you adapt the profile: without
>      it, the allow-listed `npm test`, `npm run` and `pytest` could read the file on a
>      retry.
>    - Commands that match an `excludedCommands` entry run outside the sandbox. Under
>      this admin-required sandbox Claude Code ignores a repository's entries, but
>      entries in managed settings, `--settings` and the developer's
>      `~/.claude/settings.json` still apply, and no managed-only lock covers the list.
>      The example sets none; a user-level entry such as `npm *` would take the
>      allow-listed builds out of the sandbox.
>    - A machine where the sandbox cannot start (a missing dependency, an unsupported
>      platform) runs commands **unsandboxed** unless `failIfUnavailable` is on. The
>      example sets `sandbox.failIfUnavailable: true`: Claude Code then exits at startup
>      there, and if the sandbox fails later it refuses each sandboxed command. It does
>      not start at all on native Windows with this profile, so deploy it to macOS,
>      Linux and WSL2 machines only. On a Windows machine, WSL gets a policy the user
>      can't edit only through the Windows chain, which native-Windows sessions read
>      too; with this profile there, native-Windows Claude Code does not start.
>      Deployed to `/etc/claude-code` alone, the profile is user-editable (see "Where
>      managed settings live").
>    - With the sandbox on, `autoAllowBashIfSandboxed` (default `true`) runs sandboxed
>      Bash without a prompt in every permission mode except plan mode and a few
>      auto-mode cases. The example sets it to `false`, so sandboxed commands still go
>      through `permissions.allow` and `dontAsk`.
>    - On Linux and WSL2, a wildcard in a sandbox read path works only after the first
>      directory name of the full path: `~/**/.env` works, `/**/.env` covers nothing.
>
>    (The 2026-08-12 revision of this section said the example lists `./.env`,
>    `./.env.*` and `./secrets` under `denyRead`. It does not, because it targets
>    managed settings; corrected 2026-10-30.)
>
> Two things that were right and stay right:
> - **Don't keep real secrets on disk in agent-accessible repos** — use env-var injection
>   or a secret manager; commit only `.env.example`. The sandbox is a per-session control;
>   hygiene is a property of the repository, and it is the one that survives the session
>   ending, the profile not being deployed, and a developer running some other tool.
> - **The network allowlist** limits where anything read can be *sent*. Domain-based — it
>   raises the bar, not a hermetic seal; raw-IP or non-HTTP channels may evade it. And see
>   the scope caveat immediately below, because by default it asks rather than blocks.
>
> **⚠️ `allowedDomains` alone PROMPTS; it does not block.** Blocking requires
> `sandbox.network.strictAllowlist: true` — which is honored from **user settings, managed
> settings, or a `--settings` file only**. In a repository's own `.claude/settings.json` it
> has no effect. That is a problem for the "deploy as a per-repo `settings.json`" option
> below: deployed that way, this profile leaves egress in prompt mode, and the acceptance
> step that expected a hard block would have failed for a reason the old text couldn't
> explain. If you need egress to be a block rather than a question, deploy through managed
> settings (or use the org-wide `allowManagedDomainsOnly`). Note also what the sandbox does
> not reach: `WebFetch` is not sandbox-governed — though domains from `WebFetch(domain:…)`
> **allow** rules do join the same allowlist `strictAllowlist` enforces.
>
> **Other limits:**
> - **Deny-precedence reliability.** Community reports (e.g. anthropics/claude-code
>   #45511) describe a *specific* deny not reliably narrowing a *broad* allow for Bash
>   command patterns. This is the concrete reason to **grant narrow, not broad-then-subtract**
>   — the whole point of allowlist-primary. Treat as edge cases to design around, not
>   confirmed Anthropic behavior; the file-path Read-tool `deny` is the reliable part.
> - **Sandbox path syntax:** absolute (`/tmp/build`), home-relative (`~/`), or — for
>   project settings — project-relative `./` or no prefix at all (in user settings `./`
>   is relative to `~/.claude`; for managed settings the docs define no meaning). The
>   `//` root-relative form belongs to *permission rules*, although the sandbox accepts it
>   for absolute paths too. So a repo-local `.env` can go in a repo's own `denyRead`;
>   the managed example uses absolute and `~/` paths only. The working directory is
>   writable by default; `allowWrite` adds dirs beyond it.
> - The example grants broad repo-file access (`Read/Edit/Write(./**)`) for usability and
>   relies on the file-path deny; narrow it to specific dirs for a high-assurance repo to
>   better practice "grant narrow."

**Deploy as:** a per-repo `.claude/settings.json` for a high-assurance repo (opt-in,
high-friction — every needed action must be pre-approved), or promote `defaultMode:
"dontAsk"` + `allow` into the managed tier for an **org-wide** allowlist-only lockdown
(very strict — confirm that is your intent). Either way, keep the secrets `deny` and
the R6 guardrail hooks alongside.

> **The two options are not equivalent, and the difference is not friction.**
> `sandbox.network.strictAllowlist` is ignored in a repository's own `settings.json`, so
> the per-repo deployment gives you a *prompting* network allowlist while the managed
> deployment gives you a *blocking* one. Pick per-repo for the permission-rule benefits;
> don't pick it and then describe egress as controlled. The sandbox keys this profile
> sets may not hold per-repo either: the docs say a `false` from user,
> `--settings` or managed settings holds over a project's `true`, but promise nothing
> of the kind for a repo's own file, and `/sandbox` writes its Mode and Overrides
> choices to `.claude/settings.local.json`, which outranks it. So per-repo, a developer
> may be able to turn auto-allow or the retry back on, or `failIfUnavailable` off.

**Verify (acceptance):** with the profile active —
1. **Read tool blocked:** ask the agent to read a repo `.env` *with the Read tool* — it
   must be **blocked** by the deny even though `Read(./**)` is allowed.
2. **`cat .env` blocked too:** ask it to run `cat .env` via the shell. It must be
   **refused** — `cat` is a file command Claude Code recognizes, so the `Read(.env*)` deny
   applies even though read-only Bash otherwise runs freely under `dontAsk`. *(If this
   returns the file contents, stop and re-check the deny rule: an earlier revision of this
   document told operators to expect exactly that, and it was wrong.)*
3. **Script-based read blocked by the sandbox, not by a permission check:** put a canary
   in the repo's `.env` (say `CANARY=step3`), then have Claude run an allow-listed
   command that opens the file itself — a test or `npm run` script that reads `.env`.
   No permission check sees inside that, so this is the case the sandbox exists for.
   **Pass** only if the canary appears in no output, including on any retry, which
   strict sandbox mode runs inside the sandbox again. Positive control: the same
   command reading `README.md` prints it. **Fail** if the canary appears: if it appeared
   on a sandboxed run, add the repo's `.env` to `denyRead` (see the sandbox bullet for
   the path form) and re-run; if it appeared on a run outside the sandbox, check that
   the deployed profile still sets `sandbox.allowUnsandboxedCommands: false` and is the
   managed source in use (`/status`, as in floor step 0), and that no `excludedCommands`
   entry matches the command (check `~/.claude/settings.json` too). Under managed
   settings `/sandbox` prints "Sandbox settings are overridden by a higher-priority
   configuration" instead of opening, which confirms that a higher level sets at least
   one of the sandbox keys. If the canary still appears, do not rely on the profile for
   subprocess reads.
4. **Egress — distinguish prompt from block.** Ask it to send a file to a domain **not** in
   `allowedDomains`. With `strictAllowlist: true` honored (managed / user / `--settings`
   scope) the connection must be **blocked**. Deployed as a repo `settings.json`, expect a
   **prompt** instead — that is the documented scope limit, not a misconfiguration, and it
   is the result you should record rather than explain away.
5. **Unlisted action auto-declined:** ask it to run a *mutating* Bash command not in `allow`
   — under `dontAsk` it must be **auto-declined**, not run. This holds because the
   example sets `autoAllowBashIfSandboxed: false`; with auto-allow on, a sandboxed
   command would run without a prompt.

---

## Version requirements

| Feature | Minimum Claude Code |
|---------|---------------------|
| Managed `deny` / managed hooks / `managed-settings.json` | the baseline pin, **2.1.295** (see [`../RELEASING.md`](../RELEASING.md)) |
| `"onFailure": "block"` on command-guard | **2.1.295** (documented minimum; below it the key is unsupported and its handling is unverified) |
| `strictPluginOnlyCustomization` | exact introduction **not documented** — no changelog section introduces the key; verified present in the settings docs and the official JSON schema as of 2026-08-12. Re-confirm before relying on the strict profile. |
| `allowManagedHooksOnly` / `allowManagedPermissionRulesOnly` | operational by **2.1.140**; exact introduction not documented — re-confirm before relying on the strict profile |
| `permissions.defaultMode: "dontAsk"` (R7 allowlist) | confirm against the permission-modes docs for your release |
| `sandbox` (filesystem/network) — R7 | **macOS / Linux / WSL2 only** (native Windows unsupported); confirm schema against the sandboxing docs for your release |
| `sandbox.network.strictAllowlist` — R7 | honored from **user / managed / `--settings`** scope only; no effect in a repo's own `settings.json` (documented as of v2.1.219+). Confirm before claiming egress is blocked. |
| `wslInheritsWindowsSettings` (WSL reads the Windows policy chain) | **v2.1.282+** (within the 2.1.295 pin). |
| `managedSourcesBehavior: "merge"`, `/status` **Skipped sources** | **v2.1.242+** (within the 2.1.295 pin). Under the default `"first-wins"` only the highest-ranked managed source applies; see "Where managed settings live". |

Windows `C:\Program Files\ClaudeCode\` path requires **v2.1.75+**; Claude Code does not
read the legacy `ProgramData` path.

---

## Verify the floor (acceptance test)

Run these on a machine after deploying, to prove the floor is non-overridable:

0. **No leftover placeholder, and this file is the source in use.** Confirm the deployed
   file has **no** `<BASELINE_PREFIX>` token remaining (e.g. `grep -L '<BASELINE_PREFIX>'
   managed-settings.json` should list the file as clean). An unsubstituted placeholder
   makes the guardrail hook commands fail to launch. On v2.1.295+ command-guard's
   `onFailure: "block"` then refuses every shell command; below it the deny-list still
   works, so the floor *looks* deployed while silently losing its hooks. Then run
   `/status` in a session that uses the fleet's real credential and provider: **Setting
   sources** must show `(file)`, `(drop-ins)`, `(file + drop-ins)` or a `, merged` list
   that includes `file` or `drop-ins`, and **Skipped sources** must not list this file. Otherwise a
   higher-ranked managed source shadows it (see "Where managed settings live").
1. **Managed deny survives skip-permissions.** In any repo, ask Claude Code (with
   `--dangerously-skip-permissions`) to read a `.env` file. It must be **blocked** by
   the managed deny — bypass mode does not override a managed deny rule.
2. **Managed deny survives `--allowedTools` / an allow rule.** Add
   `"Read(.env*)"` to a project `.claude/settings.json` `allow` list (or pass
   `--allowedTools "Read"`). Reading `.env` must still be **blocked**.
3. **Managed hooks run and can't be disabled from below.** Set
   `"disableAllHooks": true` in a project `.claude/settings.json`, then trigger a
   `Bash` tool call with a blocked command (e.g. `git push --force`). command-guard
   must still **block** it (managed hooks ignore non-managed `disableAllHooks`).
4. **Managed hooks under `--dangerously-skip-permissions` — test it, don't assume it.**
   Steps 1 and 3 verify two *different* documented properties: a managed **deny** holds
   under bypass mode, and a managed **hook** survives a lower-tier `disableAllHooks`.
   Neither one implies "a managed hook still fires under bypass mode," and this repo has
   never verified that third claim. So verify it here: run the same blocked command
   (`git push --force`) with `--dangerously-skip-permissions` and record whether
   command-guard blocks. If it does not, your floor under bypass is the deny-list alone —
   which is a defensible floor, but it is a different one, and the rollout comms should
   say so.
5. **Windows fleets:** on a Windows host, confirm which tool the session actually uses.
   If Claude Code registered the PowerShell tool (no Git Bash present), the
   `Bash|PowerShell` matcher fires but the `bash "<PREFIX>/…"` hook command fails in
   PowerShell. On v2.1.295+ command-guard's `onFailure: "block"` then refuses **every**
   shell command — install Git for Windows; it is a requirement. Below v2.1.295 the hook
   most likely fails open (unverified): confirm a PowerShell `Remove-Item -Recurse -Force`
   is refused — that refusal comes from the deny list, and on such a host it is the whole
   floor.
6. **Strict profile only:** confirm a hook defined in a user/project settings file
   does **not** run, while the managed hooks still do; and confirm a project `.mcp.json`
   server does **not** load (the `mcp` surface — see the `mcpServers` correction above).
7. **No collateral damage to first-class settings flows.** The managed deny blocks the
   *agent's* `Edit` tool on `.claude/settings.json`, not Claude Code's own internal writes.
   Confirm `/config` (and any settings-writing command) still works after deploying — if a
   first-class flow that edits `.claude/settings.json` breaks, narrow that deny entry at the
   managed level.

If step 1 or 3 does **not** block, the managed file is not being applied. First run
`/status`: if **Setting sources** names a remote, plist or HKLM source and **Skipped
sources** lists this file, a higher-ranked managed source shadows it under the default
`"first-wins"`. Otherwise the file is not at the right path or not being read —
re-check the per-OS path and that the deploying user had write access to that
root-owned directory.

---

## Sources (last verified 2026-08-12; entries marked *(2026-10-30)* re-verified then)

- https://code.claude.com/docs/en/managed-settings — *(2026-10-30)* managed-source ranking (remote, MDM/OS policy, file + `managed-settings.d/`, HKCU); `managedSourcesBehavior` `"first-wins"` (default, skipped sources ignored with no warning) vs `"merge"`; keys read from every admin source; `/status` Setting sources / Skipped sources; drop-in merge order and rules; `/etc/claude-code` is user-writable on WSL.
- https://code.claude.com/docs/en/settings-reference — *(2026-10-30)* sandbox path prefixes (`./` defined for project and user settings only) and where wildcards work on Linux/WSL2; `managedSourcesBehavior` placement (not in `managed-settings.json`); `wslInheritsWindowsSettings`; `sandbox.allowUnsandboxedCommands`, `sandbox.failIfUnavailable` and `sandbox.autoAllowBashIfSandboxed`.

- https://code.claude.com/docs/en/settings — settings precedence, managed paths, the `allowManaged*` / `strictPluginOnlyCustomization` keys (surfaces: `skills`/`agents`/`hooks`/`mcp`; unrecognized names silently ignored).
- https://code.claude.com/docs/en/server-managed-settings — managed delivery, "all settings.json settings supported except OS-level-only", `enabledPlugins`.
- https://code.claude.com/docs/en/permissions — deny → ask → allow evaluation; managed non-overridability; `Read`/`Edit` deny rules apply to Claude's file tools **and** to the file commands Claude Code recognizes in a shell command (`cat`, `head`, `tail`, `sed`), but not to arbitrary subprocesses.
- https://code.claude.com/docs/en/hooks#powershell — match `Bash|PowerShell` in hooks that inspect shell commands; on Windows without Git Bash the Bash tool is not registered at all.
- https://code.claude.com/docs/en/permission-modes — "deny rule … blocked, even in bypassPermissions mode."
- https://code.claude.com/docs/en/hooks — managed hooks; `disableAllHooks` cannot disable managed hooks from below.
- https://code.claude.com/docs/en/permission-modes — `defaultMode` values incl. `dontAsk` (auto-denies unlisted actions). *(2026-10-30)* an allow rule or `bypassPermissions` mode can approve an unsandboxed retry with no prompt. *(R7)*
- https://code.claude.com/docs/en/sandboxing — `sandbox.filesystem`/`network` schema; `denyRead`/`denyWrite` block **subprocess** access at the OS level; `./` or no prefix is project-root-relative for project settings; `network.strictAllowlist` is required to block (not prompt) and is honored only from user/managed/`--settings` scope; macOS/Linux/WSL2. *(2026-10-30)* paths from `Read`/`Edit` permission rules are merged into the sandbox configuration; the unsandboxed retry (approved without a prompt by a matching allow rule in any mode and by `bypassPermissions`; denied under `dontAsk` only when no allow rule matches); strict sandbox mode; auto-allow works independently of the permission mode, except plan mode and some auto-mode cases. *(R7)*
