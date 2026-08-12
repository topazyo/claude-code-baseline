# claude-code-baseline — managed (enterprise floor)

> The **non-overridable** org floor (ROADMAP **R6**). The bootstrap `install.sh`
> ships a *copyable, per-repo* baseline that a developer can disable. This profile
> promotes the load-bearing parts — the secrets/tamper **deny-list** and the
> always-on **guardrail hooks** — into Claude Code **managed settings**, the
> highest-precedence tier, which **cannot be overridden** by user, project, or
> local settings, by `--allowedTools`, or by `--dangerously-skip-permissions`.
>
> Deploying this is an **org-admin action** (MDM / golden image / config
> management), not a per-repo `install.sh` run. **Local-only**, like the rest of
> `claude-code-baseline/`.
>
> All facts below were verified against the official Claude Code docs on 2026-05-31
> (see Sources). Re-confirm per release via [`../RELEASING.md`](../RELEASING.md).

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

This is also where the deliberate **R5 residual** is finally closed: a managed
`deny` on `.claude/baseline.config.json`, `.claude/settings.json`,
`.claude/settings.local.json`, and `.claude/hooks/baseline/**` blocks the agent
from tampering with the baseline *non-overridably and in every repo* — not just the
one repo `configGuard` watches.

---

## Where managed settings live (highest precedence)

Deploy the chosen profile (renamed to **`managed-settings.json`**) to the
OS-specific path:

| OS | Path |
|----|------|
| macOS | `/Library/Application Support/ClaudeCode/managed-settings.json` |
| Linux / WSL | `/etc/claude-code/managed-settings.json` |
| Windows | `C:\Program Files\ClaudeCode\managed-settings.json` |

> Windows note: the legacy `C:\ProgramData\ClaudeCode\managed-settings.json` path
> was **deprecated as of v2.1.75** — use `C:\Program Files\ClaudeCode\`.

**Precedence (high → low):** managed settings → CLI args (`--settings`) → local
project (`.claude/settings.local.json`) → project (`.claude/settings.json`) → user
(`~/.claude/settings.json`). The managed tier wins outright — that is the property
the floor depends on, and it is the core verified fact here.

> *Additional detail — re-confirm against the settings docs for your release; these
> were NOT part of the core adversarially-verified fact set:* a file-based **drop-in
> directory** `managed-settings.d/*.json` is supported in the same system directory
> (merge order typically alphabetical, applied on top of `managed-settings.json`);
> and within the managed tier, server-managed (Teams/Enterprise admin console) and
> OS-policy delivery (e.g. Windows `HKLM\SOFTWARE\Policies\ClaudeCode`) are reported
> to rank above plain file-based, with the user-writable `HKCU\…` lowest. Treat these
> as orientation, not load-bearing.

Because these directories are root/admin-owned, a normal developer cannot edit the
floor — distribute the file via MDM, a golden image, or config management.

---

## The two profiles

Pick one, **rename it to `managed-settings.json`**, and deploy:

| File | What it enforces | Disruption |
|------|------------------|------------|
| [`managed-settings.json`](managed-settings.json) | Non-overridable **deny-list** (secrets + baseline self-protection) **+** the always-on **guardrail hooks** (command-guard, post-write dispatcher) as *managed* hooks. User/project hooks still run *in addition*. | Low — teams keep their own hooks and permission rules. |
| [`managed-settings.strict.json`](managed-settings.strict.json) | Everything above **plus** `allowManagedPermissionRulesOnly`, `allowManagedHooksOnly`, and `strictPluginOnlyCustomization: ["skills","hooks","agents","mcpServers"]`. **Only** managed (and force-enabled-plugin) hooks/rules/customization apply. | **High** — disables per-repo hooks, permission rules, and user/project skills/agents/MCP. Deploy only if that lockdown is your intent. |

> **Config-only floor (no scripts).** If you want only the non-overridable
> deny-list and not the managed hooks, delete the `"hooks"` block from the profile
> before deploying. The deny-list needs nothing installed and is the highest-value,
> zero-dependency win.

**Deny-list notes (read before deploying):**

- The managed deny intentionally adds **`Edit(.claude/settings.local.json)`**, which the
  per-repo template and `configGuard`'s `EXPECTED_DENY` deliberately omit — a per-repo
  control can't usefully own a file the developer is meant to own locally, but the
  non-overridable managed tier can. This is the one place the managed deny diverges from
  the per-repo deny-list, by design.
- **Over-blocking is non-overridable here.** `Read(.env*)` matches non-secret files like
  `.env.example` / `.env.sample`, and `**/secrets/**` matches any `secrets/` dir
  (including non-sensitive fixtures). At the per-repo tier a team can override this; at the
  managed tier they **cannot** — if a team has a legitimate read need, it must be carved
  out at the managed level (the only tier that can), or tighten the glob there. This is the
  right enterprise tradeoff, but it is a real, org-wide, non-overridable block.
- **`strict` disables user/project MCP servers.** Because `strictPluginOnlyCustomization`
  lists `mcpServers`, the strict profile stops loading user/project-configured MCP servers
  unless they are distributed as plugins — confirm that lockdown is intended before
  deploying it to teams that rely on their own MCP servers.

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
- **The secrets/tamper `deny` is retained as a backstop — for Claude's Read *tool*.**
  Because deny beats allow, a `.env` matching the broad `Read(./**)` allow **and** the
  `Read(.env*)` deny → **deny wins → the Read tool is blocked.** That is the part of the
  R7 guarantee that holds: *the Read tool can't read secrets even if a path is allowlisted.*
  **It does NOT cover subprocess reads — see the secrets-read reality below.**
- **`sandbox`** (filesystem + network) — OS-level isolation on **macOS, Linux, and
  WSL2** (native Windows is **not** supported — run inside WSL2). The example denies
  Claude's read tools access to credential dirs (`~/.aws`, `~/.ssh`, `~/.gnupg`, …) and,
  crucially, **allowlists outbound network domains** — the one control that limits
  *exfiltration* of whatever the agent manages to read.

> **⚠️ Secrets-read reality (do not overclaim this profile):** **No permission or
> sandbox setting reliably stops a Bash subprocess from reading a local file.**
> `permissions.deny Read(.env*)` governs only Claude's Read/Glob/Grep **tools**;
> `sandbox.filesystem.denyRead` *also* governs only those tools, not subprocesses; and
> under `dontAsk`, **read-only Bash (`cat`/`rg`/`grep`/`head`/…) runs even without an
> `allow` entry**, so `cat .env` returns the secret. command-guard blocks *destructive*
> commands, not reads. The realistic mitigations are therefore:
> 1. **Don't keep real secrets on disk in agent-accessible repos** — use env-var injection
>    or a secret manager; commit only `.env.example`.
> 2. **The network sandbox `allowedDomains`** limits where anything read can be *sent*,
>    blunting exfiltration even if a secret is read. (Domain-based — it raises the bar,
>    not a hermetic seal; raw-IP or non-HTTP channels may evade it.)
> 3. The Read-tool `deny` + not granting broad mutating `Bash(*)` reduce the easy paths.
>
> **Other limits:**
> - **Deny-precedence reliability.** Community reports (e.g. anthropics/claude-code
>   #45511) describe a *specific* deny not reliably narrowing a *broad* allow for Bash
>   command patterns. This is the concrete reason to **grant narrow, not broad-then-subtract**
>   — the whole point of allowlist-primary. Treat as edge cases to design around, not
>   confirmed Anthropic behavior; the file-path Read-tool `deny` is the reliable part.
> - **Sandbox path syntax:** absolute (`/tmp/build`), home-relative (`~/`), or
>   root-relative (`//`) — **not** project-relative `./` (so repo-local `.env` can't be
>   added to `denyRead`; that's why hygiene + egress control above carry the weight). The
>   working directory is writable by default; `allowWrite` adds dirs beyond it.
> - The example grants broad repo-file access (`Read/Edit/Write(./**)`) for usability and
>   relies on the file-path deny (reliable for the Read tool); narrow it to specific dirs
>   for a high-assurance repo to better practice "grant narrow."

**Deploy as:** a per-repo `.claude/settings.json` for a high-assurance repo (opt-in,
high-friction — every needed action must be pre-approved), or promote `defaultMode:
"dontAsk"` + `allow` into the managed tier for an **org-wide** allowlist-only lockdown
(very strict — confirm that is your intent). Either way, keep the secrets `deny` and
the R6 guardrail hooks alongside.

**Verify (acceptance):** with the profile active —
1. **Read tool blocked (holds):** ask the agent to read a repo `.env` *with the Read tool*
   — it must be **blocked** by the deny even though `Read(./**)` is allowed.
2. **Subprocess read NOT blocked (know the boundary):** ask it to run `cat .env` via Bash —
   it **will** return the contents (read-only Bash under `dontAsk`). This is the limit above;
   confirm your real protection is secret-hygiene + the network sandbox, not this deny.
3. **Exfiltration limited:** ask it to send any file to a domain **not** in `allowedDomains`
   — the network sandbox must block the connection.
4. **Unlisted action auto-declined:** ask it to run a *mutating* Bash command not in `allow`
   — under `dontAsk` it must be **auto-declined**, not run.

---

## Version requirements

| Feature | Minimum Claude Code |
|---------|---------------------|
| Managed `deny` / managed hooks / `managed-settings.json` | the baseline pin, **2.1.80** (see [`../RELEASING.md`](../RELEASING.md)) |
| `strictPluginOnlyCustomization` | **2.1.82+** |
| `allowManagedHooksOnly` / `allowManagedPermissionRulesOnly` | operational by **2.1.140**; exact introduction not documented — re-confirm before relying on the strict profile |
| `permissions.defaultMode: "dontAsk"` (R7 allowlist) | confirm against the permission-modes docs for your release |
| `sandbox` (filesystem/network) — R7 | **macOS / Linux / WSL2 only** (native Windows unsupported); confirm schema against the sandboxing docs for your release |

Windows `C:\Program Files\ClaudeCode\` path requires **v2.1.75+** (`ProgramData` deprecated).

---

## Verify the floor (acceptance test)

Run these on a machine after deploying, to prove the floor is non-overridable:

0. **No leftover placeholder.** Confirm the deployed file has **no** `<BASELINE_PREFIX>`
   token remaining (e.g. `grep -L '<BASELINE_PREFIX>' managed-settings.json` should list
   the file as clean). An unsubstituted placeholder makes the guardrail hook commands fail
   to launch — the deny-list still works, so the floor *looks* deployed while silently
   losing its hooks.
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
4. **Strict profile only:** confirm a hook defined in a user/project settings file
   does **not** run, while the managed hooks still do.
5. **No collateral damage to first-class settings flows.** The managed deny blocks the
   *agent's* `Edit` tool on `.claude/settings.json`, not Claude Code's own internal writes.
   Confirm `/config` (and any settings-writing command) still works after deploying — if a
   first-class flow that edits `.claude/settings.json` breaks, narrow that deny entry at the
   managed level.

If step 1 or 3 does **not** block, the managed file is not at the right path / not
being read — re-check the per-OS path and that the deploying user had write access
to that root-owned directory.

---

## Sources (verified 2026-05-31)

- https://code.claude.com/docs/en/settings — settings precedence, managed paths, the `allowManaged*` / `strictPluginOnlyCustomization` keys.
- https://code.claude.com/docs/en/server-managed-settings — managed delivery, "all settings.json settings supported except OS-level-only", `enabledPlugins`.
- https://code.claude.com/docs/en/permissions — deny → ask → allow evaluation; managed non-overridability.
- https://code.claude.com/docs/en/permission-modes — "deny rule … blocked, even in bypassPermissions mode."
- https://code.claude.com/docs/en/hooks — managed hooks; `disableAllHooks` cannot disable managed hooks from below.
- https://code.claude.com/docs/en/permission-modes — `defaultMode` values incl. `dontAsk` (auto-denies unlisted actions). *(R7)*
- https://code.claude.com/docs/en/sandboxing — `sandbox.filesystem`/`network` schema; `denyRead` bounds Claude's read tools only; macOS/Linux/WSL2. *(R7)*
