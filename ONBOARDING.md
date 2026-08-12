<!-- Maintainer notes (safe to keep or strip before publishing):
  • Security-lead contact is set to Topaz Hurvitz <topazhu@postil.com> (Part 6).
    Optional: add a quickstart screen-recording link in Part 0 if/when one exists.
  • Hook mechanics (events, exit codes, payload) are sourced from Anthropic's
    Claude Code docs and were verified during research. The hook/permissions
    surface evolves between Claude Code versions — re-verify against the live docs
    each time you cut a baseline release, and pin a minimum Claude Code version.
  • Pedagogy/rollout claims are vendor/community-sourced (Snyk, Cycode, OWASP).
-->

# Onboarding: Claude Code Hooks & Our Security Baseline

> **New to Claude Code? New to hooks? Start here.** By the end you'll understand
> what hooks are, why our org ships a security baseline, what it protects you
> from, and how to turn on the optional pieces that fit your project.

**Time:** ~5 min to get protected (Part 0) · ~30 min to understand it all · ~15 min hands-on (Part 5).
**Prereqs:** Claude Code installed, Python 3 on your PATH, and a repo you can experiment in.

---

## What you'll be able to do after this

- Explain, in one sentence each, what a Claude Code **hook**, **event**, **matcher**, and **exit code** are.
- Describe *why* an AI coding agent needs **guardrails**, and name the three always-on protections (two guardrail hooks + the secrets deny-list rule).
- Decide which **optional modules** to enable for your repo — and justify the choice.
- React correctly when a hook **blocks** you (fix vs. legitimate, reviewed override).
- Install and upgrade the baseline in a repo you own.

> 💡 You do **not** need to read this end-to-end to be protected. Part 0 makes you
> safe in 5 minutes; everything after it is the "understand it" path. Skim, then
> come back when a hook does something you don't expect.

---

## Part 0 — Quickstart (get protected in 5 minutes)

From inside the repo you want to protect:

```bash
/path/to/claude-code-baseline/install.sh
```

What that just did, in one breath: it copied the hook scripts into
`.claude/hooks/baseline/`, wrote a `.claude/baseline.config.json` control file,
and **merged** safe defaults into `.claude/settings.json` (backing up any existing
one first). It adds a secrets deny-list to `permissions.deny`, but never touches
your `permissions.allow` list or `model`.

You now have **three always-on protections** (explained in Part 2). Everything
else is **opt-in and off by default** — you turn modules on deliberately, later.

> 🧪 **Try it:** ask Claude to run `git push --force` and watch it get **blocked**
> with a message. That's the command-guard. *(Why these commands? Part 2.)*
>
> The guard normalizes + tokenizes the command (Part 2.3), so it catches common
> evasions (extra spaces, quotes, flag reordering, wrappers). It's scoped to
> *catastrophic* targets: `rm -rf /` is blocked, while a targeted `rm -rf ./build`
> is intentionally allowed. Defense-in-depth — not an evasion-proof wall.

> ✅ **Check:** you can see `.claude/hooks/baseline/` and
> `.claude/baseline.config.json` in your repo, and `git push --force` is refused.

<!-- Optional: add a link to a 60-second screen recording of the above when one exists. -->

---

## Part 1 — Hooks from zero

> **Goal:** build an accurate mental model of how hooks work, so the rest of this
> doc — and any hook you ever read — makes sense.

### 1.1 What *is* a hook?

A hook is a **script that Claude Code runs automatically at a specific moment** —
for example, just *before* it runs a shell command, or right *after* it edits a
file. Hooks let your org enforce rules at the boundary of what the agent does,
and some hooks can **stop an action** the agent (or a malicious instruction) tries
to take.

> 💡 **Analogy:** think git pre-commit hooks — scripts that fire automatically at
> lifecycle points. The difference: git hooks gate *your commits*; Claude Code
> hooks gate *the agent's actions*, and a `PreToolUse` hook can refuse the action
> outright.

### 1.2 The lifecycle — events

Claude Code fires hooks at named **events**, grouped by the official docs into
three *cadences* — a clean way to remember them:

- **Once per session:** `SessionStart`, `SessionEnd`
- **Once per turn** (one user message + Claude's reply): `UserPromptSubmit`, `Stop`
- **On every tool call:** `PreToolUse`, `PostToolUse`

(Others exist — `Setup`, `Notification`, `PreCompact`, `SubagentStop`,
`StopFailure`, `ConfigChange`, `UserPromptExpansion`. The three cadences are what
matter for everyday use; `ConfigChange` fires on its own cadence — whenever a
settings file changes mid-session — and the baseline's opt-in `configGuard` module
uses it; see Part 7.)

The events our baseline uses:

| Event | Cadence | When it fires | We use it for | Can it block? |
|-------|---------|---------------|---------------|---------------|
| `PreToolUse` | per tool call | *before* a tool runs | command-guard (Bash), scope-guard (Write/Edit) | ✅ **yes** |
| `PostToolUse` | per tool call | *after* a tool ran | auto-format, security-defaults, fix-tags, run-tests, auto-stage | ❌ no — tool already ran |
| `Stop` | per turn | when Claude finishes responding | tracker-reminder *(opt-in — see Part 4)* | ✅ yes (keeps it going) |
| `ConfigChange` | on settings change | a settings file is edited mid-session | config-guard *(opt-in — Part 7)* | ✅ yes (rejects the change) |

> ⚠️ **Crucial, and easy to miss:** only `PreToolUse` (and `Stop`) can actually
> *stop* an action. `PostToolUse` runs *after* the edit already happened — it
> can't undo it, only feed the problem back to Claude so Claude fixes it on the
> next step. (Exact rules in 1.5.) *Source: Anthropic Claude Code hooks docs.*

```
        ┌─────────────┐   PreToolUse    ┌──────────────┐  PostToolUse   ┌─────────┐
  you → │ agent plans │ ──────────────► │ agent runs   │ ─────────────► │ result  │
        │ a tool call │  (can BLOCK)    │ the tool     │  (feedback)    │         │
        └─────────────┘                 └──────────────┘                └─────────┘
                                                                              │ Stop
                                                                              ▼
                                                                     (reminders, etc.)
```
✅ Validated against the official three-cadence model. *(Diagram simplified to the per-tool-call loop + Stop.)*

### 1.3 Matchers — which tools a hook watches

A hook is registered against a **matcher** — a string matched against the tool
name. `"Bash"` matches shell commands; `"Write|Edit"` matches either file-writing
tool; an omitted matcher (as on `Stop`) matches everything. Only matching tool
calls trigger the hook.

In our baseline: command-guard matches `Bash`; the file-related hooks (auto-format,
security-defaults, scope-guard, …) match `Write|Edit`; tracker-reminder is on `Stop`.

### 1.4 How a hook receives information — the JSON payload

When an event fires and a matcher matches, Claude Code passes **JSON event
context** to your hook: on **stdin** for command hooks (what our baseline uses),
or as the **POST body** for HTTP hooks. Our hooks parse it to find the file or
command in question (e.g. `tool_input.file_path`, `tool_input.command`). The hook
also gets useful environment variables such as `CLAUDE_PROJECT_DIR` (the repo
root). *Source: Anthropic Claude Code hooks docs.*

> 🧪 **Try it — see the payload yourself.** Save this as `peek.sh`:
> ```bash
> #!/usr/bin/env bash
> echo "----- hook stdin -----" >&2
> cat >&2            # the JSON Claude Code sent us
> echo "----------------------" >&2
> exit 0             # 0 = no objection
> ```
> Then feed it a sample payload the way Claude Code would:
> ```bash
> echo '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}' | bash peek.sh
> ```
> You'll see the exact JSON shape our hooks read.

### 1.5 How a hook says "no" — exit codes

The hook's **exit code** is how it talks back — and the meaning of exit `2`
*depends on the event*:

| Exit code | Meaning |
|-----------|---------|
| `0` | No objection. **But for `PreToolUse`, `0` does NOT auto-approve** — the normal permission flow still runs. Silence never approves. |
| `2` | "Stop — don't do this." stderr is fed back to Claude as actionable feedback. **What it actually does is event-dependent** (below). |
| any other non-zero | The action proceeds anyway; Claude sees only a generic "hook error" notice plus the *first line* of stderr. |

What exit `2` does, per event:

- **`PreToolUse` → blocks the tool call.** This is our real enforcement point.
- **`Stop` → prevents Claude from stopping**, continuing the conversation.
- **`PostToolUse` → cannot block** (the tool already ran); it only shows stderr to Claude so it can react and fix.

(The "any other non-zero" exit is event-dependent too: on `PreToolUse` the action
proceeds; on `PostToolUse` the tool already ran, so the only difference from exit
`2` is *how much* of your stderr Claude sees — the first line vs. the full report.)

> ⚠️ **The single most important mechanic:** real *prevention* happens at
> `PreToolUse`. Our `PostToolUse` security checks can't un-write a file — they
> surface the violation so Claude corrects it on the next step. That's why the
> destructive-command blocker (a `PreToolUse` hook) is the load-bearing guardrail.
> It's also why our `PostToolUse` modules exit `2` (full report fed back to Claude)
> rather than `1` (which would be a generic hook error showing only the first line).

> 💡 A `PreToolUse` hook can also deny via a JSON response
> (`permissionDecision: "deny"`) — equivalent to exit `2`. Crucially, an exit-`2`
> `PreToolUse` block fires *before* permission rules, so it overrides even an
> "allow" rule or `--dangerously-skip-permissions` (the flag that normally tells
> Claude Code to skip its per-action approval prompts). That's what makes it
> *enforceable*, not just advisory. *Source: Anthropic hooks / permissions docs.*

> ✅ **Check your understanding (Part 1):**
> 1. Which event fires *before* a shell command runs? *(PreToolUse.)*
> 2. Your `PostToolUse` hook exits `2` after Claude edited a file — does the edit get undone? *(No. The tool already ran; exit 2 only feeds your message back to Claude.)*
> 3. Where does a hook read the file path / command it's inspecting? *(From the JSON payload on stdin — e.g. `tool_input.file_path`.)*

---

## Part 2 — Why secure-by-default for an AI coding agent

> **Goal:** understand the threat model in plain language, so the guardrails feel
> obvious rather than annoying.

### 2.1 The risk, in plain terms

Claude Code can run shell commands and edit files on your machine and in your
repo. That power is the point — and the risk. Two concrete, well-documented
reasons guardrails matter (use these to motivate the team):

- **Indirect prompt injection (OWASP LLM01).** The agent reads external content —
  web pages, and *files inside the repo* (READMEs, configs, rule files).
  Attacker-controlled content can steer the agent into running malicious shell
  commands. A `PreToolUse:Bash` blocker is widely cited as the highest-value
  control against this exact class of attack.
- **The repo's own `.claude/` is a proven attack surface — not hypothetical.**
  Real, now-patched CVEs make it concrete:
  - *CVE-2025-59536* — hooks defined in a repo's `.claude/settings.json`
    auto-executed shell commands on every collaborator's machine, with **no**
    per-command approval.
  - *CVE-2026-21852* — a malicious `ANTHROPIC_BASE_URL` in settings could
    exfiltrate your API key in plaintext *before* you even accepted the trust dialog.
  - An MCP auto-approval bypass could start a server before the trust dialog was readable.

> 💡 **Honest framing for the team:** hooks are **guardrails, not walls.**
> Blocklists can be evaded (command padding, wrappers, aliases, or allowlisting
> `Bash` to defeat the network-fetch block — the curl/wget entries you'll meet in
> Part 2.3). The baseline is **defense-in-depth** — it raises the floor; it is not a
> complete security boundary. *Sources: OWASP LLM01 & AI Agent Security Cheat Sheet;
> Anthropic security docs; Check Point Research.*

### 2.2 Two tiers: guardrails (always on) vs. modules (opt-in)

The baseline is split into two tiers, and one switch decides how strict it is:

- **Guardrails** — universal safety that *everyone* gets, on by default. Hard to
  justify turning off. (command-guard, auto-format, the secrets deny-list.)
- **Modules** — workflow-specific checks, **off by default**. You enable the ones
  that fit your repo. (securityDefaults, fixTags, scopeGuard, configGuard, runTests,
  trackerReminder, autoStage.)
- **`enforcement` posture** — one global setting: `"block"` (a violation fails the
  action / feeds it back to Claude) or `"warn"` (advise only, never fail).

> 💡 **Recommended ramp** (the industry "visibility-first, then enforce" pattern,
> reconciled with our security floor): keep **all three always-on guardrails on from
> day one** — command-guard in `block`, the secrets deny-list always enforced, and
> auto-format (which never blocks anyway) — since they cover irreversible,
> universally-bad actions. Then introduce each **opt-in module in `warn` first**,
> watch it for a week, and dial it to `block` once the team trusts it. Staying in
> `warn` *forever* trains people to ignore it, so the goal is always to graduate to
> `block`. *(Snyk; Cycode.)*

### 2.3 The three always-on guardrails (and *why* each)

**1. command-guard** — a `PreToolUse:Bash` hook that **blocks** a curated list of
destructive or unapproved shell commands via a **token-aware matcher** (it
lowercases, strips quotes/backslashes, collapses whitespace, splits compound
commands, and matches on tokens — hardened against common evasions). The list,
and why each entry is on it:

| Blocked | Why |
|---------------------|-----|
| `rm -rf /`, `rm -rf .`, `rm -rf ./` | irreversible data loss |
| `git push --force`, `git push -f` | irreversible remote history loss |
| `git reset --hard` | irreversible local work loss |
| `drop table`, `truncate table`, `delete from` | destructive data operations |
| `curl http…`, `wget http…` | unreviewed remote fetch (injection / supply-chain) |
| `npm install`, `pnpm install`, `yarn add`, `pip install` | unvetted dependency (supply-chain) |

You can extend it per-repo via `guardrails.commandGuard.extraPatterns` (e.g.
`["terraform destroy"]`). *(Anthropic ships a near-identical `block-rm.sh` example —
this is the officially recommended pattern.)* The matcher resists common evasions
(whitespace, quoting, flag reordering, `/bin/rm` wrappers, `&&`/`;`/`|` chains) but
is **defense-in-depth, not a wall** — encoding (base64), arbitrary variable
indirection (the literal `$HOME`/`${HOME}` *are* caught; other `$VAR`s are not), and
runtime aliases can still bypass it. Its delete scope is deliberately *catastrophic-
only* (e.g. `/`, `.`, `./`, `~`, `~/`, `*`, `/*`, `$HOME`), so a targeted
`rm -rf ./build` is intentionally allowed.

**2. auto-format** — a `PostToolUse:Write|Edit` hook that runs whatever formatter
is available for the changed file (prettier/eslint, black, `dotnet format`). It
**never blocks** — formatting is a convenience, not a gate.

**3. secrets deny-list** — entries in `permissions.deny` that refuse reads and
edits to `.env*` and `**/secrets/**`. Note the distinction: this is a **permission
rule**, not a hook — Claude Code enforces it directly, and a managed deny can't be
overridden. *(This mirrors OWASP's prescribed secret-blocking patterns.)*

> 💡 **Teaching point:** guardrails target **irreversible or outward-facing**
> actions. Reversible mistakes are fine — that's what review and git are for.

> ✅ **Check (Part 2):**
> 1. Name one thing command-guard blocks and why it's irreversible. *(e.g. `git push --force` — overwrites remote history.)*
> 2. What's the difference between a guardrail and a module? *(Guardrails are always-on universal safety; modules are opt-in and workflow-specific.)*
> 3. Is the secrets deny-list a hook? *(No — it's a permission rule enforced by Claude Code itself.)*

---

## Part 3 — Anatomy of the baseline (what you installed)

> **Goal:** demystify the files so nothing feels like magic.

**Directory tour** (everything lives under `.claude/hooks/baseline/`):

```
.claude/
├── baseline.config.json          ← the control panel (you edit this)
├── settings.json                 ← Claude Code's hook/permission wiring (merged)
└── hooks/baseline/
    ├── lib/common.sh             ← shared helpers (config reads, payload parsing)
    ├── guardrails/
    │   ├── command-guard.sh      ← PreToolUse:Bash  (always on)
    │   └── auto-format.sh        ← PostToolUse      (always on, never blocks)
    ├── dispatcher/post-write.sh  ← single PostToolUse entry point
    └── modules/                  ← opt-in: security-defaults, fix-tags, scope-guard,
                                     config-guard (ConfigChange), run-tests,
                                     tracker-reminder, auto-stage
```

- **The config file is the control panel.** `enforcement` (block|warn), `failClosed`
  (default true — fail closed when a check *can't run*), `guardrails.*`, and
  `modules.*` all live in `baseline.config.json`. Turning a module on or off is a
  **config edit** — you never touch `settings.json` for that.
- **The dispatcher + ordering.** `settings.json` points one PostToolUse hook at
  `dispatcher/post-write.sh`, which runs the file hooks in a fixed, safe order:
  **auto-format → security-defaults → fix-tags → run-tests → auto-stage**. If a
  blocking check fails, the chain short-circuits, so `auto-stage` never stages a
  file that just failed a gate.
  > ⚠️ **Terminology, told honestly:** for these `PostToolUse` modules, "block"
  > means *fail the step and hand the full report back to Claude to fix* — the edit
  > already happened (see 1.5). Only the `PreToolUse` guardrails truly *prevent* an
  > action.
- **Namespacing.** Everything is under `.claude/hooks/baseline/`, so it never
  collides with a repo's own `.claude/hooks/` scripts.
- **What the installer did to `settings.json`.** It merged in the baseline hook
  wiring and the secrets deny-list, leaving your `permissions.allow`, `model`, and
  any existing hooks untouched, and saved a `settings.json.bak.<timestamp>` first.

> 🧪 **Try it:** open `.claude/baseline.config.json`, set `"enforcement": "warn"`,
> re-run the Part 0 `git push --force` test, and watch it **warn instead of block**.
> Then set it back to `"block"`.

---

## Part 4 — The optional modules: a decision guide

> **Goal:** a confident "should I turn this on?" answer per module.

| Module | What it enforces | Turn it on when… | Friction / watch-outs | Default |
|--------|------------------|------------------|-----------------------|---------|
| `securityDefaults` | infra files don't drift from declared rules | you have Docker / TLS / gateway / IaC config to protect | you must author the rules file; regex rules can false-positive — start in `warn` | off |
| `fixTags` | every added line carries a traceability tag (e.g. `FIX: TICKET-1`) | you run audited / ticketed change cycles | high friction; best gated to an env var (`requireWhenEnv`) so it's only on during audits | off |
| `scopeGuard` | edits stay within a declared file scope | you do tightly-scoped fix tasks and maintain a scope file | needs an up-to-date scope file or it no-ops | off |
| `configGuard` | `.claude/settings.json` keeps the baseline wiring + deny-list (and no `disableAllHooks`) | you want in-session tamper detection — incl. **human/external** edits the deny-list can't see | watches settings.json only (it's a `ConfigChange` hook); not `baseline.config.json` / hook scripts (those are deny-listed) | off |
| `runTests` | type-appropriate tests/linters run on each edit | you have a *fast* test/lint suite | slow suites add latency to every edit; missing tools are skipped, not failed | off |
| `trackerReminder` | nudge to update a tracking doc at `Stop` | you maintain a changelog / plan file | low; reminder only, never blocks | off |
| `autoStage` | `git add`s changed files after all gates pass | you want a commit-ready working tree | low; surprises people who stage manually | off |

> Each module's settings live under `modules.<name>` in `baseline.config.json`.
> Keys you'll meet in the lab: `securityDefaults.rulesFile`,
> `trackerReminder.commitGrep` + `.tracker`, `fixTags.tagMarker` + `.requireWhenEnv`,
> `scopeGuard.scopeFile`.

**Pick by repo profile:**

```
  Greenfield app with a fast test suite ........ runTests        (warn → block)
  Infra / IaC / Docker / TLS / gateway ......... securityDefaults
  Audit / compliance / ticketed changes ........ fixTags  (+ scopeGuard for tight tasks)
  Maintains a changelog / plan file ............ trackerReminder
  Wants a commit-ready tree .................... autoStage
```

> 💡 **Recommended starting posture for a newcomer's repo:** enable **nothing** for
> the first week — the always-on guardrails already protect you. Then add **one**
> module you understand, in `warn` first, and graduate it to `block` once it's
> behaving. Resist enabling several at once; you won't know which one is talking.

---

## Part 5 — Hands-on lab (~15 min)

> **Goal:** learn by doing. Run these from inside a throwaway repo that has the
> baseline installed. Each hook can be invoked manually by piping it a sample
> payload — that's the fastest way to *see* it work and read its output.

> 🧪 **Need a disposable sandbox?** You don't have to risk a real repo — spin one up,
> `cd` into it, and run the exercises there (throw it away when done):
> ```bash
> sbx="$(mktemp -d)" && bash /path/to/claude-code-baseline/install.sh --target "$sbx" && cd "$sbx"
> ```
> That *is* the "interactive sandbox" — the same installer you'd use for real, pointed
> at a fresh temp dir. No separate lab tool to learn. *(`--target` must be an existing
> dir, which is why we capture the `mktemp -d` path first.)*

**Exercise 1 — Trigger a block.** See the command-guard refuse a command and read
its exit code:
```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
  | CLAUDE_PROJECT_DIR="$PWD" bash .claude/hooks/baseline/guardrails/command-guard.sh
echo "exit=$?"     # expect: a block message on stderr, exit=2
```

**Exercise 2 — Switch posture.** In `.claude/baseline.config.json` set
`"enforcement": "warn"`, re-run Exercise 1, and note `exit=0` with the message
still printed (advise, don't block). Set it back to `"block"`.

**Exercise 3 — Enable a module.** Turn on `trackerReminder`
(`modules.trackerReminder.enabled = true`, set `commitGrep` to a commit-subject
substring like `"FIX:"` and `tracker` to `"CHANGELOG.md"`). Make a commit whose
message contains that substring *(in a brand-new repo, first set `git config
user.email "you@example.com"` and `git config user.name "You"`)*, then fire the
`Stop` hook:
```bash
echo '{}' | CLAUDE_PROJECT_DIR="$PWD" bash .claude/hooks/baseline/modules/tracker-reminder.sh
```
You'll see the reminder. (Disable it again when done.)

**Exercise 4 — Author a security rule.** Create `.claude/security-defaults.json`:
```json
{ "infraPattern": "docker-compose",
  "rules": [ { "id": "no-root", "appliesWhen": "^\\s*user:\\s",
               "mustMatch": "1000:1000",
               "message": "Container user must be non-root (1000:1000)" } ] }
```
> ⚠️ The doubled backslashes (`\\s`) are **required JSON escaping** for the regex
> `\s`. A single `\s` is invalid JSON; the check then can't run and **fails closed**
> under the default `block`+`failClosed` (exits `2` with a "CONTROL COULD NOT RUN"
> message) instead of silently passing. Copy the block exactly. *(Set
> `failClosed: false` to downgrade such cases to a warning.)*

Enable `securityDefaults`, write a `docker-compose.yml` containing `user: "0:0"`,
then run:
```bash
echo "{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"$PWD/docker-compose.yml\"}}" \
  | CLAUDE_PROJECT_DIR="$PWD" bash .claude/hooks/baseline/modules/security-defaults.sh
echo "exit=$?"     # expect: the literal "REGRESSION BLOCKER …" message on stderr, exit=2
```
Change the user to `"1000:1000"` and re-run — it now passes (`exit=0`).

> ✅ **Check (Part 5):** after these four, you can (1) read a hook's block message,
> (2) tell block from warn, (3) enable a module from config, and (4) write a
> declarative rule. That's the whole operating model.

---

## Part 6 — Operating it day to day

**A hook blocked me — now what?**

```
1. Read the stderr message — it names the hook and the reason.
2. Is the block correct? (Did I/Claude really try something destructive or
   out-of-policy?)
     YES → fix the action. Don't fight the guardrail. Done.
     NO  → it's a false positive or a legitimate exception:
        a. Temporary local unblock: set enforcement: "warn", finish, set it back.
        b. Recurring/legitimate: open a PR that changes the config (add an allowed
           pattern, scope/relax a rule) so the exception is reviewed and recorded.
        c. Unsure or security-relevant → ping the security lead (Topaz Hurvitz, topazhu@postil.com).
```
> ⚠️ **Never silently delete or weaken a guardrail** to get unblocked. The
> sanctioned override path is a *reviewed config change* (or, for a hard floor,
> managed settings — see Part 7), never an unreviewed edit to a hook script.

- **Extending.** Add a repo-specific blocked command via
  `guardrails.commandGuard.extraPatterns`; add more `securityDefaults` rules in
  your rules file.
- **Upgrading.** Re-run `install.sh`. It's idempotent: it refreshes the hook
  scripts, preserves your `baseline.config.json`, and re-merges `settings.json`
  (with a fresh backup). Pin a **minimum Claude Code version** for your team — the
  hook/permissions surface changes between releases.
- **Getting help / escalation.** Security lead: **Topaz Hurvitz** — topazhu@postil.com.

---

## Part 7 — For repo owners & team leads

> **Goal:** the "I'm responsible for a repo or team" path. *(Adoption guidance
> here is vendor/community-sourced — Snyk, Cycode, OWASP — not peer-reviewed.)*

- **Adopt + choose modules by repo type.** Run `install.sh` in the repo, then pick
  modules from the Part 4 table. Start guardrails-only; add modules in `warn`.
- **Commit the baseline so it travels with the repo.** Commit
  `.claude/hooks/baseline/`, `.claude/baseline.config.json`, and the schema.
  **Do not commit** `.claude/settings.local.json` (per-developer overrides) or the
  `settings.json.bak.*` backups.
- **Org rollout (multi-repo).** Loop `install.sh --target <repo>` over your repo
  list; upgrades are just a re-run. Each install stamps a **`baselineVersion`** (in
  `baseline.config.json`, mirrored into `.claude/hooks/baseline/VERSION`), so you can
  keep all repos on one baseline and spot stragglers with
  `tools/baseline-status.sh --drift <repos…>` (add `--strict` for a CI gate). Re-run
  `install.sh` on a regular cadence to reconcile drift. *(Education should precede
  rollout: share this guide and the "why" before flipping anything on, and pair each
  tightening with comms — Snyk.)*
- **Measuring it (with our no-external-telemetry constraint).** Our org rules forbid
  webhooks / external telemetry, so every signal is **locally collectable**. The
  read-only `tools/baseline-status.sh` reports, per repo, which guardrails/modules are
  enabled (resolved through the hooks' own `common.sh` readers — never a second parser),
  the posture, and version drift; `--json <file>` emits the same as JSON. Two further
  effectiveness signals stay **documented one-liners** (not scripted, by design): block
  events via `git grep` over CI logs, and override/false-positive counts via `git log`
  over `baseline.config.json` history. See [`tools/README.md`](tools/README.md). These
  are signals to **interpret, not gate** — no thresholds are hard-coded.
- **Enterprise enforcement — a non-overridable floor.** *(Shipped — see [`managed/`](managed/README.md).)*
  When you need a floor individual devs *cannot* disable, deploy the `managed/` profile
  via Claude Code **managed settings** (an org-admin action: MDM / golden image, at the
  per-OS `managed-settings.json` path). A managed `deny` can't be overridden — not by
  `--allowedTools`, not by `--dangerously-skip-permissions` — and managed hooks survive a
  user `disableAllHooks`. `managed-settings.json` gives the deny-list + guardrails as a
  low-disruption floor; `managed-settings.strict.json` adds `allowManagedHooksOnly`,
  `allowManagedPermissionRulesOnly`, and `strictPluginOnlyCustomization` (≥ v2.1.82) to
  allow *only* managed/plugin sources. This is also where the `configGuard` residual below
  gets non-overridable, org-wide coverage.
- **Allowlist-primary posture (OWASP).** *(Shipped — see [`managed/allowlist.example.json`](managed/allowlist.example.json).)*
  Our deny-list blocks *known-bad*; the inverse — grant only what's needed, deny the rest —
  is OWASP's preferred posture. The supported mechanism is `permissions.defaultMode: "dontAsk"`
  (auto-denies anything not in `permissions.allow`) + a minimal `allow`, with the secrets
  `deny` kept as a backstop for Claude's Read *tool* (deny beats allow, so the Read tool can't
  read a repo `.env` even though `Read(./**)` is allowlisted) and an OS-level `sandbox`
  (macOS/Linux/WSL2). Two honest limits: **a catch-all `deny(**)` + narrow `allow` does NOT
  work** (deny is categorical and always wins), and **no setting stops `cat .env` via a Bash
  subprocess** (the deny is Read-tool-only; `dontAsk` still runs read-only Bash) — so repo
  secrets rely on hygiene (don't keep them on disk) + the sandbox's network egress allowlist.
  High friction (every action pre-approved); best for high-assurance repos.
- **In-session settings-tamper detection.** *(Shipped — opt-in `configGuard`.)* The
  `ConfigChange` hook `modules/config-guard.sh` watches `.claude/settings.json`
  (`source: project_settings`) and, on each change, rejects (block) or reports (warn)
  if the baseline hooks were unwired, the deny-list was stripped, or `disableAllHooks`
  was set. It catches **human/external** edits the deny-list can't (the deny-list only
  governs the agent's tools). Anthropic's team-security guidance recommends this, and
  CVE-2025-59536 is why it matters. **Scope note:** `ConfigChange` fires only for
  Claude Code *settings* files, so it does **not** cover `.claude/baseline.config.json`
  or the hook scripts — those remain protected against the agent by the deny-list, and
  a non-overridable floor for human/external edits is the managed-settings work above.
- **Gate baseline changes in CI.** *(Shipped — see `tests/`.)* `bash tests/run.sh`
  runs the versioned adversarial suite (`test_command_guard.py` matcher fixtures
  incl. evasions + `test_hooks.sh` end-to-end), and `tests/policy-change-gate.sh`
  is a release gate that fails any change to the deny-list / matcher / `common.sh`
  without updated fixtures. `.github/workflows/baseline-ci.yml` wires both into CI.
  *(OWASP AI Agent Security Cheat Sheet.)*

---

## Part 8 — Running a lunch-and-learn (~30 min)

> **Goal:** the *delivery format* for rolling this out to a novice team. Research told
> us *what* to teach (Parts 1–7); this is the recommended *shape* for teaching it.

**Decision — the format mix.** This doc is the **single source of truth**; the
**interactive sandbox** is the existing `install.sh --target` one-liner from Part 5
(nothing extra to build or maintain); and you run **one short live session** to carry
the "why" for newcomers. Lead with the doc, make people *do* the Part 5 lab, and keep
the live time for motivation and Q&A. An illustrative split is roughly **70% self-serve
doc / 20% hands-on lab / 10% live** — *adjust to taste; the shape matters more than the
percentages.*

> 💡 *Why a live session at all?* The vendor guidance this guide cites (Snyk, Cycode) is
> **education before enforcement** — a 30-minute kickoff explaining *why* the guardrails
> exist buys far more goodwill than flipping them on silently. Afterwards people
> self-serve the rest of the doc at their own pace.

**Suggested agenda (~30 min) — run it as a kickoff, before broad rollout:**

| Time | Segment | From |
|------|---------|------|
| 5 min | Why guardrails for an AI agent — prompt injection + the real `.claude/` CVEs | Part 2.1 |
| 5 min | Get protected: run `install.sh`, watch `git push --force` get blocked | Part 0 |
| 10 min | Hands-on — everyone runs the lab in a throwaway sandbox (below) | Part 5 |
| 5 min | Guardrails vs. modules; the `block`/`warn` posture; the recommended ramp | Parts 2.2, 4 |
| 5 min | "A hook blocked me — now what?" + where to get help | Part 6 |

Everyone runs the lab in their own disposable sandbox — no risk to a real repo:

```bash
sbx="$(mktemp -d)" && bash /path/to/claude-code-baseline/install.sh --target "$sbx" && cd "$sbx"
```

**Record it.** Capture the session once and drop the link in the Part 0 recording
placeholder, so new hires get the same kickoff asynchronously without re-running the
live event.

> ✅ The doc is canonical and always current; the sandbox is one command; the live
> session is a one-time (recorded) kickoff. That's the whole format — no bespoke tooling.

---

## Appendix

### A. Glossary

- **Hook** — a script Claude Code runs automatically at a lifecycle moment.
- **Event** — the named moment a hook fires (`PreToolUse`, `PostToolUse`, `Stop`, …).
- **Matcher** — which tool(s) a hook watches (`Bash`, `Write|Edit`, …).
- **Payload** — the JSON about the tool call, delivered to the hook on stdin.
- **Exit code** — how a hook reports back; `2` = "stop / here's feedback", `0` = no objection.
- **Guardrail** — an always-on safety *control*: a hook *or* a permission rule. Our three: command-guard and auto-format (hooks) + the secrets deny-list (a `permissions.deny` rule).
- **Module** — an opt-in, workflow-specific hook (off by default).
- **Posture** — the global `enforcement` setting: `block` or `warn`.
- **Dispatcher** — the single `PostToolUse` entry point that runs the file hooks in order.
- **Managed settings** — org-level, non-overridable Claude Code config (the hard floor).
- **Indirect prompt injection** — attacker content in files/web steering the agent into bad actions (OWASP LLM01).

### B. Cheat-sheet (one screen)

```
Install / upgrade ........ /path/to/claude-code-baseline/install.sh
Enable a module .......... edit .claude/baseline.config.json → modules.<name>.enabled = true
Switch posture ........... .claude/baseline.config.json → "enforcement": "block" | "warn"
Add a blocked command .... guardrails.commandGuard.extraPatterns: ["terraform destroy"]
See a hook fire .......... echo '<payload>' | CLAUDE_PROJECT_DIR="$PWD" bash .claude/hooks/baseline/<hook>; echo $?
Blocked? ................. read stderr → fix it, OR open a config PR, OR ping the security lead
```

### C. Troubleshooting

- **Hook didn't fire.** Check `.claude/settings.json` has the baseline hooks block;
  check the matcher matches the tool; check the module is `enabled` in
  `baseline.config.json`; if you just edited settings, restart the session.
- **"python not found".** Install Python 3 (or ensure `python`/`python3` is on
  PATH) — the baseline needs it for everything config-driven. Without Python,
  `command-guard` **fails closed** (blocks Bash under `block`+`failClosed`, since it
  can't inspect commands), the `PostToolUse` modules don't run (the dispatcher prints
  a loud `DEGRADED` banner), and only the secrets deny-list (a permission rule) is
  unaffected. Set `failClosed: false` to downgrade to warnings.
- **Windows / WSL / Git Bash paths.** Hooks run via `bash` and already handle CRLF
  and Windows-style paths; `CLAUDE_PROJECT_DIR` is set by Claude Code.
- **A hook is too aggressive.** Switch that repo to `warn`, or narrow the rule /
  pattern via a reviewed config PR — don't edit the hook script in place.
- **A `securityDefaults` rule isn't blocking, or every infra edit suddenly fails.**
  Check the rules file is valid JSON and present. A missing or malformed
  `security-defaults.json` is treated as "control could not run" and **fails closed**
  under the default `block`+`failClosed` (the hook exits `2` with a "CONTROL COULD
  NOT RUN" message). Regex backslashes must be doubled in JSON (`\\s`, not `\s`); set
  `failClosed: false` to downgrade degradations to warnings.
- **Version mismatch.** Pin a minimum Claude Code version; the hook/permissions
  surface evolves between releases (re-verify exit-code and managed-settings
  behavior against the live docs each baseline release).
- **Remember:** the baseline is defense-in-depth, not a complete boundary — a
  blocklist can be evaded. Don't treat a green run as proof nothing bad happened.

### D. Further reading

Primary / authoritative (verified during research):
- Claude Code hooks reference — https://code.claude.com/docs/en/hooks
- Claude Code hooks guide — https://code.claude.com/docs/en/hooks-guide
- Claude Code permissions — https://code.claude.com/docs/en/permissions
- Claude Code security / team security — https://code.claude.com/docs/en/security
- OWASP AI Agent Security Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html
- OWASP LLM01 Prompt Injection — https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- Check Point Research, CVE-2025-59536 (repo-file RCE / token exfiltration) — https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/

Adoption / pedagogy (vendor/community, corroborated but not peer-reviewed):
- Snyk, developer adoption (education-before-enforcement, ramp guardrails) — https://snyk.io/articles/developer-adoption/
- Cycode, AI guardrails (Report → Block ramp) — https://cycode.com/blog/ai-guardrails-real-time-ide-security/

Internal:
- `README.md` (reference / adoption) · this guide (learning).
