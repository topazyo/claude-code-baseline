# Onboarding: Claude Code Hooks & Our Security Baseline

> **New to Claude Code? New to hooks? Start here.** By the end you'll understand
> what hooks are, why our org ships a security baseline, what it protects you
> from, and how to turn on the optional pieces that fit your project.

**Time:** ~5 min to get protected (Part 0) · ~30 min to understand it all · ~15 min hands-on (Part 5).
**Prereqs:** Claude Code installed, Python 3 on your PATH, and a repo you can experiment in.

---

## What you'll be able to do after this

- Explain, in one sentence each, what a Claude Code **hook**, **event**, **matcher**, and **exit code** are.
- Describe *why* an AI coding agent needs **guardrails**, and name the two always-on protections (the command-guard hook + the secrets deny-list rule).
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

You now have **two always-on protections** (explained in Part 2). Everything
else is **opt-in and off by default** — you turn modules on deliberately, later.

> 🧪 **Try it:** ask Claude to run `git push --force` and watch it get **blocked**
> with a message. That's the command-guard. *(Why these commands? Part 2.)*
>
> The guard tokenizes the command the way a shell would (Part 2.3), so it catches
> the common evasions — extra spaces, quotes inside a word, `${IFS}`, `.exe`
> suffixes, subshells, newline sub-commands, wrappers. It's scoped to
> *catastrophic* targets: `rm -rf /` is blocked, while a targeted `rm -rf ./build`
> is intentionally allowed. Defense-in-depth — not an evasion-proof wall.

> ⚠️ **Know this before you rely on it.** At the per-repo tier everything you just
> installed is *ordinary repo files*. `baseline.config.json`, the hook scripts, and
> `settings.json` can be edited or deleted by you, by a collaborator, and — through
> a shell command the deny rules don't happen to match — by the agent. One config
> key (`guardrails.commandGuard.enabled: false`) turns the blocker into a no-op for
> the session. A floor nobody can disable exists only at the **managed settings**
> tier (Part 7). Read Part 1.5 before treating a green run as proof.

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
| `PreToolUse` | per tool call | *before* a tool runs | command-guard (Bash, PowerShell), scope-guard (Write/Edit) | ✅ **yes** |
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

In our baseline: command-guard matches `Bash|PowerShell`; the file-related hooks
(auto-format, security-defaults, scope-guard, …) match `Write|Edit`;
tracker-reminder is on `Stop`.

> ⚠️ **Why `Bash|PowerShell` and not just `Bash`.** On Windows *without* Git Bash,
> Claude Code doesn't register the Bash tool at all — it enables the PowerShell tool
> instead. A hook matching only `Bash` never fires there, silently, while the repo
> still looks protected. Matching both is the fix. Note the second half of that
> problem, which a matcher cannot solve: our hook commands are `bash "…/…sh"`, so on
> a box with no `bash` on PATH the command can't launch at all, and Claude Code
> treats a hook that fails to launch as *no objection*. On such a host the
> `permissions.deny` rules — which need nothing installed — are the only control
> that actually runs.

> 💡 **The coverage boundary, stated once so you can hold it.** The baseline hooks
> only ever see two families of tool call: shell commands (`Bash|PowerShell`) and
> file writes (`Write|Edit`). **`WebFetch`, `WebSearch`, and every `mcp__*` tool are
> unhooked** — no baseline hook inspects them and no baseline deny rule covers them.
> That is a deliberate scope, not an oversight, but it means "the baseline is
> installed" says nothing about what an MCP server or a fetch tool can do.

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

> ⚠️ **The corollary nobody enjoys: a hook that never launches fails *open*.**
> Our wiring is `bash "…/command-guard.sh"`. If that file is missing, unreadable,
> or `bash` isn't on PATH, the command exits non-zero *without ever running our
> code* — and by the table above, a non-`2` exit lets the action proceed. Our
> `failClosed` setting (Part 3) covers a hook that **runs and cannot finish its
> check**; it cannot cover a hook that never started. Deleting a hook script is not
> an `Edit` tool call, so the deny-list doesn't see it either. This is the strongest
> single reason the managed tier (Part 7) exists.

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
> Claude Code to skip its per-action approval prompts). *Source: Anthropic hooks /
> permissions docs.*
>
> ⚠️ **Read that as "enforceable *if it runs*," not "enforceable."** Exit 2
> outranks the permission rules — but only for a hook that actually fires. At the
> per-repo tier the hook script and `baseline.config.json` are ordinary files in
> your repo: the developer can edit them, and so can the agent through any shell
> command the deny rules don't happen to match. `guardrails.commandGuard.enabled:
> false` is a one-key disarm, and a deleted script is the fail-open above. Only
> **managed settings** are non-overridable (Part 7). Everything in Parts 0–6 is a
> raised floor, not a boundary.

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
  justify turning off. (command-guard, the secrets deny-list.) One guardrail —
  `autoFormat` — ships **off**, because it is the only hook here that *executes*
  code the repository supplies; see 2.3.
- **Modules** — workflow-specific checks, **off by default**. You enable the ones
  that fit your repo. (securityDefaults, fixTags, scopeGuard, configGuard, runTests,
  trackerReminder, autoStage.)
- **`enforcement` posture** — one global setting: `"block"` (a violation fails the
  action / feeds it back to Claude) or `"warn"` (advise only, never fail).

> 💡 **Recommended ramp** (the industry "visibility-first, then enforce" pattern,
> reconciled with our security floor): keep **both always-on guardrails on from
> day one** — command-guard in `block` and the secrets deny-list always enforced —
> since they cover irreversible, universally-bad actions and neither one runs
> anything. Then introduce each **opt-in module in `warn` first**,
> watch it for a week, and dial it to `block` once the team trusts it. Staying in
> `warn` *forever* trains people to ignore it, so the goal is always to graduate to
> `block`. *(Snyk; Cycode.)*

### 2.3 The two always-on guardrails (and *why* each)

**1. command-guard** — a `PreToolUse:Bash|PowerShell` hook that **blocks** a curated
list of destructive or unapproved shell commands via a **shell-aware matcher**: it
tokenizes each line the way a shell would (so a quote inside a word no longer splits
it), inspects every sub-command of a compound line, resolves the command word past a
path and a `.exe`/`.cmd` suffix, and looks through wrappers and subshells. The list,
and why each entry is on it:

| Blocked | Why |
|---------------------|-----|
| `rm -rf /`, `rm -rf .`, `rm -rf ./` | irreversible data loss |
| `git push --force`, `git push -f` | irreversible remote history loss |
| `git reset --hard` | irreversible local work loss |
| `drop table`, `truncate table`, `delete from` | destructive data operations |
| `curl`/`wget` at a remote host (with or without a `scheme://`) | unreviewed remote fetch (injection / supply-chain) |
| `npm install`, `pnpm install`, `yarn add`, `pip install` | unvetted dependency (supply-chain) |
| PowerShell: `Remove-Item`, `Invoke-WebRequest`/`iwr`, `Invoke-Expression`/`iex` | the same three categories, in the shell Windows sessions actually get |

You can extend it per-repo via `guardrails.commandGuard.extraPatterns` (e.g.
`["terraform destroy"]`). *(Anthropic ships a near-identical `block-rm.sh` example —
this is the officially recommended pattern.)* Its delete scope is deliberately
*catastrophic-only* (e.g. `/`, `.`, `./`, `~`, `~/`, `*`, `/*`, `$HOME`), so a
targeted `rm -rf ./build` is intentionally allowed.

> 💡 **What it now catches, and what it still doesn't.** The tokenizer rewrite closed
> the named bypasses this project used to carry as known gaps: `r''m -rf /`,
> `git push --fo"rce"`, `rm${IFS}-rf${IFS}/`, `git.exe push --force`, a second
> command hidden after a newline, `(rm -rf /)` and `{ rm -rf /; }`, `git push origin
> +main`, `rm -rf ~/*`, and `echo / | xargs rm -rf` all block today, with a fixture
> pinning each one. Still **not** caught, by design: base64 or other encoding,
> *arbitrary* variable indirection (the literal `$HOME`/`${HOME}` **are** caught;
> `$X` where `X` was set earlier is not), runtime aliases and shell functions, and
> any binary that isn't on the list. A blocklist raises the cost of a destructive
> action; it does not make one impossible. **Defense-in-depth, not a wall.**

**2. secrets deny-list** — entries in `permissions.deny` that refuse reads and edits
to `.env*` and `**/secrets/**`, plus path rules protecting the baseline's own files.
This is a **permission rule**, not a hook — Claude Code enforces it directly, so it
needs no Python, no `bash`, and no hook wiring. *(This mirrors OWASP's prescribed
secret-blocking patterns.)*

> ⚠️ **What a `Read`/`Edit` deny rule actually binds — the part people get backwards.**
> It binds Claude's own file tools **and the file commands Claude Code recognizes
> inside a shell command** — `cat`, `head`, `tail`, `sed`, `grep`. So `cat .env`
> **is refused**. What it does *not* bind is an arbitrary subprocess that opens the
> file itself: `python -c "print(open('.env').read())"`, `node -e …`, or an
> interpreter buried three levels down a build script sail straight through, because
> Claude Code cannot see what they will do before they do it. The answer to *that*
> gap is not a permission rule — it is `sandbox.filesystem.denyRead`, which the OS
> enforces against every child process (Part 7), plus the hygiene rule that beats
> both: don't keep real secrets on disk in a repo an agent can touch.
>
> Note also which tier you are on. A **managed** deny cannot be overridden by
> anyone below it. A deny in your repo's own `settings.json` is a file in your repo —
> it protects you from the agent, not from an edit.

**Not always-on: auto-format.** The baseline also ships a `PostToolUse:Write|Edit`
formatter hook (prettier/eslint, black, `dotnet format`) that never blocks — but it
is `enabled: false` out of the box, and it is the only hook here that **executes code
the target repository supplies**. After it `cd`s to the repo root it prefers
`./node_modules/.bin/prettier` and `./node_modules/.bin/eslint` — repo-controlled
binaries — honoring repo-controlled `prettier.config.js` / `eslint.config.js` and
their plugins, and `dotnet format` additionally *builds* the project. Cloning a repo
and letting an agent touch one file would then be enough to run whatever that repo
planted: the same primitive as CVE-2025-59536 above. Turn it on
(`guardrails.autoFormat.enabled: true`) only for a repo whose toolchain you already
trust — a convenience you opt into, not a protection you get.

> 💡 **Teaching point:** guardrails target **irreversible or outward-facing**
> actions. Reversible mistakes are fine — that's what review and git are for.

> ✅ **Check (Part 2):**
> 1. Name one thing command-guard blocks and why it's irreversible. *(e.g. `git push --force` — overwrites remote history.)*
> 2. What's the difference between a guardrail and a module? *(Guardrails are always-on universal safety; modules are opt-in and workflow-specific.)*
> 3. Is the secrets deny-list a hook? *(No — it's a permission rule enforced by Claude Code itself.)*
> 4. Does `Read(.env*)` in `deny` stop `cat .env`? What about `python -c "open('.env')"`? *(Yes to `cat` — Claude Code recognizes it as a file command. No to the Python one — an arbitrary subprocess is outside what a permission rule can see; that needs the sandbox.)*

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
    │   ├── command-guard.sh      ← PreToolUse:Bash|PowerShell  (always on)
    │   └── auto-format.sh        ← PostToolUse (never blocks; ships DISABLED — 2.3)
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
  file that just failed a gate. Out of the box the chain effectively starts at
  `security-defaults`, since `autoFormat` and every module ship disabled — a
  freshly-installed repo runs no `PostToolUse` work at all until you enable
  something. The whole chain shares one `PostToolUse` timeout, which is the other
  reason not to put a project build (`dotnet format`) at the front of it.
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

> **One opt-in lives outside this table:** `guardrails.autoFormat.enabled`. It is
> filed as a guardrail because it is universal in *scope*, but it ships off for a
> security reason rather than a workflow one — it runs the target repo's own
> formatter binaries and config (see 2.3). Decide it like a trust question about the
> repository, not like a friction question about your team.

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
        c. Unsure or security-relevant → escalate to whoever owns .claude/** in
           CODEOWNERS for this repo. If it looks like a *bypass* of the guardrail
           rather than a false positive, report it privately — see SECURITY.md.
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
- **Getting help / escalation.** For questions and false positives, ask the owners
  listed for `.claude/**` in this repo's `CODEOWNERS`. For anything that looks like a
  way *around* a guardrail — a command-guard bypass, a deny rule that doesn't hold —
  do **not** open a public issue: use GitHub's **Report a vulnerability** button
  (Private Vulnerability Reporting) on the baseline repository. The process, the
  scope, and the response window are in [`SECURITY.md`](SECURITY.md).

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
  > ⚠️ **What you are committing is executable content that auto-runs.** Those hook
  > scripts, and the `settings.json` wiring that launches them, execute on every
  > collaborator's machine the next time Claude Code opens the repo — which is the
  > exact shape of CVE-2025-59536 above, just with the scripts being yours. Before
  > you commit them, put `.claude/**` (and `hooks/**` if you vendor the source) in
  > `CODEOWNERS` with a security owner, and turn on branch protection so that
  > ownership means a required review. A one-line PR to `common.sh` runs on
  > everyone. Review these files the way you'd review a CI runner script, not the
  > way you'd review a config file.
- **Org rollout (multi-repo).** Loop `install.sh --target <repo>` over your repo
  list; upgrades are just a re-run. Each install stamps a **`baselineVersion`** (in
  `baseline.config.json`, mirrored into `.claude/hooks/baseline/VERSION`), so you can
  keep all repos on one baseline and spot stragglers with
  `tools/baseline-status.sh --drift <repos…>` (`--strict` turns the same check into a
  non-zero exit for an operator-run or org-level job — this repo's own CI does not
  invoke it; see [`tools/README.md`](tools/README.md)). Re-run `install.sh` on a
  regular cadence to reconcile drift. *(Education should precede
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
  per-OS `managed-settings.json` path). Two properties are documented and are the ones
  the floor rests on: a managed `deny` can't be overridden — not by `--allowedTools`,
  not by `--dangerously-skip-permissions` — and managed hooks survive a
  `disableAllHooks` set anywhere below the managed tier. (Those two are what
  `managed/README.md`'s acceptance test proves; don't extrapolate a third.)
  `managed-settings.json` gives the deny-list + guardrails as a low-disruption floor;
  `managed-settings.strict.json` adds `allowManagedHooksOnly`,
  `allowManagedPermissionRulesOnly`, and `strictPluginOnlyCustomization` to allow
  *only* managed/plugin sources — the exact release that introduced that last key is
  not documented in the changelog, so verify it against the settings docs for the
  version you deploy. This is also where the `configGuard` residual below gets
  non-overridable, org-wide coverage.
- **Allowlist-primary posture (OWASP).** *(Shipped — see [`managed/allowlist.example.json`](managed/allowlist.example.json).)*
  Our deny-list blocks *known-bad*; the inverse — grant only what's needed, deny the rest —
  is OWASP's preferred posture. The supported mechanism is `permissions.defaultMode: "dontAsk"`
  (auto-denies anything not in `permissions.allow`) + a minimal `allow`, with the secrets
  `deny` kept as a backstop (deny beats allow, so `.env` stays unreadable even though
  `Read(./**)` is allowlisted — and that covers `cat .env` too, per 2.3) and an OS-level
  `sandbox` (macOS/Linux/WSL2). Three honest limits: **a catch-all `deny(**)` + narrow
  `allow` does NOT work** (deny is categorical and always wins); **a permission rule
  cannot stop a subprocess that opens the file itself** (`python -c "open('.env')"`) —
  that one is closed by `sandbox.filesystem.denyRead`, which the OS enforces against
  every child process and which *does* accept project-relative `./.env` in project
  settings; and **the network allowlist only prompts unless `strictAllowlist: true`**,
  which is honored from user, managed, or `--settings` scope and has no effect in a
  repo's own `settings.json` — so a per-repo deployment leaves egress as a question,
  not a block. High friction (every action pre-approved); best for high-assurance repos.
- **In-session settings-tamper detection.** *(Shipped — opt-in `configGuard`.)* The
  `ConfigChange` hook `modules/config-guard.sh` watches `.claude/settings.json`
  (`source: project_settings`) and, on each change, rejects (block) or reports (warn)
  if the baseline hooks were unwired, the deny-list was stripped, or `disableAllHooks`
  was set. It catches **human/external** edits the deny-list can't (the deny-list only
  governs the agent's tools). Anthropic's team-security guidance recommends this, and
  CVE-2025-59536 is why it matters. **Scope note:** `ConfigChange` fires only for
  Claude Code *settings* files, so it does **not** cover `.claude/baseline.config.json`
  or the hook scripts. Those are covered against the agent by deny rules — including
  `Bash(*.claude/baseline.config.json*)` and its PowerShell/backslash variants, which
  match the command **text**, so they stop `sed -i … .claude/baseline.config.json` but
  not a `cd .claude` first or a path assembled from a variable; command-guard's own
  tamper rule is the other half of that. A non-overridable floor for human/external
  edits is the managed-settings work above. Note the deliberate side effect of a
  text match: read-only shell access to those paths (`cat .claude/settings.json`,
  `git add .claude/settings.json`) is refused too.
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
- **Guardrail** — a universal safety *control*: a hook *or* a permission rule. The two always-on ones are command-guard (a hook) and the secrets deny-list (a `permissions.deny` rule); `autoFormat` is a guardrail that ships disabled because it executes repo-supplied code.
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
Blocked? ................. read stderr → fix it, OR open a config PR, OR ask .claude/** CODEOWNERS
Found a bypass? .......... do NOT open a public issue → SECURITY.md (private reporting)
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
- **Windows *without* Git Bash — the one configuration where the hooks don't run.**
  There, Claude Code doesn't register the Bash tool; it uses the PowerShell tool.
  The matcher is `Bash|PowerShell` so it does fire — but the hook *command* is
  `bash "…/command-guard.sh"`, and with no `bash` on PATH that command can't launch.
  Claude Code treats a hook that fails to launch as no objection, so command-guard is
  absent, silently, while `tools/baseline-status.sh` still reports the baseline
  installed. What still works on such a host is the `permissions.deny` list
  (including the `PowerShell(Remove-Item *)` / `Invoke-WebRequest` / `Invoke-Expression`
  floor), because permission rules need nothing installed. Install Git Bash or run
  Claude Code inside WSL2 if you want the hook layer.
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
