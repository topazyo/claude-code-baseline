# Releasing claude-code-baseline

> Per-release re-verification checklist (ROADMAP **R4**). The Claude Code hook /
> permissions / managed-settings surface evolves between releases, and the baseline
> relies on specific documented behaviors. Re-confirm them against **live Anthropic
> docs** before adopting a new Claude Code version org-wide or bumping the pin.
>
> **Owner:** the maintainers listed in [`.github/CODEOWNERS`](.github/CODEOWNERS).
> Vulnerability reports go through GitHub Private Vulnerability Reporting, not a
> mailbox and not a public issue — see [`SECURITY.md`](SECURITY.md).

---

## The version pin

`baseline.config.json → minClaudeCodeVersion` records the **documented minimum**
(changelog-sourced) for the behaviors the baseline depends on, and the ledger below
records what was re-verified and on which version. `install.sh` detects the live
`claude --version` and prints an **advisory warning** (never blocks) when it is older.

Current pin: **`2.1.295`** — the documented minimum for `"onFailure": "block"` on the
guards (hooks docs: *"Requires Claude Code v2.1.295 or later"*; CHANGELOG 2.1.295: *"a
hook that can't start, times out, or exits with an unexpected code blocks the action
instead of letting it through"*). It also covers the v2.1.77 `deny`-bypass fix below.
Raised from `2.1.80` on 2026-10-28. That change re-verified **only** the `onFailure`
behavior, on 2.1.312 (see the ledger); the full checklist below was **not** re-walked.

**Why a pin at all:** the entire deny-list — the secrets rules and the
tamper-protection rules (`Edit(.claude/settings.json)`,
`Edit(.claude/baseline.config.json)`, `Edit(.claude/hooks/baseline/**)`, and the
`Bash(...)`/`PowerShell(...)` path rules) — is only worth anything if `deny` is
enforced unconditionally. A release in which something can route around `deny`
weakens every one of them at once, silently.

**Why *this* number, stated accurately.** The documented fix for the known
`deny`-bypass is **v2.1.77**: *"Fixed PreToolUse hooks returning `"allow"` bypassing
`deny` permission rules, including enterprise managed settings."* Note the mechanism —
that is a **hook** returning an allow decision, not a `permissions.allow` rule. Earlier
revisions of this file attributed a broader "`allow` can no longer bypass `deny`" fix to
**v2.1.80**; no changelog entry supports that, and the claim is withdrawn. The pin then
stayed at 2.1.80 as the floor the baseline's behavior had been walked through — a
*"verified at"* number. Since 2026-10-28 the pin is the documented minimum instead
(2.1.295, which sits above 2.1.77), with verification recorded per row in the ledger.

Bump the pin only after re-verifying, on a real build, the behavior the new pin is
for, and recording that in the ledger below. Say in the ledger row whether the full
checklist was re-walked; for the 2.1.295 bump it was not.

> **Eight sites carry this pin or its rationale and must move together:**
> `baseline.config.json` (`minClaudeCodeVersion` + `_minClaudeCodeVersionRationale`),
> `hooks/modules/config-guard.sh`, `install.sh` (two sites), `README.md`,
> `managed/README.md`, this file, and `ROADMAP.md` (two sites). Changing one produces a repo that contradicts itself,
> which is worse than the stale number.

---

## Behavior the baseline depends on — re-confirm each release

Confirm each against the current Anthropic Claude Code docs (hooks, hooks-guide,
permissions, security). If any has changed, fix the affected hook **and** add/adjust
a fixture in `tests/` before bumping the pin.

- [ ] **PreToolUse exit `2` blocks the tool call** and does so **before** permission
      rules are evaluated — i.e. exit 2 overrides an `allow` rule and
      `--dangerously-skip-permissions`. *(Load-bearing for `command-guard` and `scope-guard`.)*
- [ ] **PreToolUse exit `0` does NOT auto-approve** — it means "no objection," and
      normal permission evaluation still proceeds.
- [ ] **PostToolUse cannot block** (the tool already ran); exit `2` feeds the hook's
      **full stderr** back to Claude as actionable feedback, while any other non-zero
      code surfaces only the **first stderr line** as a generic hook error.
      *(R0 — the whole reason modules exit 2, not 1.)*
- [ ] **`deny` is enforced even when an `allow` rule is present**, and a PreToolUse hook
      returning `"allow"` does not bypass it either (fixed v2.1.77).
      *(Load-bearing for the secrets + tamper-protection deny-list → the version pin.)*
- [ ] **`Read`/`Edit` deny rules still cover the recognized Bash file commands**
      (`cat`, `head`, `tail`, `sed`, `grep`) and not just Claude's own file tools. If
      that ever narrows to the tools alone, `cat .env` becomes readable in every repo
      running this baseline and the secrets deny-list needs a sandbox layer beneath it.
- [ ] **A guard with `"onFailure": "block"` that can't start, times out, or exits with
      anything but `0`/`2` blocks the call** (v2.1.295+); with `"continue"` it does not.
      `failClosed` covers only a hook that *runs* and can't finish; `onFailure` is static
      in `settings.json` and ignores `enforcement`/`failClosed`. Re-run the ledger's
      `claude -p` check: delete `command-guard.sh` → a Bash `ls` is blocked; flip
      `onFailure` to `"continue"` → it runs; delete `scope-guard.sh` → a Write is
      blocked and no file is created. Also confirm that on Windows without Git Bash a
      shell-form hook still runs in PowerShell and the failed guards refuse every shell
      command and every `Write`/`Edit` (since 2.1.299 even without `onFailure`).
      *(Also: re-check that a Windows session without Git Bash still gets the
      PowerShell tool rather than Bash, which is why the matchers are `Bash|PowerShell`.)*
- [ ] **Stop hook exit `2`** semantics (continue/block) unchanged. *(trackerReminder.)*
- [ ] **`ConfigChange` event** still exists with the documented payload/semantics.
      *(R5 — tamper-detection hook; interim defense is the deny-list above.)*
- [ ] **Managed-settings knobs** — `allowManagedHooksOnly`,
      `allowManagedPermissionRulesOnly`, `strictPluginOnlyCustomization` (no introducing
      release is documented; verify it against the settings docs for your version) —
      behave as documented, **and** the surface names in
      `strictPluginOnlyCustomization` are still exactly `skills` / `agents` / `hooks` /
      `mcp`. An unrecognized surface name is *silently ignored*, so a rename turns that
      part of the lockdown off with no error anywhere;
      a managed `deny` still survives `--dangerously-skip-permissions`;
      the per-OS `managed-settings.json` paths are unchanged (macOS `/Library/Application Support/ClaudeCode/`,
      Linux `/etc/claude-code/`, Windows `C:\Program Files\ClaudeCode\`). *(R6 — **shipped** in
      `managed/`; run its README "acceptance verification" on a real deploy.)*
- [ ] **Managed hooks survive `disableAllHooks` from below** — *"disableAllHooks set in
      user/project/local cannot disable managed hooks."* *(R6 managed hooks rely on this.)*
- [ ] **`deny` is categorical and beats `allow`** — a catch-all `deny(**)` overrides a narrow
      `allow`. *(R7: the secrets deny stays a reliable backstop; the naive allowlist is invalid.)*
- [ ] **`defaultMode: "dontAsk"` auto-DENIES unlisted actions** (only `allow` matches +
      read-only Bash run) — not auto-approve. *(R7 allowlist-primary depends on this.)*
- [ ] **`sandbox.filesystem` schema** (`allowWrite`/`denyWrite`/`denyRead`) — that
      `denyRead`/`denyWrite` still **block subprocess access at the OS level for every
      child process** (this is what closes the `python -c "open('.env')"` case that no
      permission rule can reach), and that a `./`-prefixed or bare path is still
      resolved **relative to the project root for project settings**. macOS/Linux/WSL2
      only. *(R7 sandbox layer.)*
- [ ] **`sandbox.network.strictAllowlist`** still turns `allowedDomains` from a
      pre-approval list into an actual block — and is still honored **only** from user
      settings, managed settings, or a `--settings` file, never from a repository's own
      `.claude/settings.json`. Also re-confirm that `WebFetch` remains outside sandbox
      governance while `WebFetch(domain:…)` allow rules still feed the same allowlist.
      *(R7: get this wrong and the profile documents egress as blocked when it prompts.)*
- [ ] **`disableAllHooks` / hook-disable gaps** — confirm there's no regression that
      lets a repo turn the baseline hooks off. *(A `disableAllHooks` gap was fixed early 2026.)*
- [ ] **`claude --version` output format** still emits the Claude Code semver as the
      `x.y.z (Claude Code)` token. `install.sh` anchors its parse to the `(Claude Code)`
      marker (falling back to the first `x.y.z`); a format change could mis-parse the
      version. *(Observed `2.1.158 (Claude Code)` on 2026-05-31.)*

> The above were last verified in the deep-research task `wa5kmvutp` (25 claims
> verified, 0 refuted). Treat that as the baseline of record; this checklist re-runs it.

---

## Test gate

- [ ] `bash tests/run.sh` is green (matcher fixtures + hook integration tests).
- [ ] If anything in `command-guard.sh`, the matcher, `common.sh`, or the deny-list
      (`settings.template.json`) changed, a fixture changed too — `tests/policy-change-gate.sh`
      will fail the PR otherwise.
      > The gate **fails closed**: it needs a resolvable base ref and a merge-base, and
      > it diffs the whole branch rather than the tip commit. A bare local run with no
      > `origin/main` exits 1 and tells you to pass a base (`HEAD~1`) explicitly. That is
      > the intended behavior — the previous version answered "no high-risk policy files
      > changed, exit 0" when it couldn't find a base, when git wasn't there, and when the
      > diff itself errored, which is the one failure mode a release gate must not have.
- [ ] **Command-guard false-positive budget (ROADMAP Q2):** no open/unresolved
      command-guard false positive — each reported one has a committed `("fp …", …, A, ())`
      fixture — and the allow-floor did **not** decrease.
- [ ] **Bump `FP_FLOOR`:** if `test_command_guard.py`'s run printed `allow-floor stale by N`,
      raise `FP_FLOOR` to the printed allow count before release (the floor is a non-shrink
      corpus floor, not a field-FP rate — see `tests/README.md`).
- [ ] `install.sh --dry-run` against a scratch repo completes and prints the version line.
- [ ] **`baselineVersion` lockstep:** `baseline.config.json → baselineVersion` equals
      `hooks/VERSION` (`tests/run.sh` step 6 asserts this — a mismatch makes
      `tools/baseline-status.sh --drift` report a false version to every repo).

---

## Cutting a release

1. Walk the checklist above against live docs; fix + fixture any drift.
2. Update the **version-fact ledger** below with today's date.
3. If a depended-on behavior's minimum version moved, bump
   `baseline.config.json → minClaudeCodeVersion` (and the schema still validates it).
4. **Bump the baseline revision stamp:** set a new `baselineVersion` in
   `baseline.config.json` **and** the identical value in `hooks/VERSION` (they must
   match — step-6 lockstep test). This is the value `tools/baseline-status.sh --drift`
   compares against; reconciling a repo is a re-run of `install.sh --target <repo>`.
5. `bash tests/run.sh` green.
6. **Check the shipped file modes and line endings** — these are the two things that
   break *only* for people who install from a fresh clone, so they never fail for you:
   ```bash
   git ls-files -s install.sh tools/baseline-status.sh tests/*.sh   # expect 100755
   ```
   If any shows `100644`, fix it with
   `git update-index --chmod=+x <file>` and commit — a host with `core.filemode=false`
   (every Windows checkout) records `100644` no matter what the on-disk bits say, and
   the documented `claude-code-baseline/install.sh --target …` then fails with
   `Permission denied` on Linux and macOS. `.gitattributes` pins `*.sh` to `eol=lf`;
   confirm it is still in effect (`git check-attr eol -- install.sh`), because a CRLF
   `.sh` blob breaks `set -euo pipefail\r` on direct execution.
7. Note the change in `ROADMAP.md` if it shifts any item.

### Multi-repo drift (between releases)

Re-run `install.sh --target <repo>` on a regular cadence; then run
`tools/baseline-status.sh --drift <repos…>` (or `--strict` in an operator-run job) to
confirm every repo is on the current `baselineVersion`. The marker is the recopied
`.claude/hooks/baseline/VERSION`.

> **What that marker is, and is not.** `VERSION` is a **convention stamp, not an
> integrity check.** It is a plain one-line file: `install.sh` rewrites it on every run,
> which is what makes it a useful *drift* signal, but nothing verifies that its contents
> describe the tree sitting next to it. `Edit(.claude/hooks/baseline/**)` binds one tool;
> a shell redirect writes the file, and the path-text `Bash(*.claude/hooks/baseline/*)`
> rule only catches the form where the path appears literally in the command. So a stale
> or locally-weakened hook tree with a hand-forged `VERSION` reports `drift=OK`. Read it
> as "which install ran here, probably" — and if you need drift to be *trustworthy*,
> checksum the installed tree against source rather than trusting the stamp.

---

## Version-fact ledger

Each row: a behavior the baseline relies on, the Claude Code version that established
it, and when we last re-confirmed it against live docs.

| Behavior | Established in | Last re-verified | Notes |
|----------|----------------|------------------|-------|
| PreToolUse hook `"allow"` no longer bypasses `deny` | v2.1.77 | 2026-08-12 | The documented `deny`-bypass fix. Corrected 2026-08-12: this was previously recorded as a broader "`allow` rule" fix in v2.1.80, which no changelog entry supports. The pin stayed 2.1.80 as a *verified* floor above it until 2026-10-28, when it moved to 2.1.295 (the `onFailure` row below), which still covers this fix. |
| `onFailure: "block"` makes a guard that can't start, times out, or exits other than 0/2 block the call | v2.1.295 | 2026-10-28 (on 2.1.312) | The current pin. Real `claude -p` runs on a throwaway install: `command-guard.sh` deleted → Bash `ls` blocked ("blocking because onFailure is "block"" plus the hook's "No such file or directory"); `onFailure: "continue"` (negative control) → the same `ls` ran; `scope-guard.sh` deleted → Write blocked, no file created. Only this row was re-verified for the bump; the full checklist was not re-walked. Below v2.1.295 the key's handling is unverified. Not set on the `ConfigChange` config-guard by design. |
| `strictPluginOnlyCustomization` available | not documented | 2026-08-12 | Present in the settings docs and the official JSON schema; no changelog section introduces it, so no version is claimed. Same treatment as `allowManaged*Only`. Surfaces are `skills`/`agents`/`hooks`/`mcp` — an unrecognized name is silently ignored. |
| `Read`/`Edit` deny covers recognized Bash file commands | (longstanding) | 2026-08-12 | `cat`/`head`/`tail`/`sed`/`grep` are covered; arbitrary subprocesses are not. Corrected 2026-08-12 — the repo previously documented the opposite. |
| `sandbox.filesystem.denyRead` blocks subprocess reads (OS level) | (longstanding) | 2026-08-12 | Corrected 2026-08-12; `./` paths are project-root-relative for project settings. |
| `sandbox.network.strictAllowlist` required to block egress | (longstanding) | 2026-08-12 | `allowedDomains` alone prompts. Not honored from a repo's own `settings.json`. |
| Windows without Git Bash gets the PowerShell tool, not Bash | (longstanding) | 2026-08-12 | Why every matcher is `Bash\|PowerShell`. A shell-form hook with no `shell` then runs in PowerShell, where `bash "…"` fails, so the guards fail **closed** and refuse every shell command and `Write`/`Edit` (`onFailure`, v2.1.295; since 2.1.299 even without it, per CHANGELOG 2.1.299, with the behavior described in the hooks docs' "Failed hooks on Windows without Git Bash"). Git Bash is a requirement on Windows. Not re-verified 2026-10-28 — changelog/docs-sourced. |
| A hook process inherits Claude Code's environment, settings `env` included | (longstanding) | 2026-10-29 | Hooks docs: "A hook process inherits the parent environment, apart from the `OTEL_*` exporter variables" and what `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` strips; env-vars docs: Claude Code writes each `env` entry into the process environment, and subprocesses inherit even an empty value. Why config-guard, `install.sh` and `baseline-status.sh` report risky `env` keys (`RISKY_ENV_*`). Docs-sourced, not run. |
| Shell-form hooks run through a shell; `args` (exec form) spawns directly | (longstanding; `args` version not documented) | 2026-10-29 | Hooks docs: with `args`, `command` "is resolved as an executable and spawned directly … with no shell involved"; `shell` defaults to bash, or PowerShell on Windows without Git Bash. The baseline keeps shell form (`bash -p "…"`): on Windows a bare `bash` resolved on the native `PATH` is the WSL launcher (`System32\bash.exe`, measured 2026-10-29), not Git Bash, so exec form would start the wrong bash. The exact argv of the outer shell was not found in the docs read. |
| `CLAUDE_CODE_SHELL_PREFIX` wraps shell commands Claude Code runs | the release after 1.0.60 | 2026-10-29 | Changelog: "Added `CLAUDE_CODE_SHELL_PREFIX` for wrapping Claude and user-provided shell commands run by Claude Code". Reported as a risky `env` key because it would wrap every hook command. Changelog-sourced. |
| `disableAllHooks` gap fixed | early 2026 | 2026-05-31 | Re-check there's no new hook-disable bypass. |
| PreToolUse exit 2 blocks before permissions | (longstanding) | 2026-05-31 | Core of command-guard / scope-guard. |
| PostToolUse exit 2 = full feedback (no block) | (longstanding) | 2026-05-31 | Core of R0 module semantics. |
