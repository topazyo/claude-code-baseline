# claude-code-baseline — Enhancement Roadmap

> Tracked backlog of improvements to the org Claude Code hooks/settings baseline.
> Each item is research-backed (Anthropic docs + OWASP) and scoped to concrete,
> testable acceptance criteria. **Local-only**, like the rest of `claude-code-baseline/`.
>
> **Owner:** Topaz Hurvitz <topazhu@postil.com> · **Last updated:** 2026-05-31

**Status:** ✅ done · 🔜 next (P0) · ◻️ planned (P1) · 🧭 phase-2 / org-scale (P2)
**Effort:** S (≲ half-day) · M (1–2 days) · L (multi-day / cross-repo)

| ID | Item | Pri | Status | Effort | Why (source) |
|----|------|-----|--------|--------|--------------|
| R0 | PostToolUse modules emit exit `2` (full feedback to Claude) | P0 | ✅ done | S | exit 2 = actionable feedback; exit 1 truncates to first stderr line (Anthropic hooks docs) |
| R1 | **Fail-closed** when a control itself fails (missing/malformed rules; no-Python guard + banner) | P0 | ✅ done | M | OWASP: deny when classification/policy lookup/logging fails; closed the lab-caught fail-open |
| R2 | Harden `command-guard` parsing (compound / wrapped / reordered commands) | P0 | ✅ done | M | blocklists are bypassable; "guardrails not walls" (Anthropic security; adversarial research) |
| R3 | Versioned **adversarial CI** + release gate for the baseline itself | P0 | ✅ done | M | OWASP CI/CD release gates: gate any change to deny-list/blocker logic with red-team fixtures |
| R4 | Pin **minimum Claude Code version** + per-release re-verification checklist | P1 | ✅ done | S | hook/permissions surface evolves (e.g. allow-bypasses-deny fixed v2.1.80+) |
| R5 | `ConfigChange` **tamper-detection** hook *(interim: config/hooks now deny-listed)* | P1 | ✅ done | M | Anthropic team-security guidance; CVE-2025-59536 (repo-controlled settings auto-exec) |
| R6 | **Managed-settings** enterprise floor (non-overridable) | P2 | ✅ done | L | true enforcement beyond a copyable template (Anthropic permissions/hooks docs) |
| R7 | Pair secrets deny-list with a scoped **read/path allowlist** | P2 | ✅ done | M | OWASP posture is allowlist-primary; denylist is defense-in-depth secondary |

---

## R0 — PostToolUse modules emit exit `2` ✅ DONE (2026-05-31)

PostToolUse hooks can't block (the tool already ran), but exit `2` feeds the
hook's **full stderr** back to Claude as actionable feedback, whereas any other
non-zero code shows only the first line as a generic "hook error."

**Shipped:** `bcl_violation_exit` (in `hooks/lib/common.sh`) now returns `2` on
block / `0` on warn. Verified end-to-end: `security-defaults`, `fix-tags`,
`run-tests`, and the dispatcher all exit `2` on block; warn posture exits `0`;
PreToolUse guards unchanged. *Source: Anthropic Claude Code hooks docs (exit-code semantics).*

---

## R1 — Fail-closed when a control fails ✅ DONE (2026-05-31)

**Problem (verified against the code).** Several checks fail **open** — they let
the action through when the *check itself* can't run:
- `hooks/modules/security-defaults.sh`: `[[ -z "$PY" ]] && exit 0` (no Python → no check); missing rules file → warn + `exit 0`; malformed rules JSON → `__ERROR__` → `exit 0`. *(The onboarding lab reproduced the malformed-JSON fail-open.)*
- `hooks/guardrails/command-guard.sh`: *(original assumption — disproven, see Shipped)* the core blocklist was thought "bash-only"; in fact it parses the command from the payload via Python, so without Python it now **fails closed**. `extraPatterns` likewise need Python.

**Why it matters.** OWASP AI Agent Security Cheat Sheet: *"Fail closed when risk
classification, approval validation, policy lookup, or audit logging fails."* A
silently-skipped security check reads as "passed."

**What to build.**
- Add a config knob `failClosed: true|false` (default `true`) under each affected module.
- When a control can't run (no Python, unreadable/malformed rules) **and** posture is `block` **and** `failClosed`: emit a loud stderr message and exit `2` instead of `0`. Under `warn`, stay non-blocking but always print the degradation loudly (never silent).
- `command-guard`: if `extraPatterns` are configured but Python is unavailable, surface that the custom patterns are **not** being enforced.

**Acceptance criteria.**
- With `securityDefaults` enabled, `block` posture, and a malformed `security-defaults.json`: hook exits `2` (not `0`) and names the parse error.
- With no Python on PATH: `command-guard` **fails closed** (exits `2` under `block`+`failClosed`) because it can't parse/inspect the command; the dispatcher prints a loud `DEGRADED` banner and fails closed *as feedback* (PostToolUse can't block the edit). The secrets deny-list (a permission rule) is unaffected.
- Warn posture never blocks but always prints the degradation.
- Existing happy-path tests still pass.

**Files:** `hooks/modules/security-defaults.sh`, `hooks/guardrails/command-guard.sh`, `hooks/lib/common.sh`, `baseline.config.json` + schema.
**Risk:** over-blocking in environments that legitimately lack Python → mitigate with the `failClosed` toggle and clear messaging.

**Shipped (2026-05-31).** Added global `failClosed` (default true) + `bcl_failclosed` / `bcl_failclosed_exit` in `common.sh`. `security-defaults.sh` now fails closed on missing **or** malformed rules (was a silent `exit 0` — the fail-open the onboarding lab reproduced). `command-guard.sh` fails closed when Python is unavailable — it cannot parse the command, so it must not wave it through (this corrected the earlier assumption that its core was "bash-only"; payload parsing needs Python). The dispatcher emits a loud no-Python `DEGRADED` banner. Verified across happy-path, missing/malformed rules, `warn` / `failClosed:false` downgrades, no-Python (command-guard + dispatcher), and regressions. **Design note:** no-Python is the one case `failClosed:false` can't be honored (reading the flag needs Python), so it defaults to fail-closed — the safe direction; Python is a documented prereq. ONBOARDING troubleshooting + Exercise-4 notes were updated from "fails open" to "fails closed."

**Follow-up hardening (2026-05-31, from adversarial review).** Added `bcl_payload_unparseable` and `bcl_config_malformed` helpers and closed the remaining same-class fail-opens the review found: `scope-guard.sh` now fails closed on an unparseable payload (was silent allow); `command-guard.sh` and `security-defaults.sh` fail closed on an unparseable payload even with Python present; the dispatcher fails closed (loud `DEGRADED`) on a present-but-malformed `baseline.config.json` (which otherwise silently disabled all modules) and on an unparseable payload; `security-defaults.sh` fails closed on an empty rules array (neutered/substituted policy) and on standalone no-Python; and `fix-tags`/`run-tests` now print a visible note instead of silently skipping on `cd` failure. As an interim guard for the config-tamper vector (until R5), `settings.template.json` deny-lists agent edits to `.claude/baseline.config.json`, `.claude/settings.json`, and `.claude/hooks/baseline/**`. All verified; see R2 (substring evasions) and R5 (config tamper) for the residual, deliberately-deferred items.

---

## R2 — Harden `command-guard` against bypasses ✅ DONE (2026-05-31)

**Problem.** The guard does a case-insensitive **substring** match on the
command string. Documented/again-verified bypasses: wrappers (`/bin/rm`), quoting
(`r''m -rf /`), aliases, env-var indirection, compound/wrapped commands, and the
structural one Anthropic itself notes — *allowlisting `Bash` defeats the built-in
curl/wget block*. A single near-miss (`rm -rf build` vs `rm -rf ./`) slips through.

**Why it matters.** Anthropic security docs and adversarial research agree
blocklists/allowlist-patterns can be routed around (subcommand padding, option
reordering). This is the load-bearing PreToolUse guardrail, so its bypass surface
is the highest-value hardening target — while accepting it stays defense-in-depth.

**What to build.**
- Normalize before matching: collapse quotes/whitespace, resolve common wrappers (`env`, `sh -c`, `bash -c`, leading paths), and split on `;`, `&&`, `||`, `|` to inspect each sub-command.
- Match on the resolved command token + args, not raw substring, for the destructive set.
- Keep a documented "known-bypass" list in the test fixtures (R3) so coverage is explicit, and keep the honest "guardrails, not walls" framing in the docs.

**Acceptance criteria.**
- A fixture suite of ≥ 20 evasions (wrappers, quoting, compound, case, padding) is blocked where intended; intentional non-targets (e.g. `rm -rf build` if we decide it's out of scope) are documented, not silently missed.
- No regression on the current 15 blocklist entries.

**Files:** `hooks/guardrails/command-guard.sh`, fixtures (R3).
**Risk:** more parsing = more false positives → tune against R3 fixtures; ship behind the same `warn`/`block` posture.

**Shipped (2026-05-31).** Moved matching out of bash `case` substrings into a testable Python matcher (`hooks/lib/command_guard_match.py`, exposing a pure `evaluate()`), since R1 already requires Python for command-guard. It normalizes (lowercase, strip quotes/backslashes, collapse whitespace), splits compound commands on `; && || |`, and does token-aware detection: `rm -rf` with reordered/split/long flags (`-fr`, `-r -f`, `--recursive --force`) against a deliberately *catastrophic-only* target set (`/ . ./ ~ * /* /. $HOME`), wrapper paths (`/bin/rm`, `env rm`, `sh -c`), non-adjacent `git push … --force`, `git reset --hard`, SQL, curl/wget fetches, and package installs; plus repo `extraPatterns`. A matcher failure or unparseable payload fails closed. A **58-case fixture suite** (`tests/test_command_guard.py`) covers the 15 originals, 27 evasions, extraPatterns, 12 intentional non-targets (e.g. `rm -rf ./build` stays allowed), and 2 documented known-limits (base64/var-indirection) — all green, plus end-to-end verification through the hook. **Deliberately NOT caught** (documented in the header + ONBOARDING): encoding/base64, *arbitrary* variable indirection (the literal `$HOME`/`${HOME}` ARE caught; other `$VAR`s are not), runtime aliases — these belong to sandboxing, not substring/token matching.

**Follow-up hardening (2026-05-31, from adversarial review — 17 findings, all confirmed).** Re-architected the matcher to be **command-word-anchored per sub-command** (dropped the cross-contaminating whole-string segment), which fixed both classes the review found: (1) **in-scope bypasses now blocked** — `git push -fv`/`-fu` (force flag anywhere in a short-flag bundle), `rm -rf //` / `///` / `/./` / `./*` / `$HOME/` / `${HOME}/` (target tokens are now canonicalized: collapse `//`, resolve `/.`, strip leading `./` and trailing `/`); (2) **false-positives now allowed** — `git push … && tar -czf …`, `rm -rf dist && ls .`, `git rm -rf .`, `npm run install:ci`, `grep "delete from"`, `echo "git reset --hard"` (SQL only fires for a real client command word/exec-flag; install only when it's the package-manager subcommand; `git rm` is no longer treated as filesystem `rm`). Empty payloads now allow (nothing to inspect) instead of tripping the matcher-error path. Fixture suite grown to **80 cases** (all green) + end-to-end re-verified. A **second review round** (9 findings, all confirmed) then closed deeper edge cases: `git push --force-with-lease=main` (`=value` form), `python -mpip install` (glued `-m`), and false-positives where the SQL `-c`/`-e` exec-flag clause fired on `grep`/`sed`/`awk` and the bare-`http` curl regex matched local filenames — fixed by gating SQL on the runner command word only and requiring a real `scheme://`. Fixture suite now **91 cases**, all green. (Convergence 17→9; command-guard is explicitly defense-in-depth — the fixture suite + R3's CI gate are the ongoing regression guard.)

---

## R3 — Versioned adversarial CI + release gate ✅ DONE (2026-05-31)

**Problem.** The baseline is verified ad-hoc (manual shell tests). There's no
committed, repeatable gate, so a future edit to the deny-list or blocker could
regress silently.

**Why it matters.** OWASP CI/CD & Release Gates: *"Run adversarial test suites in
CI/CD for agent templates and tool policies… Block releases when high-risk tool
policies, approval logic, or credential scopes change without updated tests…
Keep red-team prompts and expected denials version controlled."*

**What to build.**
- A `tests/` fixture suite (payload + expected exit code + expected stderr substring) covering: every command-guard entry, the R2 evasions, exit-`2` semantics per module, fail-closed (R1), and the security-defaults rule engine.
- A runner script (`tests/run.sh`) usable locally and in CI.
- A CI workflow that runs it and **fails the build** on any change to `command-guard.sh` / deny-list / `common.sh` without corresponding fixture updates.

**Acceptance criteria.**
- `tests/run.sh` green locally; CI red on an intentionally weakened guard.
- A PR touching the blocklist without touching fixtures is flagged.

**Files:** new `tests/`, new CI workflow. **Risk:** none material (additive).

**Shipped (2026-05-31).** Added `tests/run.sh` (aggregate: `bash -n` on all hooks, `py_compile`, then both suites), `tests/test_command_guard.py` (**91** matcher fixtures), `tests/test_hooks.sh` (**17** end-to-end cases: installs the baseline into a throwaway repo and asserts command-guard, security-defaults fail-closed on missing/malformed/empty rules, exit-2 semantics, `block`/`warn`/`failClosed` posture, malformed-config, scope-guard, fix-tags), `tests/policy-change-gate.sh` (the release gate), and `.github/workflows/baseline-ci.yml` (runs the suite on push/PR + the gate on PRs; active once the directory is its own repo). Verified: `run.sh` green locally (108 assertions across both suites), and the gate fails a matcher change with no fixture update (exit 1) while passing matcher+fixture changes and unrelated changes. Cross-platform (Linux/WSL/macOS/Git Bash) via a `cygpath` shim for the Windows Python path namespace. *(Per OWASP CI/CD release gates — red-team prompts + expected denials are version-controlled and gate releases.)*

---

## R4 — Pin minimum Claude Code version + re-verify checklist ✅ DONE (2026-05-31)

**Why.** The hook/permissions/managed-settings surface is actively changing: a
hook-`allow`-bypasses-`deny` bug was fixed only in **v2.1.80+**;
`strictPluginOnlyCustomization` needs **v2.1.82+**; a `disableAllHooks` gap was
fixed in early 2026. Behavior the baseline relies on must be re-checked per release.

**What to build.** Record a `minClaudeCodeVersion` in `baseline.config.json` (and
check it in `install.sh` with a warning); add a short "release re-verification
checklist" to this repo (re-confirm exit-code + managed-settings behavior against
live docs).

**Acceptance criteria.** `install.sh` warns when the detected Claude Code version
is below the pin; checklist exists and is referenced from the release process.
**Files:** `install.sh`, `baseline.config.json` + schema, this roadmap / a RELEASING.md.

**Shipped (2026-05-31).** Added `minClaudeCodeVersion: "2.1.80"` to
`baseline.config.json` (+ a semver `pattern` in the schema and an inline rationale
comment). The pin is **2.1.80** because that's the release where an `allow` rule
could no longer bypass a `deny` — the tamper-protection deny-list
(`Edit(.claude/settings.json|baseline.config.json|hooks/baseline/**)`) depends on
`deny` being unconditionally enforced, so anything older silently weakens it.
`install.sh` step 0 now reads the pin, detects the live `claude --version`, compares
numerically in Python (int-tuple semver, so `2.10` > `2.9`), and prints an
**advisory** line — `>= required` when ok, a loud multi-line `WARNING` when older,
and a graceful skip note when no parseable version is found. It **never blocks**
install (acceptance: warn only). Added `RELEASING.md`: a per-release re-verification
checklist of every depended-on behavior (PreToolUse exit-2-before-permissions,
PostToolUse exit-2-as-feedback, allow-no-longer-bypasses-deny, ConfigChange,
managed-settings knobs, disableAllHooks) plus a version-fact ledger with
last-re-verified dates, anchored to deep-research task `wa5kmvutp`. Tests: 5 new
integration cases in `tests/test_hooks.sh` (stub a fake `claude` on PATH; assert
older→warn, equal/newer→ok, unparseable→skip) — suite now **22** integration tests +
91 matcher fixtures, all green.

---

## R5 — `ConfigChange` tamper-detection hook ✅ DONE (2026-05-31)

**Why.** Anthropic team-security guidance: *"Audit or block settings changes
during sessions with `ConfigChange` hooks."* CVE-2025-59536 showed repo-controlled
`.claude/settings.json` can auto-execute hooks on collaborators' machines — so
mid-session tampering of settings/baseline config is a live concern.

**What to build.** A new opt-in module on the `ConfigChange` event that detects
edits to `.claude/settings.json`, `.claude/baseline.config.json`, and
`.claude/hooks/baseline/**` during a session and (under `block`) rejects the change
for the session, logging what changed.

**Acceptance criteria.** Editing the baseline config mid-session triggers the hook;
under `block` the change is rejected for the session; under `warn` it's reported.
**Files:** new `hooks/modules/config-guard.sh`, dispatcher/settings wiring, config + schema.
**Risk:** noisy if the team legitimately edits config often → scope the watched paths tightly; `warn` first.

**Interim defense shipped (2026-05-31).** Until this lands, `settings.template.json` deny-lists agent `Edit()` to `.claude/baseline.config.json`, `.claude/settings.json`, and `.claude/hooks/baseline/**`, so a prompt-injected/careless agent can't silently downgrade posture or tamper with hooks in-session (humans editing in their own editor are unaffected). `ConfigChange` is still worth building for richer detection/logging and to cover paths a deny-list can't.

**Shipped (2026-05-31) — with a verified scope correction.** Built `hooks/modules/config-guard.sh`, an opt-in `ConfigChange` module (`modules.configGuard.enabled`, off by default), wired in `settings.template.json` with `matcher: "project_settings"`, plus config + schema. **Scope correction (verified against live Anthropic docs):** `ConfigChange`'s domain is Claude Code *settings* files — its `source` is one of `user_settings|project_settings|local_settings|policy_settings|skills` — so it fires for `.claude/settings.json` (project_settings) but **NOT** for `.claude/baseline.config.json` (our custom file) or `.claude/hooks/baseline/**` (scripts). The original acceptance wording assumed otherwise. The hook therefore guards `.claude/settings.json` — where the baseline's own footprint (hook wiring + deny-list) lives and the exact CVE-2025-59536 vector — and on each project_settings change verifies: (1) `disableAllHooks` is not set (any truthy value, not just literal `true`), (2) all five baseline scripts are still wired as actual `bash`-invoked command hooks (including config-guard itself — self-protection; a mere path mention or an `echo` does not satisfy the launcher-anchored check), (3) the baseline-managed `permissions.deny` entries (secrets + self-protection) are all still present. Any failure → tamper report; under `block` exit 2 (Claude Code rejects the change), under `warn` exit 0. This adds coverage the interim deny-list can't: it catches **human/external** edits to settings.json, not just the agent's tools. Fail-closed per R1 (unparseable payload, missing `source`, a **non-object** or unreadable/invalid settings.json after a change, or any non-zero Python exit → exit 2 under block+failClosed). *No-Python note:* like every opt-in module it gates on config the interpreter must read, so a host without Python leaves it inert (not blocking) — the always-on `command-guard` guardrail is what fails closed on no-Python, and the deny-list is a permission rule needing no Python. The matcher uses `bcl_extract_value`, so the hook is robust if `file_path` is absent (derives the path from `source`). **Residual (deliberate):** `baseline.config.json` + hook scripts aren't `ConfigChange` sources, so they stay protected against the *agent* by the deny-list; non-overridable human/external coverage of those + of `user_settings`/`local_settings` is **R6** (managed settings). Added `config-guard.sh` to the **R3 policy-change gate**, and a coupling test asserts both `EXPECTED_DENY` and `REQUIRED_HOOK_CMDS` stay identical to `settings.template.json`. Tests: **13** integration cases in `tests/test_hooks.sh` (clean→0; disableAllHooks=true / disableAllHooks=1 / neutered-marker / config-guard-unwired / deny-removed / non-object-JSON / missing-file / no-source / unparseable → block; non-watched source → 0; warn→0; disabled→0) **plus** a report-content assertion, a "no Binary-file corruption" assertion, and the deny+hooks coupling assertion. Suite now **41** integration tests + 91 matcher fixtures, all green. *Two real bugs were caught during verification and fixed:* `grep` on the Python output declared the UTF-8 finding text "binary" and dropped lines (now bash string ops, no `grep` on `$OUT`), and Windows Python emits non-ASCII stdout in the legacy code page (em-dashes → mojibake), so the Python-generated finding text is now ASCII-only while the bash-emitted decoration stays UTF-8. The exit-code-only tests had passed despite the corruption — hence the new report-content assertion.

**Adversarial review (two rounds).** Round 1 (Opus code-reviewer) returned FIX-FIRST with a reproduced CRITICAL (a valid-JSON-but-non-object `settings.json` fail-open — `data.get()` raised, the unchecked Python exit left `OUT` empty, and the hook "validated") + 3 HIGHs (truthy-but-not-`True` `disableAllHooks` missed; the hook-wiring substring could be kept present while neutered; the documented no-Python fail-closed branch was dead because the opt-in gate runs first) + 2 MEDIUMs — all fixed: `isinstance(data, dict)` guard + a `rc=$?` belt-and-suspenders so any non-zero Python exit fails closed; truthy `disableAllHooks` detection; and a launcher-anchored structured hook-walk. Round 2 confirmed all six closed with no regressions/new fail-opens (SHIP-WITH-NITS) and flagged two MEDIUM residuals on the wiring check — both then closed here: the check now requires a real `bash …/<script>` invocation (not a substring) and covers **all five** wired scripts including config-guard's own ConfigChange wiring (self-protection).

---

## R6 — Managed-settings enterprise floor ✅ DONE (2026-05-31)

**Why.** The current distribution is a bootstrap script (copyable, overridable).
For a floor individual devs **cannot** disable, Claude Code managed settings are
the mechanism: `allowManagedHooksOnly`, `allowManagedPermissionRulesOnly`,
`strictPluginOnlyCustomization` (v2.1.82+), with vetted hooks distributed via a
force-enabled org **marketplace plugin**. A managed `deny` can't be overridden —
not by `--allowedTools`, not by `--dangerously-skip-permissions`.

**What to build.** A `managed/` profile that maps the always-on guardrails + secrets
deny-list into managed-settings form, plus an org-marketplace packaging of the hooks;
docs on deploying it (this is an org-admin action, not per-repo `install.sh`).

**Acceptance criteria.** A managed deny survives `--dangerously-skip-permissions`;
user/project hooks are blocked while the force-enabled plugin's hooks still run.
**Files:** new `managed/` profile + docs. **Risk:** admin/rollout coordination; sequence after R1–R4.

**Verification first (workflow `wf_90cbc16e-ae6`).** Before building, ran a fan-out
verification workflow — 7 managed-settings facts, each through a research→adversarial-refute
pipeline against the live docs (`code.claude.com`). All confirmed at high confidence:
the per-OS `managed-settings.json` paths (macOS `/Library/Application Support/ClaudeCode/`,
Linux/WSL `/etc/claude-code/`, Windows `C:\Program Files\ClaudeCode\` — `ProgramData`
deprecated v2.1.75); managed = highest precedence; a managed `deny` survives allow
rules, `--allowedTools`, **and** bypass mode (*"if a deny rule matches, the tool is
blocked, even in bypassPermissions mode"*); hooks can be defined directly in
managed-settings.json and *"disableAllHooks set in user/project/local cannot disable
managed hooks"*; `allowManagedHooksOnly` blocks user/project/plugin hooks except those
force-enabled via `enabledPlugins`; `strictPluginOnlyCustomization` (v2.1.82+) takes
`["skills","hooks","agents","mcpServers"]`.

**Shipped (2026-05-31).** New `managed/` profile, built entirely on verified facts:
- `managed/managed-settings.json` — the recommended floor: a **non-overridable**
  `permissions.deny` (secrets `Edit/Read(.env*)` + `**/secrets/**`, plus self-protection
  on `.claude/settings.json`, `.claude/settings.local.json`, `.claude/baseline.config.json`,
  `.claude/hooks/baseline/**`) **+** the always-on guardrails (command-guard, post-write
  dispatcher) wired as **managed hooks** (run even under a user `disableAllHooks`). User/project
  hooks still run alongside — low-disruption.
- `managed/managed-settings.strict.json` — adds `allowManagedPermissionRulesOnly`,
  `allowManagedHooksOnly`, and `strictPluginOnlyCustomization: ["skills","hooks","agents","mcpServers"]`
  for orgs wanting only managed/plugin sources (high-disruption; documented as such).
- `managed/README.md` — per-OS paths + precedence, the two profiles, the global
  `<BASELINE_PREFIX>` script-install step (and the config-only subset), the
  marketplace `enabledPlugins` force-enable path (documented at the verified level —
  no fabricated plugin manifest), version gates (→ `RELEASING.md`), how it **closes the
  R5 residual** (managed deny on the baseline files is non-overridable and org-wide,
  not one-repo like configGuard), and a 4-step **acceptance verification** (managed deny
  survives `--dangerously-skip-permissions` / `--allowedTools` / an allow rule; managed
  hooks survive a user `disableAllHooks`).

Tests: `tests/test_managed.sh` (wired into `run.sh` and the policy-change gate) validates
both profiles are valid JSON; the managed deny equals the expected floor (the baseline
deny-list **plus** the managed-only `Edit(.claude/settings.local.json)`, so the floor can't
be weaker than the per-repo template and the intentional extra is pinned); the guardrail
hooks are wired with the correct **structure** (right `matcher` + `{type:command, command,
timeout}` invoking command-guard / post-write, not just a substring); the profiles still
carry the `<BASELINE_PREFIX>` placeholder (so a future hardcoded path is caught); and the
strict profile carries the three lockdown keys. *Note:* managed settings are a Claude
Code runtime mechanism, so this is structural validation + the documented manual acceptance
test — not an automated end-to-end (no managed tier in the harness). Suite green (41 hook
integration + 91 matcher fixtures + the managed-profile checks).

---

## R7 — Pair secrets deny-list with a scoped read/path allowlist ✅ DONE (2026-05-31)

**Why.** OWASP's posture is **allowlist-primary**, with denylists as
defense-in-depth *secondary*. The baseline today is denylist-centric for secrets.

**What to build.** An optional managed/permission profile that allowlists the paths
agents may read/edit and denies the rest (with the secrets deny-list retained as a
backstop). Likely co-delivered with R6.
**Acceptance criteria.** A repo profile where only allowlisted paths are accessible;
secrets remain denied even if accidentally allowlisted. **Files:** `settings.template.json` variant / `managed/`.

**Verification first (workflows `wf_f06ce12d-ad1`, `wf_8d903255-212`).** The mechanism
was non-obvious, so two fan-out verification rounds (research→adversarial-refute against
the live docs) pinned it at high confidence:
- **The naive allowlist does NOT work.** Claude Code evaluates **deny → ask → allow**
  *categorically*, deny always wins; a catch-all `deny: ["Read(**)"]` + narrow
  `allow: ["Read(src/**)"]` blocks the allowlisted paths too. Confirmed against the docs.
- **`permissions.defaultMode: "dontAsk"` is the real default-deny** (verbatim: *"dontAsk
  mode auto-denies every tool call that would otherwise prompt; only actions matching your
  permissions.allow rules and read-only Bash commands can execute"*) — it auto-**denies**
  unlisted actions (NOT auto-approve; opposite of `bypassPermissions`).
- **`sandbox` schema:** `{sandbox:{enabled,filesystem:{allowWrite,denyWrite,denyRead},network:{allowedDomains,…}}}`;
  paths are absolute / `~` / `//` (not `./`); **macOS/Linux/WSL2 only** (native Windows
  unsupported). Crucial limit: **`denyRead` bounds only Claude's Read/Glob/Grep tools, not
  Bash subprocess reads** (`cat .env` reads through the OS).
- **Deny precedence has community-reported edge cases** (e.g. #45511: a specific Bash-pattern
  deny may not narrow a broad Bash allow) — which is precisely why allowlist-primary *grants
  narrow* instead of subtracting from broad.

**Shipped (2026-05-31).** `managed/allowlist.example.json` — a starter allowlist-primary
profile built on the verified mechanism: `permissions.defaultMode: "dontAsk"` (default-deny)
+ a minimal `permissions.allow` (repo-relative file access + a small safe-Bash set, *adapt
per repo*) + the secrets/baseline-self-protection `deny` as a backstop **for Claude's Read
tool** (deny beats allow, so the Read tool can't read a repo `.env` even though `Read(./**)`
is allowed — the part of the acceptance guarantee that holds) + a `sandbox` block (deny
Claude's read tools access to `~/.aws`/`~/.ssh`/`~/.gnupg`/… and **allowlist outbound
domains** — the real exfiltration control). **Honest scope correction surfaced in review:**
the secrets-denied-even-if-allowlisted guarantee holds for the Read *tool* only — *no
permission/sandbox setting reliably stops a Bash subprocess read* (`cat .env` runs through
the OS, and `dontAsk` auto-permits read-only Bash regardless of `allow`; `denyRead` is also
Read-tool-only). So the README leads with the realistic mitigations — **secret hygiene**
(don't keep real secrets on disk) and the **network sandbox** (limits where a read secret
can be sent) — and the example drops file-reading Bash verbs (`cat`/`rg`) rather than advertise
a leak. Documented in `managed/README.md` (new "Allowlist-primary profile (R7)" section): the
mechanism, why the naive deny-all+allow fails, the secrets-read reality + mitigations, the
deny-reliability caveats (as the *rationale* for grant-narrow), the `denyRead`-is-Claude-tools-only
and Windows-needs-WSL2 limits, deploy-as (per-repo high-assurance vs org-wide managed lockdown),
and a 4-step acceptance test (incl. demonstrating the `cat .env` boundary). `tests/test_managed.sh` (+ policy gate) validates the profile:
valid JSON, `defaultMode == "dontAsk"`, non-empty `allow`, deny ⊇ the secrets/self-protection
backstop, no project-relative `./` in `sandbox.filesystem` paths, and a **footgun guard** that
fails if the `allow` grants a file-reading Bash verb (`cat`/`rg`/`grep`/…) alongside a secrets
`Read` deny (which would leak `.env` via subprocess). Suite green. *Honest limitation:*
like R6, this is structural validation + a documented manual acceptance test (permission
modes / sandbox are runtime mechanisms the harness can't exercise).

---

## Open questions — ✅ RESOLVED (2026-05-31)

These came out of the deep-research report and intersect our **no-external-telemetry /
no-webhook** rule. All four were decided via a consensus plan (Planner→Architect→Critic,
4 rounds → APPROVE) and implemented — full rationale, alternatives, pre-mortem, and
acceptance criteria in [`OPEN-QUESTIONS-PLAN.md`](OPEN-QUESTIONS-PLAN.md).

1. **Metrics.** ✅ One read-only `tools/baseline-status.sh` — a cross-repo **drift differ**
   that *sources* `common.sh`'s `bcl_*` readers (single source of truth); the per-repo
   posture table is a byproduct. The three pure-snapshot signals (bare posture read,
   block-event counts, override counts) stay **documented one-liners** in `tools/README.md`.
   No webhooks/telemetry — signals to interpret, not gate.
2. **False-positive budget.** ✅ A **non-shrink corpus floor** (`FP_FLOOR` in
   `test_command_guard.py`) + a fixture-first tuning loop + a `RELEASING.md` belt —
   *not* a field-FP percentage (unmeasurable with no telemetry). Deleting an allow
   fixture fails the suite; growing it prints a bump-the-floor nudge.
3. **Multi-repo versioning/drift.** ✅ A `baselineVersion` stamp (written create-path-only,
   so `install.sh`'s never-clobber config contract is preserved) + a gate-neutral one-line
   `hooks/VERSION` marker (recopied every run; *not* in `policy_re`, so `common.sh` is
   untouched). Drift via `baseline-status.sh --drift`; reconcile by re-running `install.sh`.
4. **Onboarding format.** ✅ `ONBOARDING.md` stays canonical; the "interactive sandbox" is
   the existing `install.sh --target` one-liner (Part 5 — no bespoke tool); and one recorded
   ~30-min **lunch-and-learn kickoff** (Part 8). The recommendation is the format *shape*
   (doc + sandbox + one live session), with the doc/lab/live weighting illustrative and
   owner-tunable.

## Sources

- Anthropic Claude Code docs — hooks, hooks-guide, permissions, security (exit codes, managed settings, ConfigChange, command blocklist).
- OWASP AI Agent Security Cheat Sheet (fail-closed, allowlist-primary, CI release gates) & LLM01 Prompt Injection.
- Check Point Research — CVE-2025-59536 (repo-file RCE / token exfiltration).
- Snyk / Cycode — education-before-enforcement, visibility→block ramp.
- Full verified report: deep-research task `wa5kmvutp` (25 claims verified, 0 refuted).
