# Releasing claude-code-baseline

> Per-release re-verification checklist (ROADMAP **R4**). The Claude Code hook /
> permissions / managed-settings surface evolves between releases, and the baseline
> relies on specific documented behaviors. Re-confirm them against **live Anthropic
> docs** before adopting a new Claude Code version org-wide or bumping the pin.
>
> **Owner:** Topaz Hurvitz <topazhu@postil.com> · **Local-only**, like the rest of `claude-code-baseline/`.

---

## The version pin

`baseline.config.json → minClaudeCodeVersion` records the **floor** the baseline's
behavior was verified against. `install.sh` detects the live `claude --version` and
prints an **advisory warning** (never blocks) when it is older.

Current pin: **`2.1.80`** — the release where a hook/permission `allow` could no
longer bypass a `deny` rule. The tamper-protection deny-list
(`Edit(.claude/settings.json)`, `Edit(.claude/baseline.config.json)`,
`Edit(.claude/hooks/baseline/**)`) depends on `deny` being unconditionally
enforced, so anything older silently weakens it.

Bump the pin **only** after walking the checklist below and updating the ledger.

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
- [ ] **`deny` is enforced even when an `allow` rule is present** (the v2.1.80 fix).
      *(Load-bearing for the secrets + tamper-protection deny-list → the version pin.)*
- [ ] **Stop hook exit `2`** semantics (continue/block) unchanged. *(trackerReminder.)*
- [ ] **`ConfigChange` event** still exists with the documented payload/semantics.
      *(R5 — tamper-detection hook; interim defense is the deny-list above.)*
- [ ] **Managed-settings knobs** — `allowManagedHooksOnly`,
      `allowManagedPermissionRulesOnly`, `strictPluginOnlyCustomization` (v2.1.82+) —
      behave as documented; a managed `deny` still survives `--dangerously-skip-permissions`;
      the per-OS `managed-settings.json` paths are unchanged (macOS `/Library/Application Support/ClaudeCode/`,
      Linux `/etc/claude-code/`, Windows `C:\Program Files\ClaudeCode\`). *(R6 — **shipped** in
      `managed/`; run its README "acceptance verification" on a real deploy.)*
- [ ] **Managed hooks survive `disableAllHooks` from below** — *"disableAllHooks set in
      user/project/local cannot disable managed hooks."* *(R6 managed hooks rely on this.)*
- [ ] **`deny` is categorical and beats `allow`** — a catch-all `deny(**)` overrides a narrow
      `allow`. *(R7: the secrets deny stays a reliable backstop; the naive allowlist is invalid.)*
- [ ] **`defaultMode: "dontAsk"` auto-DENIES unlisted actions** (only `allow` matches +
      read-only Bash run) — not auto-approve. *(R7 allowlist-primary depends on this.)*
- [ ] **`sandbox.filesystem` schema** (`allowWrite`/`denyWrite`/`denyRead`, abs/`~`/`//` paths)
      and the limit that **`denyRead` bounds only Claude's Read/Glob/Grep tools, not Bash
      subprocess reads**; macOS/Linux/WSL2 only. *(R7 sandbox layer.)*
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
6. Note the change in `ROADMAP.md` if it shifts any item.

### Multi-repo drift (between releases)

Re-run `install.sh --target <repo>` on a regular cadence; then run
`tools/baseline-status.sh --drift <repos…>` (or `--strict` in CI) to confirm every repo
is on the current `baselineVersion`. The marker is the recopied `.claude/hooks/baseline/VERSION`,
which is always truthful (not a hand-editable config field) and is deny-protected by
`Edit(.claude/hooks/baseline/**)`.

---

## Version-fact ledger

Each row: a behavior the baseline relies on, the Claude Code version that established
it, and when we last re-confirmed it against live docs.

| Behavior | Established in | Last re-verified | Notes |
|----------|----------------|------------------|-------|
| `allow` no longer bypasses `deny` | v2.1.80 | 2026-05-31 | Sets the current pin; tamper/secrets deny-list depends on it. |
| `strictPluginOnlyCustomization` available | v2.1.82 | 2026-05-31 | Needed for R6 (managed floor), not the current baseline. |
| `disableAllHooks` gap fixed | early 2026 | 2026-05-31 | Re-check there's no new hook-disable bypass. |
| PreToolUse exit 2 blocks before permissions | (longstanding) | 2026-05-31 | Core of command-guard / scope-guard. |
| PostToolUse exit 2 = full feedback (no block) | (longstanding) | 2026-05-31 | Core of R0 module semantics. |
