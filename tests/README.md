# claude-code-baseline — tests

Versioned adversarial test suite + release gate for the baseline (ROADMAP R3).
The goal: the deny-list / command-guard matcher logic **cannot change without
updated, reviewed fixtures**.

## Run everything

```bash
bash tests/run.sh
```

Requires `bash` + `python3` (and `git` for the integration suite). Exits non-zero
on any failure. Runs under Linux, WSL, macOS, and Git Bash on Windows.

## What's here

| File | What it checks |
|------|----------------|
| `run.sh` | Aggregate runner: shell `bash -n`, Python `py_compile`, then the suites below. |
| `test_command_guard.py` | Pure unit fixtures for the matcher (`hooks/lib/command_guard_match.py:evaluate`): the original blocklist, evasion variants (whitespace, quoting, flag reordering, wrappers, compound commands, `//`/`$HOME/`/`./*`, `--force-with-lease=ref`, `python -mpip`…), intentional non-targets (`rm -rf ./build` stays allowed), false-positive regressions (`grep -e "delete from"`, `git rm -rf .`, `npm run install:ci`…), and documented known-limits (base64 / `$VAR` indirection). |
| `test_hooks.sh` | End-to-end: installs the baseline into a throwaway repo and exercises each hook's exit codes — command-guard, security-defaults fail-closed (missing/malformed/empty rules), exit-2 semantics, posture (`block`/`warn`/`failClosed`) toggles, malformed-config, scope-guard, fix-tags. |
| `test_latency.sh` | **Latency regression gate** (`run.sh` step 7). Installs the baseline into a throwaway repo and times the hot-path hooks — command-guard (every Bash call), the post-write dispatcher (every Write/Edit), scope-guard, and config-guard — failing if one exceeds its budget. |
| `policy-change-gate.sh` | **Release gate.** Fails if a change touches `command-guard.sh`, the matcher, `common.sh`, or `settings.template.json` (the deny-list) without also touching `tests/`. |

## Adding a rule? Add a fixture.

Any change to the matcher, the deny-list, or a guard hook **must** come with a
fixture in `test_command_guard.py` (a `(label, command, B/A, extra)` row) and/or
`test_hooks.sh`. The `policy-change-gate.sh` check (run in CI on PRs) enforces this.

When you add a new blocked pattern, also add the matching **evasions** you expect
it to resist and at least one **near-miss that must stay allowed**, so the
true-positive and false-positive boundaries are both pinned.

## False-positive budget & tuning loop (ROADMAP Q2)

command-guard is **defense-in-depth**, not a wall — so the question isn't "what % of
real commands does it wrongly block" (unmeasurable: with no telemetry there's no
command-traffic denominator, so any percentage would be theater). The budget is a
**non-shrink floor on the committed allow corpus** instead:

- **Target: zero false positives across the `A` (allow) fixtures, and that corpus never
  shrinks.** `test_command_guard.py` defines `FP_FLOOR` (the current allow-fixture count).
  `run()` asserts `n_allow >= FP_FLOOR` and **fails** if an allow fixture was deleted —
  that deletion would silently remove a pinned "this must stay allowed" guarantee.
- **It drifts low between releases by design.** `FP_FLOOR` is a hardcoded literal, *not*
  derived from the fixtures at runtime (a derived floor would be tautological — deleting a
  fixture would lower both sides and protect nothing). So adding an allow fixture leaves
  the floor stale; `run()` prints a **non-failing** `note: allow-floor stale by N; bump
  FP_FLOOR to <n>` line until you raise it. `RELEASING.md` makes the bump a release gate.
- **`FP_FLOOR` is a non-shrink corpus floor, NOT a field-FP rate.** Don't read a green run
  as "low false positives in the field" — read it as "no committed allow case regressed."

**The tuning loop — when a real false positive is reported:**

1. **First, add a fixture** capturing it: a new `("fp <what>", "<the command>", A, ())` row
   in `test_command_guard.py` (and bump `FP_FLOOR` to the new count in the same change).
2. *Then* adjust `command_guard_match.py` so the case is allowed without regressing any
   `B` (block) fixture. The green run is the proof the boundary moved correctly.
3. `policy-change-gate.sh` already forces any matcher change to ship with a `tests/` change,
   so the fixture-first discipline is mechanically enforced on PRs.

A new *blocked* pattern is the mirror image: add the `B` fixture + its evasions + a
near-miss `A`, never flipping an existing `A` to blocked.

## Latency budgets (`test_latency.sh`)

Every other test here asserts on exit codes, and an exit code has no clock on it.
That is how a **17.4s** post-write dispatcher and a **5.6s** command-guard — one on
every file write, the other on every Bash call — survived a full adversarial review.
A security control that costs seconds per command gets switched off, and a control
that is switched off is a security outcome, so latency is a tested property here.

**What it measures.** The hooks on the hot path, each fed a payload on stdin and
timed as a process. The test is deliberately behavioural (payload in, exit code out):
it knows nothing about interpreter counts, memoisation, or `common.sh` internals, so
it survives refactors of them. It also asserts the expected exit code for each run —
without that, a hook that crashed on line 1 would post a superb time and pass.

**Why min-of-N, not a mean or a single sample.** Windows antivirus and filesystem
noise produce large one-off spikes: a bare interpreter start was observed at both
61ms and 1150ms on the same machine in one session. A mean inherits every spike and
makes the gate flaky, which is how latency tests get muted rather than fixed. The
minimum answers "how fast can this hook go on this host" — the property a real
regression actually moves, since a regression slows the fast path too. `REPS=5`.

**Budgets are ceilings, not targets**, and each sits in the empty band between the
healthy and the regressed population (~3-6x above measured, comfortably below the
pre-fix value). To adjust one, edit the `BUDGET_*` constants near the top of
`test_latency.sh` — and update the measured-numbers comment above them in the same
change, so drift stays visible to the next reader. The measurement for every hook is
printed on **every** run, passing or failing, so a hook creeping from 500ms toward
its budget is visible in CI logs before it crosses.

Raising a budget is a finding to explain, not a chore: the usual cause of a failure
is a helper that spawns its own interpreter per call, and the fix belongs in the
hook, not in the constant.

**Skips cleanly** (exit 0, with a message) where `date +%s%N` has no nanosecond
precision — BSD/macOS `date` prints a literal `N`. A latency test that reports a
false failure on a developer's machine gets deleted, not fixed.

## CI

`../.github/workflows/baseline-ci.yml` runs `run.sh` on every push/PR and the
policy gate on PRs — active once this directory is its own repository.
