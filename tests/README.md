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
| `run.sh` | Aggregate runner: shell `bash -n`, Python `py_compile`, then the two suites below. |
| `test_command_guard.py` | Pure unit fixtures for the matcher (`hooks/lib/command_guard_match.py:evaluate`): the original blocklist, evasion variants (whitespace, quoting, flag reordering, wrappers, compound commands, `//`/`$HOME/`/`./*`, `--force-with-lease=ref`, `python -mpip`…), intentional non-targets (`rm -rf ./build` stays allowed), false-positive regressions (`grep -e "delete from"`, `git rm -rf .`, `npm run install:ci`…), and documented known-limits (base64 / `$VAR` indirection). |
| `test_hooks.sh` | End-to-end: installs the baseline into a throwaway repo and exercises each hook's exit codes — command-guard, security-defaults fail-closed (missing/malformed/empty rules), exit-2 semantics, posture (`block`/`warn`/`failClosed`) toggles, malformed-config, scope-guard, fix-tags. |
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

## CI

`../.github/workflows/baseline-ci.yml` runs `run.sh` on every push/PR and the
policy gate on PRs — active once this directory is its own repository.
