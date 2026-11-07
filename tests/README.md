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
| `test_merge_settings.py` | Pure unit fixtures for the install-time merge (`lib/merge_settings.py:merge_hooks`): baseline hook entries are removed one by one, so a repo's own hook in the same matcher group, its fields and the group's keys survive; unrecognised shapes are kept in place; only a group the merge emptied is dropped; merging twice changes nothing. |
| `test_hooks.sh` | End-to-end: installs the baseline into a throwaway repo and exercises each hook's exit codes — command-guard, security-defaults fail-closed (missing/malformed/empty rules), exit-2 semantics, posture (`block`/`warn`/`failClosed`) toggles, malformed-config, scope-guard, fix-tags, that the Stop tracker-reminder prints its reminder as one JSON `systemMessage` object (and nothing when there is nothing to remind about), once per session and then only for a new matching commit, falling back to every stop when its session memory in `.git` cannot be used, that no inherited environment variable can make the hooks skip `common.sh` or pass its globals on, that every Python the baseline's own helpers start is isolated (`-I -S -X utf8`: modules planted in the project, on `PYTHONPATH` or as a `.pth` file are never imported; non-ASCII patterns and rule messages work), and that an interpreter that is found but does not run makes command-guard and the post-write dispatcher fail closed — plus the installer itself: a repo's own hooks survive the settings merge, and the installer refuses before writing anything unless the interpreter the hooks will use runs, prints nothing else on stdout, and is 3.7+ (a Windows Store `python3` stub is skipped when a real Python is there). |
| `test_latency.sh` | **Latency regression gate** (`run.sh` step 7). Installs the baseline into a throwaway repo and times the hot-path hooks — command-guard (every Bash call), the post-write dispatcher (every Write/Edit), scope-guard, and config-guard — failing if one exceeds its budget. |
| `translation_sync.py` | **Hebrew-docs drift gate** (`run.sh` step 8). Fails when an English section of `ONBOARDING.md` or a translated section of `README.md` changed after its Hebrew counterpart was translated, or when a translation altered, dropped or invented a command, carries a bidi-control character, lacks its direction wrappers, links to a missing anchor, or quotes a hook message that no longer exists. Also the maintainer tool for `stamp` / `mark-stale` (below). |
| `test_translation_sync.py` | Fixtures for the drift gate: each defect class above is planted in a throwaway repo and must fail; `mark-stale` → `stamp` round-trips. |
| `policy-change-gate.sh` | **Release gate.** Fails a change to what the baseline enforces — `hooks/`, `lib/`, `tools/`, `managed/`, `examples/`, `tests/`, `.github/`, `install.sh`, `settings.template.json`, `baseline.config.json` (beyond its version line), the schema, `.gitattributes`, `.gitmodules`, matched in any case; root-level `*.md`, any `README*.md`, `hooks/VERSION` and `.github/CODEOWNERS` are exempt — unless an enforcement fixture file at the root `tests/` (`test_command_guard.py`, `test_hooks.sh`, `test_managed.sh`, `test_merge_settings.py`, `test_status.sh`, `test_policy_gate.sh`) was added or modified. Renames count on both sides. |
| `test_policy_gate.sh` | Regression suite for the gate (`run.sh` step 9): scratch repositories, one kind of change per case — what is policy, what is exempt, what satisfies it, renames, deletions, and every way of not knowing the change set failing closed. |

## Adding a rule? Add a fixture.

Any change to the matcher, the deny-list, or a guard hook **must** come with a
fixture in `test_command_guard.py` (a `(label, command, B/A, extra)` row — in
`PS_CASES` if it is a PowerShell-tool payload) and/or `test_hooks.sh`. The `policy-change-gate.sh` check (run in CI on PRs) enforces that a fixture file changed — only that: a one-line edit to any enforcement fixture file satisfies it. It makes a reviewer look at the fixtures; it does not prove they cover the change.

A new rule site that emits a block reason also needs a `MUST_BLOCK` row (below).

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
3. `policy-change-gate.sh` already forces any matcher change to ship with an added or
   modified fixture file, so a fixture-free matcher change cannot pass a PR.

A new *blocked* pattern is the mirror image: add the `B` fixture + its evasions + a
near-miss `A`, never flipping an existing `A` to blocked.

**The block side has the same floor, and more.** Deleting a rule's `B` fixtures together
with the rule is how a disabled rule would pass, so `test_command_guard.py` also checks:

- **`BLOCK_FLOOR`** — the block-fixture count in `CASES` + `PS_CASES` never shrinks (same
  rules as `FP_FLOOR`: fails below, prints a bump note above).
- **`MUST_BLOCK`** — a frozen list outside `CASES`: the original blocklist plus one row per
  reason-producing site in the matcher, each with the reason it must block for. Several
  sites share one reason string, so a row per *site*, not per rule family. Edit a row only
  when the rule behind it is deliberately retired, under review.
- **Reason coverage** — every block-reason literal the matcher builds must be produced
  by some fixture. The literals are read with `ast` from the functions that build
  reasons (`_rules_at`, `_git_rules`, `_git_push_config_reasons`, `_reasons_for`,
  `evaluate`: a string appended, returned in a list or assigned to a name), plus every
  `_Uninspectable` message. A rule switched off with its fixtures deleted leaves its
  reason produced by nothing, and the run fails. `REASON_FLOOR` pins how many literals
  the walk finds, so a reason moved into a module constant (which the walk cannot see)
  fails the run instead of quietly leaving coverage; a new reason in another function
  needs that function added to `_REASON_FUNCS`.

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

## Hebrew translations (`translation_sync.py`)

`ONBOARDING.he.md` is a complete Hebrew translation of `ONBOARDING.md`;
`README.he.md` translates the README's opening and its "What this does not
protect against" section. The English files are authoritative. Each translated
section starts with a marker recording the hash of the English section it was
translated from:

```
<!-- he-sync: part-2--why-secure-by-default-for-an-ai-coding-agent sha256=0123456789abcdef -->
```

**You edited an English section and step 8 failed.** The failure names the section.
Then either:

1. **Retranslate it** in the same change, then record that:
   `python3 tests/translation_sync.py stamp ONBOARDING.he.md <section-id>`; or
2. **If you cannot**, mark it instead:
   `python3 tests/translation_sync.py mark-stale ONBOARDING.he.md <section-id>`.
   This records the new hash *and* puts a visible Hebrew banner on the section
   ("this section may be out of date; the English wins"). `stamp` removes it once
   someone retranslates the section.

Never `stamp` a section you did not retranslate: that hides exactly the drift the
gate exists to show. Commands, JSON and every inline code span must stay
byte-identical to the English; diagrams may be explained in Hebrew below the
original. A translator's own note goes between `<!-- he-note:start -->` and
`<!-- he-note:end -->`, and Hebrew-only appendices after `<!-- he-only -->`; the
message decoder (`<!-- he-decoder:start -->` … `end`) is checked against the hook
source instead.

## CI

`../.github/workflows/baseline-ci.yml` runs `run.sh` on every push/PR, on Ubuntu and
Windows. `../.github/workflows/policy-gate.yml` runs the policy gate on pull requests
only — the **base branch's** copy of `policy-change-gate.sh`, so a PR that weakens the
gate is judged by the gate it changes. It is its own workflow because a skipped job
reports "Success": as a job in the push-and-PR workflow it posted a skipped "Success"
under the same check name on every push. Branch protection on `main` requires both test
suites and the gate.

Limit: on `pull_request` GitHub runs the workflow from the PR's merge commit, so a PR
that edits `.github/workflows/` can change or skip the job that judges it. The gate
counts `.github/` as policy, so such a PR needs a fixture change and shows the workflow
diff to the reviewer — but only that reviewer stops it. A dependabot, issue-template
or pull-request-template change under `.github/`, or a change to only the translation
checker under `tests/`, needs a fixture touch too; accepted.
