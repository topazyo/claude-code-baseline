# tools/ — local, read-only baseline reporting

These are **operator** helpers (not hooks). They are **read-only** and make **no network
requests**: they read on-disk files, shell out to `python3`/`git` to parse them, and
write nothing unless you explicitly ask for a JSON file. That is the no-telemetry /
no-webhook rule this project is built under — every signal here is collectable from
disk, and nothing phones home.

> Why a script at all (and not just one-liners)? See **"What is deferred, and why"**
> below. The one capability a one-liner cannot give you — a single, CI-gateable
> *cross-repo* drift check — is the entire reason `baseline-status.sh` exists. Its
> posture table is a byproduct of the same read, **not** an "adoption metric."

---

## `baseline-status.sh`

```bash
tools/baseline-status.sh [--drift] [--strict] [--json <outfile>] <repo>...
```

For each repo it reports:

| Column | Meaning |
|--------|---------|
| `installed` | Is `.claude/hooks/baseline/` present? (Has the baseline been adopted at all.) This says the hook *files* are on disk; whether `settings.json` runs them is the `settings` row below. |
| `posture` | `enforcement` (`block`/`warn`), resolved via `common.sh`'s `bcl_posture`. `unknown` when `.claude/baseline.config.json` exists but cannot be read (`bcl_config_malformed`): the hooks then fail closed, so the defaults are not the repo's posture. The report prints the parse error, `failClosed` and `minClaudeCodeVersion` read `unknown` too, `guardrails` / `modules` read `unknown`, and `hookLaunchProblems` gains `baseline.config.json unreadable`. For a hook tree without its `INSTALL_SCOPE` marker (see `settings`), `posture`, `failClosed`, `guardrails` and `modules` are read as those hooks read them: from the `managed.config.json` beside them, or the safe defaults without one; an unreadable one is reported as `managed.config.json unreadable`. |
| `failClosed` | The global fail-closed toggle. |
| `version` | The repo's **installed** `.claude/hooks/baseline/VERSION` (the baseline revision its hooks came from). |
| `drift` | `OK` (matches the source `baselineVersion`), `DRIFT` (on an older/different baseline), `no-version` (installed but pre-`VERSION` baseline), or `not-installed`. |
| `minClaudeCodeVersion` + `ok` | The repo's pinned min Claude Code version, and whether it equals this source tree's canonical pin (a config-drift signal). |
| `guardrails` / `modules` | Which are **enabled**, resolved via `common.sh`'s `bcl_guardrail_enabled` (default on, for `commandGuard`), `bcl_guardrail_opted_in` (default off, for `autoFormat`, which runs repo code) and `bcl_module_enabled` — the *same* readers the hooks use. |
| `settings` (JSON `settingsEnvRisk`, `hookLaunchProblems`) | `risky env`: keys of `.claude/settings.json` / `.claude/settings.local.json` `env` that can run code before the baseline hooks, redirect them or switch them off (the installer's list, `lib/merge_settings.py`). `hook wiring`: baseline scripts the template wires that `settings.json` does not run exactly as `bash -p "<project>/.claude/hooks/baseline/<script>"` with the template's keys beside it (no `args`, a bash `shell`, not `async`, at least the template's `timeout`), including ones not wired at all; a guard a `PreToolUse` entry runs without `onFailure: block`, as config-guard reports (`<script> without onFailure block`); ones not wired under the template's event, in a group whose matcher covers the template's (match-all, or names joined by `|` that include the template's; a regex never counts), as a direct entry with no `if` (`<script> not under <event> [<matcher>]`, with no matcher for a template group without one); a hook entry in `settings.local.json` that names a baseline script in its command or args (`settings.local.json runs <script>`; the installer never writes one there); a file under the repo's `.claude/agents/` or `.claude/skills/` that names the baseline hook directory (`<path> names the baseline hook directory`, or `<path> unreadable`; scope-guard refuses writing one); plus a `disableAllHooks` in either file, and `baseline.config.json unreadable` (see `posture`); and `no INSTALL_SCOPE marker (hooks run as a managed tree)` for a `.claude/hooks/baseline/` whose hooks look for the marker `install.sh` writes and do not find it (a manual copy of `hooks/`, or a link to a managed prefix): those hooks take `enforcement`, `failClosed` and the guardrail and `runTests` switches from a `managed.config.json` beside them, never from the repo. A tree from before the marker existed follows the repo's config and is reported by `drift` instead. A check that cannot run reports `check-failed`. This tool runs outside Claude Code, so the shell those env values reach does not start it. |
| `deny-list` (JSON `denyListMissing`) | The entries of `settings.template.json`'s `permissions.deny` (the secrets and self-protection rules the installer merges in) that `.claude/settings.json`'s `permissions.deny` lacks, in template order and exactly as the template spells them; `[]` when none is missing, and every entry when `settings.json` is absent or cannot be read. The rule is config-guard's: exact strings (a rewritten but equivalent glob reads as missing), only string entries of a list under an object, the file as parsed (a duplicate key is last-wins, as in Claude Code). `settings.local.json` is not checked for it, and rules Claude Code would merge in from user or managed settings do not count. One difference from config-guard: this tool reads a settings file with a UTF-8 BOM or `//` comments, which config-guard reports as unreadable. `null` in JSON (`check-failed` in the text) when the check could not run. |

Modes:

- **`--drift`** *(default view)* — print the per-repo report. `drift` is the headline signal.
- **`--strict`** — exit non-zero if **any installed** repo has drifted from the source
  `baselineVersion`, or has a `settings` or `deny-list` finding. A `not-installed` repo does **not**
  trip this (that's "not adopted," a separate state from "behind"). *(Intended CI
  consumer below.)*
- **`--json <outfile>`** — also write the full report as JSON to `<outfile>`. This is the
  **only** filesystem write the tool performs; without it, the tool writes nothing.

**Reconciling drift:** re-run `install.sh --target <repo>`. The installer recopies the
hook subtree wholesale every run, so the installed `VERSION` is refreshed to the source
value.

> **`VERSION` is a convention stamp, not an integrity check.** Earlier revisions of this
> file called it "always truthful… deny-protected," and it is neither. It is a plain
> one-line text file. `Edit(.claude/hooks/baseline/**)` binds one *tool*; the path-text
> `Bash(*.claude/hooks/baseline/*)` rule catches only the form where that path appears
> literally in the command; and neither is a filesystem permission, so a shell redirect —
> or a human, a Makefile, a CI job — writes it freely. Nothing verifies that its contents
> describe the tree sitting beside it, so a stale or locally-weakened hook tree with a
> forged stamp reports `drift=OK`, including under `--strict`. Read `drift` as *"which
> install probably ran here."* If you need it to be trustworthy, the fix is a checksum of
> the installed tree against source, not a stricter reading of this file.

### Single source of truth (why it sources `common.sh`)

The script does **not** re-parse `baseline.config.json` itself. It sources
`hooks/lib/common.sh` and calls `bcl_config_malformed` / `bcl_module_enabled` /
`bcl_posture` / `bcl_guardrail_enabled` / `bcl_guardrail_opted_in` — the exact
functions the hooks call. So if the config schema or
the "enabled" logic ever changes, the report changes in lockstep and can never report a
posture the hooks don't actually enforce. (A second, independent parser was rejected for
exactly this reason.)

> **Known cost:** `common.sh`'s `bcl_cfg` spawns a fresh `python3` per key per repo, so
> the posture *table* is O(keys × repos) process spawns and is noticeably slow at the
> upper end (e.g. ~20 repos). The primary `--drift` signal reads one value per repo and is
> unaffected. If the table feels slow in practice, batch the per-repo reads behind one
> `python3` call — but do **not** re-implement config parsing outside `common.sh`.

### `--strict` has no CI consumer in this repository

`--strict` is intended for an **operator-run or org-level** job that fails on drift.
**No workflow in `.github/workflows/` invokes it** — `baseline-ci.yml` runs only
`tests/run.sh`, and `policy-gate.yml` only fetches the base branch and runs its copy of
`tests/policy-change-gate.sh`; neither mentions `baseline-status.sh`, `--strict`, or drift. An earlier revision of this file
blamed the inertness on the workflow being dormant while vendored, implying `--strict`
would start working once this directory became its own repository. It does not, and it
cannot: a cross-repo drift check needs the *consumer* repos checked out, which this
repo's CI has no access to. Today `--strict`'s only exerciser is `tests/test_status.sh`.

The script still earns its place via the on-demand, cross-repo `--drift` check a human
would otherwise eyeball N times — run it from wherever your repo checkouts live (a
scheduled job on an admin box, or an org-level workflow that clones the fleet).
**If you'd rather not maintain a script at all**, the data layer alone
(`baselineVersion` + `hooks/VERSION`) plus the one-liner below is a fully valid smaller
footprint.

Cross-repo drift one-liner (no script), if you go that route:

```bash
src=$(python3 -I -c 'import json;print(json.load(open("claude-code-baseline/baseline.config.json"))["baselineVersion"])')
for r in <repo1> <repo2> …; do
  printf '%s\t%s\n' "$r" "$(tr -d "\r\n" < "$r/.claude/hooks/baseline/VERSION" 2>/dev/null || echo MISSING)"
done | awk -v s="$src" '{print $0, ($2==s?"OK":"DRIFT")}'
```

---

## What is deferred, and why (the three pure-snapshot signals)

The roadmap's metrics question listed three effectiveness/adoption signals. Each is a
**snapshot a one-liner answers** at this org's scale, so none is built — they live here as
documented commands and graduate to scripted parsing only when a real stream and a real
need justify the maintenance:

1. **Bare posture read (no cross-repo drift).** A human reads N configs in minutes:
   ```bash
   git -C <repo> log -1 --format=%cd -- .claude/hooks/baseline   # when was it last installed/updated
   ```
   (Or just open `<repo>/.claude/baseline.config.json`.) The *script* is justified by the
   cross-repo **drift** diff, not by this snapshot.

2. **Block-event counts** (how often a guardrail fired), from CI logs you already keep:
   ```bash
   git grep -c "REGRESSION BLOCKER" <ci-log-glob>        # security-defaults blocks
   git grep -cE "command-guard|BLOCKED" <ci-log-glob>    # command-guard blocks
   ```
   Adapt the banner substrings to your log format. Fragile across log-format churn — hence
   not scripted until there's a stable stream.

3. **Override / false-positive counts**, from reviewable config history:
   ```bash
   git -C <repo> log -p -- .claude/baseline.config.json \
     | grep -E '(extraPatterns|"enforcement": ?"warn"|"failClosed": ?false)'
   ```
   Assumes config toggles arrive as reviewable commits (nothing enforces that shape), and
   `git log` grepping is fragile over rename/format churn — so it stays a manual command
   and pairs with the command-guard false-positive tuning loop (see `tests/README.md`).

> **These are signals to interpret, not gates.** No threshold is hard-coded anywhere; the
> tool reports and humans decide. That's deliberate under the no-telemetry constraint.
