# tools/ — local, read-only baseline reporting

These are **operator** helpers (not hooks). They are **read-only** and **local-only**:
they read on-disk files and shell out to `python3`/`git` to parse them, make **no
remote requests**, and write nothing unless you explicitly ask for a JSON file. This
honors the org's no-telemetry / no-webhook rule — every signal here is collectable
from disk, and nothing phones home.

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
| `installed` | Is `.claude/hooks/baseline/` present? (Has the baseline been adopted at all.) |
| `posture` | `enforcement` (`block`/`warn`), resolved via `common.sh`'s `bcl_posture`. |
| `failClosed` | The global fail-closed toggle. |
| `version` | The repo's **installed** `.claude/hooks/baseline/VERSION` (the baseline revision its hooks came from). |
| `drift` | `OK` (matches the source `baselineVersion`), `DRIFT` (on an older/different baseline), `no-version` (installed but pre-`VERSION` baseline), or `not-installed`. |
| `minClaudeCodeVersion` + `ok` | The repo's pinned min Claude Code version, and whether it equals this source tree's canonical pin (a config-drift signal). |
| `guardrails` / `modules` | Which are **enabled**, resolved via `common.sh`'s `bcl_guardrail_enabled` / `bcl_module_enabled` — the *same* readers the hooks use. |

Modes:

- **`--drift`** *(default view)* — print the per-repo report. `drift` is the headline signal.
- **`--strict`** — exit non-zero if **any installed** repo has drifted from the source
  `baselineVersion`. A `not-installed` repo does **not** trip this (that's "not adopted,"
  a separate state from "behind"). *(Intended CI consumer below.)*
- **`--json <outfile>`** — also write the full report as JSON to `<outfile>`. This is the
  **only** filesystem write the tool performs; without it, the tool writes nothing.

**Reconciling drift:** re-run `install.sh --target <repo>`. The installer recopies the
hook subtree wholesale every run, so the installed `VERSION` is refreshed to the source
value (always truthful — it is not a hand-editable config stamp).

### Single source of truth (why it sources `common.sh`)

The script does **not** re-parse `baseline.config.json` itself. It sources
`hooks/lib/common.sh` and calls `bcl_module_enabled` / `bcl_posture` /
`bcl_guardrail_enabled` — the exact functions the hooks call. So if the config schema or
the "enabled" logic ever changes, the report changes in lockstep and can never report a
posture the hooks don't actually enforce. (A second, independent parser was rejected for
exactly this reason.)

> **Known cost:** `common.sh`'s `bcl_cfg` spawns a fresh `python3` per key per repo, so
> the posture *table* is O(keys × repos) process spawns and is noticeably slow at the
> upper end (e.g. ~20 repos). The primary `--drift` signal reads one value per repo and is
> unaffected. If the table feels slow in practice, batch the per-repo reads behind one
> `python3` call — but do **not** re-implement config parsing outside `common.sh`.

### `--strict`'s CI consumer is currently dormant (owner decision)

`--strict` exists to be wired into CI (`baseline-ci.yml`), which fails a build on drift.
That workflow is **dormant today** — it only runs once `claude-code-baseline/` is its own
repository (while it is vendored inside another repo, GitHub Actions does not run it). So
right now `--strict`'s only exerciser is `tests/test_status.sh`. The script still earns its
place via the on-demand, cross-repo `--drift` check a human would otherwise eyeball N
times. **If you prefer to defer the script until CI is live**, the data layer alone
(`baselineVersion` + `hooks/VERSION`) plus the interim one-liner below is a fully valid
smaller footprint — that's an owner call.

Interim cross-repo drift one-liner (no script), if you go that route:

```bash
src=$(python3 -c 'import json;print(json.load(open("claude-code-baseline/baseline.config.json"))["baselineVersion"])')
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
