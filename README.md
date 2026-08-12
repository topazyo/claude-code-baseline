# claude-code-baseline

An org baseline for **Claude Code hooks + settings**, distributed as a single
bootstrap script. Run `install.sh` inside any repo and it gains a standard set
of safety guardrails plus a menu of opt-in workflow modules — all driven by one
config file, with no hand-editing of `settings.json`.

It is the generalized, repo-agnostic form of the hooks originally built for the
OpenClaw/ClawdBot security playbook.

---

## Model

Two tiers:

| Tier | Default | What it is |
|------|---------|------------|
| **Guardrails** | always on | Universal safety. Hard to justify turning off. |
| **Modules** | opt-in (off) | Workflow-specific enforcement. Enable per repo. |

A single global **posture** decides what a violation does:

- `"enforcement": "block"` *(shipped default)* — a violating hook **fails the tool call**. The agent must fix the problem before proceeding.
- `"enforcement": "warn"` — the hook prints guidance but lets the call through.

### Guardrails (always on)

- **command-guard** — `PreToolUse(Bash)`. Blocks destructive / unapproved shell
  commands: `rm -rf /` and friends, `git push --force`, `git reset --hard`,
  dangerous SQL (`drop/truncate table`, `delete from`), raw `curl|wget http…`,
  and package installs (`npm/pnpm/yarn/pip install`). Extend per repo via
  `guardrails.commandGuard.extraPatterns`.
- **auto-format** — `PostToolUse(Write|Edit)`. Formats changed files with
  whatever is available (prettier/eslint, black, `dotnet format`). Never blocks.

### Modules (opt-in)

| Module | Hook | Purpose |
|--------|------|---------|
| `securityDefaults` | PostToolUse | Verify immutable infra defaults haven't drifted, from a **declarative rules file** (see below). Blocking. |
| `fixTags` | PostToolUse | Require a traceability tag (e.g. `# FIX: TICKET-123`) on every added line. Configurable marker, file types, and an optional env gate. Blocking. |
| `scopeGuard` | PreToolUse | Flag edits to files outside a declared task scope (`.claude/active-issue-scope.txt`). Blocking under `block` posture. |
| `configGuard` | ConfigChange | Detect in-session tampering of `.claude/settings.json` — baseline hooks unwired, deny-list stripped, or `disableAllHooks` set. Catches **human/external** edits the deny-list can't. Blocking under `block`. |
| `runTests` | PostToolUse | Run the right test/lint per file type (pytest, shellcheck/bats, yamllint/actionlint). Missing tools are skipped. Blocking under `block` posture. |
| `trackerReminder` | Stop | Remind to update a tracking doc when matching commits exist this session. Never blocks. |
| `autoStage` | PostToolUse | `git add` changed files after all blocking gates pass. Never blocks. |

The `PostToolUse` modules run through one **dispatcher** in a fixed safe order
(format → security → tags → tests → stage); a blocking failure short-circuits
the chain, so nothing is staged after a violation.

---

## Install

From inside the target repo:

```bash
/path/to/claude-code-baseline/install.sh
```

Or point at a repo explicitly, and optionally seed the example security rules:

```bash
claude-code-baseline/install.sh --target ../some-repo --with-openclaw-rules
claude-code-baseline/install.sh --dry-run         # preview, change nothing
```

What it does (idempotent — safe to re-run):

1. Copies hooks to **`.claude/hooks/baseline/`** (namespaced — never collides
   with a repo's own `.claude/hooks/`). The baseline subtree is replaced wholesale
   on each run so removed hooks don't linger.
2. Writes **`.claude/baseline.config.json`** *(only if absent — your toggles are
   never clobbered)* and refreshes the JSON schema next to it.
3. **Merges** the baseline hook wiring + a security deny-list into
   **`.claude/settings.json`**, backing up the previous file to
   `settings.json.bak.<timestamp>` first. The merge replaces only baseline-managed
   entries (matched by their `/.claude/hooks/baseline/` command path) and unions
   the deny-list; your `permissions.allow`, `model`, and everything else are left
   untouched.

Requires `bash` and `python3` (or `python`). Designed to run under WSL, Git Bash,
and macOS/Linux shells; paths and CRLF are handled defensively for Windows.

It also runs an **advisory version check**: it compares your live `claude --version`
against `minClaudeCodeVersion` (currently `2.1.80`, the release where an `allow` rule
can no longer bypass a `deny` — which the tamper-protection deny-list depends on) and
prints a warning if older. This never blocks the install. See
[`RELEASING.md`](RELEASING.md) for the per-release re-verification checklist behind the pin.

---

## Configure

Everything is toggled in `.claude/baseline.config.json` (validated by
`baseline.config.schema.json`). Enabling a module is a config change only — no
`settings.json` edits.

```jsonc
{
  "enforcement": "block",                 // or "warn"
  "guardrails": {
    "commandGuard": { "enabled": true, "extraPatterns": ["terraform destroy"] },
    "autoFormat":   { "enabled": true }
  },
  "modules": {
    "securityDefaults": { "enabled": true, "rulesFile": ".claude/security-defaults.json" },
    "fixTags":          { "enabled": true, "tagMarker": "FIX:", "requireWhenEnv": "AUDIT_CYCLE" },
    "scopeGuard":       { "enabled": true, "scopeFile": ".claude/active-issue-scope.txt" },
    "configGuard":      { "enabled": true },
    "runTests":         { "enabled": true },
    "trackerReminder":  { "enabled": true, "commitGrep": "JIRA-", "tracker": "CHANGELOG.md" },
    "autoStage":        { "enabled": false }
  }
}
```

### Authoring `securityDefaults` rules

The checker is generic; the policy lives in a rules file. Each rule says *"when
the file content matches `appliesWhen`, it must (`mustMatch`) or must not
(`mustNotMatch`) contain X"*. Paths are filtered by `infraPattern` /
`skipPathPattern`. Regexes use Python `re` in multiline mode.

```json
{
  "infraPattern": "\\.(ya?ml)$|Dockerfile|docker-compose",
  "rules": [
    { "id": "no-root", "appliesWhen": "^\\s*user:\\s", "mustMatch": "1000:1000",
      "message": "Container user must be non-root (1000:1000)" }
  ]
}
```

See [`examples/security-defaults.openclaw.json`](examples/security-defaults.openclaw.json)
for the full OpenClaw immutable-defaults policy (gateway/MCP bind, cap_drop,
read-only fs, TLS 1.3, skills signing). Copy it to `.claude/security-defaults.json`
and adapt.

---

## Org rollout

- Keep this directory as the **single source of truth** (its own repo, or vendored
  here). Teams run `install.sh` against their repo; upgrades are a re-run.
- **Commit** `.claude/hooks/baseline/`, `.claude/baseline.config.json`, and the
  schema so the baseline travels with the repo and applies to every contributor.
- **Do not commit** `.claude/settings.local.json` (per-developer overrides) or the
  `settings.json.bak.*` backups.
- To roll across many repos, loop `install.sh --target <repo>` over a checkout list.
- For a non-overridable floor (deny-list, command-guard) that individual devs
  can't disable — surviving even `--dangerously-skip-permissions` — deploy the
  [`managed/`](managed/README.md) profile via Claude Code **enterprise managed
  settings** (an org-admin action). This `install.sh` template stays the
  customizable per-repo layer on top of that floor.

- For an **allowlist-primary** posture (OWASP: grant only what's needed, deny the rest),
  see [`managed/allowlist.example.json`](managed/allowlist.example.json) — `defaultMode:
  "dontAsk"` (default-deny) + a minimal `allow` + the secrets `deny` (a backstop for Claude's
  Read *tool*) + an OS-level `sandbox` whose `allowedDomains` is the real exfiltration control.
  Two caveats the managed README's R7 section covers in full: a catch-all `deny(**)` + narrow
  `allow` does NOT work (deny always beats allow), and **no setting stops `cat .env` via a Bash
  subprocess** — protect repo secrets with hygiene + network egress, not the Read-tool deny alone.

### Common hardening add-ons

Not in the baseline (they're opinionated), but easy to add to your merged
`settings.json` `permissions.deny` or `commandGuard.extraPatterns`:

- `"WebFetch(*)"` — block arbitrary web fetches.
- `"Edit(.github/workflows/deploy*.yml)"` — protect deploy pipelines.

---

## Disable / uninstall

- Disable one hook: set its `enabled` to `false` in `baseline.config.json`.
- Disable everything fast: set `"enforcement": "warn"` (nothing blocks).
- Full removal: delete `.claude/hooks/baseline/`, remove the baseline hook
  groups from `.claude/settings.json` (or restore a `settings.json.bak.*`), and
  delete `.claude/baseline.config.json`.

---

## Testing

```bash
bash tests/run.sh   # bash -n + py_compile + matcher fixtures + hook integration tests
```

Any change to the matcher, the deny-list, or a guard hook must ship with a
fixture — `tests/policy-change-gate.sh` (run in CI on PRs) fails a policy change
that lacks updated tests. See [`tests/README.md`](tests/README.md).

## Layout

```
claude-code-baseline/
├── install.sh                         # bootstrap (copy + merge, idempotent)
├── baseline.config.json               # default config (copied to target if absent)
├── baseline.config.schema.json        # schema for the config
├── settings.template.json             # hook wiring + deny-list merged into target
├── RELEASING.md                       # per-release re-verification checklist (R4)
├── lib/
│   └── merge_settings.py              # install-time JSON merge
├── examples/
│   └── security-defaults.openclaw.json
├── managed/                           # enterprise non-overridable floor (R6/R7)
│   ├── managed-settings.json          # deny-list + guardrails as managed settings
│   ├── managed-settings.strict.json   # + allowManaged*/strictPluginOnlyCustomization
│   ├── allowlist.example.json         # allowlist-primary profile (dontAsk + sandbox) (R7)
│   └── README.md                      # per-OS deploy + acceptance verification
├── tests/                             # adversarial suite + release gate (R3)
│   ├── run.sh                         # aggregate runner (local + CI)
│   ├── test_command_guard.py          # matcher fixtures (originals + evasions + FPs)
│   ├── test_hooks.sh                  # end-to-end hook integration tests
│   ├── test_managed.sh                # validates the managed/ enterprise profiles (R6)
│   └── policy-change-gate.sh          # fails policy changes lacking updated fixtures
├── .github/workflows/baseline-ci.yml  # CI (active when this dir is its own repo)
└── hooks/                             # copied to target .claude/hooks/baseline/
    ├── lib/
    │   ├── common.sh                  # shared payload/config helpers
    │   └── command_guard_match.py     # token-aware command matcher (R2)
    ├── guardrails/
    │   ├── command-guard.sh
    │   └── auto-format.sh
    ├── dispatcher/
    │   └── post-write.sh              # PostToolUse entry point
    └── modules/
        ├── security-defaults.sh
        ├── fix-tags.sh
        ├── scope-guard.sh
        ├── config-guard.sh            # ConfigChange tamper-detection (R5)
        ├── run-tests.sh
        ├── tracker-reminder.sh
        └── auto-stage.sh
```
