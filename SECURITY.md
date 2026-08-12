# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report privately through GitHub's **[Private Vulnerability Reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)**:
open the repository's **Security** tab → **Report a vulnerability**.

Please include: the affected file and version (`hooks/VERSION`), your Claude Code
version (`claude --version`), a minimal reproduction, and the impact you believe it has.

Expect an acknowledgement within 5 working days and a status update within 15.

## What counts as a vulnerability here

This project ships guardrails, so the interesting bugs are the ones where a control
**silently fails to fire** rather than one that crashes. In scope:

- A bypass of `hooks/lib/command_guard_match.py` — any input that reaches a guarded
  command while the matcher reports no match.
- A `permissions.deny` rule in `settings.template.json` or `managed/` that does not
  match what its comment claims it matches.
- `install.sh` or `lib/merge_settings.py` losing, corrupting, or weakening a
  consumer's existing `.claude/settings.json`.
- Any hook that **fails open** (allows the action) on malformed input, a missing
  interpreter, a timeout, or a crash.
- Command or path injection in the installer or any hook.

## Explicitly out of scope

These are documented limitations, not vulnerabilities. See
**"What this does not protect against"** in [`README.md`](README.md) before reporting:

- A developer editing or deleting `.claude/hooks/baseline/**` or
  `.claude/baseline.config.json` in their own checkout. The per-repo tier is
  ordinary repo content and is **self-disarming by design**; only enterprise
  [managed settings](managed/README.md) provide a non-overridable floor.
- Reading a secret through an arbitrary subprocess (`python -c "open('.env')"`,
  `node -e ...`). Permission rules bind Claude's tools and the Bash file commands
  Claude Code recognizes — not every process the shell can spawn. Use sandbox
  `filesystem.denyRead` and network egress control for that boundary.
- Prompt injection itself. This baseline constrains what actions are *permitted*;
  it does not make the model resistant to malicious instructions in files, web
  content, or MCP responses.
- Any binary not on the command-guard's blocklist. It is a named-command
  blocklist, not an allowlist.

## Supported versions

Only the latest tagged release is supported. `hooks/VERSION` records the version of
an installed baseline tree; it is a convention stamp, not an integrity check.
