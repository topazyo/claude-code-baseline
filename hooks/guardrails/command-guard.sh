#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# claude-code-baseline :: guardrails/command-guard.sh
#
# PreToolUse hook (matcher: Bash|PowerShell). Inspects the proposed shell command
# and blocks a curated set of destructive / unapproved operations via a token-aware
# matcher (lib/command_guard_match.py). It is hardened against common evasions —
# whitespace, quoting, flag reordering, wrapper paths (/bin/rm, sh -c ...), and
# compound commands (; && || |); see lib/command_guard_match.py for exactly what is
# normalized — but is still BEST-EFFORT, NOT an evasion-proof boundary:
# encoding/base64, variable indirection, and runtime aliases can bypass it. Treat it
# as defense-in-depth; real enforcement of dangerous actions belongs in
# permissions.deny / sandboxing.
#
# Per-SHELL coverage is best-effort too. The hook is wired for both tools that run
# shell commands (Bash and PowerShell — on Windows without Git Bash, Claude Code
# registers the PowerShell tool and no Bash tool at all, so a Bash-only matcher
# would never fire there), but the blocklist is a list of command NAMES: a verb the
# matcher does not know, or a shell whose quoting/expansion rules its tokenizer does
# not model, passes uninspected. "The hook fired" does not mean "the command was
# understood".
#
# Blocking model (Claude Code PreToolUse protocol):
#   exit 2  -> tool call is BLOCKED, stderr is fed back to the model
#   exit 0  -> tool call proceeds
# Under enforcement: "warn", a hit prints to stderr but still exits 0.
#
# Extend the blocklist per-repo via baseline.config.json:
#   "guardrails": { "commandGuard": { "enabled": true, "extraPatterns": ["foo", "bar"] } }
# extraPatterns are matched case-insensitively as substrings of the command.

set -euo pipefail

# ${BASH_SOURCE[0]%/*} rather than $(dirname ...): dirname is an external binary
# under Git Bash and a fork measures ~21ms here — paid by every hook, on every tool call.
HERE="${BASH_SOURCE[0]%/*}"
[[ "$HERE" == "${BASH_SOURCE[0]}" ]] && HERE=.
HERE="$(cd "$HERE" && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"

# Read stdin BEFORE the enable-gate, then prime once from what we read. The gate
# needs the config, priming needs the payload, and each extra prime is a whole
# interpreter start on the hook that runs before EVERY Bash call — so we do both in
# one call and defer *acting* on a read failure until after the gate, below. A
# repo that disabled commandGuard must still exit 0, not get blocked by our stdin.
read_rc=0
bcl_read_payload PAYLOAD || read_rc=1

# ONE interpreter for the guardrail gate and the payload state, leaving the matcher
# below as the only other process this guard starts. It runs before EVERY Bash tool
# call, so this is the hook where a saved interpreter start is felt most.
bcl_prime "$PAYLOAD"

bcl_guardrail_enabled commandGuard || exit 0

# A guard that could not read its input must not wave the command through. `cat`
# used to block until EOF, so a caller that left stdin open wedged this hook until
# Claude Code killed it — and a killed PreToolUse hook emits no exit 2, so the
# command ran uninspected. Distinct message from the unparseable case below so the
# two causes stay diagnosable.
if [[ $read_rc -ne 0 ]]; then
  echo "[command-guard] CONTROL COULD NOT RUN — could not read the tool payload from stdin: $BCL_READ_ERROR; the command was NOT inspected." >&2
  if bcl_failclosed_exit; then exit 0; else exit 2; fi
fi

# Empty payload -> no command to inspect (nothing to check) -> allow. (Without
# this, an empty payload would reach the matcher and trip its parse-error path.)
[[ -z "${PAYLOAD//[[:space:]]/}" ]] && exit 0

# A PreToolUse guard that cannot read the command must not wave it through.
# Parsing the payload needs Python; without it we cannot inspect the command at
# all, so fail closed (block under block+failClosed; otherwise warn and allow).
# Written as an `if` so `set -e` doesn't swallow the non-zero return.
PY="$(bcl_python)"
if [[ -z "$PY" ]]; then
  echo "[command-guard] CONTROL COULD NOT RUN — Python unavailable; the command was NOT inspected (blocklist + extraPatterns skipped)." >&2
  if bcl_failclosed_exit; then exit 0; else exit 2; fi
fi

# Payload present but unparseable -> we can't read the command, so we can't vet
# it. Treat the same as no-Python: fail closed rather than allow uninspected.
if bcl_payload_unparseable "$PAYLOAD"; then
  echo "[command-guard] CONTROL COULD NOT RUN — tool payload unparseable; the command was NOT inspected." >&2
  if bcl_failclosed_exit; then exit 0; else exit 2; fi
fi

# The matcher is a CHILD of this hook, and a child that never launches is a
# fail-open: `python <missing-script>` exits 2 for Python's own usage error and
# non-zero generally, but a truncated matcher (`printf '' > command_guard_match.py`)
# exits 0 printing nothing, which reads exactly like "clean command". Neither
# deletion nor truncation is an Edit-tool call, so the deny-list cannot see it —
# check the child ourselves before trusting its silence.
MATCHER="$HERE/../lib/command_guard_match.py"
if MATCHER_STATE="$(bcl_child_unusable "$MATCHER")"; then
  echo "[command-guard] CONTROL COULD NOT RUN — matcher script $MATCHER_STATE; the command was NOT inspected." >&2
  if bcl_failclosed_exit; then exit 0; else exit 2; fi
fi

# Inspect the command with the R2 token-aware matcher: it normalizes (lowercase,
# strip quotes/backslashes, collapse whitespace), splits compound commands, does
# token-aware detection, and applies repo extraPatterns. It prints a block reason
# (or nothing) and always exits 0; a non-zero exit means the matcher itself failed
# -> fail closed. PY is guaranteed non-empty here.
#
# Bounded at 5s against the 10s hook timeout wired in settings.template.json: if
# Claude Code kills the HOOK, no exit code is produced at all and the command runs
# uninspected (fail-open). A matcher we kill ourselves surfaces rc=124 below and
# routes through the fail-closed path — which also covers a pathological command
# crafted to make the matcher slow.
match_rc=0
REASON="$(printf '%s' "$PAYLOAD" | bcl_timeout 5 "$PY" "$MATCHER" "$(bcl_config_path)")" || match_rc=$?

if [[ $match_rc -eq 124 ]]; then
  echo "[command-guard] CONTROL COULD NOT RUN — matcher exceeded its 5s budget and was killed; the command was NOT fully inspected." >&2
  if bcl_failclosed_exit; then exit 0; else exit 2; fi
fi

if [[ $match_rc -ne 0 ]]; then
  echo "[command-guard] CONTROL COULD NOT RUN — matcher failed (rc=$match_rc); command was NOT inspected." >&2
  if bcl_failclosed_exit; then exit 0; else exit 2; fi
fi

# NOTE: test the sentinel with bash string ops, never grep. A reason line can carry
# non-ASCII (repo-supplied extraPatterns, or a rule message), and grep declares such
# stdin "binary", drops the line, and on GNU grep >= 3.5 reports that only on
# stderr — so a "control could not run" state could be mis-read as a clean command.
# Same precedent as the note in modules/config-guard.sh.
REASON="${REASON//$'\r'/}"   # Windows Python print() emits CRLF; strip CR first.

if [[ "$REASON" == "__MATCHER_ERROR__"* ]]; then
  echo "[command-guard] CONTROL COULD NOT RUN — ${REASON#__MATCHER_ERROR__ }" >&2
  if bcl_failclosed_exit; then exit 0; else exit 2; fi
fi

if [[ -n "$REASON" ]]; then
  printf 'Blocked by Claude Code baseline command-guard: %s\n' "$REASON" >&2
  if [[ "$(bcl_posture)" == "block" ]]; then exit 2; fi
  exit 0
fi

exit 0
