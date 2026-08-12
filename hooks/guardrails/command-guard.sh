#!/usr/bin/env bash
# claude-code-baseline :: guardrails/command-guard.sh
#
# PreToolUse hook (matcher: Bash). Inspects the proposed shell command and blocks
# a curated set of destructive / unapproved operations via a token-aware matcher
# (lib/command_guard_match.py). It is hardened against common evasions —
# whitespace, quoting, flag reordering, wrapper paths (/bin/rm, sh -c ...), and
# compound commands (; && || |) — but is still BEST-EFFORT, NOT an evasion-proof
# boundary: encoding/base64, variable indirection, and runtime aliases can bypass
# it. Treat it as defense-in-depth; real enforcement of dangerous actions belongs
# in permissions.deny / sandboxing.
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

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"

bcl_guardrail_enabled commandGuard || exit 0

PAYLOAD="$(cat)"

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

# Inspect the command with the R2 token-aware matcher: it normalizes (lowercase,
# strip quotes/backslashes, collapse whitespace), splits compound commands, does
# token-aware detection, and applies repo extraPatterns. It prints a block reason
# (or nothing) and always exits 0; a non-zero exit means the matcher itself failed
# -> fail closed. PY is guaranteed non-empty here.
match_rc=0
REASON="$(printf '%s' "$PAYLOAD" | "$PY" "$HERE/../lib/command_guard_match.py" "$(bcl_config_path)")" || match_rc=$?

if [[ $match_rc -ne 0 ]]; then
  echo "[command-guard] CONTROL COULD NOT RUN — matcher failed (rc=$match_rc); command was NOT inspected." >&2
  if bcl_failclosed_exit; then exit 0; else exit 2; fi
fi

if printf '%s' "$REASON" | grep -q '^__MATCHER_ERROR__'; then
  echo "[command-guard] CONTROL COULD NOT RUN — ${REASON#__MATCHER_ERROR__ }" >&2
  if bcl_failclosed_exit; then exit 0; else exit 2; fi
fi

if [[ -n "$REASON" ]]; then
  printf 'Blocked by Claude Code baseline command-guard: %s\n' "$REASON" >&2
  if [[ "$(bcl_posture)" == "block" ]]; then exit 2; fi
  exit 0
fi

exit 0
