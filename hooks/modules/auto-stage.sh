#!/usr/bin/env bash
# claude-code-baseline :: modules/auto-stage.sh
#
# PostToolUse module (matcher: Write|Edit). Stages changed files with `git add`
# so they are ready to commit. Runs only after all blocking checks pass (the
# dispatcher invokes it last). Never blocks — exits 0 regardless.
#
# Config (baseline.config.json):
#   "modules": { "autoStage": { "enabled": true } }

set -uo pipefail

# ${BASH_SOURCE[0]%/*} rather than $(dirname ...): dirname is an external binary
# under Git Bash and a fork measures ~21ms here — paid by every hook, on every tool call.
HERE="${BASH_SOURCE[0]%/*}"
[[ "$HERE" == "${BASH_SOURCE[0]}" ]] && HERE=.
HERE="$(cd "$HERE" && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"

# Bounded read before the gate, so one prime covers the config and the payload.
# `cat` blocked until EOF; this hook is not a security control, but a wedged child
# still burns the dispatcher's shared PostToolUse budget for every gate after it.
read_rc=0
bcl_read_payload PAYLOAD || read_rc=1
bcl_prime "$PAYLOAD"

bcl_module_enabled autoStage || exit 0

# Staging is a convenience, never a gate: an unread payload means there is nothing
# to stage, which is the safe direction. Announce it rather than stage nothing
# silently, then exit 0 — this hook must never block a write.
if [[ $read_rc -ne 0 ]]; then
  echo "[auto-stage] NOTE: could not read the tool payload from stdin ($BCL_READ_ERROR); nothing was staged." >&2
  exit 0
fi

cd "$(bcl_repo_root)" || exit 0

while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  [[ -f "$f" ]] || continue
  git add "$f" 2>/dev/null || true
done < <(bcl_extract_paths "$PAYLOAD")

exit 0
