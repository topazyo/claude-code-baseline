#!/usr/bin/env bash
# claude-code-baseline :: modules/tracker-reminder.sh
#
# Stop hook. When the session produced commits matching a pattern, reminds the
# agent to update a tracking document before closing. Informational only —
# never blocks (Stop hooks should not trap the user in the session).
#
# Config (baseline.config.json):
#   "modules": { "trackerReminder": {
#       "enabled": true,
#       "commitGrep": "C5-",                 // LITERAL substring matched against recent commit subjects (not a regex)
#       "tracker": "BATCH_EXECUTION_PLAN.md" // file to remind about
#   } }

set -uo pipefail

# ${BASH_SOURCE[0]%/*} rather than $(dirname ...): dirname is an external binary
# under Git Bash and a fork measures ~21ms here — paid by every hook, on every tool call.
HERE="${BASH_SOURCE[0]%/*}"
[[ "$HERE" == "${BASH_SOURCE[0]}" ]] && HERE=.
HERE="$(cd "$HERE" && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"

# ONE interpreter for all three config keys this module reads instead of three. No
# argument: a Stop hook gets no tool payload.
bcl_prime

bcl_module_enabled trackerReminder || exit 0

COMMIT_GREP="$(bcl_cfg modules.trackerReminder.commitGrep "")"
TRACKER="$(bcl_cfg modules.trackerReminder.tracker "")"
[[ -z "$COMMIT_GREP" || -z "$TRACKER" ]] && exit 0

cd "$(bcl_repo_root)" || exit 0

# -F: COMMIT_GREP is a literal substring (ticket prefix), not a regex.
# --: never let a value beginning with '-' be parsed as a grep option.
# 2>/dev/null: keep a malformed value from leaking grep errors into hook output.
MATCHES="$(git log --oneline -20 2>/dev/null | grep -cF -- "$COMMIT_GREP" 2>/dev/null || true)"
[[ "${MATCHES:-0}" -eq 0 ]] && exit 0

echo ""
echo "📋 [tracker-reminder] $MATCHES recent commit(s) matched '$COMMIT_GREP'."
echo "   Before closing: confirm $TRACKER is up to date."
echo ""
exit 0
