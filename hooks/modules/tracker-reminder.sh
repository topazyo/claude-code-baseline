#!/usr/bin/env bash
# claude-code-baseline :: modules/tracker-reminder.sh
#
# Stop hook. While a commit matching a pattern is among the last 20 commits, shows
# YOU a reminder to update a tracking document, each time Claude stops. It is printed
# as a JSON `systemMessage`, the only exit-0 channel a user sees; plain stdout from an
# exit-0 hook reaches only the debug log. It is deliberately NOT passed to Claude:
# on Stop, additionalContext and decision:"block" both send Claude back to work, and
# the matching commit would still be there at the next stop. Informational only —
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
# The unprimed bcl_cfg fallback can keep a CR from Python's CRLF on Windows.
COMMIT_GREP="${COMMIT_GREP%$'\r'}"; TRACKER="${TRACKER%$'\r'}"
[[ -z "$COMMIT_GREP" || -z "$TRACKER" ]] && exit 0

cd "$(bcl_repo_root)" || exit 0

# -F: COMMIT_GREP is a literal substring (ticket prefix), not a regex.
# --: never let a value beginning with '-' be parsed as a grep option.
# 2>/dev/null: keep a malformed value from leaking grep errors into hook output.
MATCHES="$(git log --oneline -20 2>/dev/null | grep -cF -- "$COMMIT_GREP" 2>/dev/null || true)"
[[ "${MATCHES:-0}" -eq 0 ]] && exit 0

# The script's only stdout: one JSON object (see bcl_system_message).
bcl_system_message "📋 [tracker-reminder] $MATCHES of the last 20 commits matched '$COMMIT_GREP'."$'\n'"Before closing: confirm $TRACKER is up to date."
exit 0
