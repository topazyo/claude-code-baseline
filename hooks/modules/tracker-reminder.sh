#!/usr/bin/env bash
# claude-code-baseline :: modules/tracker-reminder.sh
#
# Stop hook. When commits whose SUBJECT contains a pattern are among the last 20,
# shows YOU a reminder to update a tracking document — once per session for the
# matches it finds, then again only when a NEW matching commit appears. It is printed
# as a JSON `systemMessage`, the only exit-0 channel a user sees; plain stdout from an
# exit-0 hook reaches only the debug log. It is deliberately NOT passed to Claude: on
# Stop, additionalContext and decision:"block" both send Claude back to work.
# Informational only — never blocks (Stop hooks should not trap the user in the session).
#
# Session memory: the commit hashes already reminded about are kept per session in
# <git dir>/baseline/tracker-reminder/<session_id> — inside .git, so never in the
# working tree, and per worktree. A rewritten commit (amend, rebase, cherry-pick) has a
# new hash and is reminded about again; so is everything after /clear (a new session).
# Whenever that memory cannot be used — no or an odd session_id in the Stop input, a
# payload that cannot be read, a state path that is not a plain directory/file — the
# module reminds as it always did, at every Stop: it fails toward reminding, never
# toward silence. Threat model: the agent's own shell can write that file and so
# silence its own session's reminder. This is an advisory module whose real off-switch
# (baseline.config.json) is just as reachable, so that is accepted.
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

# ONE interpreter for the three config keys. No payload yet: stdin is read only once a
# commit matches, so a disabled module, or a Stop with nothing to remind about, costs
# what it always did.
bcl_prime

# A config that exists but cannot be read would read trackerReminder as off. This is a
# Stop hook, where exit 2 keeps Claude working (and would loop), so it never blocks:
# it shows the user that the config needs a human, and exits 0.
if bcl_config_malformed; then
  bcl_system_message "$(bcl_config_malformed_text tracker-reminder)"
  exit 0
fi

bcl_module_enabled trackerReminder || exit 0

COMMIT_GREP="$(bcl_cfg modules.trackerReminder.commitGrep "")"
TRACKER="$(bcl_cfg modules.trackerReminder.tracker "")"
# The unprimed bcl_cfg fallback can keep a CR from Python's CRLF on Windows.
COMMIT_GREP="${COMMIT_GREP%$'\r'}"; TRACKER="${TRACKER%$'\r'}"
[[ -z "$COMMIT_GREP" || -z "$TRACKER" ]] && exit 0

cd "$(bcl_repo_root)" || exit 0
bcl_git_init

# Matches, by SUBJECT only (the old `--oneline | grep -F` also matched the abbreviated
# hash). A quoted pattern in [[ == ]] is a literal substring, so COMMIT_GREP is never a
# regex or an option. Hashes are kept as a |h1|h2| string (no arrays: an empty array
# under `set -u` aborts bash <= 4.3). --no-show-signature: log.showSignature would
# interleave gpg lines.
MATCHED="|"; M=0
while IFS=$'\t' read -r h subj || [[ -n "$h" ]]; do
  h="${h%$'\r'}"; subj="${subj%$'\r'}"
  [[ -n "$h" && "$subj" == *"$COMMIT_GREP"* ]] || continue
  MATCHED+="$h|"; M=$((M + 1))
done < <(bcl_git log --no-show-signature -20 --format='%H%x09%s' 2>/dev/null)
(( M > 0 )) || exit 0

# The reminder as it always read: every match among the last 20 commits.
MSG_ALL="📋 [tracker-reminder] $M of the last 20 commits matched '$COMMIT_GREP'."$'\n'"Before closing: confirm $TRACKER is up to date."
remind_all() { bcl_system_message "$MSG_ALL"; exit 0; }
# stateless <why>: the session memory cannot be used; say why in the debug log only (a
# user-facing note would repeat at every Stop), then remind as before.
stateless() {
  echo "[tracker-reminder] no session memory ($1); reminding at every Stop." >&2
  remind_all
}

# The Stop input. The read is bounded at 2 s, inside the 5 s Stop timeout
# (settings.template.json): a read that hangs must end here, in a reminder, not in
# Claude Code killing the hook (a killed Stop hook shows nothing).
_BCL_STDIN_TIMEOUT=2
bcl_read_payload PAYLOAD || stateless "stdin: $BCL_READ_ERROR"
# session_id in bash, not a second Python start (a slow interpreter, such as the
# Windows Store alias at ~2 s, would eat the Stop timeout). Safe without a JSON parser:
# inside a JSON string every `"` is escaped, so `"session_id"` followed by `:` can only
# be a key, and the value must be a plain name, 1-128 of [A-Za-z0-9_-], or nothing
# matches and the module reminds without a memory.
sid_re='"session_id"[[:space:]]*:[[:space:]]*"([A-Za-z0-9_-]{1,128})"'
SID=""
if [[ "$PAYLOAD" =~ $sid_re ]]; then SID="${BASH_REMATCH[1]}"; fi
[[ -n "$SID" ]] || stateless "no usable session_id"

# <git dir>/baseline/tracker-reminder: every level a real directory (never a symlink,
# which would aim the writes and the prune elsewhere), created one level at a time.
BASE="$(bcl_git rev-parse --git-path baseline 2>/dev/null)"; BASE="${BASE%$'\r'}"
[[ -n "$BASE" ]] || stateless "no git directory"
STATE="$BASE/tracker-reminder"
for d in "$BASE" "$STATE"; do
  # A failed mkdir (another session won the race) is judged by the check below.
  if [[ ! -e "$d" && ! -L "$d" ]]; then mkdir -- "$d" 2>/dev/null || true; fi
  [[ -d "$d" && ! -L "$d" ]] || stateless "$d is missing or not a plain directory"
done
F="$STATE/$SID"

# Hashes already reminded about in this session. Only full hex hashes count.
SEEN="|"; FIRST=1
hash_re='^[0-9a-f]{40}([0-9a-f]{24})?$'
if [[ -e "$F" || -L "$F" ]]; then
  [[ -f "$F" && ! -L "$F" ]] || stateless "$F is not a plain file"
  FIRST=0
  while IFS= read -r l || [[ -n "$l" ]]; do
    l="${l%$'\r'}"
    if [[ "$l" =~ $hash_re ]]; then SEEN+="$l|"; fi
  done < "$F" || stateless "cannot read $F"
fi

NEW=""; N=0; rest="${MATCHED#|}"
while [[ -n "$rest" ]]; do
  h="${rest%%|*}"; rest="${rest#*|}"
  if [[ "$SEEN" != *"|$h|"* ]]; then NEW+="$h"$'\n'; N=$((N + 1)); fi
done
(( N > 0 )) || exit 0

# Remind FIRST, remember LAST: a write that fails, or a hook killed before it, costs a
# repeat at the next Stop, never a reminder that was recorded but not shown.
if (( FIRST )); then
  bcl_system_message "$MSG_ALL"
else
  bcl_system_message "📋 [tracker-reminder] $N new matching commit(s) since the last reminder ('$COMMIT_GREP')."$'\n'"Before closing: confirm $TRACKER is up to date."
fi
# A session's first reminder prunes the memory files not updated for more than 14 days:
# one fork per session, and it keeps the directory from growing for ever. A pruned file
# only means one more reminder. All output discarded: stdout must stay one JSON object.
if (( FIRST )); then
  find "$STATE" -maxdepth 1 -type f -mtime +14 -delete >/dev/null 2>&1 || true
fi
{ printf '%s' "$NEW" >> "$F"; } 2>/dev/null \
  || echo "[tracker-reminder] could not record the reminder in $F; it will repeat." >&2
exit 0
