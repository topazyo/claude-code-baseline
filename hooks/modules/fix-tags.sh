#!/usr/bin/env bash
# claude-code-baseline :: modules/fix-tags.sh
#
# PostToolUse module (matcher: Write|Edit). Requires that every added line in
# the working diff carries a traceability tag (e.g. `# FIX: TICKET-123`). Blank
# lines, comment-only lines, imports and docstrings are exempt.
#
# Config (baseline.config.json):
#   "modules": { "fixTags": {
#       "enabled": true,
#       "tagMarker": "FIX:",                 // substring that marks a tagged line
#       "fileRegex": "\\.(py|sh|bash|ps1|yml|yaml)$|Dockerfile|Makefile",
#       "requireWhenEnv": "AUDIT_CYCLE"      // optional: only enforce when this env var is set
#   } }
# If requireWhenEnv is omitted/empty, enforcement is active whenever enabled.

set -uo pipefail

# ${BASH_SOURCE[0]%/*} rather than $(dirname ...): dirname is an external binary
# under Git Bash and a fork measures ~21ms here — paid by every hook, on every tool call.
HERE="${BASH_SOURCE[0]%/*}"
[[ "$HERE" == "${BASH_SOURCE[0]}" ]] && HERE=.
HERE="$(cd "$HERE" && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"

# ONE interpreter for every config key this module reads (the enable gate, the env
# gate, tagMarker, fileRegex) instead of one per key. No argument: this hook does not
# read stdin, so the payload helpers stay on their per-call path.
bcl_prime

bcl_module_enabled fixTags || exit 0

# Optional env gate. The value comes from the repo's config and is used as a variable
# NAME (${!GATE_VAR}), so it must be one; anything else is refused. Empty means "no gate".
GATE_VAR="$(bcl_cfg modules.fixTags.requireWhenEnv "")"
GATE_VAR="${GATE_VAR%$'\r'}"   # the unprimed bcl_cfg fallback can keep Windows' CR
# Explicit ASCII lists, not ranges: what a range matches depends on the locale.
_bcl_first='_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
_bcl_rest="${_bcl_first}0123456789"
if [[ -n "$GATE_VAR" ]] && [[ "${GATE_VAR:0:1}" != ["$_bcl_first"] || "$GATE_VAR" == *[!"$_bcl_rest"]* ]]; then
  echo "[fix-tags] CONTROL COULD NOT RUN — modules.fixTags.requireWhenEnv must be an environment variable name (letters, digits and _, not starting with a digit); the tag check did not run." >&2
  bcl_failclosed_exit; exit $?
fi
if [[ -n "$GATE_VAR" && -z "${!GATE_VAR:-}" ]]; then
  exit 0
fi

MARKER="$(bcl_cfg modules.fixTags.tagMarker "FIX:")"
FILE_REGEX="$(bcl_cfg modules.fixTags.fileRegex '\.(py|sh|bash|ps1|yml|yaml)$|Dockerfile|Makefile')"

cd "$(bcl_repo_root)" || { echo "[fix-tags] could not enter repo root — tag check skipped." >&2; exit 0; }
bcl_git_init

# The diff is read as git's plain text, whatever the repository configures: no colour
# codes in front of the `+` (color.ui=always), and no external diff or textconv program
# (which would also run code; see bcl_git). A file a textconv driver covers diffs as
# binary and is not checked. Names come NUL-separated (-z), exactly as stored: in the
# line form git quotes a name holding a newline, a quote, a backslash or (core.quotePath)
# a non-ASCII byte, and the quoted name matches no file.
DIFF_OPTS=(--no-color --no-ext-diff --no-textconv)
CHANGED=()
while IFS= read -r -d '' FILE; do
  CHANGED+=("$FILE")
done < <(bcl_git diff "${DIFF_OPTS[@]}" --name-only -z 2>/dev/null)
(( ${#CHANGED[@]} )) || exit 0

VIOLATIONS=0
for FILE in "${CHANGED[@]}"; do
  [[ -z "$FILE" ]] && continue
  printf '%s\n' "$FILE" | grep -qE -- "$FILE_REGEX" || continue

  # Added lines are the `+` lines after the first hunk header. The file header before it
  # (`+++ b/name`, or another prefix a repository's diff config picks) is not one, and an
  # added line that itself begins with `++` is.
  ADDED_LINES="$(bcl_git diff "${DIFF_OPTS[@]}" -- "$FILE" 2>/dev/null \
    | awk 'h && /^\+/ { print } /^@@/ { h = 1 }' || true)"
  [[ -z "$ADDED_LINES" ]] && continue

  UNTAGGED="$(echo "$ADDED_LINES" \
    | grep -vF -- "$MARKER" \
    | grep -Ev '^\+[[:space:]]*(#|//|--|$)' \
    | grep -Ev '^\+(import |from |require |source |use )' \
    | grep -Ev "^\+[[:space:]]*(\"\"\"|''')" \
    | grep -Ev '^\+[[:space:]]*$' \
    | head -5 || true)"

  if [[ -n "$UNTAGGED" ]]; then
    echo "⚠️  [fix-tags] Untagged changed lines in $FILE:" >&2
    echo "$UNTAGGED" | head -5 >&2
    echo "   Add a '$MARKER <id>' tag to each changed line." >&2
    VIOLATIONS=$((VIOLATIONS + 1))
  fi
done

if [[ $VIOLATIONS -gt 0 ]]; then
  echo "" >&2
  echo "❌ [fix-tags] $VIOLATIONS file(s) have untagged changes." >&2
  echo "   All changed lines must carry a '$MARKER <id>' tag." >&2
  bcl_violation_exit; exit $?
fi

exit 0
