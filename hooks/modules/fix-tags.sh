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

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"

bcl_module_enabled fixTags || exit 0

# Optional env gate.
GATE_VAR="$(bcl_cfg modules.fixTags.requireWhenEnv "")"
if [[ -n "$GATE_VAR" && -z "${!GATE_VAR:-}" ]]; then
  exit 0
fi

MARKER="$(bcl_cfg modules.fixTags.tagMarker "FIX:")"
FILE_REGEX="$(bcl_cfg modules.fixTags.fileRegex '\.(py|sh|bash|ps1|yml|yaml)$|Dockerfile|Makefile')"

cd "$(bcl_repo_root)" || { echo "[fix-tags] could not enter repo root — tag check skipped." >&2; exit 0; }

CHANGED="$(git diff --name-only 2>/dev/null || true)"
[[ -z "$CHANGED" ]] && exit 0

VIOLATIONS=0
while IFS= read -r FILE; do
  [[ -z "$FILE" ]] && continue
  echo "$FILE" | grep -qE -- "$FILE_REGEX" || continue

  ADDED_LINES="$(git diff -- "$FILE" 2>/dev/null | grep -E '^\+' | grep -v '^+++' || true)"
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
done <<< "$CHANGED"

if [[ $VIOLATIONS -gt 0 ]]; then
  echo "" >&2
  echo "❌ [fix-tags] $VIOLATIONS file(s) have untagged changes." >&2
  echo "   All changed lines must carry a '$MARKER <id>' tag." >&2
  bcl_violation_exit; exit $?
fi

exit 0
