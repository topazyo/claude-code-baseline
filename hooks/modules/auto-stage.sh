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

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"

bcl_module_enabled autoStage || exit 0

PAYLOAD="$(cat 2>/dev/null || true)"
cd "$(bcl_repo_root)" || exit 0

while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  [[ -f "$f" ]] || continue
  git add "$f" 2>/dev/null || true
done < <(bcl_extract_paths "$PAYLOAD")

exit 0
