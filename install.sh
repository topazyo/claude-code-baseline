#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# claude-code-baseline :: install.sh
#
# Inject (or update) the org Claude Code hook baseline into a target repo.
# Idempotent: re-running refreshes the hooks and re-merges settings without
# duplicating anything. Safe-by-default: it never overwrites an existing
# baseline.config.json, and it backs up settings.json before merging.
#
# Usage:
#   ./install.sh [--target <repo-dir>] [--with-openclaw-rules] [--dry-run]
#
#   --target DIR            Repo to install into (default: current directory).
#   --with-openclaw-rules   Also drop examples/security-defaults.openclaw.json
#                           as .claude/security-defaults.json (does not enable it).
#   --dry-run               Print actions without changing anything.
#
# Requires: bash, python3 (or python), git (recommended).

set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="$PWD"
WITH_OPENCLAW=0
DRY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --target=*) TARGET="${1#*=}"; shift ;;
    --with-openclaw-rules) WITH_OPENCLAW=1; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

PY=""
command -v python3 >/dev/null 2>&1 && PY=python3
[[ -z "$PY" ]] && command -v python >/dev/null 2>&1 && PY=python
if [[ -z "$PY" ]]; then
  echo "ERROR: python3 (or python) is required for the settings merge." >&2
  exit 1
fi

TARGET="$(cd "$TARGET" 2>/dev/null && pwd || true)"
if [[ -z "$TARGET" || ! -d "$TARGET" ]]; then
  echo "ERROR: target directory does not exist." >&2
  exit 1
fi
if [[ ! -d "$TARGET/.git" ]]; then
  echo "NOTE: $TARGET is not a git repository root — installing anyway." >&2
fi

say() { echo "  $*"; }
run() { if [[ $DRY -eq 1 ]]; then echo "  [dry-run] $*"; else eval "$@"; fi; }

echo "claude-code-baseline → installing into: $TARGET"
[[ $DRY -eq 1 ]] && echo "(dry run — no files will be changed)"

# 0. Advisory version check. The hook/permissions surface evolves across releases
#    (e.g. an 'allow' could bypass a 'deny' before v2.1.80, which the tamper-
#    protection deny-list relies on). Warn — never block — if the live Claude Code
#    predates the version this baseline was verified against. See RELEASING.md.
echo "› version check"
MIN_CC="$("$PY" -c 'import json,sys
try:
    sys.stdout.write(str(json.load(open(sys.argv[1],encoding="utf-8")).get("minClaudeCodeVersion","") or ""))
except Exception:
    pass' "$SRC/baseline.config.json" 2>/dev/null || true)"
if [[ -z "$MIN_CC" ]]; then
  say "no minClaudeCodeVersion pinned in baseline.config.json — version check skipped."
else
  CC_VER=""
  if command -v claude >/dev/null 2>&1; then
    # 'claude --version' prints e.g. '2.1.158 (Claude Code)'. Prefer the semver tied
    # to the '(Claude Code)' marker so a runtime/SDK version printed alongside can't
    # be mistaken for it; fall back to the first semver if the marker is ever dropped.
    # (|| true is load-bearing under pipefail: grep exits 1 on no match, and head
    #  closing the pipe early can SIGPIPE grep.)
    CC_RAW="$(claude --version 2>/dev/null || true)"
    CC_VER="$(printf '%s\n' "$CC_RAW" | grep -oiE '[0-9]+\.[0-9]+\.[0-9]+[[:space:]]*\(claude code\)' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
    [[ -z "$CC_VER" ]] && CC_VER="$(printf '%s\n' "$CC_RAW" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
  fi
  if [[ -z "$CC_VER" ]]; then
    say "could not detect a 'claude' CLI version on PATH — skipping check (baseline verified against Claude Code >= $MIN_CC)."
  elif "$PY" -c 'import sys
def p(v): return tuple(int(x) for x in v.split("."))
sys.exit(0 if p(sys.argv[1]) >= p(sys.argv[2]) else 1)' "$CC_VER" "$MIN_CC" 2>/dev/null; then
    say "Claude Code v$CC_VER detected (>= required v$MIN_CC)."
  else
    echo "  WARNING: Claude Code v$CC_VER is older than the baseline's required v$MIN_CC." >&2
    echo "           Some controls may behave differently below the pin (e.g. an 'allow' rule could bypass" >&2
    echo "           'deny' before v2.1.80, weakening the tamper-protection deny-list)." >&2
    echo "           Upgrade Claude Code, or review RELEASING.md first." >&2
  fi
fi

CLAUDE_DIR="$TARGET/.claude"
HOOKS_DST="$CLAUDE_DIR/hooks/baseline"

# 1. Hooks (namespaced under .claude/hooks/baseline — never collides with the
#    repo's own hooks). Wipe the baseline subtree first so removed hooks don't
#    linger across upgrades, then copy fresh.
echo "› hooks"
run "mkdir -p \"$HOOKS_DST\""
run "rm -rf \"$HOOKS_DST\"/{lib,guardrails,modules,dispatcher}"
run "cp -R \"$SRC/hooks/.\" \"$HOOKS_DST/\""
if [[ $DRY -eq 0 ]]; then
  find "$HOOKS_DST" -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
fi
say "copied lib/ guardrails/ modules/ dispatcher/ → .claude/hooks/baseline/"

# 2. Config — never clobber an existing one (it carries local toggles).
echo "› config"
if [[ -f "$CLAUDE_DIR/baseline.config.json" ]]; then
  say "kept existing .claude/baseline.config.json (not overwritten)"
else
  run "cp \"$SRC/baseline.config.json\" \"$CLAUDE_DIR/baseline.config.json\""
  say "wrote default .claude/baseline.config.json"
  # Stamp note (create path only — never rewrites an existing config). The value
  # itself rides along in the copied config; hooks/VERSION (recopied below) is the
  # drift marker tools/baseline-status.sh reads. See RELEASING.md.
  BLV="$("$PY" -c 'import json,sys
try: sys.stdout.write(str(json.load(open(sys.argv[1],encoding="utf-8")).get("baselineVersion","") or ""))
except Exception: pass' "$SRC/baseline.config.json" 2>/dev/null || true)"
  [[ -n "$BLV" ]] && say "stamped baselineVersion: $BLV"
fi
run "cp \"$SRC/baseline.config.schema.json\" \"$CLAUDE_DIR/baseline.config.schema.json\""
say "refreshed .claude/baseline.config.schema.json"

# 3. Settings merge (back up first, then idempotent merge).
echo "› settings.json"
SETTINGS="$CLAUDE_DIR/settings.json"
TMP="$CLAUDE_DIR/.settings.merge.$$"
if [[ -f "$SETTINGS" ]]; then
  BACKUP="$SETTINGS.bak.$(date +%Y%m%d%H%M%S)"
  run "cp \"$SETTINGS\" \"$BACKUP\""
  say "backed up existing settings.json → $(basename "$BACKUP")"
  if [[ $DRY -eq 0 ]]; then
    "$PY" "$SRC/lib/merge_settings.py" "$SETTINGS" "$SRC/settings.template.json" "$TMP"
    mv "$TMP" "$SETTINGS"
  fi
  say "merged baseline hooks + deny-list into existing settings.json"
else
  if [[ $DRY -eq 0 ]]; then
    "$PY" "$SRC/lib/merge_settings.py" "-" "$SRC/settings.template.json" "$SETTINGS"
  fi
  say "created settings.json from baseline"
fi

# 4. Optional example rules for the securityDefaults module.
if [[ $WITH_OPENCLAW -eq 1 ]]; then
  echo "› security-defaults rules"
  if [[ -f "$CLAUDE_DIR/security-defaults.json" ]]; then
    say "kept existing .claude/security-defaults.json"
  else
    run "cp \"$SRC/examples/security-defaults.openclaw.json\" \"$CLAUDE_DIR/security-defaults.json\""
    say "wrote .claude/security-defaults.json (enable via modules.securityDefaults.enabled)"
  fi
fi

cat <<EOF

Done. Always-on guardrails are active (command-guard + auto-format + deny-list).
Opt-in modules are OFF by default — enable them in:
  $CLAUDE_DIR/baseline.config.json

Recommended next steps:
  • Commit .claude/hooks/baseline/, .claude/baseline.config.json, and the schema.
  • Keep .claude/settings.local.json out of git (per-developer overrides).
  • Verify a hook fires: edit a file and watch for the post-write dispatcher.
EOF
