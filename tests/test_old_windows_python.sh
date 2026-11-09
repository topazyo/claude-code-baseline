#!/usr/bin/env bash
# claude-code-baseline :: tests/test_old_windows_python.sh
#
# Windows needs Python 3.8 or later. This proves it on a real Windows Python 3.7, which
# the other suites never run on (their Windows floor is 3.8): the installer refuses it,
# and a baseline installed with a newer Python whose hooks later find 3.7 first on PATH
# has scope-guard refuse every Write naming a file, saying what to install.
#
# CI only (the "Old Python refused" job): python3 on PATH must be a Windows Python 3.7,
# and NEWER_PY the path of a newer Python to install with. Anywhere else it exits 1
# rather than passing without having checked anything.
set -uo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pass=0; fail=0
ok() { pass=$((pass + 1)); }
no() { fail=$((fail + 1)); echo "  FAIL [$1]"; }

host="$(python3 -I -S -c 'import os, sys; print("%s %d.%d" % (os.name, sys.version_info[0], sys.version_info[1]))' 2>/dev/null | tr -d '\r')"
if [ "$host" != "nt 3.7" ]; then
  echo "test_old_windows_python: needs a Windows Python 3.7 first on PATH (found '${host:-none}')"
  exit 1
fi
if [ -z "${NEWER_PY:-}" ] || [ ! -f "$NEWER_PY" ]; then
  echo "test_old_windows_python: NEWER_PY must name a newer Python to install with"
  exit 1
fi
NEWER_DIR="$(cygpath -u "$(dirname "$NEWER_PY")")"
OLD_PATH="$PATH"
NEW_PATH="$NEWER_DIR:$PATH"

TMP="$(mktemp -d)"
cleanup() { cd / 2>/dev/null; rm -rf "$TMP"; }
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
R="$TMP/repo"
mkdir -p "$R/src" "$TMP/home"
( cd "$R" && git init -q )
RW="$(cygpath -m "$R")"

# 1. The installer refuses a Windows Python 3.7, before writing anything.
out="$(PATH="$OLD_PATH" timeout -k 5 120 bash "$SRC/install.sh" --target "$RW" 2>&1 </dev/null)"; rc=$?
if [ "$rc" = 1 ] && printf '%s' "$out" | grep -qF "On Windows the hooks need Python 3.8 or later" && [ ! -e "$R/.claude" ]; then ok
else no "install with a Windows Python 3.7 must refuse before writing: rc=$rc"; printf '%s\n' "$out" | tail -n 5; fi

# 2. A newer Python installs it.
out="$(PATH="$NEW_PATH" timeout -k 5 120 bash "$SRC/install.sh" --target "$RW" 2>&1 </dev/null)"; rc=$?
if [ "$rc" = 0 ] && [ -f "$R/.claude/settings.json" ]; then ok
else no "install with a newer Python: rc=$rc"; printf '%s\n' "$out" | tail -n 5; fi

# 3. Its hooks, finding Python 3.7 first on PATH, refuse a write naming a file (an
#    ordinary one: the newer Python lets it through), refuse one naming a protected
#    path as a violation, and pass one naming no file. (The definition-path check runs
#    whether or not the scopeGuard module is on.)
H="$R/.claude/hooks/baseline"
sg() { printf '%s' "$2" | PATH="$1" CLAUDE_PROJECT_DIR="$RW" HOME="$TMP/home" timeout -k 5 60 bash "$H/modules/scope-guard.sh" 2>&1; }
WRITE='{"tool_name":"Write","tool_input":{"file_path":"src/x.py","content":"x"}}'
NOFILE='{"tool_name":"Write","tool_input":{"content":"x"}}'
PROTECTED='{"tool_name":"Write","tool_input":{"file_path":".claude/agents/x.md","content":"x"}}'
out="$(sg "$NEW_PATH" "$WRITE")"; rc=$?
[ "$rc" = 0 ] && ok || { no "control: an ordinary write under the newer Python passes: rc=$rc"; printf '%s\n' "$out" | tail -n 3; }
out="$(sg "$OLD_PATH" "$WRITE")"; rc=$?
if [ "$rc" = 2 ] && printf '%s' "$out" | grep -qF "needs Python 3.8 or later on Windows"; then ok
else no "an ordinary write under Windows Python 3.7 must be refused: rc=$rc"; printf '%s\n' "$out" | tail -n 3; fi
out="$(sg "$OLD_PATH" "$NOFILE")"; rc=$?
[ "$rc" = 0 ] && ok || { no "a payload naming no file passes under Windows Python 3.7: rc=$rc"; printf '%s\n' "$out" | tail -n 3; }
out="$(sg "$OLD_PATH" "$PROTECTED")"; rc=$?
if [ "$rc" = 2 ] && printf '%s' "$out" | grep -qF "REFUSED"; then ok
else no "a protected path under Windows Python 3.7 is REFUSED: rc=$rc"; printf '%s\n' "$out" | tail -n 3; fi

echo ""
echo "test_old_windows_python: $pass passed, $fail failed"
[ "$fail" -eq 0 ] && [ "$pass" -eq 6 ] || exit 1
