#!/usr/bin/env bash
# claude-code-baseline :: tests/test_msys_python.sh
#
# A Cygwin or MSYS Python on a Windows host reads Windows paths as POSIX paths, so the
# baseline refuses it. This proves it with MSYS2's own Python, which the other suites
# never run: the installer refuses it, and a baseline installed with a native Python
# whose hooks later find the MSYS one first on PATH has scope-guard fail closed on a
# write naming a file (including user settings, protected by where they are), refuse a
# protected name as a violation, and pass a payload naming no file.
#
# CI only (the "MSYS Python refused" job): MSYS_PY names MSYS2's python3.exe and
# NATIVE_PY a native Windows Python to install with. Anywhere else it exits 1 rather
# than passing without having checked anything.
set -uo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pass=0; fail=0
ok() { pass=$((pass + 1)); }
no() { fail=$((fail + 1)); echo "  FAIL [$1]"; }

if [ -z "${MSYS_PY:-}" ] || [ ! -f "$MSYS_PY" ] || [ -z "${NATIVE_PY:-}" ] || [ ! -f "$NATIVE_PY" ]; then
  echo "test_msys_python: MSYS_PY and NATIVE_PY must name MSYS2's python3.X.exe and a native Windows Python"
  exit 1
fi
# The workflow step that installs it prints what it reports (sys.platform, os.name);
# the probe check below proves what the baseline makes of it here.

TMP="$(mktemp -d)"
cleanup() { cd / 2>/dev/null; rm -rf "$TMP"; }
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
# One shim each, so that nothing else from MSYS2 (its bash, coreutils) joins PATH.
mkdir -p "$TMP/msys" "$TMP/native"
printf '#!/usr/bin/env bash\nexec "%s" "$@"\n' "$(cygpath -u "$MSYS_PY")" > "$TMP/msys/python3"
printf '#!/usr/bin/env bash\nexec "%s" "$@"\n' "$(cygpath -u "$NATIVE_PY")" > "$TMP/native/python3"
chmod +x "$TMP/msys/python3" "$TMP/native/python3"
MSYS_PATH="$TMP/msys:$PATH"
NATIVE_PATH="$TMP/native:$PATH"
# What the baseline's own probe makes of it under Git Bash. Everything below rests on
# this answer: an interpreter that does not start here would leave the hooks on their
# no-Python path, which is not the path under test, so that ends the run as inconclusive.
probe="$(PATH="$MSYS_PATH" bash -c '. "$1/hooks/lib/common.sh"; bcl_python_probe "$(bcl_python)"' _ "$SRC")"
echo "bcl_python_probe under Git Bash: $probe"
case "$probe" in
  *' posixwin') ok ;;
  *) no "the probe must answer posixwin for MSYS2's Python under Git Bash, got '$probe'"
     echo "test_msys_python: inconclusive, the interpreter under test did not answer as one"; exit 1 ;;
esac

R="$TMP/repo"
mkdir -p "$R/src" "$TMP/home"
( cd "$R" && git init -q )
RW="$(cygpath -m "$R")"

# 1. The installer refuses the MSYS Python, before writing anything.
out="$(PATH="$MSYS_PATH" timeout -k 5 120 bash "$SRC/install.sh" --target "$RW" 2>&1 </dev/null)"; rc=$?
if [ "$rc" = 1 ] && [ ! -e "$R/.claude" ] && printf '%s' "$out" | grep -qF "is a Cygwin or MSYS Python"; then ok
else no "install with an MSYS Python must refuse before writing: rc=$rc"; printf '%s\n' "$out" | tail -n 5; fi

# 2. A native Python installs it.
out="$(PATH="$NATIVE_PATH" timeout -k 5 120 bash "$SRC/install.sh" --target "$RW" 2>&1 </dev/null)"; rc=$?
if [ "$rc" = 0 ] && [ -f "$R/.claude/settings.json" ]; then ok
else no "install with a native Python: rc=$rc"; printf '%s\n' "$out" | tail -n 5; fi

# 3. Its hooks, finding the MSYS Python first on PATH, fail closed on a write naming a
#    file, refuse a protected name as a violation, and pass a payload naming no file
#    (the definition-path check runs whether or not the scopeGuard module is on).
H="$R/.claude/hooks/baseline"
CFGW="$(cygpath -m "$TMP/cfg")"
sg() { printf '%s' "$2" | PATH="$1" CLAUDE_PROJECT_DIR="$RW" HOME="$TMP/home" CLAUDE_CONFIG_DIR="$CFGW" \
  timeout -k 5 60 bash "$H/modules/scope-guard.sh" 2>&1; }
WRITE='{"tool_name":"Write","tool_input":{"file_path":"src/x.py","content":"x"}}'
NOFILE='{"tool_name":"Write","tool_input":{"content":"x"}}'
PROTECTED='{"tool_name":"Write","tool_input":{"file_path":".claude/agents/x.md","content":"x"}}'
USERSET="{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"$CFGW/settings.json\",\"content\":\"x\"}}"
CLOSED='not a Cygwin, MSYS or other POSIX one'
out="$(sg "$NATIVE_PATH" "$WRITE")"; rc=$?
[ "$rc" = 0 ] && ok || { no "control: an ordinary write under the native Python passes: rc=$rc"; printf '%s\n' "$out" | tail -n 3; }
out="$(sg "$MSYS_PATH" "$WRITE")"; rc=$?
if [ "$rc" = 2 ] && printf '%s' "$out" | grep -qE "$CLOSED"; then ok
else no "an ordinary write under the MSYS Python must fail closed: rc=$rc"; printf '%s\n' "$out" | tail -n 3; fi
out="$(sg "$MSYS_PATH" "$USERSET")"; rc=$?
if [ "$rc" = 2 ] && printf '%s' "$out" | grep -qE "REFUSED|$CLOSED"; then ok
else no "user settings under CLAUDE_CONFIG_DIR under the MSYS Python must fail closed: rc=$rc"; printf '%s\n' "$out" | tail -n 3; fi
out="$(sg "$MSYS_PATH" "$PROTECTED")"; rc=$?
if [ "$rc" = 2 ] && printf '%s' "$out" | grep -qF "REFUSED"; then ok
else no "a protected name under the MSYS Python is REFUSED: rc=$rc"; printf '%s\n' "$out" | tail -n 3; fi
out="$(sg "$MSYS_PATH" "$NOFILE")"; rc=$?
[ "$rc" = 0 ] && ok || { no "a payload naming no file passes under the MSYS Python: rc=$rc"; printf '%s\n' "$out" | tail -n 3; }

echo ""
echo "test_msys_python: $pass passed, $fail failed"
[ "$fail" -eq 0 ] && [ "$pass" -eq 8 ] || exit 1
