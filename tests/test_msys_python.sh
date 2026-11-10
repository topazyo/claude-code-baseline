#!/usr/bin/env bash
# claude-code-baseline :: tests/test_msys_python.sh
#
# A Cygwin or MSYS Python on a Windows host reads Windows paths as POSIX paths, and
# launched from Git Bash (another MSYS runtime) it has its arguments parsed again,
# which mangles the scripts the hooks pass it. So the baseline never runs its code on
# one. This proves it with MSYS2's own Python, which the other suites never run:
#   - bcl_python skips it when it sits beside its runtime DLL (MSYS2's own bin first
#     on PATH), and picks the next interpreter;
#   - behind a wrapper that hides the DLL, the baseline's probe calls it posixwin, the
#     installer refuses it, and hooks that find it first on PATH treat it as no
#     interpreter: command-guard and scope-guard fail closed, naming it.
#
# CI only (the "MSYS Python refused" job): MSYS_PY names MSYS2's python3.X.exe and
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
MSYS_BIN="$(cygpath -u "$(dirname "$MSYS_PY")")"
# A wrapper each (no DLL beside them), so that nothing else from MSYS2 (its bash,
# coreutils) joins PATH, and so that the DLL check cannot see the MSYS one.
mkdir -p "$TMP/msys" "$TMP/native"
printf '#!/usr/bin/env bash\nexec "%s" "$@"\n' "$(cygpath -u "$MSYS_PY")" > "$TMP/msys/python3"
printf '#!/usr/bin/env bash\nexec "%s" "$@"\n' "$(cygpath -u "$NATIVE_PY")" > "$TMP/native/python3"
chmod +x "$TMP/msys/python3" "$TMP/native/python3"
MSYS_PATH="$TMP/msys:$PATH"
NATIVE_PATH="$TMP/native:$PATH"

# 1. With MSYS2's own bin first on PATH, its python3 and python sit beside its DLL:
#    bcl_python uses neither (it looks each name up once), so there is no interpreter,
#    and the reason the hooks give names the MSYS one.
picked="$(PATH="$MSYS_BIN:$NATIVE_PATH" "$BASH" -c '. "$1/hooks/lib/common.sh"; printf "[%s] %s" "$(bcl_python)" "$(bcl_nopy_reason)"' _ "$SRC")"
echo "bcl_python with MSYS2's bin first: $picked"
case "$picked" in
  "[] the Python on PATH is a Cygwin or MSYS one"*) ok ;;
  *) no "bcl_python must not use MSYS2's own python3, and say why: got '$picked'" ;;
esac

# 2. Behind a wrapper, the baseline's probe calls it posixwin. Everything below rests on
#    this answer: an interpreter that does not start here is not the case under test.
probe="$(PATH="$MSYS_PATH" "$BASH" -c '. "$1/hooks/lib/common.sh"; bcl_python_probe "$(bcl_python)"' _ "$SRC")"
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

# 3. The installer refuses it, before writing anything.
out="$(PATH="$MSYS_PATH" timeout -k 5 120 bash "$SRC/install.sh" --target "$RW" 2>&1 </dev/null)"; rc=$?
if [ "$rc" = 1 ] && [ ! -e "$R/.claude" ] && printf '%s' "$out" | grep -qF "is a Cygwin or MSYS Python"; then ok
else no "install with an MSYS Python must refuse before writing: rc=$rc"; printf '%s\n' "$out" | tail -n 5; fi

# 4. A native Python installs it.
out="$(PATH="$NATIVE_PATH" timeout -k 5 120 bash "$SRC/install.sh" --target "$RW" 2>&1 </dev/null)"; rc=$?
if [ "$rc" = 0 ] && [ -f "$R/.claude/settings.json" ]; then ok
else no "install with a native Python: rc=$rc"; printf '%s\n' "$out" | tail -n 5; fi

# 5. Its hooks, finding the wrapped MSYS Python first on PATH, run none of their code on
#    it: scope-guard fails closed on every edit (user settings and protected names too,
#    and one naming no file), and command-guard blocks a clean command, both naming it.
H="$R/.claude/hooks/baseline"
CFGW="$(cygpath -m "$TMP/cfg")"
hook() { printf '%s' "$3" | PATH="$1" CLAUDE_PROJECT_DIR="$RW" HOME="$TMP/home" CLAUDE_CONFIG_DIR="$CFGW" \
  timeout -k 5 60 bash "$H/$2" 2>&1; }
WRITE='{"tool_name":"Write","tool_input":{"file_path":"src/x.py","content":"x"}}'
NOFILE='{"tool_name":"Write","tool_input":{"content":"x"}}'
PROTECTED='{"tool_name":"Write","tool_input":{"file_path":".claude/agents/x.md","content":"x"}}'
USERSET="{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"$CFGW/settings.json\",\"content\":\"x\"}}"
CLEAN='{"tool_name":"Bash","tool_input":{"command":"ls"}}'
CLOSED='not a Cygwin, MSYS or other POSIX one'
out="$(hook "$NATIVE_PATH" modules/scope-guard.sh "$WRITE")"; rc=$?
[ "$rc" = 0 ] && ok || { no "control: an ordinary write under the native Python passes: rc=$rc"; printf '%s\n' "$out" | tail -n 3; }
for p in WRITE USERSET PROTECTED NOFILE; do
  out="$(hook "$MSYS_PATH" modules/scope-guard.sh "${!p}")"; rc=$?
  if [ "$rc" = 2 ] && printf '%s' "$out" | grep -qF "$CLOSED"; then ok
  else no "scope-guard, $p, under the MSYS Python must fail closed naming it: rc=$rc"; printf '%s\n' "$out" | tail -n 3; fi
done
out="$(hook "$MSYS_PATH" guardrails/command-guard.sh "$CLEAN")"; rc=$?
if [ "$rc" = 2 ] && printf '%s' "$out" | grep -qF "is a Cygwin or MSYS one"; then ok
else no "command-guard under the MSYS Python must block naming it: rc=$rc"; printf '%s\n' "$out" | tail -n 3; fi
for hk in modules/security-defaults.sh dispatcher/post-write.sh; do
  out="$(hook "$MSYS_PATH" "$hk" "$WRITE")"; rc=$?
  if [ "$rc" = 2 ] && printf '%s' "$out" | grep -qF "is a Cygwin or MSYS one"; then ok
  else no "$hk under the MSYS Python must fail closed naming it: rc=$rc"; printf '%s\n' "$out" | tail -n 3; fi
done

# On a failed hook row, show why: the prime as the hooks run it under this interpreter,
# and what it receives from Git Bash.
if [ "$fail" -gt 0 ]; then
  echo "--- diagnostics: the prime under the MSYS Python"
  PATH="$MSYS_PATH" CLAUDE_PROJECT_DIR="$RW" HOME="$TMP/home" "$BASH" -c '
    . "$1/lib/common.sh"
    bcl_prime "$2" definition
    echo "prime: state=[$_BCL_PRIME_STATE] py=[${_BCL_PY-unset}] definition=[${_BCL_PL_DEFINITION-unset}]"
    out="$(python3 -I -S -X utf8 -c "import sys; print(repr(sys.argv), repr(sys.stdin.read()), sys.platform)" "$3" <<< "$2" 2>&1)"; rc=$?
    echo "argv and stdin: rc=$rc $out"
  ' _ "$H" "$NOFILE" "$RW"
fi

echo ""
echo "test_msys_python: $pass passed, $fail failed"
[ "$fail" -eq 0 ] && [ "$pass" -eq 12 ] || exit 1
