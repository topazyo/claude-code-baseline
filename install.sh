#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# claude-code-baseline :: install.sh
#
# Inject (or update) the org Claude Code hook baseline into a target repo.
# Idempotent: re-running refreshes the hooks and re-merges settings without
# duplicating anything. Safe-by-default: it never overwrites an existing
# baseline.config.json, and it backs up settings.json before replacing it with a
# merged copy (no backup, and no write, when the merge changes nothing).
#
# Usage:
#   ./install.sh [--target <repo-dir>] [--with-openclaw-rules]
#                [--enable-security-defaults] [--dry-run]
#
#   --target DIR            Repo to install into (default: current directory).
#   --with-openclaw-rules   Also drop examples/security-defaults.openclaw.json
#                           as .claude/security-defaults.json (does not enable it).
#   --enable-security-defaults
#                           Turn the securityDefaults post-write module on in a
#                           NEWLY written baseline.config.json. Every post-write
#                           module ships off; this is the one-step way to see one
#                           fire. Refuses (nothing written) unless a rules file will
#                           exist: pass --with-openclaw-rules or create the rules
#                           file first. An existing config is never rewritten.
#   --dry-run               Print what a real run would do and change nothing. It
#                           still runs the settings merge, into a system temp file,
#                           so a settings.json the real run would reject fails the
#                           dry run too (exit 1).
#
# Requires: bash, Python 3.7+ (3.8+ on Windows) as python3 (or python), git (recommended).

set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="$PWD"
WITH_OPENCLAW=0
ENABLE_SD=0
DRY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) [[ $# -ge 2 && -n "$2" ]] || { echo "--target needs a directory" >&2; exit 2; }
              TARGET="$2"; shift 2 ;;
    --target=*) TARGET="${1#*=}"
                [[ -n "$TARGET" ]] || { echo "--target needs a directory" >&2; exit 2; }
                shift ;;
    --with-openclaw-rules) WITH_OPENCLAW=1; shift ;;
    --enable-security-defaults) ENABLE_SD=1; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# Use the interpreter the hooks will use, and make sure it runs. The hooks pick theirs
# with bcl_python (hooks/lib/common.sh) on every call: python3, then python, skipping
# the Windows Store "app execution alias" under %LOCALAPPDATA%\Microsoft\WindowsApps
# unless it is all there is. Asking bcl_python here — in a subshell, so the library's
# globals stay out of this script — keeps the installer and the hooks on one
# interpreter: an installer that went looking for a better one could report success
# while every guarded call was refused. A name on PATH is not proof of a Python,
# though: when Python is not installed from the Store, the alias is a stub that prints
# an install hint and exits 9009 (49 to bash), which used to surface only at the merge,
# as "merge exited 49 ... Fix the JSON error". So launch it once and refuse, before
# anything is written, unless it is Python 3.7+ (lib/merge_settings.py and the
# command-guard matcher need `from __future__ import annotations`), or 3.8+ when the
# interpreter is a Windows one (os.name "nt"): scope-guard's definition-path check
# needs 3.8 there, and on an older one it refuses every Write and Edit instead.
# Every launch below passes `-I -S -X utf8`, as the hooks do (see bcl_python): the
# installer often runs from inside the repo it installs into, and nothing there may be
# imported by it.
if ! PY="$(. "$SRC/hooks/lib/common.sh"; bcl_python)"; then
  echo "ERROR: could not load $SRC/hooks/lib/common.sh to find the hooks' interpreter." >&2
  echo "       Nothing was written." >&2
  exit 1
fi
# The version comes back behind a marker, alone on stdout. A Python that prints
# anything else at startup (a sitecustomize, say) is refused too: command-guard treats
# any output from its matcher as a block reason, so the hooks would refuse every shell
# command.
PY_RC=1; PY_OUT=""; PY_VER=""; PY_OSN=""
if [[ -n "$PY" ]]; then
  PY_RC=0
  PY_OUT="$("$PY" -I -S -X utf8 -c 'import os, sys; print("PYVER=%d.%d %s" % (sys.version_info[0], sys.version_info[1], os.name))' 2>/dev/null </dev/null)" || PY_RC=$?
  PY_OUT="${PY_OUT//$'\r'/}"
fi
PY_RE='^PYVER=([0-9]+)[.]([0-9]+) ([a-z]+)$'
if [[ $PY_RC -eq 0 && "$PY_OUT" =~ $PY_RE ]]; then
  PY_VER="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"
  PY_OSN="${BASH_REMATCH[3]}"
fi
PY_MIN=7
if [[ "$PY_OSN" == nt ]]; then PY_MIN=8; fi
PY_OK=0
if [[ -n "$PY_VER" ]] && (( ${PY_VER%%.*} > 3 || (${PY_VER%%.*} == 3 && ${PY_VER#*.} >= PY_MIN) )); then
  PY_OK=1
fi
if [[ $PY_OK -ne 1 ]]; then
  echo "ERROR: no working Python 3.7+ (3.8+ on Windows) found. The hooks and the settings merge need one." >&2
  if [[ -z "$PY" ]]; then
    echo "       Neither python3 nor python is on PATH." >&2
  else
    PY_PATH="$(command -v "$PY" 2>/dev/null || true)"
    if [[ -n "$PY_VER" ]]; then
      echo "       '$PY' ($PY_PATH) is Python $PY_VER." >&2
      if [[ "$PY_OSN" == nt ]]; then
        echo "       On Windows the hooks need Python 3.8 or later." >&2
      fi
    elif [[ $PY_RC -eq 0 ]]; then
      echo "       '$PY' ($PY_PATH) ran but printed unexpected output on stdout. The" >&2
      echo "       hooks read its output, so it must not print anything at startup." >&2
    else
      echo "       '$PY' ($PY_PATH) did not run." >&2
    fi
    case "$(printf '%s' "$PY_PATH" | tr '[:upper:]' '[:lower:]')" in
      *windowsapps*)
        echo "       It is the Windows Store app execution alias. Install Python, or turn" >&2
        echo "       the alias off under Settings > Apps > Advanced app settings >" >&2
        echo "       App execution aliases, or put your Python ahead of WindowsApps on PATH." >&2 ;;
      *)
        echo "       The hooks run this interpreter on every tool call (python3 first, then" >&2
        echo "       python), so fix PATH until that is a working Python 3.7+ (3.8+ on Windows)." >&2 ;;
    esac
  fi
  echo "       Nothing was written." >&2
  exit 1
fi

# Refuse a --target containing shell metacharacters. Nothing below interpolates the
# path into a shell string any more (run() execs an argument vector directly), so
# this is not what stops injection — it is a second line of defence in case a future
# edit reintroduces one, and it keeps an install from landing somewhere other than
# the directory the operator named. Only characters a shell would act on are
# rejected, so a path with spaces, a drive letter, a backslash or non-ASCII
# components (an accented user directory, say) still installs normally.
assert_safe_path() {
  case "$1" in
    *'$'*|*'`'*|*';'*|*'|'*|*'&'*|*'<'*|*'>'*|*'"'*|*"'"*|*$'\n'*)
      echo "ERROR: refusing a target path containing shell metacharacters:" >&2
      echo "       $1" >&2
      exit 2 ;;
  esac
}
assert_safe_path "$TARGET"

TARGET="$(cd "$TARGET" 2>/dev/null && pwd || true)"
if [[ -z "$TARGET" || ! -d "$TARGET" ]]; then
  echo "ERROR: target directory does not exist." >&2
  exit 1
fi
# Re-check after canonicalisation: a symlink can resolve somewhere unexpected.
assert_safe_path "$TARGET"
# A linked worktree or a submodule checkout has a .git FILE (a gitfile) at its root.
if [[ ! -e "$TARGET/.git" ]]; then
  echo "NOTE: $TARGET is not a git repository root — installing anyway." >&2
fi

say() { echo "  $*"; }
# run <cmd> <arg>...  — executes an argument vector. It must never eval: every
# argument below carries the caller-supplied $TARGET, and inside an eval a quoted
# "$(...)", backtick or $VAR in that path is expanded by the shell, so a crafted
# --target would both execute code and install into a directory other than the one
# reported. Dry-run prints %q-quoted arguments, so what is shown is exactly what
# would be exec'd, with no second round of interpretation.
run() {
  if [[ $DRY -eq 1 ]]; then
    printf '  [dry-run]'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

echo "claude-code-baseline → installing into: $TARGET"
[[ $DRY -eq 1 ]] && echo "(dry run — no files will be changed)"

# 0. Advisory version check. The hook/permissions surface evolves across releases
#    (e.g. onFailure:block on the guards needs v2.1.295; below it a guard that
#    cannot start most likely fails open). Warn — never block — if the live Claude Code
#    predates the version this baseline was verified against. See RELEASING.md.
echo "› version check"
MIN_CC="$("$PY" -I -S -X utf8 -c 'import json,sys
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
  elif "$PY" -I -S -X utf8 -c 'import sys
def p(v): return tuple(int(x) for x in v.split("."))
sys.exit(0 if p(sys.argv[1]) >= p(sys.argv[2]) else 1)' "$CC_VER" "$MIN_CC" 2>/dev/null; then
    say "Claude Code v$CC_VER detected (>= required v$MIN_CC)."
  else
    echo "  WARNING: Claude Code v$CC_VER is older than the baseline's required v$MIN_CC." >&2
    echo "           Some controls behave differently below the pin: shell commands started by" >&2
    echo "           the Monitor tool do not reach command-guard before v2.1.314, and the guards'" >&2
    echo "           onFailure:block is unsupported before v2.1.295, so a guard that cannot start" >&2
    echo "           or times out may let the call through instead of blocking it." >&2
    echo "           Upgrade Claude Code, or review RELEASING.md first." >&2
  fi
fi

# 0b. Advisory platform note. The guard hooks run `bash -p "..."` and set onFailure:
#     block, so a Claude Code that cannot find Git Bash on Windows refuses every
#     shell command and every edit (fail-closed). Never blocks the install.
case "$(uname -s 2>/dev/null)" in
  MINGW*|MSYS*|CYGWIN*)
    say "Windows: Claude Code must find Git Bash (Git for Windows, or CLAUDE_CODE_GIT_BASH_PATH set in"
    say "your user environment or ~/.claude/settings.json, not in the repo's settings);"
    say "without it the guard hooks cannot start and every shell command and edit is refused." ;;
  *)
    if [[ -n "${WSL_DISTRO_NAME:-}" || -e /proc/sys/fs/binfmt_misc/WSLInterop ]] \
        || grep -qi microsoft /proc/version 2>/dev/null; then
      say "WSL: Claude Code running inside WSL uses WSL's bash and is fine. Claude Code running"
      say "natively on Windows for this repo needs Git for Windows; without it every guarded"
      say "call is refused."
    fi ;;
esac

CLAUDE_DIR="$TARGET/.claude"
HOOKS_DST="$CLAUDE_DIR/hooks/baseline"

# A .claude or .claude/hooks that is a link (a repo can ship one) would aim the hook
# tree's replacement, and every write below, outside the target: refuse first.
for d in "$CLAUDE_DIR" "$CLAUDE_DIR/hooks"; do
  if [[ -L "$d" ]]; then
    echo "ERROR: $d is a symbolic link (or junction). The installer replaces and writes" >&2
    echo "       files under it, so it would act outside $TARGET. Nothing was written." >&2
    exit 2
  fi
done

# real_dir <dir> -> its physical path plus "/", lower-cased where the filesystem
# ignores case (Windows), so two spellings of one directory compare equal.
real_dir() {
  local p
  # cd -P: a plain cd drops `..` lexically, so link/.. would read as the link's parent
  # rather than the parent of where the link really points.
  p="$(cd -P "$1" 2>/dev/null && pwd -P)" || return 1
  p="$p/"
  case "$(uname -s 2>/dev/null)" in MINGW*|MSYS*|CYGWIN*) p="$(printf '%s' "$p" | tr '[:upper:]' '[:lower:]')" ;; esac
  printf '%s' "$p"
}

# Files under .claude/ that this run writes or creates must not be links (or other
# non-files) that aim the write somewhere else — a repo can ship any of them. Checked
# here, before anything is written, and in a dry run too:
#   settings.json — refused if it is a link: the merge would read the link's target
#     (a file outside the repo, say) into this repo's settings.json and into its backup.
#     Refused if it exists and is not a regular file: `mv` onto a directory moves the
#     merge INTO it, which may be outside the target.
#   baseline.config.json, security-defaults.json — created only when absent. A dangling
#     link is refused (cp would create a file wherever it points), and so is anything
#     else that is not a regular file (a link to a directory: cp writes inside it). A link
#     to a regular file is kept — a shared config the installer only reads, as the hooks
#     do — and named when it resolves outside the target.
#   baseline.config.schema.json — baseline-owned and refreshed every run: a link is
#     replaced by a regular file in step 2; anything else not a regular file is refused.
refuse_write() {
  echo "ERROR: $1" >&2; shift
  local l; for l in "$@"; do echo "       $l" >&2; done
  echo "       Nothing was written." >&2
  exit 2
}
# link_dirs <path>: the physical directory (real_dir form) of every hop of a chain of
# links at <path> — each link after the first, and the file the chain ends at — one per
# line, the final one last. Fails when the chain is longer than 40 links or unresolvable.
link_dirs() {
  local p="$1" t n=0
  while [[ -L "$p" ]]; do
    n=$((n + 1)); [[ $n -le 40 ]] || return 1
    t="$(readlink "$p")" || return 1
    case "$t" in /*|?:*) p="$t" ;; *) p="$(dirname "$p")/$t" ;; esac
    real_dir "$(dirname "$p")" || return 1
    echo
  done
}
# check_created <rel>: the rules for a file created only when absent (see above).
check_created() {
  local p="$CLAUDE_DIR/$1" d dirs hooks_real
  if [[ -L "$p" && ! -e "$p" ]]; then
    refuse_write "$p is a symbolic link to a path that does not exist." \
      "Creating .claude/$1 would create a file wherever it points. Remove the link."
  elif [[ -e "$p" && ! -f "$p" ]]; then
    refuse_write "$p exists and is not a regular file (or a link to one)." \
      "The installer would write inside it. Remove it, or replace it with the file."
  elif [[ -L "$p" ]]; then
    dirs="$(link_dirs "$p")" || refuse_write "$p is a symbolic link that cannot be resolved." \
      "Remove the link, or replace it with the file."
    # Step 1 replaces .claude/hooks/baseline/ wholesale: a chain with any hop in it
    # would dangle by step 2, and the create step would then write through it.
    hooks_real="$(real_dir "$CLAUDE_DIR")hooks/baseline/"
    while IFS= read -r d; do
      case "$d" in
        "$hooks_real"*)
          refuse_write "$p is a link into .claude/hooks/baseline/, which the installer replaces." \
            "Remove the link, or replace it with the file." ;;
      esac
    done <<< "$dirs"
    case "${dirs##*$'\n'}" in
      "$(real_dir "$TARGET")"*) ;;
      *) say "note: .claude/$1 is a link to a file outside $TARGET; kept, and only read" ;;
    esac
  fi
}
# refuse_dangled <rel>: the write-time half of check_created. Every link the preflight
# kept resolved to a file, so a link still at <rel> when a create step is about to copy
# there can only be one that stopped resolving since (a path running through the hook
# tree step 1 replaced, say). Never copy through it — whatever path shape got it there.
# A dry run cannot see this case: it does not replace the tree, so the link still resolves.
# refuse_dangled <rel> <what this run already wrote>
refuse_dangled() {
  if [[ -L "$CLAUDE_DIR/$1" ]]; then
    echo "ERROR: $CLAUDE_DIR/$1 is a link that stopped resolving when the hook tree was" >&2
    echo "       replaced; not writing through it. Already written: $2." >&2
    echo "       Replace the link with the file, then re-run." >&2
    exit 2
  fi
}
if [[ -L "$CLAUDE_DIR/settings.json" ]]; then
  refuse_write "$CLAUDE_DIR/settings.json is a symbolic link." \
    "The installer merges into it and backs it up, which would copy the link's target" \
    "into this repository. Replace the link with a regular file, then re-run."
elif [[ -e "$CLAUDE_DIR/settings.json" && ! -f "$CLAUDE_DIR/settings.json" ]]; then
  refuse_write "$CLAUDE_DIR/settings.json exists and is not a regular file." \
    "Remove it, then re-run."
fi
check_created baseline.config.json
if [[ $WITH_OPENCLAW -eq 1 ]]; then check_created security-defaults.json; fi
if [[ -e "$CLAUDE_DIR/baseline.config.schema.json" && ! -L "$CLAUDE_DIR/baseline.config.schema.json" \
      && ! -f "$CLAUDE_DIR/baseline.config.schema.json" ]]; then
  refuse_write "$CLAUDE_DIR/baseline.config.schema.json exists and is not a regular file." \
    "Remove it, then re-run."
fi

# --enable-security-defaults preflight, before anything is written. An enabled
# securityDefaults module whose rules file is missing fails closed and blocks every
# infra write, so refuse unless the rules file will exist once this run finishes.
# Only a NEW config is ever enabled (step 5), so only that case is checked.
if [[ $ENABLE_SD -eq 1 && ! -f "$CLAUDE_DIR/baseline.config.json" ]]; then
  SD_RULES="$("$PY" -I -S -X utf8 -c 'import json,sys
c=json.load(open(sys.argv[1],encoding="utf-8"))
sys.stdout.write(str(((c.get("modules") or {}).get("securityDefaults") or {}).get("rulesFile") or ".claude/security-defaults.json"))' "$SRC/baseline.config.json")"
  case "$SD_RULES" in /*|?:*) SD_RULES_ABS="$SD_RULES" ;; *) SD_RULES_ABS="$TARGET/$SD_RULES" ;; esac
  if [[ ! -f "$SD_RULES_ABS" ]] && ! [[ $WITH_OPENCLAW -eq 1 && "$SD_RULES" == ".claude/security-defaults.json" ]]; then
    echo "ERROR: --enable-security-defaults needs a rules file, and $SD_RULES does not exist." >&2
    echo "       Pass --with-openclaw-rules to seed the example rules, or create the file" >&2
    echo "       first. Nothing was written." >&2
    exit 2
  fi
fi

# 1. Hooks (namespaced under .claude/hooks/baseline — never collides with the
#    repo's own hooks). The whole baseline tree is replaced: removed hooks don't
#    linger across upgrades, and nothing planted in it survives a re-install.
echo "› hooks"
# Never delete the source we are installing from: refuse a baseline checkout that was
# vendored inside the destination itself.
SRC_REAL="$(real_dir "$SRC")"
if [[ -d "$HOOKS_DST" ]]; then
  DST_REAL="$(real_dir "$HOOKS_DST")" || {
    echo "ERROR: cannot read $HOOKS_DST. Nothing was written." >&2; exit 2; }
  case "$SRC_REAL" in
    "$DST_REAL"*)
      echo "ERROR: the baseline source ($SRC_REAL) is inside $HOOKS_DST, which this" >&2
      echo "       installer replaces wholesale. Install from a checkout outside it." >&2
      echo "       Nothing was written." >&2
      exit 2 ;;
  esac
fi
# Name every file the baseline does not ship before it goes: a file planted here may be
# the evidence of tampering, and deleting it silently would destroy that evidence.
if [[ -d "$HOOKS_DST" && ! -L "$HOOKS_DST" ]]; then
  # comm must collate like the sorts that feed it (C), or a name such as .DS_Store
  # makes it report unsorted input and exit 1, which set -e turns into an abort.
  EXTRA="$(LC_ALL=C comm -23 \
    <(cd "$HOOKS_DST" && find . \( -type f -o -type l \) ! -path '*/__pycache__/*' ! -path ./INSTALL_SCOPE | LC_ALL=C sort) \
    <(cd "$SRC/hooks" && find . \( -type f -o -type l \) ! -path '*/__pycache__/*' | LC_ALL=C sort))"
  if [[ -n "$EXTRA" ]]; then
    while IFS= read -r f; do
      f="${f//[[:cntrl:]]/?}"   # a planted name must not drive the terminal
      if [[ $DRY -eq 1 ]]; then
        say "would remove a file the baseline does not ship: .claude/hooks/baseline/${f#./}"
      else
        say "removing a file the baseline does not ship: .claude/hooks/baseline/${f#./}"
      fi
    done <<< "$EXTRA"
  fi
fi
# rm -rf on a symlink (or junction) operand removes the link, never its target; a test
# pins this, since a link here would otherwise aim the wipe outside the repo.
run rm -rf "$HOOKS_DST"
run mkdir -p "$HOOKS_DST"
run cp -R "$SRC/hooks/." "$HOOKS_DST/"
if [[ $DRY -eq 0 ]]; then
  find "$HOOKS_DST" -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
  # Never propagate compiled bytecode into a consumer repo: .pyc files embed the
  # absolute path of the machine that built them and go stale against the source.
  find "$HOOKS_DST" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
  # The per-repo marker. A hook tree WITHOUT it is a managed deployment (an admin's copy
  # of the source hooks/ under <BASELINE_PREFIX>), whose posture and code-running
  # switches come from <BASELINE_PREFIX>/managed.config.json, never from the repo
  # (common.sh _bcl_cfg_scope). The source tree never ships one; a stray copy is
  # replaced by this installer's own.
  rm -f "$HOOKS_DST/INSTALL_SCOPE"
  printf 'per-repo\n' > "$HOOKS_DST/INSTALL_SCOPE"
fi
if [[ $DRY -eq 1 ]]; then
  say "would replace .claude/hooks/baseline/ with the baseline hook tree (marked per-repo)"
else
  say "replaced .claude/hooks/baseline/ with the baseline hook tree (marked per-repo)"
fi

# 2. Config — never clobber an existing one (it carries local toggles).
echo "› config"
CFG_CREATED=0
if [[ -f "$CLAUDE_DIR/baseline.config.json" ]]; then
  say "kept existing .claude/baseline.config.json (not overwritten)"
  # The hooks read it the same way (common.sh bcl_config_malformed) and fail closed on
  # one they cannot read, so say so now rather than at the first blocked call.
  CFG_BAD="$("$PY" -I -S -X utf8 -c 'import json,sys
try:
    with open(sys.argv[1], "rb") as fh:
        data = json.loads(fh.read())
except json.JSONDecodeError as exc:
    print("line %d column %d: %s" % (exc.lineno, exc.colno, exc.msg))
except Exception as exc:
    print(type(exc).__name__)
else:
    print("OK" if isinstance(data, dict) else "the top level is not a JSON object")' "$CLAUDE_DIR/baseline.config.json" 2>/dev/null || true)"
  CFG_BAD="${CFG_BAD%$'\r'}"
  [[ -n "$CFG_BAD" ]] || CFG_BAD="the check could not run"
  if [[ "$CFG_BAD" != "OK" ]]; then
    echo "WARNING: the existing .claude/baseline.config.json cannot be read ($CFG_BAD)." >&2
    echo "         The baseline hooks fail closed until it is fixed or deleted." >&2
  fi
else
  CFG_CREATED=1
  refuse_dangled baseline.config.json "the hook tree under .claude/hooks/baseline/ (settings.json was not changed)"
  run cp "$SRC/baseline.config.json" "$CLAUDE_DIR/baseline.config.json"
  if [[ $DRY -eq 1 ]]; then
    say "would write default .claude/baseline.config.json"
  else
    say "wrote default .claude/baseline.config.json"
  fi
  # Stamp note (create path only — never rewrites an existing config). The value
  # itself rides along in the copied config; hooks/VERSION (recopied below) is the
  # drift marker tools/baseline-status.sh reads. See RELEASING.md.
  BLV="$("$PY" -I -S -X utf8 -c 'import json,sys
try: sys.stdout.write(str(json.load(open(sys.argv[1],encoding="utf-8")).get("baselineVersion","") or ""))
except Exception: pass' "$SRC/baseline.config.json" 2>/dev/null || true)"
  if [[ -n "$BLV" && $DRY -eq 1 ]]; then
    say "would stamp baselineVersion: $BLV"
  elif [[ -n "$BLV" ]]; then
    say "stamped baselineVersion: $BLV"
  fi
fi
# A link here would have cp write the schema through it, over whatever it points at.
# The schema is the baseline's own file, so the link is replaced, never followed.
if [[ -L "$CLAUDE_DIR/baseline.config.schema.json" ]]; then
  run rm -f "$CLAUDE_DIR/baseline.config.schema.json"
  if [[ $DRY -eq 1 ]]; then
    say "would replace the symbolic link at .claude/baseline.config.schema.json with the schema file"
  else
    say "replaced the symbolic link at .claude/baseline.config.schema.json with the schema file"
  fi
fi
run cp "$SRC/baseline.config.schema.json" "$CLAUDE_DIR/baseline.config.schema.json"
if [[ $DRY -eq 1 ]]; then
  say "would refresh .claude/baseline.config.schema.json"
else
  say "refreshed .claude/baseline.config.schema.json"
fi

# 3. Settings merge: merge into a temp file, then — only if that changes the file —
#    back up the original and move the result into place.
echo "› settings.json"
SETTINGS="$CLAUDE_DIR/settings.json"
# The merge always writes to $MERGE_TMP and is only moved into place on success, so an
# interrupted or failed merge can never leave a truncated settings.json behind. A dry
# run merges too — into a system temp file, so nothing under the target is written —
# so that a settings.json the real run would reject fails the dry run as well.
if [[ $DRY -eq 1 ]]; then
  MERGE_TMP="$(mktemp 2>/dev/null)" || {
    echo "ERROR: cannot create a temp file for the dry-run settings merge." >&2; exit 1; }
else
  # A random name, created exclusively: a fixed one ($$) could be a link the repo ships,
  # and the merge would be written through it. mktemp makes it 0600, which the mv would
  # carry onto settings.json, so give it the mode a plain new file gets.
  MERGE_TMP="$(mktemp "$CLAUDE_DIR/.settings.merge.XXXXXX" 2>/dev/null)" || {
    echo "ERROR: cannot create a temp file under $CLAUDE_DIR for the settings merge." >&2
    echo "       Hook files were written; settings.json was not changed." >&2
    exit 1; }
  chmod "$(printf '%o' $(( 0666 & ~0$(umask) )))" "$MERGE_TMP" 2>/dev/null || true
fi
trap 'rm -f "${MERGE_TMP:-}" 2>/dev/null || true' EXIT

# merge_failed <exit-code> — the merge is the one step that can destroy consumer
# configuration, so it is the one step whose exit status is never assumed. Rather
# than treating an unparseable settings.json as empty (which would silently drop
# the repo's own deny rules, hooks, allow list and model), merge_settings.py exits
# non-zero and says why on stderr; we report where the untouched original is and
# stop before the mv. The original stays byte-identical.
merge_failed() {
  rm -f "$MERGE_TMP" 2>/dev/null || true
  echo "" >&2
  if [[ $DRY -eq 1 ]]; then
    echo "DRY RUN: the real run would stop here — settings.json could not be merged (merge exited $1)." >&2
    echo "  Nothing was written. Fix the error reported above, then re-run." >&2
    exit 1
  fi
  echo "INSTALL INCOMPLETE — settings.json was NOT merged (merge exited $1)." >&2
  echo "  Your settings.json was not modified: $SETTINGS" >&2
  echo "  Hook files WERE written under $CLAUDE_DIR/hooks/baseline/, but nothing is" >&2
  echo "  wired up until the merge succeeds — this install grants NO guardrails yet." >&2
  echo "  Fix the JSON error reported above, then re-run this installer." >&2
  exit 1
}

# same_settings <a> <b>: the same text once a UTF-8 BOM and CRLF line ends are set
# aside. Native Windows Python writes the merge with CRLF, so a byte compare would call
# an LF settings.json (or a CRLF one on Linux) changed on every run.
same_settings() {
  "$PY" -I -S -X utf8 -c 'import sys
def norm(p):
    b = open(p, "rb").read()
    if b[:3] == b"\xef\xbb\xbf":
        b = b[3:]
    return b.replace(b"\r\n", b"\n")
sys.exit(0 if norm(sys.argv[1]) == norm(sys.argv[2]) else 1)' "$1" "$2" 2>/dev/null
}

# tgit <args>: git in the target, never steered by the operator's GIT_DIR-style
# variables, and with core.fsmonitor off (a hostile repo's config must not run code).
tgit() {
  env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE -u GIT_COMMON_DIR \
    git -C "$TARGET" -c core.fsmonitor=false "$@"
}

# ignore_backups: keep settings.json.bak.* out of git through the repo's LOCAL exclude
# file (backups only exist on the machine that ran this). Only when the target is the
# repo's own top level — never a parent repo the target merely sits inside — and git
# does not already ignore the backup. Never fatal: settings.json is merged already.
ignore_backups() {
  local top excl line
  top="$(tgit rev-parse --show-toplevel 2>/dev/null)" || return 0
  [[ -n "$top" && "$(real_dir "$top")" == "$(real_dir "$TARGET")" ]] || return 0
  # --no-index: the backup is untracked, and reading the index is what runs fsmonitor.
  if tgit check-ignore --no-index -q -- "$BACKUP" 2>/dev/null; then return 0; fi
  excl="$(tgit rev-parse --git-path info/exclude 2>/dev/null)" || return 0
  [[ -n "$excl" ]] || return 0
  case "$excl" in /*|?:*) ;; *) excl="$TARGET/$excl" ;; esac
  line="/.claude/settings.json.bak.*"
  # Do not append through a link at the exclude file or its info/ directory, which
  # would write wherever it points (a clone cannot plant one in .git, an unpacked
  # archive can). Where git itself keeps the file (a .git link, a gitfile) is git's
  # own resolution and is not second-guessed here; the line written is fixed text.
  if [[ -L "$excl" || -L "${excl%/*}" || ( -e "$excl" && ! -f "$excl" ) ]]; then
    echo "  WARNING: $excl is a link or not a regular file; not adding $line to it." >&2
    return 0
  fi
  # Already there (a negation elsewhere can make check-ignore say "not ignored"): once.
  if [[ -f "$excl" ]] && grep -qF -- "$line" "$excl" 2>/dev/null; then return 0; fi
  if [[ $DRY -eq 1 ]]; then
    say "would add $line to the repo's local git exclude ($excl)"
    return 0
  fi
  if { mkdir -p "${excl%/*}" &&
       if [[ -s "$excl" && -n "$(tail -c 1 "$excl")" ]]; then printf '\n' >> "$excl"; fi &&
       printf '%s\n' "$line" >> "$excl"; } 2>/dev/null; then
    say "added $line to the repo's local git exclude ($excl)"
  else
    echo "  WARNING: could not add $line to $excl; keep settings.json.bak.* out of git yourself." >&2
  fi
}

# What the closing banner reports for settings.json (the unchanged case says so).
SETTINGS_BANNER="  • the hook wiring from settings.template.json → $CLAUDE_DIR/settings.json
  • the deny-list, merged into permissions.deny in that same file"
if [[ -f "$SETTINGS" ]]; then MERGE_IN="$SETTINGS"; else MERGE_IN="-"; fi
MERGE_RC=0
"$PY" -I -S -X utf8 "$SRC/lib/merge_settings.py" "$MERGE_IN" "$SRC/settings.template.json" "$MERGE_TMP" || MERGE_RC=$?
[[ $MERGE_RC -eq 0 ]] || merge_failed "$MERGE_RC"

if [[ ! -f "$SETTINGS" ]]; then
  if [[ $DRY -eq 1 ]]; then
    say "would create settings.json from baseline"
  else
    mv "$MERGE_TMP" "$SETTINGS"
    say "created settings.json from baseline"
  fi
elif same_settings "$SETTINGS" "$MERGE_TMP"; then
  rm -f "$MERGE_TMP"
  SETTINGS_BANNER="  • nothing in $CLAUDE_DIR/settings.json: it already had the baseline wiring and deny-list"
  if [[ $DRY -eq 1 ]]; then
    say "would leave settings.json as it is (already up to date; no backup)"
  else
    say "settings.json already up to date — left as it is, no backup"
  fi
else
  # A unique name: two runs in the same second must not overwrite the first backup.
  BACKUP="$SETTINGS.bak.$(date +%Y%m%d%H%M%S)"
  BACKUP_BASE="$BACKUP"; n=0
  while [[ -e "$BACKUP" || -L "$BACKUP" ]]; do n=$((n + 1)); BACKUP="$BACKUP_BASE.$n"; done
  if [[ $DRY -eq 1 ]]; then
    say "would back up settings.json → $(basename "$BACKUP")"
    say "would merge baseline hooks + deny-list into settings.json"
  else
    cp "$SETTINGS" "$BACKUP"
    mv "$MERGE_TMP" "$SETTINGS"
    say "backed up settings.json → $(basename "$BACKUP")"
    say "merged baseline hooks + deny-list into settings.json"
  fi
  ignore_backups
fi
# The merge keeps a disableAllHooks it found (and warned about on stderr); say it again
# in the banner, whose "command-guard is on" would otherwise read as true. Same reading
# as the merge's warning and config-guard (1). Exit 10: set; 11: not set; anything else
# (a traceback exits 1) means the check could not run, and the banner says so.
DAH_RC=11
if [[ "$MERGE_IN" != "-" ]]; then
  DAH_RC=0
  "$PY" -I -S -X utf8 -c 'import sys
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
import merge_settings as ms
sys.exit(10 if ms.disables_all_hooks(ms.load(sys.argv[2], "existing settings")) else 11)' \
    "$SRC/lib" "$MERGE_IN" 2>/dev/null </dev/null || DAH_RC=$?
fi
if [[ $DAH_RC -eq 10 ]]; then
  SETTINGS_BANNER="$SETTINGS_BANNER
  • NOT IN EFFECT: settings.json sets disableAllHooks; while Claude Code reads it as
    true it runs none of these hooks, command-guard included. Remove it unless you
    set it on purpose"
elif [[ $DAH_RC -ne 11 ]]; then
  SETTINGS_BANNER="$SETTINGS_BANNER
  • could not check settings.json for disableAllHooks (exit $DAH_RC); see the merge's
    warnings above"
fi

# 4. Optional example rules for the securityDefaults module.
if [[ $WITH_OPENCLAW -eq 1 ]]; then
  echo "› security-defaults rules"
  if [[ -f "$CLAUDE_DIR/security-defaults.json" ]]; then
    say "kept existing .claude/security-defaults.json"
  else
    refuse_dangled security-defaults.json "the hook tree, the schema (and the config, where it was absent), and the settings.json merge"
    run cp "$SRC/examples/security-defaults.openclaw.json" "$CLAUDE_DIR/security-defaults.json"
    if [[ $DRY -eq 1 ]]; then
      say "would write .claude/security-defaults.json"
    elif [[ $ENABLE_SD -eq 1 ]]; then
      say "wrote .claude/security-defaults.json"
    else
      say "wrote .claude/security-defaults.json (enable via modules.securityDefaults.enabled)"
    fi
  fi
fi

# 5. Optional: turn securityDefaults on (--enable-security-defaults). Runs last, so
# the rules file is already in place, and only on a config this run created: an
# existing config carries local toggles and is never rewritten.
if [[ $ENABLE_SD -eq 1 ]]; then
  echo "› securityDefaults module"
  if [[ $CFG_CREATED -eq 0 ]]; then
    SD_ON="$("$PY" -I -S -X utf8 -c 'import json,sys
c=json.loads(open(sys.argv[1],"rb").read())
sys.stdout.write("1" if ((c.get("modules") or {}).get("securityDefaults") or {}).get("enabled") is True else "0")' "$CLAUDE_DIR/baseline.config.json" 2>/dev/null || echo 0)"
    if [[ "$SD_ON" == "1" ]]; then
      say "securityDefaults is already enabled in the existing .claude/baseline.config.json."
    else
      say "kept existing .claude/baseline.config.json, so securityDefaults was NOT changed."
      say "To turn it on, set modules.securityDefaults.enabled to true in that file."
    fi
  elif [[ $DRY -eq 1 ]]; then
    say "would set modules.securityDefaults.enabled = true in .claude/baseline.config.json"
  else
    # The temp file is random and created exclusively (mkstemp): a fixed name such as
    # baseline.config.json.tmp could be a link the repo ships, written through and then
    # renamed over the config. It takes the config's mode before the rename.
    "$PY" -I -S -X utf8 -c 'import json,os,sys,tempfile
p=sys.argv[1]
c=json.load(open(p,encoding="utf-8"))
c.setdefault("modules",{}).setdefault("securityDefaults",{})["enabled"]=True
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(p),prefix=".baseline.config.",suffix=".tmp")
try:
    with os.fdopen(fd,"w",encoding="utf-8",newline="\n") as fh:
        json.dump(c,fh,indent=2,ensure_ascii=False); fh.write("\n")
    os.chmod(tmp,os.stat(p).st_mode & 0o777)
    os.replace(tmp,p)
except BaseException:
    try: os.unlink(tmp)
    except OSError: pass
    raise' "$CLAUDE_DIR/baseline.config.json"
    say "enabled modules.securityDefaults (post-write checks of infra files)"
  fi
fi

# Closing banner. It states what was WRITTEN — not that anything is "active":
# the installer copies files and edits settings.json, and never runs a hook or
# checks that one fires, so any stronger claim here would be unverified. Under
# --dry-run nothing was written at all, so the tense changes too.
if [[ $DRY -eq 1 ]]; then
  HEADLINE="Dry run complete. NOTHING was written. A real run would write:"
else
  HEADLINE="Baseline written. What this installer did, and only this:"
fi
cat <<EOF

$HEADLINE
  • the hook tree  → $CLAUDE_DIR/hooks/baseline/
$SETTINGS_BANNER

Nothing here has been verified to fire. Which guardrails and modules actually run
is decided by:
  $CLAUDE_DIR/baseline.config.json
By default only command-guard is on. Every post-write module is off, so writing a
file triggers no visible check until you enable one; to see one fire, re-install
into a fresh repo with --with-openclaw-rules --enable-security-defaults. Auto-format
is off too, because it runs formatters resolved from the repo it is invoked in,
which is code execution.

These are defense-in-depth defaults, not a security boundary. Read the README
section "What this does not protect against" before relying on them.

Recommended next steps:
  • Commit .claude/hooks/baseline/, .claude/baseline.config.json, and the schema.
  • Keep .claude/settings.local.json out of git (per-developer overrides).
  • Verify a hook fires: ask Claude to run \`git push --force\`; command-guard
    should refuse it.
EOF
