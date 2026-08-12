#!/usr/bin/env bash
# claude-code-baseline :: tools/baseline-status.sh
#
# Read-only, local-only reporter for the baseline across one or more repos.
#
# Primary job (--drift): compare each repo's INSTALLED hook-version marker
# (.claude/hooks/baseline/VERSION) against THIS source tree's canonical
# baseline.config.json -> baselineVersion, so an org can see at a glance which
# repos are on an old baseline. Reconciliation is just a re-run of install.sh.
#
# The per-repo posture table (enforcement / enabled guardrails + modules) is a
# BYPRODUCT of the same per-repo read. It is resolved through the baseline's OWN
# config readers (hooks/lib/common.sh bcl_*), so it can never silently diverge
# from what the hooks actually enforce — there is exactly one notion of "enabled".
#
# It only READS on-disk files and shells out to python3/git for parsing. It makes
# no remote requests and writes nothing unless you pass --json <file>. See
# tools/README.md for the deferred one-liner signals and the design rationale.
#
# Usage:
#   tools/baseline-status.sh [--drift] [--strict] [--json <outfile>] <repo>...
#     --drift           (default view) report version drift + posture per repo.
#     --strict          exit non-zero if ANY installed repo has drifted from the
#                       source version (an un-installed repo does NOT trip this).
#     --json <outfile>  ALSO write the full per-repo report as JSON to <outfile>
#                       (the only filesystem write this tool ever performs).
#
# Requires: bash, python3 (or python).
set -uo pipefail

SRC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../hooks/lib/common.sh
source "$SRC_ROOT/hooks/lib/common.sh"

STRICT=0
JSON_OUT=""
REPOS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --drift)   shift ;;                      # default behaviour; accepted for clarity
    --strict)  STRICT=1; shift ;;
    --json)    JSON_OUT="${2:-}"; shift 2 ;;
    --json=*)  JSON_OUT="${1#*=}"; shift ;;
    -h|--help) grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --)        shift; while [[ $# -gt 0 ]]; do REPOS+=("$1"); shift; done ;;
    -*)        echo "unknown option: $1" >&2; exit 2 ;;
    *)         REPOS+=("$1"); shift ;;
  esac
done

PY="$(bcl_python)"
[[ -z "$PY" ]] && { echo "python3 (or python) is required" >&2; exit 1; }
[[ ${#REPOS[@]} -eq 0 ]] && { echo "usage: baseline-status.sh [--drift] [--strict] [--json <file>] <repo>..." >&2; exit 2; }

# Read a top-level scalar key from the canonical SOURCE config (this tree).
read_src_key() {
  "$PY" - "$SRC_ROOT/baseline.config.json" "$1" <<'PY'
import json, sys
try:
    print(json.load(open(sys.argv[1], encoding="utf-8")).get(sys.argv[2], "") or "")
except Exception:
    print("")
PY
}
SRC_VER="$(read_src_key baselineVersion)"
SRC_MIN="$(read_src_key minClaudeCodeVersion)"

GUARDRAILS=(commandGuard autoFormat)
MODULES=(securityDefaults fixTags scopeGuard configGuard runTests trackerReminder autoStage)

RECORDS=""
any_drift=0

echo "baseline status — source baselineVersion: ${SRC_VER:-<unset>}  (min Claude Code pin: ${SRC_MIN:-<unset>})"
echo

for repo in "${REPOS[@]}"; do
  installed=0; enf=""; fc=""; guards=""; mods=""; minver=""; minok=0; instver=""; drift="not-installed"
  hooks_dir="$repo/.claude/hooks/baseline"
  ver_file="$hooks_dir/VERSION"

  if [[ -d "$hooks_dir" ]]; then
    installed=1
    export CLAUDE_PROJECT_DIR="$repo"
    enf="$(bcl_posture)"
    fc="$(bcl_cfg failClosed true)"
    minver="$(bcl_cfg minClaudeCodeVersion "")"
    [[ -n "$minver" && "$minver" == "$SRC_MIN" ]] && minok=1 || minok=0
    for g in "${GUARDRAILS[@]}"; do bcl_guardrail_enabled "$g" && guards="${guards:+$guards,}$g"; done
    for m in "${MODULES[@]}"; do bcl_module_enabled "$m" && mods="${mods:+$mods,}$m"; done
    if [[ -f "$ver_file" ]]; then
      instver="$(tr -d '\r\n' < "$ver_file" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    fi
    if   [[ -z "$instver" ]]; then drift="no-version"
    elif [[ -z "$SRC_VER" ]];  then drift="no-source-version"
    elif [[ "$instver" == "$SRC_VER" ]]; then drift="OK"
    else drift="DRIFT"; fi
    [[ "$drift" != "OK" ]] && any_drift=1
  fi

  # Human-readable per-repo block (the report; --json is the machine form).
  echo "$repo"
  if [[ $installed -eq 1 ]]; then
    echo "  installed=yes  posture=$enf  failClosed=$fc  version=${instver:-<none>}  drift=$drift"
    echo "  minClaudeCodeVersion=${minver:-<none>}  (canonical $SRC_MIN, ok=$([[ $minok -eq 1 ]] && echo yes || echo no))"
    echo "  guardrails: ${guards:-<none>}   modules: ${mods:-<none>}"
  else
    echo "  installed=no   (no .claude/hooks/baseline/ — baseline not adopted here)"
  fi
  echo

  RECORDS+="$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' \
    "$repo" "$installed" "$enf" "$fc" "$guards" "$mods" "$minver" "$minok" "$instver" "$drift")"$'\n'
done

if [[ -n "$JSON_OUT" ]]; then
  # NOTE: use `-c <code>` (code as an argument), NOT `python - <<HEREDOC`, because the
  # records arrive on STDIN via the pipe — a heredoc would itself claim stdin and the
  # piped records would never be read. (Same pattern as common.sh's bcl_extract_*.)
  printf '%s' "$RECORDS" | "$PY" -c '
import json, sys
srcver, srcmin, out = sys.argv[1], sys.argv[2], sys.argv[3]
recs = []
for line in sys.stdin.read().splitlines():
    if not line:
        continue
    f = line.split("\t")
    while len(f) < 10:
        f.append("")
    repo, installed, enf, fc, guards, mods, minver, minok, instver, drift = f[:10]
    recs.append({
        "repo": repo,
        "installed": installed == "1",
        "enforcement": enf or None,
        "failClosed": (fc == "true") if fc in ("true", "false") else None,
        "enabledGuardrails": [x for x in guards.split(",") if x],
        "enabledModules": [x for x in mods.split(",") if x],
        "minClaudeCodeVersion": minver or None,
        "minVersionOk": minok == "1",
        "baselineVersion": instver or None,
        "drift": drift,
    })
with open(out, "w", encoding="utf-8") as fh:
    json.dump({"sourceBaselineVersion": srcver or None,
               "sourceMinClaudeCodeVersion": srcmin or None,
               "repos": recs}, fh, indent=2)
    fh.write("\n")
' "$SRC_VER" "$SRC_MIN" "$JSON_OUT"
  echo "wrote JSON report: $JSON_OUT"
fi

if [[ $STRICT -eq 1 && $any_drift -eq 1 ]]; then
  echo "drift detected (--strict): one or more installed repos are not on baselineVersion ${SRC_VER:-<unset>}" >&2
  exit 1
fi
exit 0
