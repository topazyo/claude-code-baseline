#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# claude-code-baseline :: modules/security-defaults.sh
#
# PostToolUse module (matcher: Write|Edit). Verifies that immutable security
# defaults have not drifted in changed infrastructure files. The actual rules
# are DECLARATIVE and live outside this script, so the same engine serves any
# repo — no editing this file to change policy.
#
# Enable + point at a rules file in baseline.config.json:
#   "modules": { "securityDefaults": {
#       "enabled": true, "rulesFile": ".claude/security-defaults.json" } }
#
# Rules file shape (see examples/security-defaults.openclaw.json):
#   {
#     "infraPattern":    "<regex: only check files whose PATH matches>",
#     "skipPathPattern": "<regex: skip files whose PATH matches>"   (optional),
#     "rules": [
#       { "id": "...", "appliesWhen": "<regex on content>",
#         "mustMatch":    "<regex content must contain>", "message": "..." },
#       { "id": "...", "appliesWhen": "<regex on content>",
#         "mustNotMatch": "<regex content must NOT contain>", "message": "..." }
#     ]
#   }
# A rule with no "appliesWhen" is always evaluated. Each rule supplies exactly
# one of "mustMatch" / "mustNotMatch".

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"

bcl_module_enabled securityDefaults || exit 0

PY="$(bcl_python)"
if [[ -z "$PY" ]]; then
  echo "[security-defaults] CONTROL COULD NOT RUN — Python unavailable; infra files were NOT verified." >&2
  bcl_failclosed_exit; exit $?
fi

PAYLOAD="$(cat 2>/dev/null || true)"
if bcl_payload_unparseable "$PAYLOAD"; then
  echo "[security-defaults] CONTROL COULD NOT RUN — tool payload unparseable; infra files were NOT verified." >&2
  bcl_failclosed_exit; exit $?
fi
RULES="$(bcl_cfg modules.securityDefaults.rulesFile .claude/security-defaults.json)"
case "$RULES" in /*|?:*) : ;; *) RULES="$(bcl_repo_root)/$RULES" ;; esac

mapfile -t PATHS < <(bcl_extract_paths "$PAYLOAD")
[[ ${#PATHS[@]} -eq 0 ]] && exit 0

if [[ ! -f "$RULES" ]]; then
  {
    echo "[security-defaults] CONTROL COULD NOT RUN — rules file not found: $RULES"
    echo "   securityDefaults is enabled but its rulesFile is missing; infra files were NOT verified."
    echo "   Create the rules file, disable modules.securityDefaults, or set failClosed:false to warn only."
  } >&2
  bcl_failclosed_exit; exit $?
fi

# PYTHONIOENCODING=utf-8: rule messages come from the repo's rules file and routinely
# contain non-ASCII (an em-dash in examples/security-defaults.openclaw.json). Without
# it, Windows Python encodes stdout in the legacy code page and one em-dash arrives as
# the lone byte 0x97 — invalid UTF-8, which is exactly what made the old grep pipeline
# below declare this stream "binary" and drop the violation text.
REPO_ROOT="$(bcl_repo_root)"
py_rc=0
OUT="$(PYTHONIOENCODING=utf-8 "$PY" - "$RULES" "$REPO_ROOT" "${PATHS[@]}" <<'PY'
import json, os, re, sys
rules_path = sys.argv[1]
repo_root = sys.argv[2]
paths = sys.argv[3:]
try:
    with open(rules_path, encoding="utf-8") as fh:
        spec = json.load(fh)
except Exception as exc:
    print(f"__ERROR__ cannot read rules file: {exc}")
    raise SystemExit(0)

infra = spec.get("infraPattern")
skip = spec.get("skipPathPattern")
rules = spec.get("rules") or []
if not rules:
    print("__EMPTY__ rules file parses but defines no rules")
    raise SystemExit(0)
violations = []
unreadable = []
checked = 0

for raw in paths:
    # Resolve repo-relative paths against the repo root: enforcement must not be
    # silently skipped just because the hook's working directory differs from it.
    path = raw if os.path.isabs(raw) else os.path.join(repo_root, raw)
    norm = path.replace("\\", "/")
    if skip and re.search(skip, norm):
        continue
    if infra and not re.search(infra, norm):
        continue
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except Exception:
        # In policy scope but unreadable -> surface it (a silent skip is a
        # fail-open bypass of the security check).
        unreadable.append(path)
        continue
    checked += 1
    for rule in rules:
        when = rule.get("appliesWhen")
        if when and not re.search(when, content, re.MULTILINE):
            continue
        msg = rule.get("message") or rule.get("id") or "policy violation"
        if "mustMatch" in rule and not re.search(rule["mustMatch"], content, re.MULTILINE):
            violations.append(f"{msg} (in {path})")
        if "mustNotMatch" in rule and re.search(rule["mustNotMatch"], content, re.MULTILINE):
            violations.append(f"{msg} (in {path})")

for v in violations:
    print(v)
for u in unreadable:
    print("__WARN__ infra file in policy scope could not be read: " + u)
# How many in-scope files were actually READ. The summary line must not be able to
# claim "defaults intact" when the honest answer is "nothing was examined".
print("__COUNT__ %d" % checked)
PY
)" || py_rc=$?

OUT="${OUT//$'\r'/}"   # Windows Python print() emits CRLF; strip CR before parsing.

# A non-zero Python exit (an unhandled engine error) means verification never
# finished — that is a degraded control, not a pass.
if [[ $py_rc -ne 0 ]]; then
  echo "[security-defaults] CONTROL COULD NOT RUN — rules engine errored (rc=$py_rc); infra files were NOT verified." >&2
  bcl_failclosed_exit; exit $?
fi

# Classify the engine output with bash string ops ONLY — never pipe it through grep.
# Rule messages are repo-supplied and routinely non-ASCII; grep then declares the
# stream "binary", drops the matching line, and on GNU grep >= 3.5 sends its notice to
# stderr instead of stdout. Reproduced both ways: Git Bash grep 3.0 exited 2 with the
# rule text annihilated, and WSL grep 3.11 exited 0 — a real regression rendering as
# "all immutable security defaults intact". modules/config-guard.sh documents the same
# hazard ("filter with bash string ops, never grep"); this applies that precedent here.
VIOLATIONS=""; UNREADABLE=""; ERROR_MSG=""; EMPTY_MSG=""; CHECKED=0
while IFS= read -r line; do
  [[ -z "${line//[[:space:]]/}" ]] && continue
  case "$line" in
    __ERROR__*) ERROR_MSG="${line#__ERROR__ }" ;;
    __EMPTY__*) EMPTY_MSG="${line#__EMPTY__ }" ;;
    __COUNT__*) CHECKED="${line#__COUNT__ }" ;;
    __WARN__*)  UNREADABLE+="${line#__WARN__ }"$'\n' ;;
    *)          VIOLATIONS+="$line"$'\n' ;;
  esac
done <<< "$OUT"
[[ "$CHECKED" =~ ^[0-9]+$ ]] || CHECKED=0

if [[ -n "$ERROR_MSG" ]]; then
  {
    echo "[security-defaults] CONTROL COULD NOT RUN — $ERROR_MSG"
    echo "   The rules file is unreadable/invalid JSON; infra files were NOT verified."
    echo "   Fix it (regex backslashes must be doubled in JSON), or set failClosed:false to warn only."
  } >&2
  bcl_failclosed_exit; exit $?
fi

if [[ -n "$EMPTY_MSG" ]]; then
  {
    echo "[security-defaults] CONTROL COULD NOT RUN — $EMPTY_MSG"
    echo "   The policy verifies nothing (empty rules) — possible neutered/substituted rules file."
  } >&2
  bcl_failclosed_exit; exit $?
fi

# Surface in-scope-but-unreadable files as visible warnings (never a silent skip).
if [[ -n "$UNREADABLE" ]]; then
  while IFS= read -r w; do
    [[ -n "${w//[[:space:]]/}" ]] && echo "[security-defaults] $w" >&2
  done <<< "$UNREADABLE"
fi

if [[ -n "$VIOLATIONS" ]]; then
  {
    echo ""
    echo "[security-defaults] REGRESSION BLOCKER — immutable security defaults violated:"
    while IFS= read -r v; do [[ -n "${v//[[:space:]]/}" ]] && echo "   ❌ $v"; done <<< "$VIOLATIONS"
    echo ""
    echo "   These defaults are immutable. Fix before proceeding."
    echo "   Policy source: $RULES"
  } >&2
  bcl_violation_exit; exit $?
fi

# An unreadable in-scope file is a control that could not run ON THAT FILE. Warning
# about it and then exiting 0 was a contradiction with teeth: exit 0 means stderr never
# reaches the model, so the warning was invisible AND the summary below announced the
# defaults were intact. Route it through the fail-closed exit instead.
if [[ -n "$UNREADABLE" ]]; then
  {
    echo "[security-defaults] CONTROL COULD NOT RUN — in-scope infra file(s) could not be read (listed above);"
    echo "   those files were NOT verified. Fix their permissions/encoding, exclude them via skipPathPattern,"
    echo "   or set failClosed:false to warn only."
  } >&2
  bcl_failclosed_exit; exit $?
fi

# Report what was actually examined. "Intact" after reading zero files is a false
# all-clear, and the commonest cause is an infraPattern that matches nothing.
if [[ "$CHECKED" -eq 0 ]]; then
  echo "[security-defaults] no changed file matched infraPattern — nothing was checked."
else
  echo "[security-defaults] $CHECKED changed infra file(s) checked — all immutable security defaults intact."
fi
exit 0
