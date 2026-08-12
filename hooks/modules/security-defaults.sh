#!/usr/bin/env bash
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

REPO_ROOT="$(bcl_repo_root)"
OUT="$("$PY" - "$RULES" "$REPO_ROOT" "${PATHS[@]}" <<'PY'
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
PY
)"

if printf '%s' "$OUT" | grep -q '^__ERROR__'; then
  {
    echo "[security-defaults] CONTROL COULD NOT RUN — ${OUT#__ERROR__ }"
    echo "   The rules file is unreadable/invalid JSON; infra files were NOT verified."
    echo "   Fix it (regex backslashes must be doubled in JSON), or set failClosed:false to warn only."
  } >&2
  bcl_failclosed_exit; exit $?
fi

if printf '%s' "$OUT" | grep -q '^__EMPTY__'; then
  {
    echo "[security-defaults] CONTROL COULD NOT RUN — ${OUT#__EMPTY__ }"
    echo "   The policy verifies nothing (empty rules) — possible neutered/substituted rules file."
  } >&2
  bcl_failclosed_exit; exit $?
fi

# Surface in-scope-but-unreadable files as visible warnings (never a silent skip).
WARNINGS="$(printf '%s\n' "$OUT" | grep '^__WARN__' || true)"
if [[ -n "$WARNINGS" ]]; then
  while IFS= read -r w; do
    [[ -n "$w" ]] && echo "[security-defaults] ${w#__WARN__ }" >&2
  done <<< "$WARNINGS"
fi

VIOLATIONS="$(printf '%s\n' "$OUT" | grep -Ev '^(__WARN__|__ERROR__)' | grep -v '^[[:space:]]*$' || true)"
if [[ -n "$VIOLATIONS" ]]; then
  {
    echo ""
    echo "[security-defaults] REGRESSION BLOCKER — immutable security defaults violated:"
    while IFS= read -r v; do [[ -n "$v" ]] && echo "   ❌ $v"; done <<< "$VIOLATIONS"
    echo ""
    echo "   These defaults are immutable. Fix before proceeding."
    echo "   Policy source: $RULES"
  } >&2
  bcl_violation_exit; exit $?
fi

echo "[security-defaults] changed infra files — all immutable security defaults intact."
exit 0
