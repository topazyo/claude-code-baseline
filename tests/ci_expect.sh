# claude-code-baseline :: tests/ci_expect.sh
#
# Sourced by the integration suites (test_hooks.sh, test_status.sh, test_policy_gate.sh,
# test_latency.sh). Two helpers:
#
#   skip ID REASON...    print "  SKIP [ID: REASON]", count it, and record ID.
#   ci_expect SUITE N    on a CI leg, check the skips and the pass count; returns 1 after
#                        printing a FAIL line when they are not what that leg expects.
#
# Why: a case that skips is not a case that passed, and a skip on CI used to be visible
# only to someone reading the log. Each leg's runner is a fixed environment, so on CI the
# set of cases that may skip is known exactly; a skip outside it (a runner image change, a
# setup step that broke, a case that started skipping on one OS) fails the run instead
# of shrinking the coverage without a word. The pass floor catches the other direction: a
# block of cases that stopped running altogether, or many cases behind one skip ID.
#
# BCL_CI_LEG names the leg (the workflow sets it). With it unset nothing is enforced, so
# local runs on hosts with other capabilities (8.3 names, symbolic-link rights, an older
# git) are not judged by a runner's table. On GitHub Actions an unset BCL_CI_LEG is itself
# a failure: a job that forgot it would otherwise pass with every check here switched off.
#
# Updating a row: take the counts from the CI log of the change that alters them (the
# "floor stale by N" note says by how much), and add a skip ID to a leg only with the
# reason it cannot run there. On the python-floor legs a skip caused by the old Python is
# exactly what those legs exist to catch, so it is a bug to fix, not a row to add.

skipped=0
skip_ids=""

skip() {
  local id="$1"
  shift
  skipped=$((skipped + 1))
  skip_ids="$skip_ids $id"
  echo "  SKIP [$id: $*]"
}

ci_expect() {
  local suite="$1" passed="$2" leg="${BCL_CI_LEG:-}" allowed floor id rc=0
  if [ -z "$leg" ]; then
    if [ "${GITHUB_ACTIONS:-}" = true ]; then
      echo "  FAIL [$suite: running on GitHub Actions without BCL_CI_LEG, so the per-leg skip and pass-count checks would be off]"
      return 1
    fi
    return 0
  fi
  case "$leg:$suite" in
    ubuntu-latest:test_hooks)        allowed="";  floor=671 ;;
    ubuntu-latest:test_status)       allowed="";  floor=73 ;;
    ubuntu-latest:test_policy_gate)  allowed="";  floor=53 ;;
    ubuntu-latest:test_latency)      allowed="";  floor=5 ;;
    windows-latest:test_hooks)       allowed="newline-name venv-pth-elsewhere no-link dotdot-lexical unix-modes"; floor=684 ;;
    windows-latest:test_status)      allowed="symlinked-skill"; floor=72 ;;
    windows-latest:test_policy_gate) allowed="newline-name invalid-utf8-name"; floor=51 ;;
    windows-latest:test_latency)     allowed="";  floor=5 ;;
    python-floor-ubuntu-22.04:test_hooks)       allowed="";  floor=671 ;;
    python-floor-ubuntu-22.04:test_status)      allowed="";  floor=73 ;;
    python-floor-ubuntu-22.04:test_policy_gate) allowed="";  floor=53 ;;
    python-floor-ubuntu-22.04:test_latency)     allowed="";  floor=5 ;;
    python-floor-windows-latest:test_hooks)       allowed="newline-name venv-pth-elsewhere no-link dotdot-lexical unix-modes"; floor=684 ;;
    python-floor-windows-latest:test_status)      allowed="symlinked-skill"; floor=72 ;;
    python-floor-windows-latest:test_policy_gate) allowed="newline-name invalid-utf8-name"; floor=51 ;;
    python-floor-windows-latest:test_latency)     allowed="";  floor=5 ;;
    # Not a runner: fixed values for test_status.sh's checks of this function.
    selftest:test_status)            allowed="fifo symlinked-skill"; floor=10 ;;
    *)
      echo "  FAIL [$suite: no CI expectations for leg '$leg': add its row to tests/ci_expect.sh]"
      return 1 ;;
  esac
  # A count that is not a number would make both comparisons below false, not fail.
  case "$passed" in
    ''|*[!0-9]*) echo "  FAIL [$suite: pass count '$passed' is not a number]"; return 1 ;;
  esac
  for id in $skip_ids; do
    case " $allowed " in
      *" $id "*) ;;
      *) echo "  FAIL [$suite: skip '$id' is not expected on the $leg leg]"; rc=1 ;;
    esac
  done
  if [ "$passed" -lt "$floor" ]; then
    echo "  FAIL [$suite: $passed passed on the $leg leg, below its floor of $floor]"
    rc=1
  elif [ "$passed" -gt "$floor" ]; then
    echo "   note: $suite floor stale by $((passed - floor)) on the $leg leg (raise it to $passed in tests/ci_expect.sh)"
  fi
  return $rc
}
