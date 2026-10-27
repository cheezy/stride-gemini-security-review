#!/usr/bin/env bash
# Top-level smoke-test runner for the stride-gemini-security-review extension.
#
# Runs the structure check, the frontmatter check, the agent contract check
# (check_agent_contract.sh) and the eval invocation check
# (check_eval_invocation.sh) in sequence, then the offline policy pattern
# check (check_policy_patterns.mjs) when node is on PATH (reported as
# skipped, not passed, without it), and exits non-zero if any fails.
# Offline and read-only (the self-tests write only to temporary directories) —
# suitable for gating a release. The eval invocation check pins how
# run_eval.sh would dispatch the agent, against a fake gemini on a temporary
# PATH, and exercises check_fixtures.sh's considerations guards on a scratch
# copy of the tree; it needs no model, no credentials and no network.
#
# The deterministic transform golden tests (run_transform_tests.sh), the
# fixture/EXPECTED.md parity guard (check_fixtures.sh), and the agent eval
# runner itself (run_eval.sh, which needs a real Gemini CLI and auth) are
# separate entry points — see their headers.
#
# Usage:
#   ./lib/test-all.sh
#
# Exit code: 0 only if ALL checks pass; 1 if any fails.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

FAILED=0

printf '=== structure ===\n'
if bash "${SCRIPT_DIR}/test-structure.sh"; then
  :
else
  FAILED=1
fi

printf '\n=== frontmatter ===\n'
if bash "${SCRIPT_DIR}/test-frontmatter.sh"; then
  :
else
  FAILED=1
fi

printf '\n=== agent contract ===\n'
if bash "${SCRIPT_DIR}/check_agent_contract.sh"; then
  :
else
  FAILED=1
fi

printf '\n=== eval invocation (fake CLI) ===\n'
if bash "${SCRIPT_DIR}/check_eval_invocation.sh"; then
  :
else
  FAILED=1
fi

printf '\n=== policy patterns (offline, node) ===\n'
if command -v node >/dev/null 2>&1; then
  if node "${SCRIPT_DIR}/check_policy_patterns.mjs"; then
    :
  else
    FAILED=1
  fi
else
  printf 'skipped: check_policy_patterns.mjs needs node on PATH\n'
fi

printf '\n=== result ===\n'
if [ "$FAILED" -eq 0 ]; then
  printf 'ALL CHECKS PASSED\n'
  exit 0
else
  printf 'ONE OR MORE CHECKS FAILED\n'
  exit 1
fi
