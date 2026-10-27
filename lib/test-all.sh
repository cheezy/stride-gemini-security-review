#!/usr/bin/env bash
# Top-level smoke-test runner for the stride-gemini-security-review extension.
#
# Runs the structure check, the frontmatter check and the agent contract check
# (check_agent_contract.sh) in sequence and exits non-zero if any fails.
# Offline and read-only (the contract check's self-tests write only to a
# temporary directory) — suitable for gating a release.
#
# The deterministic transform golden tests (run_transform_tests.sh), the
# fixture/EXPECTED.md parity guard (check_fixtures.sh), and the agent eval
# runner (run_eval.sh) are separate entry points — see their headers. This
# runner is the fast structure + frontmatter + agent contract gate.
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

printf '\n=== result ===\n'
if [ "$FAILED" -eq 0 ]; then
  printf 'ALL CHECKS PASSED\n'
  exit 0
else
  printf 'ONE OR MORE CHECKS FAILED\n'
  exit 1
fi
