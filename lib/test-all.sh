#!/usr/bin/env bash
# Top-level smoke-test runner for the stride-gemini-security-review extension.
#
# Runs the structure check and the frontmatter check in sequence and exits
# non-zero if either fails. Offline and read-only — suitable for gating a
# release.
#
# The deterministic transform golden tests (run_transform_tests.sh), the
# fixture/EXPECTED.md parity guard (check_fixtures.sh), and the agent eval
# runner (run_eval.sh) are separate entry points — see their headers. This
# runner is the fast structure + frontmatter gate.
#
# Usage:
#   ./lib/test-all.sh
#
# Exit code: 0 only if BOTH checks pass; 1 if either fails.

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

printf '\n=== result ===\n'
if [ "$FAILED" -eq 0 ]; then
  printf 'ALL CHECKS PASSED\n'
  exit 0
else
  printf 'ONE OR MORE CHECKS FAILED\n'
  exit 1
fi
