#!/usr/bin/env bash
# Structure smoke test for the stride-gemini-security-review extension.
#
# Confirms the extension's required files and directories exist and that the
# gemini-extension.json manifest is valid JSON carrying name/version/
# contextFileName. Offline and read-only — it never executes or evaluates any
# extension file; it only checks for existence and parses the manifest as data.
#
# The manifest is gemini-extension.json at the ROOT (Gemini CLI convention).
# This test deliberately does NOT look for a .claude-plugin/plugin.json or a
# package.json — the Gemini extension has neither.
#
# Exit code: 0 if every check passes; 1 if any check fails.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PASS=0
FAIL=0

ok()   { PASS=$(( PASS + 1 )); printf '  ✓  %s\n' "$1"; }
nope() { FAIL=$(( FAIL + 1 )); printf '  ✗  %s\n     %s\n' "$1" "${2:-}"; }

# exists <relative-path> <label>
exists() {
  if [ -e "${PLUGIN_ROOT}/$1" ]; then
    ok "$2 exists ($1)"
  else
    nope "$2 missing" "$1"
  fi
}

printf 'stride-gemini-security-review structure test\n'
printf 'plugin root: %s\n\n' "$PLUGIN_ROOT"

# --- Manifest ---------------------------------------------------------------

printf 'Manifest\n'
MANIFEST="${PLUGIN_ROOT}/gemini-extension.json"
if [ ! -f "$MANIFEST" ]; then
  nope "gemini-extension.json missing at the root" "$MANIFEST"
else
  if MANIFEST_ERR="$(python3 - "$MANIFEST" <<'PY' 2>&1
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except Exception as e:  # noqa: BLE001 - report any parse error as a failure
    print(f"invalid JSON: {e}")
    sys.exit(1)
missing = [k for k in ("name", "version", "contextFileName") if k not in data]
if missing:
    print("missing keys: " + ", ".join(missing))
    sys.exit(1)
PY
  )"; then
    ok "gemini-extension.json is valid JSON with name/version/contextFileName"
  else
    nope "gemini-extension.json invalid" "$MANIFEST_ERR"
  fi
fi

# Guard: the Gemini extension must NOT rely on Claude Code / npm manifests.
if [ -f "${PLUGIN_ROOT}/.claude-plugin/plugin.json" ]; then
  nope "unexpected .claude-plugin/plugin.json present" "the Gemini extension is declared by gemini-extension.json only"
else
  ok "no .claude-plugin/plugin.json (correct for a Gemini extension)"
fi
if [ -f "${PLUGIN_ROOT}/package.json" ]; then
  nope "unexpected package.json present" "the Gemini extension does not use npm"
else
  ok "no package.json (correct for a Gemini extension)"
fi

# --- Skills -----------------------------------------------------------------

printf '\nSkills\n'
for skill in security-review-essentials; do
  exists "skills/${skill}/SKILL.md" "skill '${skill}' SKILL.md"
done

# --- Agents -----------------------------------------------------------------

printf '\nAgents\n'
for agent in security-reviewer; do
  exists "agents/${agent}.md" "agent '${agent}'"
done

# --- Commands ---------------------------------------------------------------

printf '\nCommands\n'
for cmd in security-review; do
  exists "commands/${cmd}.toml" "command /${cmd}"
done

# --- lib tooling ------------------------------------------------------------

printf '\nlib tooling\n'
for tool in sarif_transform.sh run_eval.sh run_transform_tests.sh check_fixtures.sh; do
  exists "lib/${tool}" "lib helper ${tool}"
done

# --- Fixtures & golden ------------------------------------------------------

printf '\nFixtures\n'
exists "fixtures/EXPECTED.md" "fixtures EXPECTED.md"
for g in input_findings.json fingerprint.golden dedup.golden.json sarif.golden.json; do
  exists "fixtures/golden/${g}" "golden ${g}"
done

# Considerations-mode controls: a positive control (unmitigated verdict + backing
# finding) and a negative control (all mitigated, no spurious finding), each a
# .diff paired with a .considerations sidecar.
printf '\nConsiderations controls\n'
for c in token_logging_unmitigated parameterized_query_all_mitigated; do
  exists "fixtures/considerations/${c}.diff" "considerations control ${c}.diff"
  exists "fixtures/considerations/${c}.considerations" "considerations control ${c}.considerations"
done

# --- Install scripts --------------------------------------------------------

printf '\nInstall scripts\n'
for inst in install.sh install.ps1; do
  exists "$inst" "$inst"
done

# --- Root docs & license ----------------------------------------------------

printf '\nRoot docs\n'
for doc in GEMINI.md README.md CHANGELOG.md LICENSE; do
  exists "$doc" "$doc"
done

# --- Summary ----------------------------------------------------------------

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
