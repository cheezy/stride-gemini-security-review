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
for tool in sarif_transform.sh run_eval.sh run_transform_tests.sh check_fixtures.sh check_eval_invocation.sh; do
  exists "lib/${tool}" "lib helper ${tool}"
done

# --- Fixtures & golden ------------------------------------------------------

printf '\nFixtures\n'
exists "fixtures/EXPECTED.md" "fixtures EXPECTED.md"
for g in input_findings.json fingerprint.golden dedup.golden.json sarif.golden.json; do
  exists "fixtures/golden/${g}" "golden ${g}"
done

# Considerations-mode fixtures: each is a .diff paired with a .considerations
# sidecar. The stems are read from disk rather than listed here, so a new pair
# needs no edit to this file; check_fixtures.sh owns the pairing, row and
# verdict-count rules. This only requires that the directory holds at least one
# .diff and that every .diff found has its sidecar.
printf '\nConsiderations fixtures\n'
cons_found=0
for d in "${PLUGIN_ROOT}"/fixtures/considerations/*.diff; do
  [ -e "$d" ] || continue
  cons_found=$(( cons_found + 1 ))
  c="$(basename "$d" .diff)"
  exists "fixtures/considerations/${c}.diff" "considerations fixture ${c}.diff"
  exists "fixtures/considerations/${c}.considerations" "considerations input ${c}.considerations"
done
if [ "$cons_found" -gt 0 ]; then
  ok "fixtures/considerations/ holds ${cons_found} .diff fixture(s)"
else
  nope "no considerations fixtures found" "fixtures/considerations/*.diff"
fi

# --- Install scripts --------------------------------------------------------

printf '\nInstall scripts\n'
for inst in install.sh install.ps1; do
  exists "$inst" "$inst"
done

# --- Policies (W2488) ---------------------------------------------------------
# The security-reviewer subagent's Policy Engine deny rules, and both installers
# copying the directory (lib/check_agent_contract.sh checks the rules).

printf '\nPolicies\n'
exists "policies/security-reviewer.toml" "policy security-reviewer.toml"
if grep -qE '^for dir in .* policies(;| )' "${PLUGIN_ROOT}/install.sh"; then
  ok "install.sh copies policies/"
else
  nope "install.sh does not copy policies/" "install.sh: for dir in ... policies"
fi
if grep -qE "^ *foreach \(\\\$dir in @\(.*'policies'" "${PLUGIN_ROOT}/install.ps1"; then
  ok "install.ps1 copies policies/"
else
  nope "install.ps1 does not copy policies/" "install.ps1: foreach (\$dir in @(... 'policies'))"
fi

# --- Packs and modes (W2482) --------------------------------------------------
# The rule packs and mode files the agent reads on demand, at the extension
# root (a .md under agents/ would register as an agent), and both installers
# copying them (lib/check_agent_contract.sh checks their content).

printf '\nPacks and modes\n'
for p in android django express ios phoenix rails react-nextjs web-defense supply-chain ci-cd agentic; do
  exists "packs/${p}.md" "rule pack ${p}"
done
for m in considerations result-file reproduction; do
  exists "modes/${m}.md" "mode file ${m}"
done
for d in packs modes; do
  if grep -qE "^for dir in .* ${d}(;| )" "${PLUGIN_ROOT}/install.sh"; then
    ok "install.sh copies ${d}/"
  else
    nope "install.sh does not copy ${d}/" "install.sh: for dir in ... ${d}"
  fi
  if grep -qE "^ *foreach \(\\\$dir in @\(.*'${d}'" "${PLUGIN_ROOT}/install.ps1"; then
    ok "install.ps1 copies ${d}/"
  else
    nope "install.ps1 does not copy ${d}/" "install.ps1: foreach (\$dir in @(... '${d}'))"
  fi
done
agents_md="$(cd "${PLUGIN_ROOT}/agents" && find . -name '*.md' | sort | tr '\n' ' ')"
if [ "$agents_md" = "./security-reviewer.md " ]; then
  ok "agents/ holds only security-reviewer.md"
else
  nope "agents/ holds other .md files" "$agents_md"
fi

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
