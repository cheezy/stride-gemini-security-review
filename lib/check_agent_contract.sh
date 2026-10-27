#!/usr/bin/env bash
# Contract pins on agents/security-reviewer.md for the Gemini CLI port.
#
# Modelled on upstream cheezy/stride-security-review scripts/check_agent_contract.sh:
# one section per item, headed by the task that added it, each pin printing
# `ok: <label>` or `FAIL: <label> -- <why>`. Every later port task adds its own
# section here. Unlike upstream, each pin also carries a break-it in the
# self-test section at the bottom, which plants the broken shape in a temporary
# copy of the agent and checks that this script fails on it.
#
# W2480 -- the template-token pin. Gemini CLI runs templateString() over a
# subagent's system prompt (the agent body) and throws "Template validation
# failed: Missing required input parameters: ..." for any ${word} placeholder
# that is not one of its inputs (@google/gemini-cli-core 0.65.0,
# dist/src/agents/utils.js and local-executor.js). The pin uses the CLI's own
# placeholder regex, /\$\{(\w+)\}/g, where \w is ASCII [A-Za-z0-9_], so it
# catches exactly what the CLI would try to fill. It scans the whole file,
# frontmatter included. A token the CLI does supply (cliVersion, activeModel,
# today, or ${extensionPath} once the W2285 port adds it) is still refused
# here: a task that needs one must allow it deliberately.
#
# lib/check_agent_contract.ps1 is the PowerShell mirror: same labels, same
# exit codes. Change both together.
#
# Offline. Reads the agent; the self-tests write only to a temporary directory.
#
# Usage:  bash lib/check_agent_contract.sh [agent-file]
#         (default: agents/security-reviewer.md beside this script's lib/)
# Exit code: 0 when every pin and self-test holds; 1 when any fails, or when
#            the agent file is missing or empty.
set -uo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SELF="$SCRIPT_DIR/$(basename "$0")"
AGENT="${1:-$SCRIPT_DIR/../agents/security-reviewer.md}"
fail=0

[ -f "$AGENT" ] || { echo "FAIL: agent file not found: $AGENT"; exit 1; }
[ -s "$AGENT" ] || { echo "FAIL: agent file is empty: $AGENT"; exit 1; }
[ -r "$AGENT" ] || { echo "FAIL: agent file is not readable: $AGENT"; exit 1; }

# --- W2480: no Gemini CLI template token -------------------------------------

TEMPLATE_TOKEN_RE='\$\{[A-Za-z0-9_]+\}'

# template_tokens <file> -- print `line:token` for every ${word} placeholder.
template_tokens() {
  grep -noE -- "$TEMPLATE_TOKEN_RE" "$1"
}

# grep exits 1 for no match and 2 for an error; an error must never read as a pass.
tokens="$(template_tokens "$AGENT")"; rc=$?
if [ "$rc" -gt 1 ]; then
  echo "FAIL: no Gemini CLI template token in the agent -- grep could not read the agent (exit $rc)"
  fail=1
elif [ -z "$tokens" ]; then
  echo "ok: no Gemini CLI template token in the agent"
else
  echo "FAIL: no Gemini CLI template token in the agent -- found: $(printf '%s' "$tokens" | tr '\n' ' ')"
  fail=1
fi

# --- Self-tests: a break-it per pin ------------------------------------------
# Each case writes a variant of the agent to a temporary directory and runs this
# script on it as a child. CHECK_AGENT_CONTRACT_CHILD stops the child running the
# self-tests again. Skipped when a custom agent path is given, so a run against a
# copy reports on that copy alone.

if [ -z "${CHECK_AGENT_CONTRACT_CHILD:-}" ] && [ "$#" -eq 0 ]; then
  TMP="$(mktemp -d "${TMPDIR:-/tmp}/check-agent-contract.XXXXXX")" || {
    echo "FAIL: self-tests could not create a temporary directory"; exit 1; }
  trap 'rm -rf "$TMP"' EXIT

  # expect <label> <want-exit> <needle-or-empty> <file>
  expect() {
    local out rc
    out="$(CHECK_AGENT_CONTRACT_CHILD=1 bash "$SELF" "$4" 2>&1)"; rc=$?
    if [ "$rc" -ne "$2" ]; then
      echo "FAIL: self-test: $1 -- exit $rc, wanted $2"; fail=1
    elif [ -n "$3" ] && ! printf '%s\n' "$out" | grep -qF -- "$3"; then
      echo "FAIL: self-test: $1 -- output lacks: $3"; fail=1
    else
      echo "ok: self-test: $1"
    fi
  }

  base="$TMP/agent.md"
  cp "$AGENT" "$base"
  expect "the shipped agent passes the template-token pin" 0 "ok: no Gemini CLI template token" "$base"

  { cat "$base"; printf '%s\n' 'Planted: <a href={`/redirect?to=${url}`}>'; } > "$TMP/planted-body.md"
  expect "a planted \${url} in the body fails the pin" 1 'found: ' "$TMP/planted-body.md"

  awk 'NR == 3 { print; print "  Planted ${id} in the description."; next } { print }' "$base" > "$TMP/planted-fm.md"
  expect "a \${word} token in the frontmatter description fails the pin" 1 'found: 4:${id}' "$TMP/planted-fm.md"

  { cat "$base"; printf '%s\n' 'Digit key: ${1}'; } > "$TMP/planted-digit.md"
  expect "a digit-only \${1} (the CLI's \\w) fails the pin" 1 'found: ' "$TMP/planted-digit.md"

  { cat "$base"; printf '%s\n' 'Escaped: \${url}'; } > "$TMP/planted-escaped.md"
  expect "a backslash-escaped \\\${url} still fails the pin" 1 'found: ' "$TMP/planted-escaped.md"

  {
    cat "$base"
    printf '%s\n' 'Price: $5, a bare $ and $$ and $VAR and $(cmd)'
    printf '%s\n' 'Open brace with no word: ${ and ${} and ${ url } and ${-x}'
    printf '%s\n' 'Dotted and doubled: ${req.body.path} and ${{ github.event.issue.title }}'
  } > "$TMP/dollars.md"
  expect "a bare \$, \$\$ or \${ with no word does not trip the pin" 0 "ok: no Gemini CLI template token" "$TMP/dollars.md"

  awk '{ printf "%s\r\n", $0 }' "$base" > "$TMP/crlf.md"
  expect "the agent with CRLF line endings passes the pin" 0 "ok: no Gemini CLI template token" "$TMP/crlf.md"

  awk '{ printf "%s\r\n", $0 }' "$TMP/planted-body.md" > "$TMP/crlf-planted.md"
  expect "a planted \${url} under CRLF line endings fails the pin" 1 'found: ' "$TMP/crlf-planted.md"

  expect "a missing agent file exits non-zero with a message" 1 "FAIL: agent file not found" "$TMP/missing.md"

  : > "$TMP/empty.md"
  expect "an empty agent file exits non-zero with a message" 1 "FAIL: agent file is empty" "$TMP/empty.md"

  cp "$base" "$TMP/unreadable.md"; chmod 000 "$TMP/unreadable.md"
  if [ -r "$TMP/unreadable.md" ]; then
    echo "ok: self-test: an unreadable agent file exits non-zero with a message -- skipped (permissions not enforced for this user)"
  else
    expect "an unreadable agent file exits non-zero with a message" 1 "FAIL: agent file is not readable" "$TMP/unreadable.md"
  fi
  chmod 600 "$TMP/unreadable.md"
fi

if [ "$fail" -ne 0 ]; then
  echo "agent contract: FAILED"
  exit 1
fi
echo "agent contract: all pins present"
