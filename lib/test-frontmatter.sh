#!/usr/bin/env bash
# Frontmatter / command-key smoke test for the stride-gemini-security-review
# extension.
#
# Confirms:
#   - every agents/*.md has `name:` and `description:` YAML frontmatter,
#     handling the block-scalar `description: |` form;
#   - the agent's frontmatter uses only the keys Gemini CLI's strict agent
#     schema accepts (W2484): kind, name, description, display_name, tools,
#     mcp_servers, model, temperature, max_turns and timeout_mins
#     (@google/gemini-cli-core 0.65.0, dist/src/agents/agentLoader.js:68-87).
#     Any other key makes Gemini CLI refuse to load the agent, so a key copied
#     from a Claude Code agent (`color:`, say) fails here first. `model` is
#     allowed but not required: this port inherits the session model;
#   - every description, the agent's and the skill's, is non-empty (W2484):
#     an inline value, a quoted value or a `|` / `>` block with at least one
#     non-blank character;
#   - every commands/*.toml has a `description` key AND a `prompt` key (TOML,
#     not YAML).
#
# Offline and read-only. It extracts the YAML frontmatter block between the
# first two `---` fences and greps for keys at the start of a line; it never
# evaluates or sources any file, so a malicious prompt body cannot execute.
#
# Self-tests (W2484): run with no arguments, it then writes broken copies of
# the agent and the skill to a temporary directory and runs itself on each as
# a child, which must fail: an unknown agent key and an empty description,
# inline, quoted or block. lib/test-frontmatter.ps1 is the PowerShell mirror.
#
# Usage:  bash lib/test-frontmatter.sh [--agent <file>] [--skill <file>]
#         (a child run checks only the files it is given)
# Exit code: 0 if every check passes; 1 if any check fails.

set -u
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SELF="${SCRIPT_DIR}/$(basename "${BASH_SOURCE[0]}")"

PASS=0
FAIL=0

ok()   { PASS=$(( PASS + 1 )); printf '  ✓  %s\n' "$1"; }
nope() { FAIL=$(( FAIL + 1 )); printf '  ✗  %s\n     %s\n' "$1" "${2:-}"; }

# Gemini CLI's agent frontmatter keys (agentLoader.js:68-87).
GEMINI_AGENT_KEYS="kind name description display_name tools mcp_servers model temperature max_turns timeout_mins"

# frontmatter <file> — print the lines between the first two `---` fences,
# CR stripped.
frontmatter() {
  tr -d '\r' < "$1" | awk '
    NR == 1 && /^---[[:space:]]*$/ { infm = 1; next }
    infm && /^---[[:space:]]*$/    { exit }
    infm                          { print }
  '
}

# has_key <text> <key> — true if a line starts with `<key>:` (YAML).
has_key() {
  printf '%s\n' "$1" | grep -qE "^${2}:"
}

# top_keys <text> — every top-level key, one per line: a line that starts
# with a key character and holds a colon. Indented lines (a block scalar's
# text, a list item under `tools:`) are not keys.
top_keys() {
  printf '%s\n' "$1" | awk '/^[^[:space:]#-][^:]*:/ { k = $0; sub(/:.*/, "", k); print k }'
}

# description_text <text> — the description's value: an inline value with
# one pair of surrounding quotes removed, or the lines of a `|` / `>` block.
description_text() {
  printf '%s\n' "$1" | awk '
    !b && /^description:[[:space:]]*[|>][-+0-9]*[[:space:]]*$/ { b = 1; next }
    b && (/^[[:space:]]/ || /^$/) { print; next }
    b { exit }
    /^description:/ {
      v = $0; sub(/^description:[[:space:]]*/, "", v); sub(/[[:space:]]+$/, "", v)
      if (v ~ /^".*"$/ || v ~ /^'"'"'.*'"'"'$/) v = substr(v, 2, length(v) - 2)
      print v; exit }'
}

# check_md_frontmatter <file> <label> <kind: agent|skill>
check_md_frontmatter() {
  local file="$1" label="$2" kind="$3" fm unknown k
  if [ ! -f "$file" ]; then
    nope "$label missing" "$file"
    return
  fi
  fm="$(frontmatter "$file")"
  if [ -z "$fm" ]; then
    nope "$label has no YAML frontmatter block" "$file"
    return
  fi
  if has_key "$fm" name; then
    ok "$label has name:"
  else
    nope "$label missing name:" "$file"
  fi
  if has_key "$fm" description; then
    ok "$label has description: (inline or block-scalar)"
    if description_text "$fm" | grep -q '[^[:space:]]'; then
      ok "$label has a non-empty description"
    else
      nope "$label has an empty description" "$file"
    fi
  else
    nope "$label missing description:" "$file"
  fi
  if [ "$kind" = agent ]; then
    unknown=""
    for k in $(top_keys "$fm"); do
      case " $GEMINI_AGENT_KEYS " in
        *" $k "*) ;;
        *) unknown="$unknown $k" ;;
      esac
    done
    if [ -z "$unknown" ]; then
      ok "$label uses only Gemini CLI's agent frontmatter keys"
    else
      nope "$label has a frontmatter key Gemini CLI rejects:$unknown" "$file"
    fi
  fi
}

check_command() { # $1=command name
  local cmd="$1" file="${PLUGIN_ROOT}/commands/$1.toml"
  if [ ! -f "$file" ]; then
    nope "command /${cmd} missing" "$file"
    return
  fi
  if has_toml_key "$file" description; then
    ok "command /${cmd} has a description key"
  else
    nope "command /${cmd} missing a description key" "$file"
  fi
  if has_toml_key "$file" prompt; then
    ok "command /${cmd} has a prompt key"
  else
    nope "command /${cmd} missing a prompt key" "$file"
  fi
}

# has_toml_key <file> <key> — true if a line starts with `<key>` (TOML `key =`).
has_toml_key() {
  grep -qE "^${2}([[:space:]]|=)" "$1"
}

# --- Arguments ----------------------------------------------------------------

AGENT_ARG=""; SKILL_ARG=""; CHILD=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --agent) [ "$#" -ge 2 ] || { echo "usage: $0 [--agent <file>] [--skill <file>]"; exit 2; }
             AGENT_ARG="$2"; CHILD=1; shift 2 ;;
    --skill) [ "$#" -ge 2 ] || { echo "usage: $0 [--agent <file>] [--skill <file>]"; exit 2; }
             SKILL_ARG="$2"; CHILD=1; shift 2 ;;
    *) echo "usage: $0 [--agent <file>] [--skill <file>]"; exit 2 ;;
  esac
done

summary() {
  printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
  if [ "$FAIL" -gt 0 ]; then
    exit 1
  fi
  exit 0
}

if [ "$CHILD" = 1 ]; then
  [ -n "$SKILL_ARG" ] && check_md_frontmatter "$SKILL_ARG" "skill '$(basename "$SKILL_ARG")'" skill
  [ -n "$AGENT_ARG" ] && check_md_frontmatter "$AGENT_ARG" "agent '$(basename "$AGENT_ARG")'" agent
  summary
fi

printf 'stride-gemini-security-review frontmatter test\n'
printf 'plugin root: %s\n\n' "$PLUGIN_ROOT"

# --- Skills -----------------------------------------------------------------

printf 'Skill frontmatter\n'
for skill in security-review-essentials; do
  check_md_frontmatter "${PLUGIN_ROOT}/skills/${skill}/SKILL.md" "skill '${skill}'" skill
done

# --- Agents -----------------------------------------------------------------

printf '\nAgent frontmatter\n'
for agent in security-reviewer; do
  check_md_frontmatter "${PLUGIN_ROOT}/agents/${agent}.md" "agent '${agent}'" agent
done

# --- Commands ---------------------------------------------------------------

printf '\nCommand TOML keys\n'
for cmd in security-review; do
  check_command "$cmd"
done

# --- Self-tests (W2484) -------------------------------------------------------
# Each case writes a broken copy of the shipped agent or skill to a temporary
# directory and runs this script on it as a child; the child must fail with the
# named line. The shipped copies, and copies that only add keys Gemini CLI
# accepts, must pass.

printf '\nSelf-tests\n'
TMP="$(mktemp -d "${TMPDIR:-/tmp}/test-frontmatter.XXXXXX")" || {
  nope "self-tests could not create a temporary directory"; summary; }
trap 'rm -rf "$TMP"' EXIT
AGENT_BASE="$TMP/security-reviewer.md"; SKILL_BASE="$TMP/SKILL.md"
cp "${PLUGIN_ROOT}/agents/security-reviewer.md" "$AGENT_BASE"
cp "${PLUGIN_ROOT}/skills/security-review-essentials/SKILL.md" "$SKILL_BASE"

# self_test <label> <want-exit> <needle-or-empty> <args...>
self_test() {
  local label="$1" want="$2" needle="$3" out rc; shift 3
  out="$(bash "$SELF" "$@" 2>&1)"; rc=$?
  if [ "$rc" -ne "$want" ]; then
    nope "self-test: $label" "exit $rc, wanted $want"
  elif [ -n "$needle" ] && ! printf '%s\n' "$out" | grep -qF -- "$needle"; then
    nope "self-test: $label" "output lacks: $needle"
  else
    ok "self-test: $label"
  fi
}
# add_key <in> <out> <line> -- <line> added as the frontmatter's last line.
add_key() {
  L="$3" awk 'NR > 1 && !d && /^---[[:space:]]*$/ { print ENVIRON["L"]; d = 1 } { print }' "$1" > "$2"
}
# set_description <in> <out> <lines> -- the frontmatter's description key, and
# any block lines under it, replaced by <lines> (newline-separated).
set_description() {
  L="$3" awk '
    NR > 1 && /^---[[:space:]]*$/ { fm_done = 1 }
    !fm_done && /^description:/ { print ENVIRON["L"]; skip = 1; next }
    skip && /^[[:space:]]/ { next }
    { skip = 0; print }' "$1" > "$2"
}

self_test "the shipped agent passes" 0 "uses only Gemini CLI's agent frontmatter keys" --agent "$AGENT_BASE"
self_test "the shipped skill passes" 0 "has a non-empty description" --skill "$SKILL_BASE"

add_key "$AGENT_BASE" "$TMP/unknown-key.md" 'color: red'
self_test "an unknown agent frontmatter key fails the check" 1 "has a frontmatter key Gemini CLI rejects: color" --agent "$TMP/unknown-key.md"
add_key "$AGENT_BASE" "$TMP/claude-key.md" 'skills_version: 1.0'
self_test "a skill-only key in the agent frontmatter fails the check" 1 "has a frontmatter key Gemini CLI rejects: skills_version" --agent "$TMP/claude-key.md"
{ add_key "$AGENT_BASE" "$TMP/k1.md" 'kind: local'; add_key "$TMP/k1.md" "$TMP/gemini-keys.md" 'display_name: Security reviewer'; }
self_test "kind and display_name, both in Gemini CLI's schema, pass" 0 "uses only Gemini CLI's agent frontmatter keys" --agent "$TMP/gemini-keys.md"
awk '{ printf "%s\r\n", $0 }' "$AGENT_BASE" > "$TMP/crlf.md"
self_test "the agent with CRLF line endings passes" 0 "has a non-empty description" --agent "$TMP/crlf.md"

set_description "$AGENT_BASE" "$TMP/empty-inline.md" 'description:'
self_test "an empty description fails the check" 1 "has an empty description" --agent "$TMP/empty-inline.md"
set_description "$AGENT_BASE" "$TMP/empty-quoted.md" 'description: ""'
self_test "an empty quoted description fails the check" 1 "has an empty description" --agent "$TMP/empty-quoted.md"
set_description "$AGENT_BASE" "$TMP/empty-block.md" 'description: |'
self_test "an empty block description fails the check" 1 "has an empty description" --agent "$TMP/empty-block.md"
set_description "$AGENT_BASE" "$TMP/blank-block.md" "description: |
   "
self_test "a whitespace-only block description fails the check" 1 "has an empty description" --agent "$TMP/blank-block.md"
set_description "$SKILL_BASE" "$TMP/empty-skill.md" 'description:'
self_test "an empty skill description fails the check" 1 "has an empty description" --skill "$TMP/empty-skill.md"
set_description "$SKILL_BASE" "$TMP/empty-skill-quoted.md" "description: ''"
self_test "an empty quoted skill description fails the check" 1 "has an empty description" --skill "$TMP/empty-skill-quoted.md"
set_description "$SKILL_BASE" "$TMP/empty-skill-block.md" 'description: >'
self_test "an empty block skill description fails the check" 1 "has an empty description" --skill "$TMP/empty-skill-block.md"
set_description "$SKILL_BASE" "$TMP/blank-skill-block.md" "description: |
   "
self_test "a whitespace-only block skill description fails the check" 1 "has an empty description" --skill "$TMP/blank-skill-block.md"

# --- Summary ----------------------------------------------------------------

summary
