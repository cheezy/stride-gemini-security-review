#!/usr/bin/env bash
# Frontmatter / command-key smoke test for the stride-gemini-security-review
# extension.
#
# Confirms:
#   - every agents/*.md has `name:` and `description:` YAML frontmatter,
#     handling the block-scalar `description: |` form;
#   - every commands/*.toml has a `description` key AND a `prompt` key (TOML,
#     not YAML).
#
# Offline and read-only. It extracts the YAML frontmatter block between the
# first two `---` fences and greps for keys at the start of a line; it never
# evaluates or sources any file, so a malicious prompt body cannot execute.
#
# Exit code: 0 if every check passes; 1 if any check fails.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PASS=0
FAIL=0

ok()   { PASS=$(( PASS + 1 )); printf '  ✓  %s\n' "$1"; }
nope() { FAIL=$(( FAIL + 1 )); printf '  ✗  %s\n     %s\n' "$1" "${2:-}"; }

# frontmatter <file> — print the lines between the first two `---` fences.
frontmatter() {
  awk '
    NR == 1 && /^---[[:space:]]*$/ { infm = 1; next }
    infm && /^---[[:space:]]*$/    { exit }
    infm                          { print }
  ' "$1"
}

# has_key <text> <key> — true if a line starts with `<key>:` (YAML).
has_key() {
  printf '%s\n' "$1" | grep -qE "^${2}:"
}

# has_toml_key <file> <key> — true if a line starts with `<key>` (TOML `key =`).
has_toml_key() {
  grep -qE "^${2}([[:space:]]|=)" "$1"
}

# check_md_frontmatter <file> <label>
check_md_frontmatter() {
  local file="$1" label="$2" fm
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
  else
    nope "$label missing description:" "$file"
  fi
}

printf 'stride-gemini-security-review frontmatter test\n'
printf 'plugin root: %s\n\n' "$PLUGIN_ROOT"

# --- Skills -----------------------------------------------------------------

printf 'Skill frontmatter\n'
for skill in security-review-essentials; do
  check_md_frontmatter "${PLUGIN_ROOT}/skills/${skill}/SKILL.md" "skill '${skill}'"
done

# --- Agents -----------------------------------------------------------------

printf '\nAgent frontmatter\n'
for agent in security-reviewer; do
  check_md_frontmatter "${PLUGIN_ROOT}/agents/${agent}.md" "agent '${agent}'"
done

# --- Commands ---------------------------------------------------------------

printf '\nCommand TOML keys\n'
for cmd in security-review; do
  file="${PLUGIN_ROOT}/commands/${cmd}.toml"
  if [ ! -f "$file" ]; then
    nope "command /${cmd} missing" "$file"
    continue
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
done

# --- Summary ----------------------------------------------------------------

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
