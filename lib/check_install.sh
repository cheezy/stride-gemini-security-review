#!/usr/bin/env bash
# check_install.sh -- runs install.sh into a scratch HOME and checks what it
# installed (W2482).
#
# Since W2482 the security-reviewer agent reads its rule packs and mode files
# from the installed extension's packs/ and modes/, so an install that leaves
# either out leaves the agent with its core rules alone. lib/test-structure.sh
# only reads install.sh's copy list; this check runs the installer. It sets HOME
# to a new temporary directory, runs install.sh in its default (global) mode,
# and checks that packs/ and modes/ under
# $HOME/.gemini/extensions/stride-gemini-security-review/ match this checkout
# file for file, and that the installed agents/ holds only security-reviewer.md
# (Gemini CLI loads every .md directly in agents/ as an agent).
#
# The installer copies from the directory it lives in when that directory holds
# gemini-extension.json, which a checkout does, so this run makes no network
# call. Everything it writes is under temporary directories, removed on exit.
# A self-test runs a copy of the checkout whose install.sh no longer copies
# packs/, then one that no longer copies modes/, and requires each to fail.
#
# lib/check_install.ps1 is the PowerShell mirror, for install.ps1.
#
# Usage:  bash lib/check_install.sh
# Exit code: 0 when the install matches and the self-tests hold; 1 otherwise.
set -uo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
EXT_NAME="stride-gemini-security-review"
fail=0
TMP="$(mktemp -d "${TMPDIR:-/tmp}/check-install.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# install_problems <root> -- install from <root> into a fresh HOME; print one
# line per problem and nothing when the install matches <root>.
install_problems() {
  local src="$1" home dest d agents
  home="$(mktemp -d "$TMP/home.XXXXXX")"
  if ! HOME="$home" bash "$src/install.sh" > "$home.log" 2>&1; then
    echo "install.sh exited non-zero"
  fi
  dest="$home/.gemini/extensions/$EXT_NAME"
  for d in packs modes; do
    if [ ! -d "$dest/$d" ]; then
      echo "$d/ was not installed"
    elif ! diff -r "$src/$d" "$dest/$d" > /dev/null 2>&1; then
      echo "$d/ differs from the checkout"
    fi
  done
  agents="$(cd "$dest/agents" 2>/dev/null && find . -name '*.md' | sort | tr '\n' ' ')"
  [ "$agents" = "./security-reviewer.md " ] || echo "agents/ holds: ${agents:-nothing}"
}

problems="$(install_problems "$ROOT")"
if [ -z "$problems" ]; then
  echo "ok: install.sh installs packs/ and modes/ as in the checkout, and agents/ holds only the agent"
else
  while IFS= read -r p; do echo "FAIL: install.sh installs packs/ and modes/ as in the checkout -- $p"; done <<< "$problems"
  fail=1
fi

# Self-tests: a copy of the checkout whose installer drops one directory.
# copy_root <name> -- the checkout's tracked and untracked (not ignored) files.
copy_root() {
  local dest="$TMP/$1"
  mkdir -p "$dest"
  (cd "$ROOT" && git --no-pager --no-lazy-fetch -c core.fsmonitor=false ls-files -z --cached --others --exclude-standard) > "$TMP/$1.list"
  (cd "$ROOT" && tar --null -T "$TMP/$1.list" -cf -) | (cd "$dest" && tar -xf -)
}
for d in packs modes; do
  copy_root "no-$d"
  sed -i.bak "s/^\(for dir in .*\) $d\( .*\)\{0,1\}; do\$/\1\2; do/" "$TMP/no-$d/install.sh"
  if grep -qE "^for dir in .* $d(;| )" "$TMP/no-$d/install.sh"; then
    echo "FAIL: self-test: an install.sh that does not copy $d/ fails -- the edit did not apply"
    fail=1
    continue
  fi
  problems="$(install_problems "$TMP/no-$d")"
  case "$problems" in
    *"$d/ was not installed"*) echo "ok: self-test: an install.sh that does not copy $d/ fails" ;;
    *) echo "FAIL: self-test: an install.sh that does not copy $d/ fails -- got: ${problems:-no problem}"; fail=1 ;;
  esac
done

if [ "$fail" -ne 0 ]; then
  echo "install check: FAILED"
  exit 1
fi
echo "install check: all checks passed"
exit 0
