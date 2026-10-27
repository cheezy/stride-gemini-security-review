#!/usr/bin/env bash
# install.sh — Install the Stride security-review extension for Gemini CLI
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/cheezy/stride-gemini-security-review/main/install.sh | bash
#
# Or clone and run locally:
#   ./install.sh            # global:  ~/.gemini/extensions/stride-gemini-security-review/
#   ./install.sh --project  # project: .gemini/extensions/stride-gemini-security-review/
#
# Prefer `gemini extensions install https://github.com/cheezy/stride-gemini-security-review`
# when available — this script is the manual fallback.

set -euo pipefail

REPO="https://github.com/cheezy/stride-gemini-security-review.git"
EXT_NAME="stride-gemini-security-review"
MODE="global"

for arg in "$@"; do
  case "$arg" in
    --project) MODE="project" ;;
    --help|-h)
      echo "Usage: install.sh [--project]"
      echo ""
      echo "Prefer: gemini extensions install https://github.com/cheezy/$EXT_NAME"
      echo "        (this script is the manual fallback)"
      echo ""
      echo "  (default)   Install globally to ~/.gemini/extensions/$EXT_NAME/"
      echo "  --project   Install to .gemini/extensions/$EXT_NAME/ in the current directory"
      exit 0
      ;;
  esac
done

if [ "$MODE" = "project" ]; then
  INSTALL_DIR=".gemini/extensions/$EXT_NAME"
  echo "Installing $EXT_NAME into .gemini/extensions/ (project-local)..."
else
  INSTALL_DIR="$HOME/.gemini/extensions/$EXT_NAME"
  echo "Installing $EXT_NAME into ~/.gemini/extensions/ (global)..."
fi

mkdir -p "$INSTALL_DIR"

# Determine the source: the directory this script lives in if it already
# contains the extension files, otherwise clone a fresh copy to a temp dir.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/gemini-extension.json" ]; then
  SRC="$SCRIPT_DIR"
  CLEANUP=""
else
  TMPDIR="$(mktemp -d)"
  CLEANUP="$TMPDIR"
  echo "Downloading from $REPO..."
  git clone --quiet --depth 1 "$REPO" "$TMPDIR/$EXT_NAME"
  SRC="$TMPDIR/$EXT_NAME"
fi
trap '[ -n "${CLEANUP:-}" ] && rm -rf "$CLEANUP"' EXIT

# Copy the manifest, context file, and the content directories (policies/ holds
# the security-reviewer subagent's Policy Engine deny rules). Use cp -a to
# preserve the executable bit on the lib/*.sh helpers.
cp "$SRC/gemini-extension.json" "$INSTALL_DIR/"
cp "$SRC/GEMINI.md" "$INSTALL_DIR/"
[ -f "$SRC/LICENSE" ] && cp "$SRC/LICENSE" "$INSTALL_DIR/"
for dir in commands skills agents lib fixtures policies; do
  mkdir -p "$INSTALL_DIR/$dir"
  cp -a "$SRC/$dir/." "$INSTALL_DIR/$dir/"
done

echo ""
echo "Stride Security Review for Gemini CLI installed to $INSTALL_DIR"
echo ""
echo "Installed:"
echo "  Commands: $(ls "$INSTALL_DIR/commands"/*.toml 2>/dev/null | wc -l | tr -d ' ') (.toml)"
echo "  Skills:   $(ls -d "$INSTALL_DIR/skills"/*/ 2>/dev/null | wc -l | tr -d ' ')"
echo "  Agents:   $(ls "$INSTALL_DIR/agents"/*.md 2>/dev/null | wc -l | tr -d ' ')"
echo "  Helpers:  $(ls "$INSTALL_DIR/lib" 2>/dev/null | wc -l | tr -d ' ') files in lib/"
echo "  Fixtures: $(ls "$INSTALL_DIR/fixtures" 2>/dev/null | wc -l | tr -d ' ') files in fixtures/"
echo "  Policies: $(ls "$INSTALL_DIR/policies"/*.toml 2>/dev/null | wc -l | tr -d ' ') (.toml)"
echo ""
echo "Next steps:"
echo "  1. Restart Gemini CLI so it picks up the new extension (/security-review)."
echo "  2. From a project with staged or committed changes, run /security-review"
echo "     to review the current diff, or /security-review --full to scan the tree."
