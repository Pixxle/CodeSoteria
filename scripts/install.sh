#!/usr/bin/env bash
# install.sh — Install CodeSoteria as global Claude Code commands
#
# This copies commands to ~/.claude/commands/codesoteria/ so you can
# use /codesoteria:scan from any project directory.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

COMMANDS_DIR="$HOME/.claude/commands/codesoteria"
CODESOTERIA_DIR="$HOME/.claude/codesoteria"

echo "CodeSoteria Installer"
echo "====================="
echo ""
echo "Source:   $PROJECT_ROOT"
echo "Commands -> $COMMANDS_DIR"
echo "Data     -> $CODESOTERIA_DIR"
echo ""

# Create directories
mkdir -p "$COMMANDS_DIR"
mkdir -p "$CODESOTERIA_DIR/references/agents"
mkdir -p "$CODESOTERIA_DIR/scripts"

# Copy command file
cp "$PROJECT_ROOT/.claude/commands/codesoteria/"*.md "$COMMANDS_DIR/"
echo "Installed commands:"
for f in "$COMMANDS_DIR"/*.md; do
    echo "  /codesoteria:$(basename "$f" .md)"
done

# Copy reference files
cp "$PROJECT_ROOT/references/"*.md "$CODESOTERIA_DIR/references/"
cp "$PROJECT_ROOT/references/agents/"*.md "$CODESOTERIA_DIR/references/agents/"
echo ""
echo "Installed references:"
for f in "$CODESOTERIA_DIR/references/"*.md; do
    [ "$(basename "$f")" = "*.md" ] && continue
    echo "  $(basename "$f")"
done
agent_count=$(ls "$CODESOTERIA_DIR/references/agents/"*.md 2>/dev/null | wc -l | tr -d ' ')
echo "  agents/ ($agent_count playbooks)"

# Copy scripts
cp "$PROJECT_ROOT/scripts/preflight.sh" "$CODESOTERIA_DIR/scripts/"
chmod +x "$CODESOTERIA_DIR/scripts/preflight.sh"
echo ""
echo "Installed scripts:"
echo "  preflight.sh"

echo ""
echo "Done. Use /codesoteria:scan <path> from any project in Claude Code."
