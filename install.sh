#!/usr/bin/env bash
# Link every skill in this repo into your personal Claude Code skills directory.
#
# Claude Code discovers skills exactly one directory deep, so the domain/tactic
# tree here cannot be linked wholesale. This creates one flat symlink per skill,
# named by the skill, pointing back at its home in the tree. Edits to a skill
# take effect immediately; no copying, no second source of truth.
#
#   ./install.sh              link all skills
#   ./install.sh --dry-run    show what would happen
#   ./install.sh --uninstall  remove only the links that point into this repo

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${CLAUDE_SKILLS_DIR:-$HOME/.claude/skills}"
MODE="install"

case "${1:-}" in
  --dry-run)   MODE="dry" ;;
  --uninstall) MODE="uninstall" ;;
  --help|-h)   sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  "")          ;;
  *)           echo "unknown option: $1" >&2; exit 2 ;;
esac

mkdir -p "$DEST"

if [ "$MODE" = "uninstall" ]; then
  removed=0
  for link in "$DEST"/*; do
    [ -L "$link" ] || continue
    case "$(readlink "$link")" in
      "$REPO"/*) rm "$link"; removed=$((removed + 1)) ;;
    esac
  done
  echo "removed $removed link(s) pointing into $REPO"
  exit 0
fi

linked=0 skipped=0 conflict=0
while IFS= read -r skill_md; do
  dir="$(dirname "$skill_md")"
  name="$(basename "$dir")"
  target="$DEST/$name"

  if [ -L "$target" ]; then
    if [ "$(readlink "$target")" = "$dir" ]; then
      skipped=$((skipped + 1)); continue
    fi
    echo "CONFLICT: $name already links elsewhere -> $(readlink "$target")" >&2
    conflict=$((conflict + 1)); continue
  elif [ -e "$target" ]; then
    echo "CONFLICT: $name exists and is not a symlink" >&2
    conflict=$((conflict + 1)); continue
  fi

  if [ "$MODE" = "dry" ]; then
    echo "would link $name -> $dir"
  else
    ln -s "$dir" "$target"
  fi
  linked=$((linked + 1))
done < <(find "$REPO/skills" -name SKILL.md | sort)

echo "linked=$linked already-current=$skipped conflicts=$conflict  ->  $DEST"
[ "$conflict" -eq 0 ] || exit 1
