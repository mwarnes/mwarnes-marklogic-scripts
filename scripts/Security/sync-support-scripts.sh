#!/usr/bin/env bash
# Copy the Security gather scripts into the marklogic-support skill and verify the copies are identical.
# Usage: sync-support-scripts.sh [skill-assets-dir]
# Default target: ~/Projects/marklogic-support-skill/skills/marklogic-support/assets/support-scripts
set -euo pipefail
src="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dest="${1:-$HOME/Projects/marklogic-support-skill/skills/marklogic-support/assets/support-scripts}"
[ -d "$dest" ] || { echo "target folder not found: $dest" >&2; exit 1; }
for f in ml-security-gather.py ml-trace-events.py; do
  cp "$src/$f" "$dest/$f"
  cmp "$src/$f" "$dest/$f" && echo "in sync: $f"
done
