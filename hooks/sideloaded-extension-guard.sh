#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if ! printf '%s' "$INPUT" | grep -Eqi '(/plugin[[:space:]]+install|marketplace[[:space:]]+add|install-extension|extensionDevelopmentPath|\.vsix|\.zip|Expand-Archive|unzip|tar[[:space:]]+-x|7z[[:space:]]+x)'; then
  exit 0
fi

case "$INPUT" in
  *runwall@runwall*|*github.com/efij/secure-claude-code*|*efij/secure-claude-code*)
    exit 0
    ;;
esac

case "$INPUT" in
  *file://*|*.vsix*|*.zip*|*/tmp/*|*/var/tmp/*|*Downloads/*|*AppData\\Local\\Temp\\*|*extensionDevelopmentPath*|*--unpacked*)
    shield_audit "sideloaded-extension-guard" "block" "sideloaded plugin or extension install path detected" "$INPUT"
    printf '%s\n' '[runwall] blocked sideloaded plugin or extension install path' >&2
    printf '%s\n' 'reason: the install flow points at a local package, unpacked extension path, or scratch directory outside reviewed plugin sources' >&2
    printf '%s\n' 'next: install plugins from a reviewed marketplace or repository source instead of sideloaded archives or unpacked paths' >&2
    exit 2
    ;;
esac

exit 0
