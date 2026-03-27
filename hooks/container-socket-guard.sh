#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/container-socket-paths.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PATTERN_FILE" ] || exit 0

socket_match="false"
case "$INPUT" in
  */var/run/docker.sock*|*/run/docker.sock*|*/run/containerd/containerd.sock*|*/var/run/containerd/containerd.sock*|*/var/run/crio/crio.sock*|*/run/crio/crio.sock*|*/run/podman/podman.sock*|*docker_engine*)
    socket_match="true"
    ;;
esac

if [ "$socket_match" != "true" ] && ! shield_match_pattern_file "$INPUT" "$PATTERN_FILE"; then
  exit 0
fi

if printf '%s' "$INPUT" | grep -Eqi '(curl|docker|podman|ctr|crictl|socat|nc|--mount|-v[[:space:]]|DOCKER_HOST|CONTAINER_HOST|unix-socket)'; then
  shield_audit "container-socket-guard" "block" "container runtime socket access detected" "$INPUT"
  printf '%s\n' '[runwall] blocked container socket access' >&2
  printf '%s\n' 'reason: the command reaches a container runtime socket that can widen execution beyond the workspace' >&2
  printf '%s\n' 'next: avoid direct socket access and use reviewed local tooling or mocked runtimes instead' >&2
  exit 2
fi

exit 0
