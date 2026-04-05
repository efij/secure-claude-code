#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if ! printf '%s\n' "$INPUT" | grep -Eqi '(^|[[:space:]])(docker|podman|nerdctl|buildah|nsenter|chroot)([[:space:]]|$)'; then
  exit 0
fi

if ! printf '%s\n' "$INPUT" | grep -Eqi '(^|[[:space:]])(--privileged|--pid=host|--network=host|--net=host|--cap-add=SYS_ADMIN|nsenter([[:space:]]|$)|chroot[[:space:]]+/host|/var/run/docker\.sock|/run/containerd/containerd\.sock|/run/crio/crio\.sock|(^|[[:space:]])-v[[:space:]]+/[:]|--mount[^[:space:]]*type=bind[^[:space:]]*(src|source)=/)'; then
  exit 0
fi

shield_audit "container-escape-guard" "block" "container escape or host mount pattern detected" "$INPUT"
printf '%s\n' '[runwall] blocked container escape pattern' >&2
printf '%s\n' 'reason: the command uses privileged container settings, host namespaces, or host sockets that create a direct escape path to the machine' >&2
printf '%s\n' 'next: keep containers unprivileged and use reviewed runtime boundaries instead of host-level mounts or namespaces' >&2
exit 2
