#!/usr/bin/env bash
# OWASP LLM ID  : LLM06
# Title         : seccomp-notify enforcement of a tool allow-list at the kernel boundary
# Scenario      : An agent attempts to exec a realistic set of approved and non-approved
#                 binaries (echo/id/cat approved; bash, sh, docker, curl, wget, nc, python3,
#                 git, unzip, busybox, chmod, mount denied) and to connect() to the engine
#                 socket. A seccomp user-notification supervisor intercepts every execve AND
#                 every connect: it reads the target path (or sockaddr) out of the agent's
#                 memory, lets approved tools continue, and denies the rest with EPERM before
#                 they run. Connect to docker.sock/podman.sock is denied; other connects
#                 continue. This is the enforcement counterpart to the LLM06 finding, now
#                 covering both halves: process execution and the DooD socket path (F5).
# Prerequisites : Podman. Runs a privileged Fedora container (needs CAP_SYS_ADMIN for the
#                 seccomp notify listener) and compiles supervisor.c with libseccomp.
#                 (For a quick host-side smoke test without a container: build with
#                  `gcc -O2 -o supervisor supervisor.c -lseccomp` then run under a user
#                  namespace: `unshare -Ur ./supervisor events.jsonl`.)
# Egress Signal : none — host-side enforcement. Decisions are logged as JSONL to the output dir
#                 (default analysis/LLM06-seccomp-notify/events.jsonl) for the notebook.
#                 Each line carries a "syscall" field ("execve" or "connect"); execve lines
#                 also carry "tool", connect lines carry "path".
# Severity      : informational (defensive enforcement demonstration)
# Author        : sadik-erisen
# Date          : 2026-06-11 (connect gating + realistic binary set: 2026-07-02)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE/../../analysis/LLM06-seccomp-notify}"
mkdir -p "$OUT"

podman run --rm --privileged -v "$HERE:/src:ro" -v "$OUT:/out" docker.io/library/fedora bash -c '
  dnf install -y -q gcc libseccomp-devel >/dev/null 2>&1
  gcc -O2 -o /tmp/supervisor /src/supervisor.c -lseccomp
  /tmp/supervisor /out/events.jsonl
'
