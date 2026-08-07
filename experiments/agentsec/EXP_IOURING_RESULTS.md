# EXP-IOU: io_uring bypasses the seccomp gate; Landlock follows onto the ring

The paper asserted that `io_uring` lets an agent submit file and network work "that never reaches the
syscall-entry filter." That was read off the ABI, not measured. It is measured now, and the same probe
answers the open question about whether a Landlock domain follows asynchronous work.

`iouring_probe.c` opens the same path twice in one process: once with `openat`, once as an
`IORING_OP_OPENAT` through an established ring. Raw ring interface (mmap'd SQ/CQ + `io_uring_enter`),
no liburing, so it builds with plain gcc like everything else here. The oracle is the kernel's errno
and the `cqe->res`, plus whether the file exists afterwards.

Reproduce: `bash landlock_bench.sh` (benchmark 4), or `bash reproduce.sh` for the seccomp row as a
pass/fail check.

## Result

| control | direct `openat` | ring `openat` | file created |
|---|---|---|---|
| unprotected baseline | opened | opened | yes |
| seccomp persist gate (`SCMP_ACT_NOTIFY` on `openat`) | denied (EPERM) | **opened** | **yes** |
| Landlock allowlist | denied (EACCES) | denied (EACCES) | no |

20/20 identical across repeats under each control.

## Reading

**The seccomp gate is bypassed completely.** The supervisor denies the direct `openat` and increments
its own counter (`denied_persist=1`), and the ring submission writes the persistence file anyway.
`SCMP_ACT_NOTIFY` sits at syscall entry; an `io_uring` operation is performed inside the kernel
without traversing that entry, so the filter never fires. This is a second full bypass of the gate,
structurally unrelated to the EXP-11 TOCTOU race, and it is not fixed by removing the second argument
read -- there is no argument read to remove.

**Landlock follows the work onto the ring.** It mediates at the LSM hook rather than at syscall entry,
and `io_uring` performs submitted work under the submitting task's credentials, so the domain the task
entered still applies. The asynchronous open is denied exactly as the synchronous one is.

## What this does NOT establish

Filesystem opens only, on this kernel. Landlock implements none of the `io_uring`-specific LSM hooks,
so these are untested and should be assumed ungoverned until someone measures them:

- registered **personalities**, which can select a credential registered before the sandbox was
  entered and therefore carry a pre-sandbox (typically empty) domain;
- `IORING_OP_URING_CMD` device passthrough, which does not go through the file path;
- `IORING_SETUP_SQPOLL`, where a task submits work with no syscalls at all after setup.

Single x86_64 host, `kernel.io_uring_disabled = 0`. On a host where the sysctl disables `io_uring`, or
under a container runtime that blocks the three `io_uring` syscalls in its seccomp profile, the
seccomp row does not reproduce -- which is the point: blocking ring creation is the mitigation, and it
has to be done at the ring-creation boundary because the gate cannot see individual operations through
a ring that already exists.
