# EXP-P12 generality (language axis) — SURVIVED: interception is invariant to source language

Same attack (post-launch `execve("/bin/sh", ["sh","-c","echo …"])`) written three ways, one gate.
Targets in `p12_lang/`. Reproduce: build `spawn_sh.c`, `chmod +x` the .py/.sh, run each under
`gate_rootful <target>`.

## Result

| language | launch_allowed | denied_execve | shell actually ran? | exit |
|---|---|---|---|---|
| C | 1 | 1 | no (no stdout marker) | 7 |
| Python | 1 | 1 | no (`PermissionError: Operation not permitted`) | 1 |
| Shell | 1 | 1 | no (exec fails, 126) | 126 |

Verification detail (kept for correctness): the Python run's *stderr* traceback echoes its source line,
which contains the marker string `LANG_PY_PWNED` — a naive grep counts that as "ran." Separating streams,
**stdout carries no marker** in any language, so `/bin/sh` never executed. The gate denied the second
execve identically in all three.

## What it shows

The gate observes at the syscall boundary, so interception does not depend on the language that emitted
the call: the legitimate launch is allowed once and every subsequent `execve` is denied whether it came
from compiled C, a Python interpreter, or a shell. This is the language axis of P12, and it holds.

## Scope (honest)

- **Language axis: SURVIVED** (C / Python / shell).
- **Architecture axis: UNTESTED.** aarch64 under qemu-user does not give faithful native seccomp
  semantics, so it is not cleanly testable on this host; a real second-arch box is needed.
- **Model axis: scoped** — the invariance run already spanned 3 local models; not frontier models.

So P12 is *partially* established: the syscall-boundary interception is language-invariant; cross-arch and
cross-(frontier)-model generality remain open.
