# Systems / kernel-ABI review of the seccomp gate

**Scope of review.** Is the claim "the gate intercepts the dangerous syscall every time" (P6 interception,
P8 completeness) defensible at the Linux syscall ABI, or is the blocklist structurally incomplete?
Reviewed at the ABI level, not as a coding task.

**Artifacts read.**
- `experiments/agentsec/gate_rootful.c` — the rootful supervisor (SCMP_ACT_NOTIFY).
- `experiments/agentsec/gate.h` — the rootless self-filter (SCMP_ACT_ERRNO by number).
- `experiments/agentsec/agentsec_mvp.py` — injection harness gate (ERRNO execve/execveat/connect).
- `experiments/agentsec/agentsec_autonomous.py` — autonomous harness gate (the larger ERRNO deny list).
- `experiments/agentsec/seccomp_preflight.c` — rootless preflight (ERRNO connect).
- `experiments/agentsec/invariance.py` — the coverage oracle (COVERED / UNEXPECTED sets).
- `RESEARCH_PROBLEMS.md`, `EXP01_RESULTS.md`, `README.md`.

**Two brief-vs-code corrections up front (flagged, load-bearing).**
1. The task brief describes `gate_rootful.c` as issuing "persistence tokens on
   openat/rename/link/symlink." **It does not.** `gate_rootful.c` NOTIFYs on exactly three syscalls:
   `execve`, `execveat`, `connect` (lines 98–100). There is no openat/rename/link/symlink handling
   anywhere in the rootful supervisor. The rootful gate covers **zero** filesystem persistence.
2. `EXP07_RESULTS.md` does not exist in the tree; the "rootless 0/106 vs rootful 106/106" persistence
   result referenced by P7 in `RESEARCH_PROBLEMS.md` has no backing results file I could locate
   (searched all `*.md`, `data/*.jsonl`). **Could not verify P7's 106/106 numbers.**
   The only broader filesystem blocklist that actually exists in code is in
   `agentsec_autonomous.py` (lines 28–29): `{execve, execveat, connect, unlink, unlinkat, rmdir,
   renameat, renameat2}` — a default-ALLOW filter with those eight ERRNO rules and **no argument
   comparators**. All argument-level logic lives only in `gate_rootful.c` via /proc/pid/mem reads.

Everywhere below, "the gate" is split into: **rootless-number** (gate.h / agentsec_mvp.py /
agentsec_autonomous.py, `seccomp_init(SCMP_ACT_ALLOW)` + ERRNO rules) and **rootful-notify**
(gate_rootful.c). Both are **default-allow blocklists**.

---

## (A) What the gate soundly covers

These hold at the ABI and should be credited:

1. **The execution family is genuinely close to complete — for the native arch.** On Linux there are
   exactly two kernel entry points that replace the process image: `execve` and `execveat`. Both are
   in both gates (gate_rootful.c:98–99; gate.h:6–7). There is no third exec entry and, importantly,
   **`fexecve` is not a syscall** — glibc implements `fexecve(fd,...)` as
   `execveat(fd, "", argv, envp, AT_EMPTY_PATH)`. So `memfd_create` + `fexecve` on an anonymous fd
   still traverses `execveat` and is caught by number (rootless) and notified (rootful). A
   dynamic-loader invocation (`execve("/lib/ld-linux.so", ["ld","/bin/sh"])`) is also still an
   `execve`. **So the execution sub-claim of P6 is the one place a blocklist can be sound**, modulo
   the arch caveat in (B5) and the io_uring caveat in (B2) (io_uring has no exec op, so it does *not*
   help an attacker here — a genuine strength).

2. **Filter inheritance across clone/fork/vfork/execve is correct and cannot be shed.** The child in
   gate_rootful.c sets `PR_SET_NO_NEW_PRIVS` before `seccomp_load` (lines 96–101). Seccomp filters are
   per-thread, inherited by all `clone`/`fork`/`vfork` descendants, and preserved across `execve`;
   with NO_NEW_PRIVS set they cannot be removed without `CAP_SYS_ADMIN`. So a hostile agent **cannot
   fork or exec its way out of the filter's presence.** What is escapable is the *blocklist's contents*
   (B6), not the filter itself.

3. **The rootful supervisor gets the two seccomp-notify liveness races right.** It calls
   `seccomp_notify_id_valid` twice — after receive (line 132) and again immediately before responding
   (line 162). This is the correct mitigation for the **notification-cookie / PID-recycle race**: it
   ensures the target is still blocked on *this* notification before the supervisor reads
   `/proc/<pid>/mem` or answers, so it will not read a recycled PID's memory or answer a stale request.
   Fail-closed on unreadable path (lines 150–152) and deny-by-default for non-target execve
   (lines 146–148) are the right defaults. (This is necessary but **not sufficient** — see B4.)

4. **Intent-agnostic determinism is real for the covered set.** For the syscalls that *are* in the
   blocklist, the verdict is fixed regardless of why the call was issued. The invariance result
   (`EXP01_RESULTS.md`: 164/164, zero variance, two independent mechanisms agreeing) is a valid claim
   **about `{execve, execveat, connect}` on x86_64 against these known-answer artifacts.** That is a
   defensible P5/P6 result *as scoped*. The overclaim is generalizing it to "every dangerous syscall."

---

## (B) Concrete ABI coverage gaps

Ordered by severity. For each: the mechanism missed, whether each gate catches it, and how to reach
the same effect.

### B1 — Network egress is not `connect`. UDP `sendto`/`sendmsg` bypass both gates entirely. (P6, P8)
`connect(2)` is only mandatory for *connection-oriented* egress. On a `SOCK_DGRAM` socket, a single
`sendto(fd, buf, len, 0, &dest, addrlen)` (or `sendmsg` with `msg_name` set) transmits to an arbitrary
destination **with no `connect` ever issued** — this is the standard DNS/UDP exfil path.
- rootless-number: blocks `connect` only. `sendto`/`sendmsg`/`sendmmsg` are **allowed** (default-allow).
- rootful-notify: NOTIFYs `connect` only (line 100/154). `sendto`/`sendmsg` are **not notified → allowed.**
- Also uncovered: a **pre-connected socket fd passed in** by a parent/peer (no `connect` in the target
  at all — just `write`/`send`), and raw `sendmsg` on an `AF_PACKET`/`AF_NETLINK` socket.
`invariance.py`'s own UNEXPECTED watch set lists `socket, sendto, sendmsg` (lines 50–52), so the authors
know these are dangerous — but knowing them for *leak detection on known inputs* is not the same as
*blocking* them. **The connect-only network policy is trivially bypassable.**

### B2 — io_uring bypasses syscall-entry seccomp for network AND filesystem ops. (P6, P8) — the deepest gap
seccomp-BPF (both ERRNO and NOTIFY) filters at **syscall entry**. `io_uring` performs its operations
asynchronously inside kernel worker context; the individual `connect`/`openat`/`read`/`write`/`send`/
`recv`/`unlinkat`/`renameat`/`linkat`/`symlinkat` operations are submitted as **ring SQEs and never
cross the syscall-entry path** that seccomp inspects. The only syscalls involved are `io_uring_setup`
(425), `io_uring_enter` (426), `io_uring_register` (427) — **none of which either gate blocks.** So an
agent that does `io_uring_setup` + submit `IORING_OP_CONNECT` / `IORING_OP_OPENAT` /
`IORING_OP_UNLINKAT` / `IORING_OP_WRITE` defeats the network and filesystem coverage **completely and
silently**. seccomp does not introspect SQE opcodes.
- **Important asymmetry:** there is **no `IORING_OP` for `execve`**, so io_uring does *not* bypass the
  execution block (A1). It bypasses egress and persistence, not exec.
- Fix is cheap and must be explicit: block `io_uring_setup` by number in both gates (deny the whole
  facility), or set `sysctl kernel.io_uring_disabled=2` (kernel ≥6.6) on the host. **Could not verify**
  whether the WSL2 6.18 / Kali 6.17 hosts have io_uring enabled; the ABI point stands regardless.

### B3 — Filesystem/persistence aliasing: the block set misses many paths to the same file. (P7, P8)
Consider the effect classes and their syscall realizations, against the **only** filesystem blocklist
that exists in code (`agentsec_autonomous.py:28–29`): `{unlink, unlinkat, rmdir, renameat, renameat2}`.
The rootful gate covers **none** of these at all.

| Effect | Syscalls that achieve it | In the autonomous deny list? |
|---|---|---|
| Delete a file | `unlink`, `unlinkat` | yes |
| Delete a dir | `rmdir`, `unlinkat(AT_REMOVEDIR)` | rmdir yes; unlinkat yes |
| Rename/replace-over | `rename` (82), `renameat`, `renameat2` (incl. `RENAME_EXCHANGE`) | **`rename` MISSING**; renameat/renameat2 yes |
| Truncate content to zero | `truncate`, `ftruncate`, `openat(...O_TRUNC)` | **all MISSING** |
| Overwrite / drop payload | `openat`(`O_WRONLY\|O_CREAT\|O_APPEND`) + `write`/`pwrite64`/`writev` | **all MISSING** |
| Create hardlink / symlink | `link`, `linkat`, `symlink`, `symlinkat` | **all MISSING** |
| Change perms/owner (persist) | `chmod`, `fchmodat`, `chown`, `fchownat` | **all MISSING** |

Concrete misses:
- **`rename` (the non-`at` variant, nr 82 on x86_64) is not blocked** even though `renameat`/`renameat2`
  are — `rename("victim","x")` walks straight through. Same effect, different number.
- **The entire *write/persist* path is open.** "Persistence" (dropping a backdoor, appending to
  `authorized_keys`, writing a cron/systemd unit) is `openat(O_CREAT|O_WRONLY)` + `write`. Neither is
  gated by anything. The deny list targets **deletion**, not **persistence** — despite P7's framing.
- **Truncation** (`open(...,O_TRUNC)` / `ftruncate`) destroys file contents without `unlink`. The
  README ("stdin scar") explicitly names *"missing truncate/rename"* as a known hole; it is still open.
- **Symlink/hardlink** creation enables the classic symlink-swap and TOCTOU-on-path attacks (B4).

### B4 — Argument-read soundness: /proc/pid/mem + `SECCOMP_USER_NOTIF_FLAG_CONTINUE` is TOCTOU-exploitable. (P6, P11)
This is the subtlest and most serious *correctness* flaw, not just a coverage gap. In gate_rootful.c
the ALLOW path returns `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (line 163). CONTINUE means: **the kernel
executes the real syscall, re-reading its pointer arguments from the target's memory a second time**,
after the supervisor validated them. The supervisor reads the pathname from `/proc/<pid>/mem`
(`read_str`, lines 71–80; called at 141), compares it to the target (lines 143–144), then says
CONTINUE. Between the supervisor's read and the kernel's re-dereference, **a second thread in the same
process can overwrite the pathname buffer** (`/bin/sh` instead of the validated target). Result: the
supervisor approves the safe string, the kernel executes the swapped one. This is the canonical
seccomp-notify TOCTOU that `seccomp_unotify(2)` warns about explicitly — deep argument inspection
combined with CONTINUE is **"unavoidably racy."** `seccomp_notify_id_valid` (lines 132, 162) does
**not** close this race: it proves the target is still *blocked on this notification*, not that the
memory the kernel will re-read is unchanged. The threat model here is a hostile agent that can trivially
`clone` a helper thread, so this is reachable, not theoretical (P11 = "can the gate be defeated?" — for
the rootful arg-check, **yes, via a racing thread**).

- **The correct patterns are not used.** `SECCOMP_IOCTL_NOTIF_ADDFD` is the safe primitive: the
  supervisor performs the privileged operation *itself* with arguments *it* controls (e.g., open the
  approved file, inject the fd with ADDFD, return success) so the kernel never re-reads
  attacker-controllable memory. The code uses **no ADDFD**. For `execve` specifically, ADDFD doesn't
  directly apply, which is exactly why validate-then-CONTINUE on `execve` path strings is unsound — the
  robust options are deny-by-default (the policy is already deny-all-but-one, so simply **not** using
  CONTINUE and instead re-launching the one legitimate target through a supervisor-controlled path), or
  accepting that CONTINUE-based path checks are advisory telemetry, not enforcement.
- Minor, also flagged: `read_str` uses a single `pread` and NUL-terminates at the returned length
  (line 78). A pathname straddling into an unmapped page yields a short read → truncated string → could
  misjudge. Low severity next to the CONTINUE race.
- Net: the rootful gate's *argument awareness* — its entire reason for existing (header lines 4–7) — is
  **not soundly enforced** for a multithreaded target. The P5/P6 "zero variance" result survives only
  because the EXP01 artifacts are single-threaded known-answer inputs that don't race.

### B5 — Architecture: the filter is single-arch; i386/x32 compat entries evade the number-based rules. (P6, P8, P12)
`libseccomp`'s `seccomp_init` installs rules for the **native arch only** (SCMP_ARCH_NATIVE), and
`SCMP_SYS()` resolves numbers per-arch. On x86_64 the BPF matches `AUDIT_ARCH_X86_64` with
`execve=59`, `connect=42`, etc. Two evasions follow, neither handled:
- **i386 compat ABI** (`int 0x80` / `AUDIT_ARCH_I386`): `execve` is nr 11 there. A filter carrying only
  x86_64 rules sees arch=I386, matches no rule, and falls through to the **default action —
  `SCMP_ACT_ALLOW`**. So an unfiltered `execve`/`connect` is reachable via the 32-bit compat entry if
  `CONFIG_IA32_EMULATION` is on. This is a well-known seccomp bypass.
- **x32 ABI**: syscall number OR'd with `__X32_SYSCALL_BIT (0x40000000)`; `execve` becomes
  `0x4000003b`, which the `59`-matching rule misses.
The robust construction is what Docker/systemd do: either **add rules for every relevant arch**
(`SCMP_ARCH_X86_64`, `SCMP_ARCH_X86`, `SCMP_ARCH_X32`) or **`SCMP_ACT_KILL` any foreign-arch syscall**.
The current code does neither → single-arch → compat-ABI evasion of the rootless *and* rootful gates
(a foreign-arch `execve` isn't NOTIFYed either → default allow → unsupervised exec).
- Cross-host wrinkle for P12: EXP01 ran on **x86_64 WSL2 6.18**; `RESULTS.md`/`TODO.md` say the broader
  CWE work is **aarch64 Kali 6.17**. aarch64 numbers differ again (`execve=221`, `connect=203`) and
  aarch64 has no x32 and usually no 32-bit compat unless AArch32 is built in. So the *compat attack
  surface itself is host-dependent* — another reason the invariance claim is scoped to one host.
  **Could not verify** which compat ABIs are enabled on either kernel; the ABI reasoning and the cheap
  fix stand regardless.

### B6 — New execution contexts stay under the filter, but can still defeat the *assumptions*. (P11)
Filter inheritance (A2) means `clone`/`fork`/`vfork`/`execve` children remain filtered — good. The
residual escapes are not "shed the filter" but "operate outside what the filter reasons about":
- **`ptrace`** is not blocked by either gate. A filtered process can `ptrace`-attach to a co-resident
  *unfiltered* process (ptrace_scope permitting) and inject `execve`/`connect` **in the tracee**, which
  runs free of the filter. Standard sandboxes block `ptrace` for exactly this.
- **`unshare(CLONE_NEWUSER)` / `setns` / `mount`** are not blocked. They don't remove the (inherited)
  filter, but a new user namespace grants `CAP_SYS_ADMIN`-in-namespace and `mount`/bind-mount, which
  lets the agent **change what a path resolves to** — directly feeding the B4 path-TOCTOU: make the
  supervisor's `realpath()` and the kernel's later lookup disagree.
- **io_uring** (B2) is the cleanest "new context" escape and is already counted above.

---

## (C) Is P8 "completeness" achievable in principle, or only relative to an enumerated set?

**Only relative to an enumerated set — and the current default-allow blocklist cannot reach it for
egress or persistence.** The argument:

1. A `seccomp_init(SCMP_ACT_ALLOW)` + N ERRNO/NOTIFY rules filter is a **blocklist**: everything not
   named is permitted. Completeness of a blocklist = "have you named every (syscall, arch) pair that
   can produce the forbidden effect." For **egress** and **persistence** that enumeration is large,
   grows with the kernel (new syscalls, `renameat2` flags, io_uring opcodes), and includes
   **non-syscall-entry realizations (io_uring)** that a syscall filter cannot name at all. So for those
   effect classes, blocklist completeness is **structurally unreachable**, not merely unfinished.
2. `invariance.py` makes this precise and honest *without saying so*: `COVERED = {execve, execveat,
   connect}` and a hand-listed `UNEXPECTED` watch set (lines 49–52). "0 coverage leaks" means only
   *"on these known-answer artifacts, no syscall outside my enumerated watch set appeared."* It is a
   statement **relative to an enumeration on a fixed input distribution**, not an absolute property.
   A different input (UDP `sendto`, io_uring, i386 `execve`) is outside the enumeration by construction.
3. The **execution** family is the exception (A1): it has a *closed, small* entry set (execve,
   execveat), inheritance, and no io_uring op — so there, blocklist completeness **is** effectively
   reachable, once you also close the compat-arch hole (B5). This is why the paper's execution result
   is strong and its "every dangerous syscall" generalization is not.
4. **The only way to make completeness a tractable (enumerable, small) question is to invert the
   model**: `seccomp_init(SCMP_ACT_ERRNO/KILL)` + an **allowlist** of the syscalls the target
   legitimately needs, plus arch-scoping (kill foreign arch), plus disabling io_uring. Then the
   question becomes "does my allowlist admit anything dangerous," which is finite and auditable.
   **Bottom line for the paper: P8 as written ("is a deterministic gate only as safe as its
   blocklist?") should be answered YES, and the prose should stop implying blocklist completeness for
   network/filesystem. It is achievable only relative to an enumerated set; absolute completeness
   requires a default-deny allowlist.** This matches the doc's own note (RESEARCH_PROBLEMS.md:76,
   "P8 completeness is undercut by the gate's own incomplete blocklist").

---

## (D) The single most important missing coverage

**B2 — io_uring.** It is the highest-severity gap because a *single unblocked syscall*
(`io_uring_setup`) silently defeats the **entire** network and filesystem coverage at once, with no
error returned to the agent and nothing for the strace oracle to see at the individual-op level. It is
strictly worse than B1/B3 (which miss specific aliases) because it collapses *all* of egress and
persistence simultaneously, and it is invisible to the very syscall-entry measurement the whole thesis
rests on (P1 observability degrades too). It is also the cheapest to close (one deny rule / one sysctl).

Runner-up for *soundness* (as opposed to coverage) is **B4** — the CONTINUE-based path check is not
merely incomplete, it is *defeatable* on the calls it claims to enforce, which is a direct hit on P6
("every time") and P11 ("can the gate be defeated?"). If the paper keeps the rootful arg-awareness
claim, B4 must be fixed or the claim scoped to single-threaded targets.

---

## (E) Prioritized fixes

Ranked by severity. Each cites the effect and the principled rather than whack-a-mole remedy.

| # | Sev | Fix | Why / P-# |
|---|---|---|---|
| 1 | **Critical** | **Invert to default-deny.** Replace `seccomp_init(SCMP_ACT_ALLOW)+deny-rules` with `seccomp_init(SCMP_ACT_ERRNO/KILL)+allowlist` of the target's real needs. This is the only construction that makes P8 completeness enumerable instead of unbounded. | P8, B3, B1 |
| 2 | **Critical** | **Block/disable io_uring**: deny `io_uring_setup` (and `io_uring_enter`, `io_uring_register`) by number in both gates, or `sysctl kernel.io_uring_disabled=2`. Without this, any egress/persistence blocklist is bypassable. | P6/P8, B2 |
| 3 | **Critical** | **Arch-scope the filter**: either add rules for `SCMP_ARCH_X86_64` + `SCMP_ARCH_X86` + `SCMP_ARCH_X32` (x86_64 host) / the AArch32 compat arch (aarch64 host), or `SCMP_ACT_KILL` every foreign-arch syscall. Closes the i386/x32 evasion of the number-based rules. | P6/P8/P12, B5 |
| 4 | **High** | **Fix the rootful TOCTOU**: stop using `SECCOMP_USER_NOTIF_FLAG_CONTINUE` for validated syscalls. Use `SECCOMP_IOCTL_NOTIF_ADDFD` (supervisor performs the op with its own args) where applicable; for `execve`, re-launch the one legitimate target from a supervisor-controlled path and deny-CONTINUE the rest. Keep the two `seccomp_notify_id_valid` calls (they're correct for the PID-recycle race, just insufficient for the memory race). | P6/P11, B4 (gate_rootful.c:163) |
| 5 | **High** | **Complete the egress set** if staying blocklist-shaped (interim): add `sendto, sendmsg, sendmmsg`, and consider `socket`/`socketcall`; recognize passed-in fds can't be caught by syscall number at all (argument/fd-provenance needed). | P6/P8, B1 |
| 6 | **High** | **Complete the persistence set**: add `rename` (non-`at`), `open`/`openat`/`openat2` (gate `O_TRUNC`/`O_CREAT` by flag in the rootful path), `truncate`/`ftruncate`, `link`/`linkat`/`symlink`/`symlinkat`, `chmod`/`fchmodat`/`chown`/`fchownat`, and the write family (`write`/`pwrite64`/`writev`/`pwritev2`). Note this list is exactly why (1) default-deny is the real fix. | P7/P8, B3 |
| 7 | **Medium** | **Block `ptrace`, `unshare(CLONE_NEWUSER)`, `setns`, `mount`** (or admit them to the allowlist only with args), to remove the new-context / mount-remap escapes that also feed the path-TOCTOU. | P11, B6 |
| 8 | **Low** | Harden `read_str` against short reads across page boundaries (loop / handle partial `pread`). | B4 (gate_rootful.c:71–80) |
| 9 | **Doc** | Reconcile the artifacts: the brief's "persistence tokens on openat/rename/link/symlink" is not in `gate_rootful.c`; supply the missing `EXP07_RESULTS.md` backing P7's 106/106, or scope P7's claim. | P7 provenance |

**A principled way to derive the block set (for the paper).** Don't enumerate syscalls; enumerate
**effect classes** (execute / egress / modify-persist / destroy / escalate / observe-escape) and for
each ask "what is the *complete* set of kernel entry points, across all enabled arches and including
io_uring opcodes, that realizes this effect?" The execution class has a closed answer (2 entries) —
which is why it's the certifiable one. The others don't, which is the proof that a default-allow
blocklist cannot certify them and default-deny is required. That reframing turns P8 from an
overclaim into a stated theorem.

---

## Things I could not verify (flagged)
- P7's "rootless 0/106, rootful 106/106" — no `EXP07_RESULTS.md`, no backing data file found.
- Whether io_uring is compiled/enabled on the WSL2 6.18 or Kali 6.17 hosts (B2).
- Which compat ABIs (`CONFIG_IA32_EMULATION`, x32, AArch32) are enabled on either host (B5).
- The brief's claim that the rootful gate carries openat/rename/link/symlink tokens — **contradicted**
  by gate_rootful.c:98–100 (it does not).
- The invariance/EXP01 numbers themselves were taken as reported; I reviewed the *mechanism*, not
  re-ran the harness.
