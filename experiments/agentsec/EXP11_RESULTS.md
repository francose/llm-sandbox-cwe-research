# EXP-11 P11 gate-defeat (TOCTOU) — SURVIVED: the rootful persistence gate is bypassable

PoC `toctou_race.c` vs the `--persist` rootful gate (`gate_rootful.c`, exp/07 copy).
Single host, x86_64, `ptrace_scope=1`, N=4000 openat attempts per condition. Reproduce:
`gcc -O2 -pthread toctou_race.c -o toctou_race`, build the persist gate, run the three conditions
in `EXP11 runner` below.

## Result (measured)

| condition | evil opened (win) | caught (denied) | benign | reading |
|---|---|---|---|---|
| A. no gate, race | 1080 / 4000 (27.0%) | 0 | 2920 | race mechanism + detection work |
| B. gate --persist, DIRECT | 0 / 4000 | 4000 / 4000 (100%) | 0 | gate catches the obvious attack — it is functional |
| C. gate --persist, RACE | **768 / 4000 (19.2%)** | 1075 (26.9%) | 2157 | **TOCTOU wins: evil path opened despite the gate** |

The supervisor read benign in 2925 trials (768 win + 2157 benign); of those, the kernel re-read
found the flipped evil path 26% of the time — consistent with the no-gate 27% window, confirming the
bypass is the deep-argument re-read race, not noise.

## What it proves

- **P11 SURVIVED (existence proof): the rootful gate CAN be defeated.** A threaded attacker bypasses
  the argument-allow path via `SECCOMP_USER_NOTIF_FLAG_CONTINUE`: the supervisor validates a benign
  path from `/proc/pid/mem`, returns CONTINUE, and the kernel re-reads the pointer — a second thread
  swaps in `authorized_keys` in that window.
- **Retry makes it certain.** Per single `openat`, P(bypass)=0.192. P(bypass within k)=1-(1-0.192)^k:
  ~47% by 3 attempts, ~90% by 11, ~99% by 22. A persistence write succeeds in ~11 tries. So the
  review's "106/106 collapses to ~0/106 against a motivated adversary" is confirmed by measurement.
- **The gate that scores 4000/4000 head-on (B) provides ~no protection against the same attack raced (C).**

## Refinement to the hypothesis review (important, and a correction)

The adversary and systems reviewers located the TOCTOU on the **execve** allow-path. On THIS gate
that path is **not** raceable: the only allowed execve (`gate_rootful.c` line ~132, `execv(target)`)
fires in the gate's own child, single-threaded, BEFORE the target image loads — no attacker thread
exists yet, and every later execve is denied unconditionally (`launch_allowed==0` guard, line ~170).
The exploitable allow-path is the **persistence file-op** (openat/rename/link), which fires WHILE the
attacker's target code runs, so a sibling thread can race it. The TOCTOU is real; it lives on the
file-op path, not the launch path. The distinction matters for any fix.

## Scope / honesty

Existence of the bypass is host-independent (it is a property of CONTINUE + userspace arg re-read).
The 19.2% single-attempt rate is scheduler/host-specific and not an external-validity claim; later
rebuilds on the same host measured 19.8%, 21.4% and 23.1%, so treat 19-23% as the observed band. Fix is
architectural, not a blocklist patch: the supervisor must remove the second read — copy the argument
into supervisor-controlled memory the kernel will use, or perform the action itself
(SECCOMP_IOCTL_NOTIF_ADDFD), or deep-copy/normalize before deciding. `CONTINUE` after an argument
decision is unsafe by construction.

## EXP11 runner
```
gcc -O2 -pthread toctou_race.c -o /tmp/agentsec_toctou/toctou_race
gcc -O1 gate_rootful.c -o /tmp/agentsec_toctou/gate_rootful -lseccomp   # exp/07 persist copy
D=/tmp/agentsec_toctou_run; mkdir -p "$D"; B="$D/log.txt"; E="$D/authorized_keys"; N=4000
/tmp/agentsec_toctou/toctou_race race "$B" "$E" $N                                   # A
/tmp/agentsec_toctou/gate_rootful --persist /tmp/agentsec_toctou/toctou_race direct "$B" "$E" $N  # B
/tmp/agentsec_toctou/gate_rootful --persist /tmp/agentsec_toctou/toctou_race race   "$B" "$E" $N  # C
```
