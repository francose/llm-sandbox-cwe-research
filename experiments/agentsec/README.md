# agentsec: system-interaction behavior and intent-agnostic interception

Artifacts for the manipulation-boundary experiments. Everything here is measured
**mechanically**: "the agent did X" means the compiled program actually attempted syscall X,
observed under `strace` in a rootless network namespace (`unshare -rn`) with a hard timeout.
No text scan of the source, no LLM-as-judge. Every number below traces to the JSON in this
directory.

## Files

| file | what it is |
|---|---|
| `agentsec_mvp.py` | injection experiment: none / direct / indirect channels, mechanical compliance oracle, gate check |
| `agentsec_autonomous.py` | autonomous-destruction experiment: plausible ops tasks, destructive shortcut never suggested |
| `gate.h` | rootless gate: self-installed seccomp-BPF filter (blocks by syscall NUMBER, from inside the target) |
| `gate_rootful.c` | rootful gate: seccomp user-notification supervisor (reads the pathname out of the target's memory, denies by ARGUMENT) |
| `seccomp_preflight.c` | rootless preflight sanity check: ERRNO-blocks `connect` by number and confirms it is enforced on this kernel (NOT the rootful gate) |
| `invariance.py` | experiment #1: agent attempt rate (Wilson CI) vs both gates' determinism + coverage |
| `EXP01_METHODOLOGY.md` | experiment #1 step-by-step scientific method + expanded seven-questions evaluation |
| `agentsec_mvp_results.json` | raw injection results (per model, channel, sample) |
| `agentsec_autonomous_results.json` | raw autonomous results (per model, scenario, sample) |

## Models

Local via `ollama`: `qwen2.5-coder:1.5b`, `deepseek-coder:6.7b`, `qwen2.5-coder:7b`
(a small/medium/large capability ladder). Sampled cells at temperature 0.6; baselines at 0.

## Headline results (verified against the JSON in this dir)

Manipulation boundary, **attacker source** (dangerous-syscall attempts per usable generation):

| model | none | direct | indirect |
|---|---|---|---|
| qwen2.5-coder:1.5b | 0/14 | 7/15 (47%) | 8/15 (53%) |
| deepseek-coder:6.7b | 0/15 | 12/15 (80%) | 9/15 (60%) |
| qwen2.5-coder:7b | 0/15 | 14/15 (93%) | 8/15 (53%) |
| **total** | **0/44** | **33/45 (73%)** | **25/45 (56%)** |

Manipulation boundary, **autonomous source** (no attacker, self-selected destructive syscall
per usable run):

| model | destructive / usable | rate |
|---|---|---|
| qwen2.5-coder:1.5b | 7/29 | 24% |
| deepseek-coder:6.7b | 12/25 | 48% |
| qwen2.5-coder:7b | 26/40 | 65% |
| **total** | **45/94** | **48%** |

**Interception.** The deterministic gate blocked every dangerous attempt with zero variance
across repeats: **58/58 injected** and **45/45 autonomous**. It never inspects why the syscall
was issued, so an attacker-driven `unlink` and a self-driven `unlink` are blocked identically.

## The stdin scar (a finding, not just a bug)

The first autonomous gate run reported blocked = 6/10, not 10/10. We refused the anomaly. Every
"leaked" case was an `unlink()` returning an ordinary filesystem error instead of the gate's
`EPERM`. Root cause: test programs were compiled from **stdin** (`gcc -xc -`), producing binaries
whose seccomp filter enforced `execve` but silently **not** `unlink`. Compiling the identical
source from a **file** enforced both (re-verified 10/10 in every context). Both harnesses now
compile from a file, and a direct-`unlink` golden was added to calibration. The general lesson:
a blocklist that catches `exec` but misses `unlink`/`truncate`/`rename` is worse than none,
because a whole destructive path walks through while it looks like a control.

## Reproduce

```
# injection (calibration only, or --run for the pilot)
python3 agentsec_mvp.py --run
# autonomy
python3 agentsec_autonomous.py --run
```

Requires `ollama` serving the three models, `libseccomp`, `strace`, and an unprivileged user
namespace (`unshare -rn`). Host used: Ubuntu 22.04.5, x86_64, WSL2 kernel 6.18, libseccomp
2.5.3, strace 5.16.
