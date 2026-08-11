# Discovering CWEs against a sandbox environment

I put this together to answer one question I can defend: when we run untrusted or
agent-driven code inside a sandbox, which weaknesses does the sandbox actually stop, and
which ones get through? By sandbox I mean the stack we normally trust to hold the line —
the container, the seccomp filter, the namespaces, and the flags we build the image with.

I am not trying to show that an agent is "capable" of something. That framing is wrong. What
I am doing is looking for CWE-class weaknesses that survive inside the sandbox, and for each
one I find, writing down the fix I would actually recommend.

Why this is worth doing:

- The workload we care about is an LLM agent that runs tools, and in the worst case compiles
  and runs its own code.
- So the sandbox has to hold in two places at once: at the container boundary (OWASP LLM06,
  LLM03) and at the memory boundary inside the process.
- If either layer is weaker than we assume it is, that assumption is the vulnerability.

Where I ran it:

- Everything here was built and run on my own Kali machine (aarch64, kernel 6.17, gcc 15.2,
  clang 19, podman 5.8.2, libseccomp, rootless user namespaces).
- No numbers are copied from anywhere else. Where I needed a live model I used the local ones
  (llama3.2:1b, qwen2.5:0.5b) and said so in the results.

## CWE classes I test, by sandbox layer

| Sandbox layer | CWE(s) I look for | Where | OWASP tie-in |
|---|---|---|---|
| build-time hardening | 843, 787, 416, 190→131 | `src/abi/` | LLM06 (agent-compiled code) |
| syscall boundary (seccomp) | 693, 862 | `src/enforcer/` | LLM06 |
| container / namespace boundary | 250, 668 | `scenarios/` | LLM06 |
| image / supply chain | 494, 345 | `scenarios/` | LLM03 |
| app-layer allow-list | 807, 863 | `src/agent/` | LLM06 |

## The five questions I set out to answer

The earlier version of this work had five weak spots. Each one maps to a concrete change here.

1. **It was barely tested — one binary, `unzip`.**
   - Rationale: restricting a single harmless tool tells you nothing about real acquisition.
   - Fix: a matrix of the ways an agent actually gets a capability (already on PATH, rebuilt in
     an interpreter, fetched and run, installed from a package, carried in by a container, or a
     raw socket), run against the sandbox boundary. See `src/agent/`, `scenarios/`.
2. **One model, and it was unclear what was being proven.**
   - Rationale: a claim about how often a model misbehaves needs many models and many runs; a
     claim about whether the sandbox holds does not.
   - Fix: I frame this as a structural CWE study, not a study of model behaviour. The model only
     generates realistic requests; the finding is model-independent, and I say so.
3. **The examples were not at the level an enterprise cares about.**
   - Rationale: the controls under test have to be the ones teams actually deploy.
   - Fix: seccomp, dropped capabilities, FORTIFY, no-privileged, network isolation — and I show
     exactly which CWE each one fails to contain.
4. **ABI and memory work had no clear point.**
   - Rationale: if an agent can run a compiler, the memory safety of what it builds is part of
     the sandbox, and I need to show whether the sandbox contains it.
   - Fix: `src/abi/` finds which memory-corruption CWEs survive the build-time hardening the
     image ships with. See `RESULTS.md`, Finding 1.
5. **seccomp and execve — unclear what they proved.**
   - Rationale: this is the recommendation half, not another way to break in.
   - Fix: `src/enforcer/` moves the allow-list to the kernel and shows where it holds
     (exec and connect) and where it cannot (privileged, which turns seccomp off).

## Layout

```
src/abi/        C ABI and memory CWE probes, plus the defense-flag matrix runner   [done]
src/enforcer/   seccomp user-notification supervisor (the kernel-side fix)         [done]
src/agent/      app-layer tool broker, driven by a local model                     [done]
scenarios/      podman posture matrix, acquisition matrix, LLM03 cases             [in progress]
data/           the JSONL these runs produce (kept as evidence)
analysis/       notebook that draws the figures from data/                         [in progress]
paper/          the write-up: method, findings, recommendations                    [in progress]
RESULTS.md      the findings and the fix for each one, updated as I go
```

## How to run it

```sh
python3 src/abi/run_matrix.py                         # build-time CWE matrix
gcc -O2 -o src/enforcer/supervisor src/enforcer/supervisor.c -lseccomp
unshare -Ur ./src/enforcer/supervisor data/enforcer_events.jsonl   # kernel enforcer
python3 src/agent/broker.py                           # app-layer broker (needs Ollama)
```
# Artifact: "Determinism is not soundness"

This repo holds two related bodies of work. The CWE-detector study described above, and the
artifact for the paper *Determinism is not soundness: an empirical evaluation of seccomp
argument-inspection gates for containing LLM agents*. This section covers the paper.

Everything for the paper lives in `experiments/agentsec/`. The paper's source is
`paper/agent-gate.tex`.

## Quick start

```
cd experiments/agentsec
bash reproduce.sh
```

That rebuilds every binary from committed source and re-checks the Part I headline results.
It takes about two seconds on a warm machine, compile included, and needs no privilege. You
should see `9 passed, 0 failed`.

If you only run one thing, run that.

## What you need

- Linux, x86_64. The kernel mechanisms are the point, so this does not run on macOS or WSL1.
- `gcc`, `python3`, `strace`, `unshare` with unprivileged user and network namespaces enabled.
- `libseccomp-dev` — the build needs `seccomp.h`.
- Landlock for Part II. We ran ABI v7; the scope probe negotiates the highest ABI the kernel
  offers and reports what it got.
- Root, but only for `killswitch.sh`. Nothing else asks for it.
- Ollama with local models, but only to generate fresh agent behaviour. Every published number
  re-derives from committed data without it.

## What reproduces what

| Command | Covers | Privilege |
|---|---|---|
| `bash reproduce.sh` | Part I: TOCTOU race (3 conditions), selectivity confusion matrix, language invariance across C/Python/shell, footprint refutation, io_uring bypass | none |
| `bash landlock_bench.sh` | Part II and IV: the race under each control, syscall-alias coverage, where the Landlock allowlist stops, io_uring, the composed sandbox matrix, external `process_vm_writev` mutation | none |
| `python3 enum_tree.py --analyze` | Part III: re-derives the enumeration table offline from committed JSON. No model, deterministic | none |
| `sudo bash killswitch.sh` | Part IV: `cgroup.kill` versus PID enumeration, freeze, `pids.max`, `memory.max` | root |
| `bash pidns_kill.sh` | Part IV: the rootless tree kill. Same tree, same single signal, with and without a PID namespace | none |
| `gcc -O2 observe_evade.c -o out/observe_evade -lseccomp` | Which observation channel the target can detect and evade: `strace` versus a seccomp notify listener | none |
| `gcc -O2 closed_loop.c -o out/closed_loop -lseccomp` | Part IV: detect, deny, terminate as one chain. Five arms — baseline, observe, enforce, latekill, closed | none |
| `bash egress_oracle.sh 20` | Part IV: egress with a real arrival oracle. Two netns joined by a veth, a receiver logging sentinels, an `AF_PACKET` tap. Five routes against a `connect` filter, a Landlock TCP ruleset, and an empty namespace | none |
| `bash reproduce_part3.sh` | Part III determinism gate: runs the enumeration twice at a fixed seed and asserts the two runs hash identically | none, but needs Ollama |

## Two things to know before you read the numbers

The TOCTOU win rate moves between runs. It is scheduler-dependent and we say so in the paper —
the reproducible claim is that the race wins at all, not that it wins at a particular rate. Any
run where the gate is beaten reproduces the finding. The direct-attack control is the one that
must come back exact: 4000 denied out of 4000, every time.

Model provenance is two facts, not one, and `model_manifest.py` prints them in separate columns.
*Identity* is whether the thing being served is content-addressed: a local GGUF file has a digest,
so you can answer "which weights ran"; Ollama's `:cloud` tags are ~300-byte pointer manifests the
provider can repoint under the same tag, so those results are dated observations. *Determinism* is
whether the same seed actually produces the same bytes on your host and build — and that is not
implied by having a digest. Ollama documents a digest and a seed option, but seed reproducibility
in llama.cpp is scoped to a fixed build and float-reduction order, so a different backend or thread
shape can move it. The evidence is the two-run gate in `reproduce_part3.sh`, which records its
verdict to `determinism_evidence.json`. Until that gate has run on your machine, every model reads
`determinism=unverified` no matter how good its digest is. That is deliberate.

`reproduce_part3.sh` with no arguments runs the published configuration (qwen2.5-coder:7b, 11 steps,
2 trials). Passing a smaller model or setting `STEPS`/`TRIALS` gives you a faster deterministic
trajectory but not the paper's table, and the script labels the run REDUCED and declines to record a
determinism verdict. If Ollama is not reachable it exits 77, not 0 — a gate that did not run is not
a gate that passed. One caveat on the trials: at a single seed they are duplicate trajectories by
construction, which is a repeatability check and cannot estimate behavioural variability.

## Where the numbers live

Each experiment writes a `EXP*_RESULTS.md` next to its script, and the agent-behaviour runs also
write JSON. Those files are the data of record for the paper's tables. If a table and a fresh run
disagree, the committed file is what the paper reported and the fresh run is new data.
