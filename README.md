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
