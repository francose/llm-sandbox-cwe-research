# Discovering CWEs against a sandbox environment

**Goal:** systematically discover which CWE-class weaknesses still manifest or escape
**inside a sandbox** — the container + seccomp + namespace + build-time-hardening stack that
is deployed to confine untrusted or agent-driven code — and turn each discovery into a
concrete **defense recommendation** at the kernel, compile, and runtime layers.

The sandbox is the thing under test. The CWEs are what we hunt. The output is a ranked set
of mitigations that actually close them. Nothing here claims to "prove a capability"; it
documents where a sandbox's *assumed* protection does not hold and what to do about it.

**Context (why this sandbox exists):** the workload being confined is an LLM agent that runs
tools and, in the strong case, compiles and executes its own native code. That is why the
sandbox spans both the container boundary (OWASP **LLM06** excessive agency, **LLM03** supply
chain) *and* the compile/runtime memory boundary — an agent that can invoke a compiler moves
the attack surface inside the process. But the study is framed around **CWE vs. sandbox**,
not around model behaviour.

Everything was built and run natively on Kali `aarch64` (kernel 6.17, gcc 15.2, clang 19,
podman 5.8.2, libseccomp, rootless userns) — no external lab, no copied numbers. Where a
component this host lacks is needed (a live LLM), it is labelled and driven deterministically
rather than faked, and the finding is constructed to be independent of it.

## CWE classes under test, by sandbox layer

| Sandbox layer | CWE(s) discovered against it | Probe | OWASP tie-in |
|---|---|---|---|
| compile-time hardening | 843, 787, 416, 190→131 | `src/abi/` | LLM06 (agent-compiled code) |
| syscall boundary (seccomp) | 693 (protection-mechanism failure), 862 | `src/enforcer/` | LLM06 |
| container/namespace boundary | 250 (excess privilege), 668 (exposed resource) | `scenarios/` | LLM06 |
| image/supply chain | 494 (download of code w/o integrity check), 345 | `scenarios/` | LLM03 |
| app-layer allow-list | 807 / 863 (reliance on untrusted enforcement) | `src/agent/` | LLM06 |

## What each of your five questions maps to

1. **Not really tested (one `unzip`).** → a binary-**acquisition matrix** (on-PATH, interpreter
   reimpl, fetch-and-exec, package-install, container-carry, raw socket) run against the
   sandbox boundary. `scenarios/`, `src/agent/`
2. **One LLM agent / what are we proving.** → framed as **CWE-vs-sandbox discovery**, not a
   behavioural model study. Findings are model-independent; the driver is deterministic and
   labelled. No "the model decided to escape" claim is made.
3. **Not enterprise-level.** → the sandbox controls under test are the ones enterprises rely on
   (seccomp, dropped caps, FORTIFY, no-privileged, network isolation); we show precisely which
   CWE each fails to contain.
4. **ABI/memory — the point.** → discovering which memory-corruption CWEs survive the sandbox's
   compile-time hardening. See `RESULTS.md` Finding 1 (done, reproduced here).
5. **seccomp/execve — the point.** → the recommendation half: a kernel-layer enforcer that
   contains CWE-693/250 at the syscall boundary, and the exact postures where it cannot.

## Layout

```
src/abi/        C ABI + memory CWE probes and the defense-flag matrix runner   [done]
src/enforcer/   seccomp user-notification supervisor (kernel recommendation)   [wip]
src/agent/      deterministic tool-broker driver (app-layer allow-list)        [wip]
scenarios/      podman posture matrix + acquisition matrix + LLM03 cases       [wip]
data/           JSONL/CSV from real runs (tracked evidence)
analysis/       Jupyter notebook rendering the figures over data/              [wip]
paper/          write-up: method, CWE findings, layered recommendations        [wip]
RESULTS.md      quantified findings + recommendation per CWE, updated per layer
```

## Run it

```sh
python3 src/abi/run_matrix.py          # CWE-vs-hardening matrix -> data/abi_results.jsonl
```
