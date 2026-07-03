# TODO — pick up here

## The question we're actually answering

Test the memory an LLM allocates and uses at runtime, and the memory used by code the
LLM generates, and find memory-safety bugs in it. The delivery vector is any OWASP LLM
path that gets attacker-controlled bytes to that memory — LLM03 (poisoned model file) is
the cleanest, but LLM01 (prompt injection → tokenizer/KV), LLM04 (poisoned adapter),
LLM08 (RAG/embeddings), and LLM06 (agent-run code) all reach the same surface.

Goal is (B): find the corruption (that's (A)), then push each promising bug toward a
controllable primitive, and report honestly where each one stops. (B) contains (A).

## Done (evidence in data/)

- **Finding 1** — build-time hardening misses memory bugs (`src/abi/`, `data/abi_results.jsonl`).
- **Finding 2** — kernel seccomp enforcer contains exec + connect (`src/enforcer/`, `data/enforcer_events.jsonl`).
- **Finding 3** — app-layer allow-list is the wrong layer, shown with a live model (`src/agent/`, `data/broker_events.jsonl`).
- **Runtime, first pass** — the GGUF loader (LLM03) is hardened: 0 loader bugs across 13
  malformed files; it safely rejects oversized counts/lengths, dimension overflow, bad
  types, bad offsets, truncation (`src/runtime/gen_gguf.py`, `run_gguf_probe.py`,
  `data/runtime_gguf.jsonl`). The only sanitizer hit was a null-deref in the `examples/gguf`
  demo tool, not the runtime — minor, worth a one-line upstream note.

## In progress — coverage-guided fuzzing of the GGUF loader (chosen: "push GGUF harder")

- Harness written: `src/runtime/fuzz_gguf.cpp` (libFuzzer around `gguf_init_from_file`,
  no_alloc=true so it fuzzes the parse path, not the allocator).
- Instrumented static build of ggml (clang, `-fsanitize=address,undefined,fuzzer-no-link`)
  is building in scratch at `…/scratchpad/llama.cpp/build-fuzz` (target: ggml-base/ggml/ggml-cpu).
- **Next steps to resume:**
  1. Confirm the static libs built (`build-fuzz/**/libggml*.a`).
  2. Compile the harness: `clang++ -fsanitize=address,undefined,fuzzer -g -O1
     -I llama.cpp/ggml/include src/runtime/fuzz_gguf.cpp <libggml*.a> -o gguf_fuzzer`.
  3. Seed the corpus with the valid `seed.gguf` (written by `llama-gguf seed.gguf w`) plus
     the malformed corpus, and run a bounded campaign (e.g. a few minutes, `-max_len=65536`).
  4. Triage any crash: is the corruption real and in the loader (ggml/src/gguf.cpp)? If so,
     do the (B) analysis — is the offset/value controllable, what's adjacent, how far it climbs.
  5. If the loader stays clean (likely, it's OSS-fuzzed), that's a legitimate finding:
     record the residual-risk map + keep the reusable harness, then pivot per below.

## Backlog (later)

- If GGUF stays hardened, pivot the same fuzzing method to the **tokenizer (LLM01)** — most
  reachable, historically buggiest — then chat-template/GBNF grammar, then multimodal/mmproj.
- **LLM06 second track:** memory bugs in code the LLM *generates* (reuse `src/abi/`).
- **Finding 4** — podman posture matrix (default/restricted/privileged-DinD/DooD-socket).
- **Finding 5** — LLM03 supply-chain cases (digest bypass / presigned replay) vs a local registry.
- Notebook over all `data/`, then the paper.

## Environment notes (so we can rebuild)

- The llama.cpp clone and both builds (`build-asan` sanitizer, `build-fuzz` clang+fuzzer)
  live in the session **scratch** dir, not the repo — they are large and reproducible.
- Ollama 0.30.10 is installed; local models `llama3.2:1b`, `qwen2.5:0.5b`.
- Host: Kali aarch64, kernel 6.17, gcc 15.2, clang 19, cmake 4.3.4 (pip), podman 5.8.2.
