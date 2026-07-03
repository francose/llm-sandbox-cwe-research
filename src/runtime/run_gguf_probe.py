#!/usr/bin/env python3
"""Feed the malformed GGUF corpus into a sanitizer build of llama.cpp's loader and
record, for each file, whether the loader corrupted memory or rejected it safely.

This tests the LLM03 entry point: the parser that touches a poisoned model file first.

The important distinction the classifier makes is WHERE a sanitizer fires:
  - inside ggml/src/gguf.cpp  -> a real bug in the loader the runtime uses (what I want)
  - inside examples/gguf/...   -> a bug in the demo tool, which Ollama does not use
A plain SIGABRT with the example's GGML_ASSERT is the loader returning failure safely.

Needs a sanitizer build of llama-gguf. Point LLAMA_GGUF at it, e.g.:
    cmake -B build-asan -DGGML_SANITIZE_ADDRESS=ON -DGGML_SANITIZE_UNDEFINED=ON \
      -DCMAKE_C_FLAGS="-fsanitize=address,undefined -g" \
      -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -g"
    cmake --build build-asan --target llama-gguf
    LLAMA_GGUF=.../build-asan/bin/llama-gguf python3 run_gguf_probe.py
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
DATA = os.path.join(ROOT, "data")
GGUF = os.environ.get("LLAMA_GGUF", "")
CORPUS = os.environ.get("GGUF_CORPUS",
    "/tmp/claude-1000/-home-jynx-Documents/8bbcb67c-3b4c-40be-ad43-97363f0f8957/scratchpad/gguf_corpus")


def classify(rc, out):
    lib_hit = ("ggml/src/gguf.cpp" in out or "libggml" in out) and \
              ("runtime error" in out or "AddressSanitizer" in out)
    tool_hit = "examples/gguf" in out and ("runtime error" in out or "AddressSanitizer" in out)
    if lib_hit and not tool_hit:
        return "loader_bug", "sanitizer fired inside the loader (ggml/src/gguf.cpp)"
    if "AddressSanitizer" in out and "ggml/src/gguf.cpp" in out:
        return "loader_bug", "AddressSanitizer inside the loader"
    if tool_hit:
        return "tool_bug", "sanitizer fired in the example tool, not the loader"
    if "gguf_ex_read_0" in out and "GGML_ASSERT" in out:
        return "safe_reject", "loader returned failure; example tool asserted"
    if rc == 0:
        return "parsed", "accepted"
    if rc and rc >= 128:
        return "abort", f"killed by signal {rc-128}"
    return "reject", "non-zero exit, no sanitizer"


def main():
    if not GGUF or not os.path.exists(GGUF):
        sys.exit("set LLAMA_GGUF to a sanitizer build of llama-gguf")
    os.makedirs(DATA, exist_ok=True)
    env = dict(os.environ, ASAN_OPTIONS="abort_on_error=1:detect_leaks=0",
               UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
    rows = []
    files = sorted(f for f in os.listdir(CORPUS) if f.endswith(".gguf"))
    print(f"{'file':<26}{'result':<14}note")
    print("-" * 72)
    for fn in files:
        p = os.path.join(CORPUS, fn)
        try:
            r = subprocess.run([GGUF, p, "r"], capture_output=True, text=True,
                               timeout=30, env=env)
            out = r.stdout + r.stderr
            rc = r.returncode
        except subprocess.TimeoutExpired:
            out, rc = "", 0
            result, note = "timeout", "did not finish"
        else:
            result, note = classify(rc, out)
        rows.append({"file": fn, "result": result, "note": note})
        print(f"{fn:<26}{result:<14}{note}")
    with open(os.path.join(DATA, "runtime_gguf.jsonl"), "w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    loader_bugs = [r for r in rows if r["result"] == "loader_bug"]
    print(f"\nloader bugs: {len(loader_bugs)}   (files: {len(rows)})")
    print(f"wrote {DATA}/runtime_gguf.jsonl")


if __name__ == "__main__":
    main()
