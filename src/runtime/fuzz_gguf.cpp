// libFuzzer harness for the GGUF loader -- the LLM03 entry point.
//
// The loader takes a file path, so each input is written to a tmpfs file and parsed,
// which exercises the exact code a poisoned model file would hit. no_alloc=true keeps
// it to the parser (metadata + tensor info) without allocating tensor data, so a bad
// dimension doesn't just OOM -- we want the parse path, not the allocator.
//
// Build: instrument ggml with -fsanitize=address,undefined,fuzzer-no-link, then link
// this with -fsanitize=address,undefined,fuzzer. See run notes in the README.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <unistd.h>

#include "ggml.h"
#include "gguf.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char path[] = "/dev/shm/fuzz_gguf_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return 0;
    ssize_t w = write(fd, data, size);
    close(fd);
    if (w != (ssize_t) size) { unlink(path); return 0; }

    gguf_init_params params;
    params.no_alloc = true;      // parse structure only, don't allocate tensor data
    params.ctx      = nullptr;

    gguf_context *g = gguf_init_from_file(path, params);
    if (g) {
        // touch accessors so the fuzzer explores past a bare parse
        gguf_get_version(g);
        int64_t nt = gguf_get_n_tensors(g);
        int64_t nk = gguf_get_n_kv(g);
        for (int64_t i = 0; i < nk; i++) {
            gguf_get_key(g, i);
            gguf_get_kv_type(g, i);
        }
        for (int64_t i = 0; i < nt; i++) {
            gguf_get_tensor_name(g, i);
            gguf_get_tensor_type(g, i);
            gguf_get_tensor_offset(g, i);
        }
        gguf_free(g);
    }
    unlink(path);
    return 0;
}
