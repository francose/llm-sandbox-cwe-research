#!/usr/bin/env python3
"""Build each C probe under a set of compiler flags, run it, and record what happened:
did the bug run silently, did a defense stop it, or was it refused up front.

Writes data/abi_results.jsonl, one row per probe/variant/flagset, for the notebook.
Every cell is something I actually observed on this machine, not an assumption.
"""
import json
import os
import re
import signal
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
DATA = os.path.join(ROOT, "data")
CC = os.environ.get("CC", "gcc")

# flagset name -> compile flags. -O0 is the "no hardening" baseline an agent gets by default.
FLAGSETS = [
    ("baseline",  ["-O0"]),
    ("O2",        ["-O2"]),
    ("fortify",   ["-O2", "-D_FORTIFY_SOURCE=2"]),
    ("lto",       ["-O2", "-flto"]),
    ("asan",      ["-O1", "-fsanitize=address", "-fno-omit-frame-pointer"]),
]

# probe -> (source files, list of argv-variants)
PROBES = [
    ("abi_confusion",      ["abi_confusion.c", "abi_producer.c"], [[]]),
    ("oob_write",          ["oob_write.c"],                       [["intra"], ["heap"], ["stack"]]),
    ("uaf_dealloc",        ["uaf_dealloc.c"],                     [[]]),
    ("int_overflow_alloc", ["int_overflow_alloc.c"],             [[]]),
]


def classify(rc, out, err):
    """Return (outcome, mechanism). outcome in {corrupted, trapped, prevented, clean, error}."""
    blob = out + "\n" + err
    if "AddressSanitizer" in blob or "heap-use-after-free" in blob or "heap-buffer-overflow" in blob:
        return "trapped", "asan"
    if "buffer overflow detected" in blob or "__chk" in blob or "FORTIFY" in blob:
        return "trapped", "fortify"
    if "stack smashing detected" in blob:
        return "trapped", "stack-protector"
    if rc < 0:  # killed by signal
        signame = signal.Signals(-rc).name
        return "trapped", signame.lower()  # e.g. sigsegv, sigabrt
    m = re.search(r"RESULT .*?outcome=(\w+)", blob)
    if m:
        return m.group(1), "none"
    return ("error", "none") if rc != 0 else ("clean", "none")


def detail_of(out, err):
    m = re.search(r'detail="([^"]*)"', out + err)
    return m.group(1) if m else ""


def build_and_run(name, srcs, argv, flagname, flags):
    binout = os.path.join("/tmp", f"probe_{name}_{flagname}")
    cmd = [CC, *flags, "-o", binout, *[os.path.join(HERE, s) for s in srcs]]
    comp = subprocess.run(cmd, capture_output=True, text=True)
    row = {"probe": name, "variant": " ".join(argv) or "-", "flagset": flagname,
           "flags": " ".join(flags)}
    if comp.returncode != 0:
        row.update(outcome="compile_error", mechanism="none",
                   detail=comp.stderr.strip().splitlines()[-1][:160] if comp.stderr.strip() else "")
        return row
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:abort_on_error=1")
    try:
        run = subprocess.run([binout, *argv], capture_output=True, text=True,
                             timeout=30, env=env)
        rc, out, err = run.returncode, run.stdout, run.stderr
    except subprocess.TimeoutExpired:
        row.update(outcome="timeout", mechanism="none", detail="")
        return row
    outcome, mech = classify(rc, out, err)
    row.update(outcome=outcome, mechanism=mech, detail=detail_of(out, err),
               exit=rc, compiler_warn=bool(comp.stderr.strip()))
    return row


def main():
    os.makedirs(DATA, exist_ok=True)
    rows = []
    print(f"CC={CC}  ({subprocess.run([CC,'--version'],capture_output=True,text=True).stdout.splitlines()[0]})\n")
    hdr = f"{'probe':<20}{'variant':<9}{'flagset':<10}{'outcome':<16}{'mechanism'}"
    print(hdr); print("-" * len(hdr))
    for name, srcs, variants in PROBES:
        for argv in variants:
            for flagname, flags in FLAGSETS:
                r = build_and_run(name, srcs, argv, flagname, flags)
                rows.append(r)
                print(f"{name:<20}{(' '.join(argv) or '-'):<9}{flagname:<10}"
                      f"{r['outcome']:<16}{r.get('mechanism','')}")
        print()
    with open(os.path.join(DATA, "abi_results.jsonl"), "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(rows)} rows -> {DATA}/abi_results.jsonl")


if __name__ == "__main__":
    main()
