#!/usr/bin/env python3
"""H2: does the intra-object gap (and the silent pattern) hold across toolchains?

Runs the 6 probes through 5 compilers (gcc-11, gcc-12, clang-14, clang-15, tcc) for
compile-time warnings, through FORTIFY=2 and FORTIFY=3 shipped builds, and through
ASan from both gcc-12 and clang-15. H2 holds if intra-object stays a total gap and no
new compiler/level catches it.
"""
import json, os, re, subprocess, sys

ABI = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "llm-sandbox-cwe-research/src/abi")
TMP = "/tmp/h2"; os.makedirs(TMP, exist_ok=True)

CLASSES = [
    ("abi_skew",     ["abi_confusion.c", "abi_producer.c"], []),
    ("oob_intra",    ["oob_write.c"],                       ["intra"]),
    ("oob_heap",     ["oob_write.c"],                       ["heap"]),
    ("oob_stack",    ["oob_write.c"],                       ["stack"]),
    ("uaf",          ["uaf_dealloc.c"],                     []),
    ("int_overflow", ["int_overflow_alloc.c"],             []),
]
def sp(files): return [os.path.join(ABI, f) for f in files]
def run(cmd, **k): return subprocess.run(cmd, capture_output=True, text=True, timeout=120, **k)

META = re.compile(r"unknown warning option|unused|is deprecated|redefined", re.I)
WARN = re.compile(r"warning:.*\[-W(stringop-overflow|stringop-overread|array-bounds|"
                  r"alloc-size|free-nonheap|use-after-free|dangling|uninitialized|restrict)", re.I)
DETECT = re.compile(r"buffer overflow detected|stack smashing detected|__chk|AddressSanitizer|"
                    r"runtime error:|Invalid (write|read|free)", re.I)

def warns(cc, files):
    """does this compiler emit a mem-safety warning? (tcc has no -Wextra semantics but try)"""
    flags = ["-c", "-O2", "-Wall", "-Wextra"] if "tcc" not in cc else ["-c", "-Wall"]
    r = run([cc] + flags + sp(files) + ["-o", os.path.join(TMP, "w.o")])
    blob = r.stdout + r.stderr
    lines = [l for l in blob.splitlines() if not META.search(l)]
    return "WARN" if any(WARN.search(l) for l in lines) else "-"

def ship_state(cc, files, argv, fortify):
    """state of a shipped build under this compiler + FORTIFY level."""
    extra = [f"-D_FORTIFY_SOURCE={fortify}"] if fortify else []
    binout = os.path.join(TMP, "s.bin")
    comp = run([cc, "-O2"] + extra + sp(files) + ["-o", binout], env=dict(os.environ))
    if comp.returncode != 0: return "build_err"
    try:
        r = subprocess.run([binout] + argv, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired: return "timeout"
    blob = r.stdout + r.stderr
    m = re.search(r"outcome=(\w+)", blob)
    if DETECT.search(blob): return "detected"
    if r.returncode < 0:    return "crashed"
    if m and m.group(1) == "corrupted" and r.returncode == 0: return "silent"
    if m and m.group(1) == "clean": return "clean/prevented"
    return f"?rc={r.returncode}"

def asan_catch(cc, files, argv):
    binout = os.path.join(TMP, f"a_{cc}_{files[0]}.bin".replace("/", "_"))
    comp = run([cc, "-O1", "-fsanitize=address", "-fno-omit-frame-pointer",
                "-fno-stack-protector", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0"] + sp(files) + ["-o", binout])
    if comp.returncode != 0: return "build_err"
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:abort_on_error=1")
    try:
        r = subprocess.run([binout] + argv, capture_output=True, text=True, timeout=60, env=env)
    except subprocess.TimeoutExpired: return "timeout"
    return "CAUGHT" if "AddressSanitizer" in (r.stdout + r.stderr) else "miss"

COMPILERS = ["gcc-11", "gcc-12", "clang-14", "clang-15", "tcc"]
rows = []
hdr = (f"{'class':<13}" + "".join(f"{c+'-warn':<12}" for c in COMPILERS) +
       f"{'g12-F2':<9}{'g12-F3':<9}{'cl15-F2':<9}{'tcc-ship':<10}{'g12-asan':<10}{'cl15-asan':<10}")
print(hdr); print("-"*len(hdr))
for cls, files, argv in CLASSES:
    w = {c: warns(c, files) for c in COMPILERS}
    g12f2 = ship_state("gcc-12", files, argv, 2)
    g12f3 = ship_state("gcc-12", files, argv, 3)
    cl15  = ship_state("clang-15", files, argv, 2)
    tcc_s = ship_state("tcc", files, argv, 0)
    g12a  = asan_catch("gcc-12", files, argv)
    cl15a = asan_catch("clang-15", files, argv)
    print(f"{cls:<13}" + "".join(f"{w[c]:<12}" for c in COMPILERS) +
          f"{g12f2:<9}{g12f3:<9}{cl15:<9}{tcc_s:<10}{g12a:<10}{cl15a:<10}")
    rows.append({"class": cls, "warns": w, "gcc12_F2": g12f2, "gcc12_F3": g12f3,
                 "clang15_F2": cl15, "tcc_ship": tcc_s, "gcc12_asan": g12a, "clang15_asan": cl15a})

with open("h2_toolchain_results.jsonl", "w") as f:
    for r in rows: f.write(json.dumps(r) + "\n")

intra = next(r for r in rows if r["class"] == "oob_intra")
warned = [c for c,v in intra["warns"].items() if v == "WARN"]
asan_hit = intra["gcc12_asan"] == "CAUGHT" or intra["clang15_asan"] == "CAUGHT"
print("\n=== H2 verdict for intra-object ===")
print(f"  compilers that warned:   {warned or 'NONE'}")
print(f"  shipped state (g12 F2/F3, cl15, tcc): {intra['gcc12_F2']}/{intra['gcc12_F3']}/{intra['clang15_F2']}/{intra['tcc_ship']}")
print(f"  ASan caught (gcc12/clang15): {intra['gcc12_asan']}/{intra['clang15_asan']}")
print(f"  --> intra-object gap {'HOLDS across all toolchains' if not warned and not asan_hit else 'BROKEN by a toolchain'}")
