#!/usr/bin/env python3
"""
H1 test: point every commodity detector at each memory-corruption class and record
CAUGHT vs MISSED. A real detection gap = a class MISSED by every detector.

Detectors (10, independent):
  static/compile:  gcc-warn, gcc-fanalyzer, gcc-lto(link), clang-warn, clang-analyze, cppcheck
  runtime:         fortify, asan, ubsan, valgrind

CAUGHT is only recorded when the tool emits a memory-safety diagnostic that names
the defect (for static) or aborts/reports on the bug path (for runtime). Raw
evidence is saved per cell so every CAUGHT/MISSED is auditable.
"""
import json, os, re, subprocess, signal, sys

ABI = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "llm-sandbox-cwe-research/src/abi")
OUT = os.path.abspath("detector_matrix_results.jsonl")
TMP = "/tmp/dm"
os.makedirs(TMP, exist_ok=True)

# class -> (source files, argv). abi needs two TUs; oob has 3 variants.
CLASSES = [
    ("abi_skew",          ["abi_confusion.c", "abi_producer.c"], []),
    ("oob_intra",         ["oob_write.c"],                       ["intra"]),
    ("oob_heap",          ["oob_write.c"],                       ["heap"]),
    ("oob_stack",         ["oob_write.c"],                       ["stack"]),
    ("uaf",               ["uaf_dealloc.c"],                     []),
    ("int_overflow",      ["int_overflow_alloc.c"],              []),
]

# meta noise that must never count as a catch
META = re.compile(r"unknown warning option|-Wunknown-warning-option|unused|"
                  r"unrecognized command|is deprecated", re.I)
# a compile diagnostic counts only if it is a memory-safety checker firing on a real line
WARN = re.compile(r"warning:.*\[-W(stringop-overflow|stringop-overread|array-bounds|"
                  r"alloc-size|free-nonheap|use-after-free|dangling|maybe-uninitialized|"
                  r"uninitialized|restrict|nonnull)", re.I)
FANALYZER = re.compile(r"\[-Wanalyzer-|\[CWE-", re.I)
CPPCHECK  = re.compile(r"\((error|warning)\).*(out of bounds|overflow|uninit|leak|"
                       r"double free|deallocated|dangling|buffer|negative)", re.I)
ANALYZE   = re.compile(r"warning:.*(overflow|out-of-bound|out of bound|uninitialized|"
                       r"garbage value|leak|use-after|dereference of)", re.I)

def caught_compile(blob, rx):
    """a compile-time catch requires a mem-safety diagnostic AND not just meta noise."""
    lines = [l for l in blob.splitlines() if not META.search(l)]
    return any(rx.search(l) for l in lines)

# per-tool runtime signatures, so a catch is attributed to the tool that fired
SIG = {
    "asan":    re.compile(r"AddressSanitizer|heap-buffer-overflow|heap-use-after-free|"
                          r"requested allocation size", re.I),
    "ubsan":   re.compile(r"runtime error:", re.I),
    "fortify": re.compile(r"buffer overflow detected|stack smashing detected|__chk", re.I),
    "valgrind":re.compile(r"Invalid write|Invalid read|Invalid free|ERROR SUMMARY: [1-9]", re.I),
}

def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120, **kw)

def srcpaths(files): return [os.path.join(ABI, f) for f in files]

def compile_warn(cc, extra, files, tag):
    """compile-only, harvest warnings. CAUGHT if a mem-safety warning fires (not meta noise)."""
    out = os.path.join(TMP, f"{tag}.o")
    cmd = [cc, "-c", "-O2", "-Wall", "-Wextra"] + extra + srcpaths(files) + ["-o", out]
    r = run(cmd)
    blob = r.stdout + r.stderr
    return caught_compile(blob, WARN), blob.strip()[:400]

def gcc_fanalyzer(files, tag):
    cmd = ["gcc", "-fanalyzer", "-O2", "-c"] + srcpaths(files) + ["-o", os.path.join(TMP, f"{tag}.fa.o")]
    r = run(cmd); blob = r.stdout + r.stderr
    return caught_compile(blob, FANALYZER), blob.strip()[:400]

def gcc_lto(files, tag):
    out = os.path.join(TMP, f"{tag}.lto")
    r = run(["gcc", "-O2", "-flto", "-Wall"] + srcpaths(files) + ["-o", out])
    blob = r.stdout + r.stderr
    lines = [l for l in blob.splitlines() if not META.search(l)]
    hit = any(re.search(r"type-mismatch|conflicting types|incompatible", l, re.I) for l in lines)
    return hit, blob.strip()[:400]

def clang_analyze(files, tag):
    # single-TU static analyzer pass
    caught, ev = False, ""
    for f in files:
        r = run(["clang", "--analyze", "-Xclang", "-analyzer-output=text", os.path.join(ABI, f), "-o", "/dev/null"])
        blob = r.stdout + r.stderr
        if caught_compile(blob, ANALYZE): caught = True; ev = blob.strip()[:400]
        elif not ev: ev = blob.strip()[:200]
    return caught, ev

def cppcheck_run(files, tag):
    caught, ev = False, ""
    for f in files:
        r = run(["cppcheck", "--enable=all", "--inconclusive", "--quiet", os.path.join(ABI, f)])
        blob = r.stdout + r.stderr
        if CPPCHECK.search(blob): caught = True; ev = blob.strip()[:400]
        elif not ev: ev = blob.strip()[:200]
    return caught, ev

def build_run(files, argv, flags, tag, tool):
    """Build with the isolated flags for `tool`, run, and count a catch ONLY if that
    tool's own signature fires. `tool` in {fortify, asan, ubsan, valgrind}."""
    binout = os.path.join(TMP, f"{tag}.bin")
    comp = run(["gcc"] + flags + srcpaths(files) + ["-o", binout])
    if comp.returncode != 0:
        return False, f"compile_error: {comp.stderr.strip()[-200:]}"
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:abort_on_error=1",
               UBSAN_OPTIONS="halt_on_error=1:abort_on_error=1:print_stacktrace=1")
    cmd = (["valgrind", "--error-exitcode=99", "--quiet"] if tool == "valgrind" else []) + [binout] + argv
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)
    except subprocess.TimeoutExpired:
        return False, "timeout"
    blob = r.stdout + r.stderr
    caught = bool(SIG[tool].search(blob))
    sigtxt = "" if caught else f"exit={r.returncode} (no {tool} signature)"
    return caught, (blob.strip()[:400] or sigtxt)

# isolation flags: each runtime column measures ONE tool, others turned off
F_FORTIFY = ["-O2", "-D_FORTIFY_SOURCE=2"]                       # shipped hardening bundle
F_ASAN    = ["-O1", "-fsanitize=address", "-fno-omit-frame-pointer",
             "-fno-stack-protector", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0"]
F_UBSAN   = ["-O1", "-fsanitize=undefined", "-fno-stack-protector",
             "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0"]
F_VG      = ["-O0", "-g", "-fno-stack-protector", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0"]

DETECTORS = [
    ("gcc-warn",      lambda f,a,t: compile_warn("gcc", [], f, t)),
    ("clang-warn",    lambda f,a,t: compile_warn("clang", ["-Warray-bounds", "-Wconditional-uninitialized"], f, t)),
    ("gcc-fanalyzer", lambda f,a,t: gcc_fanalyzer(f, t)),
    ("clang-analyze", lambda f,a,t: clang_analyze(f, t)),
    ("cppcheck",      lambda f,a,t: cppcheck_run(f, t)),
    ("gcc-lto",       lambda f,a,t: gcc_lto(f, t)),
    ("fortify",       lambda f,a,t: build_run(f, a, F_FORTIFY, t+"_fort", "fortify")),
    ("asan",          lambda f,a,t: build_run(f, a, F_ASAN,  t+"_asan",  "asan")),
    ("ubsan",         lambda f,a,t: build_run(f, a, F_UBSAN, t+"_ubsan", "ubsan")),
    ("valgrind",      lambda f,a,t: build_run(f, a, F_VG,    t+"_vg",    "valgrind")),
]

# --- state of the SHIPPED build, by the operational definition ---
# silent    : corruption confirmed by the probe self-check (outcome=corrupted), process
#             exited 0, and NO defense emitted a diagnostic. exploitable + undetected.
# detected  : a defense named the memory error and stopped it (fortify/canary/etc).
# crashed   : raw SIGSEGV/SIGBUS/SIGABRT with no diagnostic. DoS, corruption faulted.
# prevented : the unsafe op was refused before corruption (alloc returns NULL / aborts
#             at the call), and the probe self-check reports outcome=clean.
# clean     : the bug did not take effect on this input (self-check reports clean, no fault).
DETECT_SIG = re.compile(r"buffer overflow detected|stack smashing detected|__chk|"
                        r"AddressSanitizer|runtime error:|Invalid (write|read|free)", re.I)
PREVENT_SIG = re.compile(r"REFUSED \(overflow checked\)|calloc parameters overflow|"
                         r"allocation size.*exceeds", re.I)

def shipped_state(files, argv, tag):
    """Build the real production bundle (-O2 -D_FORTIFY_SOURCE=2, default canary) and
    classify the outcome by the definitions above."""
    binout = os.path.join(TMP, f"{tag}.ship")
    comp = run(["gcc", "-O2", "-D_FORTIFY_SOURCE=2"] + srcpaths(files) + ["-o", binout])
    if comp.returncode != 0:
        return "compile_error", comp.stderr.strip()[-160:]
    env = dict(os.environ)
    try:
        r = subprocess.run([binout] + argv, capture_output=True, text=True, timeout=60, env=env)
    except subprocess.TimeoutExpired:
        return "timeout", ""
    blob = r.stdout + r.stderr
    m = re.search(r"outcome=(\w+)", blob)
    outcome = m.group(1) if m else None
    ev = blob.strip()[:200]
    if DETECT_SIG.search(blob):                    return "detected", ev
    if r.returncode < 0:                            return "crashed", f"signal {-r.returncode}; {ev}"
    if PREVENT_SIG.search(blob) and outcome == "clean": return "prevented", ev
    if outcome == "corrupted" and r.returncode == 0:    return "silent", ev
    if outcome == "clean":                          return "clean", ev
    return "unknown", ev

def main():
    rows = []
    names = [d[0] for d in DETECTORS]
    print(f"{'class':<14}" + "".join(f"{n:<15}" for n in names))
    print("-" * (14 + 15*len(names)))
    for cls, files, argv in CLASSES:
        cells = {}
        line = f"{cls:<14}"
        for dname, fn in DETECTORS:
            try:
                caught, ev = fn(files, argv, f"{cls}_{dname}")
            except Exception as e:
                caught, ev = False, f"harness_error: {e!r}"
            cells[dname] = {"caught": caught, "evidence": ev}
            line += f"{'CAUGHT' if caught else 'miss':<15}"
        state, sev = shipped_state(files, argv, cls)
        line += f"  ship={state}"
        print(line)
        rows.append({"class": cls, "files": files, "argv": argv,
                     "shipped_state": state, "shipped_evidence": sev, "detectors": cells})
    with open(OUT, "w") as fh:
        for r in rows: fh.write(json.dumps(r) + "\n")
    # gap summary
    print("\n=== GAP ANALYSIS (classes missed by ALL detectors) ===")
    for r in rows:
        missed_by = [d for d,c in r["detectors"].items() if not c["caught"]]
        caught_by = [d for d,c in r["detectors"].items() if c["caught"]]
        verdict = "TOTAL GAP" if not caught_by else f"caught by: {', '.join(caught_by)}"
        print(f"  {r['class']:<14} {verdict}")
    print(f"\nwrote {OUT}")

if __name__ == "__main__":
    main()
