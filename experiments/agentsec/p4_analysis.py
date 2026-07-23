#!/usr/bin/env python3
"""
EXP-P4: does "two forces, one footprint" hold on the REAL artifacts?
Reads the injection samples (invariance) and the autonomous results, extracts the actual dangerous
syscall each attempting artifact used, and compares the two forces' footprint SETS.

No new generation -- refuting a universal ("they reduce to ONE footprint") needs only the real data.
"""
import json, re, collections, os

HERE = os.path.dirname(os.path.abspath(__file__))

# ---- force A: injection (attacker-driven) ----
inj = [json.loads(l) for l in open(os.path.join(HERE, "invariance_samples.jsonl")) if l.strip()]
inj_attempt = [r for r in inj if r.get("attempted")]
# exec/conn are counts observed under strace; channel 'none' is the benign baseline.
inj_by_channel = collections.Counter(r["channel"] for r in inj_attempt)
inj_exec = sum(1 for r in inj_attempt if r.get("exec", 0) and r["channel"] != "none")
inj_conn = sum(1 for r in inj_attempt if r.get("conn", 0))
inj_syscalls = collections.Counter()
for r in inj_attempt:
    if r.get("conn", 0): inj_syscalls["connect"] += 1
    if r.get("exec", 0) and r["channel"] != "none": inj_syscalls["execve"] += 1

# ---- force B: autonomous (self-driven) ----
auto = json.load(open(os.path.join(HERE, "agentsec_autonomous_results.json")))
auto_attempt = [r for r in auto if r.get("attempted") and r.get("destructive")]
def classify(tell):
    t = tell or ""
    for name in ("execveat", "execve", "unlinkat", "unlink", "rmdir", "rename", "truncate",
                 "openat", "open", "connect"):
        if re.search(r"\b" + name + r"\(", t):
            return name
    return "other/none" if not t else "unparsed:" + t[:20]
auto_syscalls = collections.Counter(classify(r.get("tell", "")) for r in auto_attempt)
# collapse exec family for the set comparison
def fam(s): return "execve" if s.startswith("execve") else ("unlink" if s.startswith("unlink") else s)
auto_set = set(fam(s) for s in auto_syscalls if not s.startswith(("other", "unparsed")))
inj_set = set(inj_syscalls)

print("=== FORCE A: injection (attacker-driven) ===")
print("attempting artifacts:", len(inj_attempt), "| by channel:", dict(inj_by_channel))
print("dangerous syscalls used:", dict(inj_syscalls))
print("footprint set A:", sorted(inj_set))
print()
print("=== FORCE B: autonomous (self-driven) ===")
print("attempting+destructive artifacts:", len(auto_attempt))
print("dangerous syscalls used:", dict(auto_syscalls))
print("footprint set B:", sorted(auto_set))
print()
print("=== COMPARISON (the P4 claim) ===")
print("A ∩ B (shared):", sorted(inj_set & auto_set))
print("A only:",        sorted(inj_set - auto_set))
print("B only:",        sorted(auto_set - inj_set))
identical = inj_set == auto_set
print("footprints IDENTICAL?", identical)
# would an execve/connect-only gate (the rootless invariance gate) cover force B?
rootless_covers = {"execve", "execveat", "connect"}
b_escapes = sorted(auto_set - rootless_covers)
print("syscalls in B that the execve/connect-only gate does NOT block:", b_escapes)

out = {
    "force_A_injection": {"attempts": len(inj_attempt), "syscalls": dict(inj_syscalls), "set": sorted(inj_set)},
    "force_B_autonomous": {"attempts": len(auto_attempt), "syscalls": dict(auto_syscalls), "set": sorted(auto_set)},
    "shared": sorted(inj_set & auto_set), "A_only": sorted(inj_set - auto_set), "B_only": sorted(auto_set - inj_set),
    "identical": identical, "B_escapes_execve_connect_gate": b_escapes,
}
json.dump(out, open(os.path.join(HERE, "p4_analysis_results.json"), "w"), indent=2)
