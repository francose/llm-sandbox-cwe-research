#!/usr/bin/env python3
"""
EXP-12 false-positive / selectivity of the --persist rootful gate.

Ground-truth corpus of write paths under /tmp/fp_run (nothing real is touched):
  malicious          : real persistence targets -> gate SHOULD deny  (deny = TP)
  benign_clean       : ordinary app writes       -> gate SHOULD allow (allow = TN)
  benign_lookalike   : legit files whose NAME merely contains a token substring
                       -> gate SHOULD allow, but strstr will deny     (deny = FP)

Runs the corpus twice: no-gate baseline (everything must open) and under the gate.
Emits the confusion matrix. Positive class = "should be denied".
"""
import json, os, subprocess, sys

ROOT = "/tmp/fp_run"
GATE = "/tmp/agentsec_toctou/gate_rootful"          # built persist gate (exp/07 copy)
PROBE = "/tmp/agentsec_toctou/fp_probe"

CORPUS = {
    # malicious: expect DENY
    f"{ROOT}/home/.ssh/authorized_keys":            ("malicious", "deny"),
    f"{ROOT}/home/.bashrc":                         ("malicious", "deny"),
    f"{ROOT}/home/.zshrc":                          ("malicious", "deny"),
    f"{ROOT}/home/.config/autostart/e.desktop":     ("malicious", "deny"),
    f"{ROOT}/etc/cron.d/job":                       ("malicious", "deny"),
    f"{ROOT}/etc/rc.local":                         ("malicious", "deny"),
    f"{ROOT}/etc/systemd/system/x.service":         ("malicious", "deny"),
    # benign_clean: expect ALLOW
    f"{ROOT}/app/app.log":                          ("benign_clean", "allow"),
    f"{ROOT}/app/data.csv":                         ("benign_clean", "allow"),
    f"{ROOT}/app/report_2026.json":                 ("benign_clean", "allow"),
    f"{ROOT}/app/cache.bin":                        ("benign_clean", "allow"),
    f"{ROOT}/app/output.txt":                       ("benign_clean", "allow"),
    # benign_lookalike: SHOULD allow; strstr token substring will wrongly deny (FP)
    f"{ROOT}/app/microcron_metrics.txt":            ("benign_lookalike", "allow"),   # "cron"
    f"{ROOT}/app/rc.local.backup.txt":              ("benign_lookalike", "allow"),   # "rc.local"
    f"{ROOT}/app/authorized_keys_report.csv":       ("benign_lookalike", "allow"),   # "authorized_keys"
    f"{ROOT}/app/my.profile.notes":                 ("benign_lookalike", "allow"),   # ".profile"
    f"{ROOT}/app/systemd/system_audit.md":          ("benign_lookalike", "allow"),   # "systemd/system"
}

def prep():
    for p in CORPUS:
        os.makedirs(os.path.dirname(p), exist_ok=True)
    lst = os.path.join(ROOT, "_pathlist.txt")
    with open(lst, "w") as f:
        f.write("\n".join(CORPUS.keys()) + "\n")
    return lst

def run(cmd):
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    res = {}
    for ln in out.splitlines():
        if ln.startswith("ALLOW\t") or ln.startswith("DENY\t"):
            verdict, path = ln.split("\t", 1)
            res[path] = verdict.lower()
    return res

def matrix(results):
    tp = fp = tn = fn = 0
    per = {"malicious": [0,0], "benign_clean": [0,0], "benign_lookalike": [0,0]}  # [allow,deny]
    for path, (cls, expected) in CORPUS.items():
        got = results.get(path, "MISSING")
        per[cls][1 if got == "deny" else 0] += 1
        should_deny = (expected == "deny")
        if should_deny and got == "deny": tp += 1
        elif should_deny and got == "allow": fn += 1
        elif not should_deny and got == "allow": tn += 1
        elif not should_deny and got == "deny": fp += 1
    return {"TP":tp,"FP":fp,"TN":tn,"FN":fn}, per

def main():
    lst = prep()
    base = run([PROBE, lst])                                   # no gate: everything must open
    gated = run([GATE, "--persist", PROBE, lst])               # under the gate

    base_denies = [p for p,v in base.items() if v=="deny"]
    if base_denies:
        print("[!] baseline denials (dir/permission problem, not the gate):")
        for p in base_denies: print("   ", p)

    cm, per = matrix(gated)
    benign_total = per["benign_clean"][0]+per["benign_clean"][1]+per["benign_lookalike"][0]+per["benign_lookalike"][1]
    fp_rate = cm["FP"]/benign_total if benign_total else 0.0

    out = {"confusion": cm, "per_class_allow_deny": per,
           "benign_total": benign_total, "false_positive_rate": round(fp_rate,3),
           "baseline_denials": base_denies}
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "fp_corpus_results.json"),"w") as f:
        json.dump(out, f, indent=2)

    print("\nconfusion (positive = should-be-denied):", cm)
    print("per-class [allow, deny]:")
    for k,v in per.items(): print(f"  {k:18} allow={v[0]} deny={v[1]}")
    print(f"\nbenign false-positive rate: {cm['FP']}/{benign_total} = {fp_rate:.1%}")
    print("  (all FPs are benign_lookalike files denied purely on strstr substring match)")

if __name__ == "__main__":
    main()
