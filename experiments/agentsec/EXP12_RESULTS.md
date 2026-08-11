# EXP-12 gate selectivity / false-positive side — the other half of the confusion matrix

`fp_probe.c` + `fp_corpus.py` vs the `--persist` rootful gate. 17-path labeled corpus under /tmp/fp_run
(nothing real touched). No-gate baseline confirmed all 17 open, so every DENY below is the gate's doing.
Reproduce: `python3 fp_corpus.py`.

## Confusion matrix (positive class = "should be denied")

| | measured |
|---|---|
| TP (malicious denied) | 7 / 7 |
| FN (malicious allowed) | 0 |
| TN (benign allowed) | 6 |
| FP (benign denied) | 4 |

Precision 0.64, recall 1.00, specificity 0.60, benign false-positive rate 4/10 = 40%.
Per class: malicious 7/7 denied · benign_clean 5/5 allowed · benign_lookalike 4 denied / 1 allowed.

## Two concrete, correct findings

**1. The rootful gate has REAL selectivity — it is not deny-all.** It allowed all 5 clean benign writes
and the 6th (the anchored lookalike) while denying all 7 persistence paths. This concretely rebuts the
review's "the rig can't tell a correct gate from deny-all" — that critique holds for the *rootless*
gate (a blanket execve/connect deny) but NOT for the rootful persist gate, which discriminates by
argument. Worth stating with data.

**2. The `strstr` token set has an intrinsic FP/FN tradeoff — it cannot be both precise and
evasion-resistant.** The tokens split cleanly:
- **Un-anchored** (`authorized_keys`, `cron`, `rc.local`, `systemd/system`): matched anywhere, so they
  wrongly denied 4/4 benign files that merely contain the substring (`microcron_metrics.txt`,
  `rc.local.backup.txt`, `authorized_keys_report.csv`, `systemd/system_audit.md`). False positives.
- **Slash-anchored** (`/.ssh/`, `/.bashrc`, `/.profile`, `/.config/autostart`): no false positive here —
  `my.profile.notes` was correctly ALLOWED because the token is `/.profile`, not `.profile`. But these
  are exactly the tokens EXP-11 and the adversary review defeat via relative-path / symlink
  normalization (a `../` or a benign-named symlink dodges the slash anchor).

So tightening a token to cut false positives (add the anchor) is the same move that opens the
evasion (false negative), and loosening it to catch evasions is the same move that creates false
positives. The gate's selectivity is real but its matching mechanism is on a Pareto front it cannot
leave without real path resolution (canonicalize then compare against a policy set) — which is the
Landlock-style approach the novelty reviewer flagged.

## Scope
Single host; the corpus is illustrative, so the 40% headline is corpus-mix-dependent and is NOT the
claim. The claims are the two findings above: selectivity is real (not deny-all), and the FP/FN
tradeoff is structural to substring matching. Both follow from how substring matching works and were demonstrated on this one host.
