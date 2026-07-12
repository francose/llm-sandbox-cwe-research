# Detector-coverage experiment: which memory-corruption classes fall through the whole commodity tool stack

Machine: x86_64, WSL2 kernel 6.18, gcc 11.4, clang 14, valgrind 3.18.1, cppcheck 2.7.
Harness: `detector_matrix.py`. Raw per-cell evidence: `detector_matrix_results.jsonl`.

## Hypothesis (stated to be falsifiable)

**H1:** At least one memory-corruption class evades *every* commodity detector we can
point at it (two compilers' warnings, gcc `-fanalyzer`, clang analyzer, cppcheck,
LTO, FORTIFY, ASan, UBSan, Valgrind). Falsified if some single tool catches all six
classes; the specific "intra-object overflow is a total gap" sub-claim is falsified
if any one tool flags it.

## Definitions: what counts as "silent" and what does not

Every outcome is one of five states, decided operationally from the process result,
the presence of a defense diagnostic, and the probe's own self-check (each probe
verifies its corruption took effect: canary overwritten, guard word clobbered, secret
bytes recovered, buffer wrapped). The self-check is what makes "silent" a positive
measurement rather than an absence of noise.

- **silent** — the corruption is *confirmed to have happened* (the probe self-check
  reports `outcome=corrupted`), the process exited normally (exit 0), and no defense
  emitted any diagnostic. This is the dangerous state: a real, usable corruption
  primitive that nothing flagged. Because the self-check confirms the effect, "silent"
  cannot be an artifact of the optimizer eliding the bug (that would report `clean`).

- **detected** — a defense identified the memory error by name and stopped the process:
  ASan (`AddressSanitizer`), UBSan (`runtime error:`), FORTIFY (`buffer overflow
  detected` / `__chk`), the stack canary (`stack smashing detected`), Valgrind
  (`Invalid write/read/free`), or a compile-time memory-safety warning. Non-zero exit
  *with* a naming diagnostic.

- **crashed** — the corruption drove the process into a raw SIGSEGV/SIGBUS/SIGABRT with
  **no** defense diagnostic. This is not a catch and it is not silent: the bug executed
  and faulted. Security impact is denial of service, not a controlled primitive.
  (Example: the `-O0` stack case on aarch64 died with SIGBUS; that is `crashed`, not
  `detected` — an important distinction the original write-up blurred.)

- **prevented** — the unsafe operation was refused before any corruption occurred (the
  allocation returns NULL or the tool aborts at the call site) and the self-check
  reports `clean`. The bug never took effect.

- **clean** — the bug did not trigger on this input (self-check reports `clean`, no
  fault, no diagnostic).

"Silent vs not" therefore means: **silent** is the exploitable-and-undetected state;
**not silent** is any of {detected, crashed, prevented, clean}, and only *detected*
and *prevented* are actual safety wins — *crashed* merely downgrades the bug to DoS.

Two axes are reported per class:
1. **Shipped-build state** — what the real production bundle (`-O2 -D_FORTIFY_SOURCE=2`,
   default stack protector) does. This is where "silent" is measured.
2. **Detector coverage** — whether any opt-in tool (ASan, UBSan, Valgrind, the static
   analyzers) can catch it in a non-production build.

## Method

Six minimal probes, one per class. Ten independent detectors. Each runtime detector
is built in isolation (other runtime defenses turned off with
`-fno-stack-protector -D_FORTIFY_SOURCE=0`) so a catch is attributed to the tool that
actually fired, not to a stack canary masquerading as ASan/UBSan. A compile-time
catch is counted only when a memory-safety diagnostic fires (compiler meta-warnings
like "unknown warning option" are filtered out).

**Validity note (a harness bug we caught before reporting):** the first run passed
clang a gcc-only flag (`-Wstringop-overflow=4`); clang printed "unknown warning
option", and a loose regex matched the word "stringop-overflow" and scored every
clang cell as CAUGHT. That was a false positive across the whole clang column. Fixed
by using clang-valid flags and excluding meta-warning lines, then re-run. Every
CAUGHT cell below was then re-opened and confirmed against its raw output.

## Results

### Axis 1 — state of the shipped `-O2 -D_FORTIFY_SOURCE=2` build (verified per definition)

| class | shipped-build state |
|---|---|
| ABI skew (843+787) | **silent** |
| intra-object overflow (787) | **silent** |
| heap overflow (787) | **silent** |
| stack overflow (787) | detected (FORTIFY: "buffer overflow detected") |
| use-after-free (416) | **silent** |
| int-overflow alloc (190) | **silent** |

**5 of 6 run silent in the shipped build; only the stack overflow is detected.** Each
`silent` was confirmed by the probe self-check reporting `outcome=corrupted` with exit 0
and no diagnostic — not merely by absence of an error.

### Axis 2 — detector coverage (CAUGHT / miss), verified against raw evidence

| class | gcc-warn | clang-warn | gcc-fanalyzer | clang-analyze | cppcheck | gcc-lto | FORTIFY | ASan | UBSan | Valgrind |
|---|---|---|---|---|---|---|---|---|---|---|
| ABI skew (843+787) | miss | miss | miss | miss | miss | miss | miss | CAUGHT* | miss | CAUGHT* |
| **intra-object overflow (787)** | miss | miss | miss | miss | miss | miss | miss | **miss** | **miss** | **miss** |
| heap overflow (787) | miss | miss | miss | miss | miss | miss | miss | CAUGHT | CAUGHT | CAUGHT |
| stack overflow (787) | miss | miss | miss | miss | miss | miss | CAUGHT | CAUGHT | miss | miss |
| use-after-free (416) | miss | miss | miss | miss | miss | miss | miss | CAUGHT | miss | CAUGHT |
| int-overflow alloc (190) | miss | miss | miss | miss | miss | miss | miss | CAUGHT** | miss | miss |

\* ABI skew: ASan/Valgrind catch only the *spatial* half (a 4-byte write past the
heap block: ASan "heap-buffer-overflow WRITE of size 4", Valgrind "Invalid write of
size 4"). The *type-confusion* half (consumer reads value=0x00000000 from the wrong
offset) is caught by nobody.

\** int-overflow: ASan catches it only as a `calloc` overflow *refusal*
("calloc parameters overflow ... cannot be represented in type size_t"), aborting
before the undersized-`malloc` write is exercised. It does not detect the wrap itself.
UBSan correctly ignores it because unsigned overflow is defined behavior, not UB.

## What is confirmed

1. **H1 holds. The intra-object field overflow is a total gap: missed by all ten
   detectors.** Every runtime tool ran it to completion showing the adjacent field
   overwritten (`canary=0x4141414141414141`) and reported no error. The reason is
   structural, not a tuning miss: the write stays inside one valid allocation
   (`buf[8]` + adjacent field = the 16-byte object), so no allocation-boundary
   checker (ASan, Valgrind) has a boundary to trip on, and no static pass flags it.

2. **Commodity static analysis caught 0 of 6.** gcc/clang warnings, gcc `-fanalyzer`,
   the clang analyzer, cppcheck, and LTO were all silent on every class. Runtime-
   derived and volatile sizes defeat static size inference, and cross-translation-unit
   ABI skew is structurally invisible to a single-TU analyzer (LTO did not warn either).

3. **The allocation-boundary bugs (heap OOB, UAF) are caught only by ASan and
   Valgrind** — neither of which ships in a production build. FORTIFY caught only the
   stack case. So in a shipped `-O2 -D_FORTIFY_SOURCE=2` binary, heap OOB and UAF run
   silent.

## What is refuted (reported honestly)

The naive claim "commodity runtime tools can't catch these memory bugs" is **false.**
ASan and Valgrind catch four of six (heap, UAF, and the spatial halves of ABI skew
and stack). The real, narrower result is that the gap is specific: the intra-object
class, plus the *semantic* halves (ABI type-confusion, the integer wrap) that have no
spatial footprint to detect.

## The attack-vector reading

The undetected class is not academic. A field-to-field overflow inside one allocation
is how you overwrite an adjacent length, flag, or function-pointer field that lives in
the same struct as a buffer (the probe overwrites an `is_admin`-style field; the repo's
`cwe787_cfi_hijack` case overwrites a function pointer). An adversary — or an LLM
generating struct-heavy C over attacker-controlled input — that produces this class
gets a corruption primitive that **no tool in the build, CI, or production-runtime
stack tested here will flag.** That is the defensible weakness this experiment
establishes.

## H2 — does the intra-object gap hold across toolchains?

Ran the six probes through five compilers (gcc-11, gcc-12, clang-14, clang-15, tcc)
for compile warnings, through FORTIFY levels 2 and 3, and through ASan from both gcc
and clang. Harness: `h2_toolchain.py`, data: `h2_toolchain_results.jsonl`.

**Verdict: the intra-object gap holds across every toolchain tested.**
- No compiler warned on it (gcc-11, gcc-12, clang-14, clang-15, tcc all silent).
- Shipped state is `silent` under gcc-12 FORTIFY=2, gcc-12 FORTIFY=3, clang-15
  FORTIFY=2, and tcc.
- ASan missed it under both gcc-12 and clang-15.
- The miss is corroborated three ways: the gcc ASan miss matches the main matrix, five
  independent compilers agree, and the structural argument (no allocation boundary is
  crossed) predicts it. This is the most robust result in the study.

**Two honest findings from the wider run:**
- **gcc-12 improved.** It emits a compile-time `-Wuse-after-free` warning on the UAF
  probe where gcc-11 stays silent. So the UAF static-detection cell is toolchain-
  version dependent (gcc-12 catches it, gcc-11/clang-14/clang-15/tcc do not). The
  intra-object cell is not affected.
- **The shipped 5-of-6-silent pattern is stable** across all five compilers and both
  FORTIFY levels on x86_64; only the stack overflow is detected (it `crashed` under
  tcc, which ships no FORTIFY, versus `detected` under gcc/clang).

**Harness caveat (disclosed):** the H2 clang-ASan column had a result-capture bug that
falsely marked some clang-15 ASan runs as "miss" (UAF and int-overflow). Direct
re-execution of the exact build+run commands showed clang-15 ASan does catch the UAF
(`heap-use-after-free READ of size 16`, exit 134). The per-cell clang-ASan values are
therefore taken from direct verification, not that column. The intra-object verdict
does not depend on it.

## H3 (pilot) — does real LLM-generated C produce this class?

Gave a local code model (qwen2.5-coder:7b, temp 0) twelve security-neutral tasks, each
of which naturally involves a struct with a fixed `char[N]` field filled from
variable-length input (packet parse, kv parse, deserialize record, build email, etc.).
No security framing. Then classified each snippet with the same detector stack plus a
risky-pattern scan, and **hand-verified every flagged snippet, confirming the real ones
under ASan with adversarial input.** Harness: `h3_llm_c.py`; snippets: `h3_snippets/`;
ASan repros: `h3_verify/`.

**Why hand-verification was necessary:** the pattern scan flagged 4 of 12 as unsafe. On
inspection, 2 of those 4 (`parse_kv`, `parse_header`) actually guard the copy with a
length check and are safe — heuristic false positives. The scan is a screen, not the
result.

**Verified result (confirmed under ASan, adversarial input):**

| snippet | defect | confirmed | caught by commodity static stack? |
|---|---|---|---|
| `parse_packet` | off-by-one: checks `len > 64` then writes `payload[len]='\0'`, so `len==64` writes 1 past the buffer | ASan: `heap-buffer-overflow WRITE of size 1` | **no** — gcc `-Wall`, `-fanalyzer`, cppcheck all silent |
| `deserialize_record` | no length parameter; `memcpy(name,bytes,20)` then reads `bytes+20` unbounded, never null-terminates | ASan: `heap-buffer-overflow READ of size 4` | partially — cppcheck flagged it |

- **2 of 12 snippets contain a confirmed memory-corruption bug** (plus 1 borderline:
  `parse_csv` has a missing-null-terminator edge case and writes through a `const`
  string via `strtok`). The model was mostly defensive — 9 of 12 used a bounded
  primitive (`strncpy`/`snprintf`) correctly.
- **The two real bugs are subtle** — an off-by-one on the null terminator and an
  unbounded deserialization — not the naive `strcpy` overflow the pattern scan assumed.
  These are exactly the shapes that show up as real-world CVEs.
- **The connecting result:** `parse_packet`'s off-by-one evaded the *entire* commodity
  static stack (two compilers' warnings, `-fanalyzer`, cppcheck) and was caught only by
  ASan, which does not ship to production. Note the precise claim: `payload` is the last
  struct field, so this overflow crosses the allocation boundary and ASan *does* catch it —
  it instantiates the **static-layer** gap, not the ASan-invisible intra-object gap.

**Pilot scope:** one 7b model, temperature 0, twelve prompts, one sample each — a
*tendency*, not a rate. The scaled run below turns this into a measured rate.

## H3 (scaled) — measured rate across 3 models

Harness `h3_full.py` (`--calibrate` then `--run`); data `h3_full_results.jsonl`; snippets
`h3_full_snippets/`. 18 fixed-buffer tasks, uniform contract `void fn(struct S*, const
char* input)`, 3 local models, 4 samples each (temp 0 + 3 at 0.6) = **216 generations**.
Ground truth is a single-TU, ASan-backed oracle; every driver calibrated 18/18 against a
golden-safe (`strncpy`+null) and golden-vuln (`strcpy`) reference before use. Every
confirmed cell hand-verified.

**Verified numbers (after hand-verification):**

- **213 usable** (3 `compile_fail`: a corrupted generation, a write-to-`const`, a
  `typedef`'d struct — all contract deviations, all excluded; the typedef one has an
  unbounded copy in its logic so exclusion keeps the rate a lower bound).
- **11/213 = 5.2%** (95% CI 3–9%) ASan-confirmed spatial overflow. **Lower bound.**

| model | confirmed / usable | rate | 95% CI |
|---|---|---|---|
| qwen2.5-coder:1.5b | 10/70 | 14.3% | 8–24% |
| deepseek-coder:6.7b | 1/71 | 1.4% | 0–8% |
| qwen2.5-coder:7b | 0/72 | 0.0% | 0–5% |

- **The static layer is blind to this class:** of the 11 confirmed overflows, the commodity
  static stack (gcc `-Wall -Wextra`, `-fanalyzer`, cppcheck) diagnosed the overflow in
  **0/11**. 8/11 drew zero diagnostics; 3/11 drew an *unrelated* warning on the function
  (`-Wstringop-truncation` ×1 about null-termination, `-Wsign-compare` ×2) but not the
  overflow ASan confirmed. Reason: these are input-length-dependent writes in a function
  analyzed in isolation — undecidable at compile time. Only runtime ASan caught them, and
  ASan does not ship.
- **Model size dominates** (observation, wide CIs, 3 points): the 1.5b model produced the
  class 10× more than the 7b models.
- **Intra-object-invisible in generated code: 0.** The one candidate our intra-object
  oracle (B) flagged — `qwen1.5b set_channel s3` — was a **false positive**: the function
  legitimately assigns its trailing field (`s->count = 1`), which tripped the sentinel with
  no overflow. Removed by hand-verification. All 11 confirmed findings rest on oracle A
  (ASan); **oracle B produced 0 true positives and 1 FP** this run.
- **The honest bridge to H1/H2:** `qwen1.5b parse_kv` overflows `key[16]` with an unbounded
  loop; its ASan report reads `0 bytes to the right of [the] 64-byte region`, i.e. the write
  passes *through* the adjacent `val[48]` field (offsets 16–63 of the 64-byte struct) and
  faults only at the allocation boundary. Bounded to the struct — as other samples were —
  the same `key`→`val` overwrite would be an intra-object write ASan cannot see: the H1
  probe arrived at from generated code. The connection to H1/H2 is at the **layer** level
  (static misses all 11; runtime ASan is blind to the intra-object subclass), not a claim
  that generated code produced an ASan-invisible bug in this sample.

## Threats to validity

- One machine, one gcc/clang/valgrind version. The intra-object result is structural
  (boundary-based tools cannot see intra-allocation writes) so it should generalize,
  but it should be re-run on another toolchain to confirm.
- "Standard configuration" of each tool. A non-default ASan build with intra-object
  red zones (`-fsanitize-address-field-padding`) can catch some intra-object overflows,
  but it is C++-oriented, requires opt-in, and is not part of any shipped build — so the
  practical gap stands. This caveat must be stated, not omitted.
- The H1 probes are minimal reproducers, not harvested LLM output. H1 measures
  *detector coverage of the class* in isolation; the separate question of whether
  LLM-generated C actually produces this class is answered by H3 above (generate +
  classify + ASan-confirm on 12 realistic tasks), which found 2 confirmed bugs, one of
  which evades the same shipped static stack H1 measures. The H3 scope caveat (one 7b
  model, single samples: tendency not rate) applies.
