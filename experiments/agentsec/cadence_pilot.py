#!/usr/bin/env python3
"""
P14 cadence pilot -- REAL DATA, not a drawing.

Measures the inter-action interval (time between an actor issuing successive
discrete actions) for three actors on THIS host, at the actor's DECISION layer:

  script     : automation -- a tight loop, one real syscall per action
  agent      : a live ollama decision loop -- model emits one action per round-trip
  script_mimic: automation with random sleeps drawn to imitate the agent
               (control: if this matches the agent, raw cadence cannot attribute)

Reports per actor: n, mean/median/min/max ms, coefficient of variation (std/mean),
and burstiness B = (std-mean)/(std+mean) in [-1,1]:
  B ~ -1  perfectly regular (metronome)   B ~ 0  Poisson   B > 0  bursty.

Honest scope: single host, one small model, non-adversarial, decision-layer timing.
This tests ONE row of the P14 matrix (execution/decision cadence). It does NOT
test the gate-reaction signal, and it is not external-validity evidence.
"""
import json, os, statistics as st, subprocess, sys, time, urllib.request, random

OLLAMA = "http://127.0.0.1:11434/api/generate"
MODEL = "qwen2.5-coder:1.5b"
N = 18                       # actions per actor
TMP = "/tmp/agentsec_cadence"; os.makedirs(TMP, exist_ok=True)
random.seed(1414)            # fixed: Date/random unavailable-in-workflow discipline; reproducible

def deltas_ms(ts_ns):
    return [(ts_ns[i] - ts_ns[i-1]) / 1e6 for i in range(1, len(ts_ns))]

def summarize(name, ts_ns):
    d = deltas_ms(ts_ns)
    mean = st.mean(d); std = st.pstdev(d)
    cv = std / mean if mean else 0.0
    B = (std - mean) / (std + mean) if (std + mean) else 0.0
    return {
        "actor": name, "n_actions": len(ts_ns), "n_intervals": len(d),
        "mean_ms": round(mean, 3), "median_ms": round(st.median(d), 3),
        "min_ms": round(min(d), 3), "max_ms": round(max(d), 3),
        "std_ms": round(std, 3), "cv": round(cv, 3), "burstiness_B": round(B, 3),
        "intervals_ms": [round(x, 3) for x in d],
    }

# ---- actor 1: script (automation) -- one real openat per action, as fast as it can
def run_script():
    ts = []
    p = os.path.join(TMP, "s.txt")
    for _ in range(N):
        ts.append(time.perf_counter_ns())
        fd = os.open(p, os.O_WRONLY | os.O_CREAT, 0o644)  # real syscall
        os.write(fd, b"x"); os.close(fd)
    return ts

# ---- actor 2: live LLM agent -- one decision (generated command) per round-trip
def gen(prompt):
    body = json.dumps({"model": MODEL, "prompt": prompt, "stream": False,
                       "options": {"temperature": 0.4, "num_predict": 40}}).encode()
    req = urllib.request.Request(OLLAMA, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())

def run_agent():
    ts = []; history = []
    goal = ("You are an agent setting up a small project directory. Each turn output "
            "exactly ONE shell command and nothing else -- no prose, no backticks.")
    for i in range(N):
        ctx = goal + "\nHistory:\n" + "\n".join(history[-6:]) + "\nNext single command:"
        out = gen(ctx)
        ts.append(time.perf_counter_ns())          # timestamp when the decision lands
        cmd = (out.get("response") or "").strip().splitlines()[0][:120] if out.get("response") else "(none)"
        history.append(f"$ {cmd}")
    return ts, history

# ---- actor 3: script mimicking the agent -- random sleeps in the agent's range
def run_script_mimic(agent_deltas_ms):
    lo, hi = min(agent_deltas_ms), max(agent_deltas_ms)
    ts = []
    for i in range(N):
        ts.append(time.perf_counter_ns())
        if i < N - 1:
            time.sleep(random.uniform(lo, hi) / 1000.0)  # fake "thinking"
    return ts

def main():
    results = {}
    print(f"[*] script (automation), N={N} ..."); s_ts = run_script()
    results["script"] = summarize("script", s_ts)

    print(f"[*] live agent ({MODEL}), N={N} round-trips (this takes a bit) ...")
    a_ts, hist = run_agent()
    results["agent"] = summarize("agent", a_ts)
    results["agent"]["sample_commands"] = hist[:6]

    print(f"[*] script_mimic (automation faking agent cadence), N={N} ...")
    m_ts = run_script_mimic(results["agent"]["intervals_ms"])
    results["script_mimic"] = summarize("script_mimic", m_ts)

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cadence_pilot_results.json")
    with open(out, "w") as f:
        json.dump({"model": MODEL, "N": N, "host_note": "single host, non-adversarial pilot",
                   "results": results}, f, indent=2)

    print("\n{:<14} {:>8} {:>9} {:>9} {:>7} {:>8}".format("actor","mean_ms","median","std_ms","CV","burst_B"))
    for k in ("script","agent","script_mimic"):
        r = results[k]
        print("{:<14} {:>8} {:>9} {:>9} {:>7} {:>8}".format(
            k, r["mean_ms"], r["median_ms"], r["std_ms"], r["cv"], r["burstiness_B"]))
    print(f"\n[*] raw intervals + stats -> {out}")

if __name__ == "__main__":
    main()
