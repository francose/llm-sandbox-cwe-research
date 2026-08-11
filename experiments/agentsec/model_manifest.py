#!/usr/bin/env python3
"""
model_manifest.py -- provenance + reproducibility class for every model a Part III run touches.

Why this exists: a Part III run touches models that differ on two INDEPENDENT axes, and collapsing
them into one "reproducible" flag is exactly the overclaim this file was written to prevent.

Axis 1 -- IDENTITY. Is the thing being served content-addressed?

  * A local GGUF model (llama3.2:3b, qwen2.5-coder:*, deepseek-coder:6.7b) is a weight file with a
    content digest, so "which weights ran" is answerable after the fact.
  * A ":cloud" tag (glm-5.2:cloud, kimi-k3:cloud, gemma4:cloud) is a ~300-byte manifest stub pointing
    at a provider-hosted checkpoint. The provider can swap the served weights under the same tag
    without the local digest changing, so identity is tag-only and any result is a DATED OBSERVATION.

Axis 2 -- DETERMINISM. Does the same seed actually produce the same bytes on this host and build?

  This is NOT implied by axis 1 and must never be inferred from it. Ollama documents a model digest
  and a seed option; neither guarantees byte-identical behaviour across builds, backends, or hardware
  (llama.cpp seed reproducibility is scoped to a fixed build and a fixed float-reduction order --
  change the build, the CPU/GPU split, or the thread/batch shape and the reduction order can change
  with it). The only evidence that determinism holds is an empirical two-run gate that ran here.
  That gate is reproduce_part3.sh; it writes its verdict to determinism_evidence.json, and this file
  REPORTS that verdict rather than predicting it. A model with a perfect digest and no recorded gate
  run is `determinism="unverified"`, not deterministic.

  Ollama API reference: https://github.com/ollama/ollama/blob/main/docs/api.md

resolve() reports both axes separately. repro_class is derived from the pair and is "exact-seed" only
when identity is content-addressed AND determinism was verified on this environment.
"""
import json, os, platform, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
EVIDENCE_FILE = os.path.join(HERE, "determinism_evidence.json")

TAGS = "http://127.0.0.1:11434/api/tags"
SHOW = "http://127.0.0.1:11434/api/show"
VERSION = "http://127.0.0.1:11434/api/version"


def _get(url, body=None, to=30):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data,
                                 headers={"content-type": "application/json"} if data else {})
    with urllib.request.urlopen(req, timeout=to) as r:
        return json.loads(r.read())


def _tags():
    return {m["name"]: m for m in _get(TAGS)["models"]}


def _env():
    """Capture the runtime facts seed-determinism is scoped to.

    llama.cpp seed reproducibility holds for a fixed build and a fixed float-reduction order; change
    the ollama build, the backend (CPU vs GPU), or the thread/batch shape and the reduction order can
    change with it. So "byte-identical" is scoped to THIS host + build, not a universal property --
    recording these fields keeps the reproducibility claim honest rather than overstated.
    """
    try:
        ver = _get(VERSION, to=5).get("version", "unknown")
    except Exception:
        ver = "unreachable"
    return {
        "ollama_version": ver,
        "host": platform.platform(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "ollama_num_threads_env": os.environ.get("OLLAMA_NUM_THREADS", "default"),
        "scope_note": ("Seed determinism is scoped to this ollama build + backend + thread/batch "
                       "shape. A reader on a different build or GPU/CPU split may get a different "
                       "but internally-consistent tree; re-run the gate on the target host to confirm."),
    }


def env_fingerprint(env=None):
    """Short hash of the facts seed determinism is scoped to. A verdict recorded under one
    fingerprint says nothing about a host with a different one."""
    import hashlib
    e = env if env is not None else _env()
    key = "|".join(str(e.get(k)) for k in
                   ("ollama_version", "machine", "cpu_count", "ollama_num_threads_env"))
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def load_evidence():
    """Recorded two-run gate verdicts, keyed by model. Absent file means nothing was ever verified."""
    try:
        with open(EVIDENCE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def record_determinism(model, verified, hashes, env=None):
    """Append this host's empirical verdict for one model. Called by the two-run gate, not inferred."""
    ev = load_evidence()
    e = env if env is not None else _env()
    ev[model] = {
        "verified": bool(verified),
        "runs": len(hashes),
        "core_hashes": [h[:16] for h in hashes],
        "env_fingerprint": env_fingerprint(e),
        "ollama_version": e.get("ollama_version"),
        "machine": e.get("machine"),
    }
    with open(EVIDENCE_FILE, "w") as f:
        json.dump(ev, f, indent=1, sort_keys=True)
    return ev[model]


def resolve(model, tags=None, evidence=None, fp=None):
    """Provenance for one model, reporting identity and determinism as separate facts."""
    tags = tags if tags is not None else _tags()
    evidence = evidence if evidence is not None else load_evidence()
    fp = fp if fp is not None else env_fingerprint()
    t = tags.get(model, {})
    det = (t.get("details") or {})
    fmt = det.get("format") or ""
    size = t.get("size") or 0

    # Axis 1: a real local weight file is gguf and megabytes+; a :cloud stub is a ~300-byte pointer.
    content_addressed = (fmt == "gguf") and (size > 10_000_000) and not model.endswith(":cloud")

    # Axis 2: only what the two-run gate actually recorded, on an environment matching this one.
    rec = evidence.get(model)
    if not rec:
        determinism = "unverified"
    elif rec.get("env_fingerprint") != fp:
        determinism = "unverified-on-this-env"
    else:
        determinism = "verified" if rec.get("verified") else "refuted"

    if not content_addressed:
        repro_class = "dated-observation"
    elif determinism == "verified":
        repro_class = "exact-seed"
    elif determinism == "refuted":
        repro_class = "identity-pinned-nondeterministic"
    else:
        repro_class = "identity-pinned-determinism-unverified"

    ps = det.get("parameter_size") or ""
    if ps.isdigit():                      # glm-5.2:cloud reports raw int 756162687872; normalise
        n = int(ps)
        ps = f"{n/1e9:.0f}B" if n >= 1e9 else str(n)
    return {
        "model": model,
        "digest": (t.get("digest") or "")[:16],
        "size_bytes": size,
        "format": fmt or ("remote" if model.endswith(":cloud") else "unknown"),
        "param_size": ps,
        "quant": det.get("quantization_level") or "",
        "identity": "content-addressed" if content_addressed else "tag-only",
        "determinism": determinism,
        "determinism_evidence": rec,
        "repro_class": repro_class,
    }


def provenance(models, seed, params, served_date):
    """A provenance block to embed at the top of any Part III results file.

    served_date is caller-supplied (scripts here cannot call Date.now equivalents deterministically);
    it dates the unpinned-model observations. Pass an ISO date string.
    """
    tags = _tags()
    env = _env()
    fp = env_fingerprint(env)
    ev = load_evidence()
    recs = [resolve(m, tags, ev, fp) for m in models]
    return {
        "served_date": served_date,
        "seed": seed,
        "sampling": params,
        "env": env,
        "env_fingerprint": fp,
        "models": recs,
        "any_tag_only": any(r["identity"] == "tag-only" for r in recs),
        "any_determinism_unverified": any(r["determinism"] != "verified" for r in recs),
        "note": ("identity and determinism are separate facts. identity=tag-only means the provider "
                 "can swap the served checkpoint under the same tag, so the row is a dated "
                 "observation. determinism reports only what the two-run gate recorded on an "
                 "environment matching env_fingerprint; a content-addressed digest does not by "
                 "itself establish byte-identical behaviour across builds or hardware."),
    }


if __name__ == "__main__":
    import sys
    ms = sys.argv[1:] or list(_tags())
    tags, ev, fp = _tags(), load_evidence(), env_fingerprint()
    print(f"  env_fingerprint={fp}   (determinism verdicts below are scoped to it)")
    for r in (resolve(m, tags, ev, fp) for m in ms):
        print(f"  {r['model']:<22} identity={r['identity']:<17} "
              f"determinism={r['determinism']:<24} {r['repro_class']:<38} "
              f"digest={r['digest']:<18} {r['param_size']:<6}")
