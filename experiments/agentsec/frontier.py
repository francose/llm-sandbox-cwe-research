#!/usr/bin/env python3
"""
Frontier-model provider router. Reads API keys from the ENVIRONMENT only (never hardcoded, never
printed, never committed). Routes generate(model, prompt) by model-name prefix so the rest of the
harness (compile, strace oracle, enum, concealment) is unchanged.

  claude-*            -> Anthropic Messages API   (env ANTHROPIC_API_KEY)
  gpt-*, o1*, o3*     -> OpenAI Chat Completions   (env OPENAI_API_KEY)
  gemini-*            -> Google Generative Language (env GEMINI_API_KEY)

No third-party SDKs; urllib only.
"""
import json, os, urllib.request, urllib.error

def _post(url, body, headers, timeout=120):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {e.read().decode()[:300]}")

def _anthropic(model, prompt, max_tokens):
    key = os.environ["ANTHROPIC_API_KEY"]
    d = _post("https://api.anthropic.com/v1/messages",
              {"model": model, "max_tokens": max_tokens,
               "messages": [{"role": "user", "content": prompt}]},
              {"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    return "".join(b.get("text", "") for b in d.get("content", []))

def _openai(model, prompt, max_tokens):
    key = os.environ["OPENAI_API_KEY"]
    body = {"model": model, "messages": [{"role": "user", "content": prompt}]}
    body["max_completion_tokens"] = max_tokens          # GPT-5-class param
    d = _post("https://api.openai.com/v1/chat/completions", body,
              {"Authorization": f"Bearer {key}", "content-type": "application/json"})
    return d["choices"][0]["message"]["content"] or ""

def _gemini(model, prompt, max_tokens):
    key = os.environ["GEMINI_API_KEY"]
    # key in the x-goog-api-key header, never in the URL query string (avoids leaking it via logs/proxies)
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    d = _post(url, {"contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"maxOutputTokens": max_tokens}},
              {"content-type": "application/json", "x-goog-api-key": key})
    cands = d.get("candidates", [])
    if not cands: return ""
    return "".join(p.get("text", "") for p in cands[0].get("content", {}).get("parts", []))

def generate(model, prompt, max_tokens=800):
    m = model.lower()
    if m.startswith("claude"): return _anthropic(model, prompt, max_tokens)
    if m.startswith(("gpt", "o1", "o3", "o4")): return _openai(model, prompt, max_tokens)
    if m.startswith("gemini"): return _gemini(model, prompt, max_tokens)
    raise ValueError(f"unknown provider for model {model!r}")

if __name__ == "__main__":
    import sys
    model = sys.argv[1] if len(sys.argv) > 1 else "claude-sonnet-5"
    print(generate(model, "Reply with exactly the word: ok", max_tokens=16)[:80])
