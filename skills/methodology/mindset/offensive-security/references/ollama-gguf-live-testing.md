# REPORT-08: Ollama GGUF Attack Testing Results

**Date:** 2026-05-27
**Target:** Ollama v0.24.0 (local, CPU-only, Ubuntu 24.04, 4GB RAM)
**Model under test:** tinyllama

## Confirmed Working

### Weight Hijack (REPORT-01) — CONFIRMED
- 25KB malicious GGUF produces constant output regardless of prompt
- "pwned by bx0" output verified with 4 different prompts
- Tokenization artifacts from custom tokens outside standard 256-byte range
- SHA256: 50e81efb6acc5b0de2f98173f4a0ae87c016afd707ca0e7d0abace5d30b3a024

### Integer Overflow DoS (REPORT-05) — CONFIRMED
- 68-byte GGUF with UINT64_MAX array count crashes server at "parsing GGUF"
- No auto-restart without systemd
- SHA256: 013cdf35ccddc897859af98df1729be99809c3748a1067d9f63ed99379cf919

### SSRF via /api/pull — CONFIRMED (Enhanced)
- Working format: IP:port/namespace/model:tag (NOT IP:port/model:tag)
- Follows 307 redirects on same host, cross-host blocked
- User-Agent leaks: ollama/0.24.0 (amd64 linux) Go/go1.26.0
- Referer header leaks original request path

## Partially Working

### n_layer OOM DoS (REPORT-06) — MITIGATED
- Model creation succeeds, model appears in ollama list
- Inference fails with "unable to load model" 
- Go validation catches block_count=U32_MAX before C++ OOM path
- Improvement over original REPORT-06

### Template Injection via tokenizer.chat_template — BLOCKED
- All injection attempts blocked by levenshtein fuzzy matching (threshold < 100)
- Tested: known names, Jinja2 syntax, exec injection, env access, 10K string, binary garbage
- No template layer applied in any case

## NOT TESTED (requires additional setup)
- Type Assertion DoS (REPORT-04) — valid per source audit
- Model Exfiltration (REPORT-02) — requires remote OCI push server
- Mass Defacement (REPORT-03) — requires multiple models

## New Findings

### N1: Disk Space Exhaustion
- /api/blobs/ accepts arbitrary data with no size limit
- Unauthenticated — anyone can fill disk

### N2: Model Name Spoofing
- /api/create accepts any model name
- Can shadow legitimate registry names (e.g., "llama3:latest")

### N3: GGUF Magic Check Oddity
- fs/gguf/gguf.go:60 has inverted logic for magic check
- Doesn't affect attacks since ggml.Decode() has correct check

## RCE Viability: NOT ACHIEVED
- Go GGUF parser: memory-safe, panics only
- Template selection: fuzzy match blocks arbitrary injection
- Blob storage: content-addressed, digest-validated
- Runner subprocess: path from os.Executable(), model from digest
- llama.cpp C++: theoretical, requires separate 0day

## Ollama Deployment Notes (Disk-Constrained)

- Full ollama tar.zst is ~1.2GB, needs ~2GB free to extract
- Extract only CPU libs to save ~1GB: `bin/ollama`, `lib/ollama/libggml-base.so`, `lib/ollama/libggml-cpu-*.so`
- Skip CUDA/ROCm/Vulkan GPU libs if not needed
- Ollama crashes on startup if ANY manifest in cache references a corrupted GGUF — the model_show_cache hydrates ALL manifests at startup
- To recover: `find ~/.ollama/models/manifests -type f -delete` then re-pull legitimate models
- Registry pull fails with "no Location header in response" if upload endpoint doesn't return 202 + Location header
- Manifest path format: `manifests/<host>/<namespace>/<model>/<tag>` — tag uses `/` not `:` separator
