# Ollama GGUF RCE Viability Assessment

**Date:** 2026-05-26
**Scope:** Source code audit of latest Ollama main branch (post v0.24.0)
**Goal:** Determine if a malicious GGUF file can achieve RCE on the Ollama host

---

## Executive Summary

**RCE via malicious GGUF: LOW viability in current code.** Go's memory safety, content-addressed blob storage, and digest validation close the direct RCE paths. No Ollama-specific RCE vector was found that doesn't require either (a) a separate 0day in llama.cpp's C++ parser, or (b) chaining with non-GGUF vulnerabilities.

---

## Architecture Overview

The GGUF processing pipeline has two layers:

1. **Go layer** (`fs/gguf/`, `fs/ggml/`): Reads KV metadata, tensor headers, validates bounds. Memory-safe. Panics on malformed input = DoS only.
2. **C++ layer** (llama.cpp): Loads tensor weights into memory for inference. Receives a **file path** from Go, opens and parses GGUF independently.

```
Upload:  POST /api/blobs/sha256:<digest>   → blob stored at models/blobs/sha256-<hex>
Create:  POST /api/create                   → ggufLayers() parses Go-side, llama.LoadModelFromFile() loads C-side
Run:     POST /api/generate                 → spawns runner subprocess, passes --model <blob path>
```

---

## Attack Surfaces Analyzed

### 1. Go GGUF Parser (`fs/gguf/gguf.go`)

| Finding | Detail |
|---------|--------|
| Magic check | Rejects `gguf` magic at line 60 (note: inverted logic — `gguf` magic is treated as unsupported, non-GGUF passes through) |
| String allocation | `readString()` at line 188: reads `uint64` length, allocates `make([]byte, n)`. Large value = OOM panic (DoS) |
| Array allocation | `readArrayData()` at line 248: `make([]T, n)` with `uint64 n`. Overflow causes panic (REPORT-05) |
| Tensor validation | `NumValues()` at `tensor.go:20`: `int64` multiplication of `uint64` dims. Can overflow silently |
| **RCE potential** | **NONE** — Go bounds checks prevent out-of-bounds memory access |

### 2. Blob Storage Path (`manifest/paths.go:40`)

Only accepts canonical sha256 hex digests. Digest becomes filename, not path component. No traversal.

**RCE potential: NONE**

### 3. Runner Subprocess (`llm/server.go:334`)

Binary path via `os.Executable()`, model path via validated blob digest. No user-controlled strings reach `exec.Command`.

**RCE potential: NONE**

### 4. Symlink Creation (`server/create.go:870`)

`createLink()` is used in safetensors path only. GGUF path doesn't call it. Safetensors path guarded by `io/fs.ValidPath`.

**RCE potential: NONE**

### 5. Template Injection via GGUF Metadata (`server/model.go:80`)

`detectChatTemplate()` reads `tokenizer.chat_template` from GGUF KV → fuzzy matches against hardcoded template names only. No arbitrary template injection.

**RCE potential: NONE** (behavioral manipulation only)

### 6. llama.cpp C++ Parser

The only realistic RCE surface — but requires a llama.cpp 0day, not an Ollama vuln.

**RCE potential: MEDIUM** — fuzz `gguf.cpp` and `ggml.c` directly.

### 7. `ggufLayers()` Flow (`server/create.go:676`)

Digest → `manifest.BlobsPath(digest)` → validated path → `os.Open(blobPath)` → `ggml.Decode(blob)`. No user-controlled path components.

**RCE potential: NONE**

---

## Non-RCE Attacks That ARE Possible

| Attack | Vector | Impact |
|--------|--------|--------|
| Weight Hijack | Malicious GGUF via `/api/create` with constant-output tensors | Persistent model output control |
| DoS (panic) | Integer overflow in array count (REPORT-05) | Process crash |
| DoS (SIGFPE) | Division by zero in `gguf.cpp:550` when `ne[1]=0` (REPORT-11) | Process crash |
| ~~Data corruption~~ | ~~Stride overflow (REPORT-10)~~ | **NOT EXPLOITABLE** — blocked by element count check at line 550 |
| DoS (OOM) | `block_count = U32_MAX` → 18 EB allocation (REPORT-06) | OOM kill |
| DoS (panic) | Type assertion on `info` field (REPORT-04) | Process crash |
| Model Exfil | `/api/copy` + `/api/push` to attacker server | Full model weights stolen |
| SSRF | `/api/pull` with attacker-controlled registry | Internal network scanning |
| Template Hijack | `tokenizer.ggml.chat_template` KV in GGUF | Behavioral manipulation |

---

## Recommended RCE Research Directions

1. **Fuzz llama.cpp's GGUF parser** — the only realistic RCE surface. Focus on:
   - Edge cases in quantized tensor block deserialization
   - `check_tensor_dims` bypass scenarios
   - Conversion paths (`gguf_fp16_to_fp32`, `gguf_bf16_to_fp32`)

2. **Audit `ggml.c` tensor operations** — integer overflow in stride calculations during `ggml_mul_mat` → heap overflow during inference

3. **Environment variable injection** — check if any `GGML/LLAMA_*` env vars can be influenced via API

4. **Future vector** — if Ollama adds structured workflow support (like ComfyUI JSON), that's a new deserialization attack surface

---

## Key Source Files

| File | Purpose |
|------|---------|
| `fs/gguf/gguf.go` | Go-side GGUF parser (KV + tensor headers) |
| `fs/gguf/tensor.go` | Tensor type/size calculations |
| `fs/ggml/ggml.go` | GGML container decoder, graph size estimation |
| `fs/ggml/gguf.go` | GGUF format decoder (second Go parser) |
| `server/create.go` | Model creation endpoint, `ggufLayers()`, `createLink()` |
| `server/images.go` | Model loading, `GetModel()`, path resolution |
| `server/sched.go` | Scheduler, model loading, runner spawning |
| `llm/server.go` | `LoadModel()`, `StartRunner()`, subprocess execution |
| `manifest/paths.go` | `BlobsPath()` digest validation |
| `manifest/layer.go` | `NewLayer()`, `NewLayerFromLayer()`, blob storage |
| `server/model.go` | `detectChatTemplate()`, template auto-detection |
