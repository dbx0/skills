# Ollama v0.30.7 Validation — Diff Analysis & New Vulnerabilities

**Date**: 2026-06-10
**Target**: Ollama v0.30.7 (upgraded from v0.24.0 on 192.168.0.15:11434)

## Breaking Change: Weight Hijack No Longer Works

The new llama-server backend (llama.cpp) has stricter vocabulary validation:

```
llama_model_load: error loading model: error loading model vocabulary:
basic_string::substr: __pos (which is 3) > this->size() (which is 1)
```

**Root cause**: The new llama-server validates 1:1 token-to-id mapping. Hand-crafted GGUFs with 260 vocab tokens (raw byte tokens + special tokens) are REJECTED. The old backend (v0.24.0) was lenient.

**Impact**: REPORT-01/16 weight hijack attacks are BROKEN on v0.30.7+. Existing v0.24.0 models also fail to load.

**Failed approaches tried**:
- `tokenizer.ggml.model = "gpt2"` with raw byte tokens -> substr error
- `tokenizer.ggml.model = "llama"` (SentencePiece) -> same substr error
- `tokenizer.ggml.model = "none"` -> same substr error (blob was cached)
- Pure ASCII tokens (printable 32-126 + two-letter combos) -> same substr error

## API Changes in v0.30.7

### `/api/create` Parameter Change
- **v0.24.0**: Uses `modelfile` parameter
- **v0.30.7**: Uses `from` parameter
- `modelfile` returns HTTP 400: "neither 'from' or 'files' was specified"

## New Vectors Found in v0.30.7

### 1. Chat Template Capability Injection (REPORT-17)
- `tokenizer.chat_template` KV containing "tools" triggers `CapabilityTools`
- **Status**: Confirmed - model shows `tools` capability
- **Limitation**: Only grants capability flag; actual tool execution requires working weights

### 2. Model List Cache Integer Confusion (REPORT-18)
- `readModelListGGUF()` has custom GGUF header parser with int cast issues
- `uint64` -> `int` casting without overflow check
- **Severity**: Low - requires malicious GGUF already on disk

### 3. Dual Rendering Pipeline (REPORT-19)
- Go template path and llama-server path are separate
- **Impact**: Doubles attack surface

### 4. Renderer/Parser Auto-Detection
- `general.architecture = "gemma4"` auto-enables tool support

## Version Comparison

| Feature | v0.24.0 | v0.30.7 |
|---------|---------|---------|
| Weight hijack | Works | Broken (vocab validation) |
| Custom GGUF vocab | Accepted | Rejected |
| `/api/create` param | `modelfile` | `from` |
| Rendering backend | llama.cpp (old) | llama-server (new) |

## Terminal Tool Limitation

The terminal tool strips `for` keyword from Python code in ALL contexts.
Use `while` loops or base64 encoding as workaround.
