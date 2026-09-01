# Ollama v0.24.0 — Complete `unsafe` Audit & Bleeding Llama Analysis

## Bleeding Llama (CVE-2026-7482) — Test Results

**Status: PATCHED in v0.24.0**

### Attack Chain
1. Upload malformed GGUF (tensor shape claims N elements, actual data < N×sizeof(type))
2. Trigger F16→F32 quantization via `/api/create` with `quantize: "F32"`
3. C++ `ggml_fp16_to_fp32_row` reads past buffer → heap memory leak
4. Exfiltrate via `/api/push` to attacker-controlled registry

### Why It's Blocked

**Defense 1 — GGUF Parser (`fs/ggml/gguf.go:258-262`):**
```go
tensorEnd := llm.tensorOffset + tensor.Offset + tensor.Size()
if tensorEnd > uint64(fileSize) {
    return fmt.Errorf("tensor %q offset+size (%d) exceeds file size (%d)", ...)
}
```
Runs at parse time. Rejects any tensor whose data region exceeds the actual file.

**Defense 2 — Quantization (`server/quantization.go:38`):**
```go
if uint64(len(data)) < q.from.Size() {
    return 0, fmt.Errorf("tensor %s data size %d is less than expected %d", ...)
}
```
Defense-in-depth. Catches truncation between parse and quantization.

### PoC Result
```
[-] create failed: 500 {"error":"tensor \"test.weight\" offset+size (2000160) exceeds file size (1184)"}
```

### Fix Origin
The `tensorEnd > fileSize` check at `gguf.go:260` was added as the Bleeding Llama fix (merged ~Feb 25, 2026). Present in v0.24.0. The original vulnerable versions (v0.23.x and earlier) lacked this check.

---

## Complete `unsafe` Audit — Ollama v0.24.0

### All `unsafe` Code Paths

| File | Lines | Operation | User Data? | Exploitable? |
|------|-------|-----------|-----------|--------------|
| `server/quantization.go:44` | `unsafe.Slice((*float32)(unsafe.Pointer(&data[0])), q.from.Elements())` | Creates F32 slice from byte buffer | Yes (GGUF tensor) | Blocked by checks at lines 38 + gguf.go:260 |
| `server/quantization.go:46` | `ggml.ConvertToF32(data, q.from.Kind, q.from.Elements())` | CGo F16→F32 conversion | Yes (GGUF tensor) | Same blocks |
| `ml/backend/ggml/quantization.go:24-48` | CGo dequantization functions (14 variants) | Read tensor data via `unsafe.Pointer` | Yes (passed from above) | Only reached if Go checks pass |
| `ml/backend/ggml/ggml.go:284` | `ggml_new_tensor` with shape pointer | Creates C tensor struct | Yes (GGUF shape) | Shape validated at parse time |
| `ml/backend/ggml/ggml.go:270,272,274` | `unsafe.Pointer(&buf[0])` for CGo calls | Passes Go buffer pointers to C | Various | All sizes validated before call |
| `discover/cpu_windows.go` | Windows CPU detection | Casts Windows API structs | No (OS only) | Not reachable from network |

### Key Findings

1. **All `unsafe` operations are behind validated boundaries.** The Go code validates tensor sizes at parse time (`gguf.go:260`) and at quantization time (`quantization.go:38`) before any `unsafe.Pointer` or CGo calls.

2. **The C++ conversion functions (`ggml_fp16_to_fp32_row`, `dequantize_row_*`) are the exact same functions that Bleeding Llama exploits**, but they're never reached with out-of-bounds data on v0.24.0.

3. **No `unsafe` in runner or llm packages.** The OS-specific files contain only `SysProcAttr` and process flags — no memory operations.

4. **Safetensors parser is safe.** `reader_safetensors.go` reads `n` as `int64` for header size, but `io.CopyN` uses an internal buffer. Huge `n` values cause OOM (DoS), not heap leak.

5. **GGUF string parser (`readGGUFString`) is safe.** Line 360 checks `length > len(llm.scratch)` and allocates accordingly. `io.ReadFull` reads only available data. `clear(buf)` zeroes before reading — no data leakage from previous reads.

### OS-Specific Code Differences

Ollama does NOT behave differently across OSes for security-relevant code paths:

- **HTTP API, GGUF parsing, quantization, model loading** — all OS-agnostic Go code, identical behavior
- **Windows**: Process priority/window flags for runner subprocess — no security impact
- **macOS**: Metal GPU backend — different GPU code but same frontend validation
- **Linux**: Primary deployment target, what we tested

**If v0.24.0 is patched on Linux, it's patched everywhere.**

### Request Smuggling Assessment

**Not viable** against Go-based servers. Go's `net/http`:
- Rejects duplicate `Content-Length` headers
- Rejects `Transfer-Encoding: chunked` + `Content-Length` combinations
- No internal reverse proxy chain to desync with
- Single strict parser throughout

Only exploitable if a misconfigured external reverse proxy sits in front — infrastructure issue, not server vulnerability.

### Agent/Bash Tool Assessment

`x/tools/bash.go` has `exec.CommandContext(ctx, "bash", "-c", command)` with user-controlled command string.

**NOT reachable from the Ollama HTTP API.** Part of the experimental OpenClaw agent system, invoked only from the desktop app/launcher TTY. Multiple approval gates: denylist, interactive TTY prompt, `--yolo` flag, session allowlist. Local-only.

---

## Technique: Vendored-Dependency Diffing

When auditing a project that vendors a dependency (e.g., Ollama → llama.cpp):

1. **Find the exact vendored commit**: Check `build-info.cpp`, `go.mod`, or `Makefile.sync`
2. **Fetch upstream**: `git fetch --depth=1 origin master` in the upstream repo
3. **Diff**: `git diff <commit> upstream/master -- <path>` to find missing security hardening
4. **Verify exploitability**: A "missing check" that's redundant with an earlier check is defense-in-depth, NOT a 0day. Check the FULL validation chain.

**Example**: ec98e2002 is missing the individual tensor byte-size overflow check that current master has. BUT the element count check at `gguf.cpp:550` already blocks ALL stride overflow payloads before they reach stride calculation. Result: defense-in-depth gap, not a 0day.
