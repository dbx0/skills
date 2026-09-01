# REPORT-11: GGUF Parser Division by Zero DoS

**Report ID:** OLLAMA-2026-01i
**Date:** May 27, 2026
**Severity:** Medium
**Attack Vector:** Network, unauthenticated, single HTTP request
**Impact:** Server crash via SIGFPE (integer division by zero)
**Affected Code:** `ggml/src/gguf.cpp:550`
**Affected Versions:** Ollama v0.24.0 (bundles llama.cpp ec98e2002)
**Status:** Identified via source code audit; PoC saved as `poc_gguf_divzero.py`

---

## Vulnerability

The GGUF parser performs `INT64_MAX / info.t.ne[1]` at line 550 without first checking that `ne[1] != 0`. Integer division by zero is undefined behavior in C++, which on all platforms typically triggers SIGFPE and crashes the process.

## Root Cause

In `ggml/src/gguf.cpp:540-558`:

```cpp
for (uint32_t j = 0; ok && j < GGML_MAX_DIMS; ++j) {
    info.t.ne[j] = 1;
    if (j < n_dims) {
        ok = ok && gr.read(info.t.ne[j]);
    }
    // Only checks < 0, not == 0
    if (info.t.ne[j] < 0) { ... }
}

// Line 550 — division by zero if ne[1] == 0
if (ok && ((INT64_MAX/info.t.ne[1] <= info.t.ne[0]) || ...))
```

The `ne` array is `int64_t[GGML_MAX_DIMS]`. Values are read directly from the file. The only validation is `ne[j] < 0` (line 541). A value of `0` passes this check. Then `INT64_MAX / 0` is undefined behavior.

## Reachability

Reachable when:
1. `n_dims >= 2` (at least 2 dimensions)
2. File contains `0` for `ne[1]` (second dimension)

Both conditions are easy to satisfy in a crafted GGUF file.

## PoC

See `poc_gguf_divzero.py`. Key crafting:
```python
struct.pack('<q', 0)  # ne[1] = 0 ← triggers div by zero
```

GGUF structure:
- Magic: GGUF, Version: 3
- n_tensors: 1, n_kv: 1
- KV: general.alignment = 32
- Tensor: dims=2, ne=[4, 0], type=F32, offset=0

## Impact

- DoS: Server crashes with SIGFPE
- Requires only one `/api/create` request with a crafted GGUF
- No authentication needed (default Ollama config)

## Recommendation

Add `ne[j] == 0` check before the division at line 550, or update llama.cpp to current master.
