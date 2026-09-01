# Ollama v0.24.0 GGUF Parser — Version Analysis & 0day Vectors

**Date:** May 27, 2026
**Target:** Ollama v0.24.0 (released May 14, 2026)
**Bundled llama.cpp commit:** `ec98e2002` (dec 16, 2025)

---

## How We Determined the Bundled Commit

In the ollama source tree at tag v0.24.0:
```
cat llama/build-info.cpp
```
Output:
```cpp
int LLAMA_BUILD_NUMBER = 0;
char const *LLAMA_COMMIT = "ec98e2002";
char const *LLAMA_COMPILER = "";
char const *LLAMA_BUILD_TARGET = "";
```

This confirms ollama v0.24.0 bundles llama.cpp at commit `ec98e2002` (dec 16, 2025).

---

## Diff: ec98e2002 vs Current Master (ggml/src/gguf.cpp)

Key hardening additions in current master that ec98e2002 LACKS:

### 1. String Length Limit

**Current master adds:**
```cpp
#define GGUF_MAX_STRING_LENGTH  (1024*1024*1024)  // 1GB
```

Applied in `gguf_reader::read(std::string &)` — rejects strings > 1GB.

**ec98e2002:** No limit. `dst.resize(size)` with `size` from file. If `size` is huge, throws `std::length_error` or `std::bad_alloc`.

### 2. Array Element Count Limit

**Current master adds:**
```cpp
#define GGUF_MAX_ARRAY_ELEMENTS (1024*1024*1024)  // 1B elements
```

**ec98e2002:** No limit. `dst.resize(n)` with `n` from file. Throws on allocation failure.

### 3. EOF/Remaining-Bytes Tracking

**Current master:** `gguf_reader` tracks `nbytes_remain`. Every read checks remaining bytes.

**ec98e2002:** No tracking. Reads from `FILE*` directly. Short reads past EOF.

### 4. Individual Tensor Size Overflow Check (MOST IMPORTANT)

**Current master adds (before stride calculation):**
```cpp
if (ok && uint64_t(ggml_nelements(&info.t)/ggml_blck_size(info.t.type)) > SIZE_MAX/ggml_type_size(info.t.type)) {
    // reject: tensor byte size exceeds SIZE_MAX
}
```

**ec98e2002:** Only checks `INT64_MAX/ne[1] <= ne[0]` (element count, not byte size). No byte-size overflow check before stride calculation.

### 5. Division by Zero Guard

**ec98e2002 line 550:**
```cpp
if (ok && ((INT64_MAX/info.t.ne[1] <= info.t.ne[0]) || ...))
```

If `ne[1] = 0`: `INT64_MAX / 0` → undefined behavior (SIGFPE).

Check at line 541 only validates `ne[j] < 0`, not `ne[j] == 0`.

---

## Stride Overflow Mechanism

Stride calculation (lines 589-593):
```cpp
info.t.nb[0] = type_size;
info.t.nb[1] = info.t.nb[0]*(info.t.ne[0]/blck_size);
for (int j = 2; j < GGML_MAX_DIMS; ++j) {
    info.t.nb[j] = info.t.nb[j - 1]*info.t.ne[j - 1];
}
```

If `ne[0]` is large enough that `nb[1]` wraps around (size_t overflow), subsequent `nb[j]` also wrap.

`ggml_nbytes()` then computes a SMALLER-than-actual size. The cumulative SIZE_MAX check passes because each individual padded_size is small.

**Result:** Buffer for tensor data is too small. Data overlaps between tensors. Inference uses corrupted data.

**RCE potential:** Low. Float data, mathematical ops, no pointer interpretation.

---

## Go vs C++ Parser Discrepancy

Two GGUF parsers in ollama:
1. **Go** (`fs/ggml/gguf.go`): Metadata + validation
2. **C++** (`ggml/src/gguf.cpp`): Full parsing + data loading

Size computation differs:
- **Go:** `Elements() = product of Shape[]`, `Size() = Elements() * typeSize() / blockSize()`
- **C++:** `ggml_nbytes()` with computed strides

If `Elements()` overflows in Go (uint64 wraps), Go validation passes. C++ computes different size. In practice, C++ parser is more strict.

---

## Confirmed ec98e2002-Specific Findings

| # | Finding | Severity | Type | Exploitable? |
|---|---------|----------|------|-------------|
| 1 | Division by zero (ne[1]=0) | Medium | DoS | **YES** — SIGFPE crash |
| 2 | Stride overflow → data misalignment | — | — | **NO** — blocked by element count check at line 550 |
| 3 | Unbounded string read | Low | DoS (OOM) | Yes (OOM panic) |
| 4 | Unbounded array read | Low | DoS (OOM) | Yes (OOM panic) |

**Important:** The stride overflow (row 2) is NOT exploitable in ec98e2002. The element count check at `gguf.cpp:550` (`INT64_MAX/ne[1] <= ne[0]`) rejects any tensor shape large enough to cause stride overflow before the stride calculation at line 589. This is a defense-in-depth gap but not a 0day. Do not report as a finding for Ollama v0.24.0.

---

## CVE Patches Confirmed Present in ec98e2002

| CVE | Fix | Date | Present? |
|-----|-----|------|----------|
| CVE-2025-49847 | `_try_copy` size check | Jun 2025 | Yes |
| CVE-2025-53630 | SIZE_MAX cumulative check | Jul 2025 | Yes |

---

## GGUF Binary Format (v3)

```
[4B] magic: "GGUF"
[4B] version: uint32
[8B] n_tensors: uint64
[8B] n_kv: uint64
[...kv pairs...]
[tensor infos...]
[padding to alignment...]
[tensor data...]
```

Tensor info:
```
[name string]
[dims: uint32]
[ne[0..dims-1]: uint64 each]
[type: uint32]
[offset: uint64]
```

See `references/gguf-crafting.md` for Python crafting scripts.
