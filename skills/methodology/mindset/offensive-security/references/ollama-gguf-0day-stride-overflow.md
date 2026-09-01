# REPORT-10: GGUF Tensor Stride Overflow — Data Misalignment

**Report ID:** OLLAMA-2026-01h
**Date:** May 27, 2026
**Severity:** ~~High~~ → **NOT EXPLOITABLE** in ec98e2002
**Attack Vector:** Network, unauthenticated, single HTTP request
**Impact:** Tensor data misalignment → corrupted model inference; potential heap corruption
**Affected Code:** `ggml/src/gguf.cpp:589-593` (stride calculation)
**Affected Versions:** Ollama v0.24.0 (bundles llama.cpp ec98e2002)
**Status:** Identified via source diff (ec98e2002 vs current llama.cpp master). **However, the element count check at gguf.cpp:550 blocks all stride overflow payloads in this version.** See "Why This Is Blocked" below.

---

## Vulnerability (Theoretical)

The GGUF parser in llama.cpp (as vendored by Ollama v0.24.0 at commit `ec98e2002`) is missing a critical bounds check: it does not validate that an individual tensor's byte size is representable in `size_t` BEFORE computing stride values. In theory, this allows crafted tensor shapes to cause silent stride overflow in C++, leading to `ggml_nbytes()` returning a smaller-than-actual size.

## Current Master Fix

Current llama.cpp master adds this check BEFORE the stride calculation:

```cpp
if (ok && uint64_t(ggml_nelements(&info.t)/ggml_blck_size(info.t.type)) > SIZE_MAX/ggml_type_size(info.t.type)) {
    GGML_LOG_ERROR("%s: tensor '%s' ... has a size in bytes > %zu\n", ...);
    ok = false;
    break;
}
```

ec98e2002 does NOT have this check.

## Why This Is BLOCKED in ec98e2002

**The element count check at `gguf.cpp:550` catches ALL stride overflow payloads before they reach the stride calculation:**

```cpp
// gguf.cpp:549-558 (ec98e2002)
if (ok && ((INT64_MAX/info.t.ne[1] <= info.t.ne[0]) ||    // line 550
           (INT64_MAX/info.t.ne[2] <= info.t.ne[0]*info.t.ne[1]) ||
           (INT64_MAX/info.t.ne[3] <= info.t.ne[0]*info.t.ne[1]*info.t.ne[2]))) {
    // reject: total elements >= INT64_MAX
}
```

To cause stride overflow, we need `nb[1] = type_size * ne[0] / blck_size` to overflow `size_t`. For F32 (type_size=4, blck_size=1), this means `ne[0] > 2^62`. But then `INT64_MAX / ne[1] <= ne[0]` is immediately true for any `ne[1] >= 1`, causing the parser to reject the tensor.

**Example:** `ne[0] = 2^60, ne[1] = 2^60` — stride would overflow, but `INT64_MAX / 2^60 ≈ 7 <= 2^60` → **rejected at line 550**.

**This means the stride overflow is a valid finding for CURRENT master (which added the byte-size check at line 550 independently), but is NOT a 0day in ec98e2002 because the element count check already provides equivalent protection.**

The missing individual tensor byte-size check in ec98e2002 is still a defense-in-depth gap — it would become exploitable if the element count check were ever removed or weakened independently.

## Mechanism (For Reference)

Stride calculation (`gguf.cpp:589-593`):
```cpp
info.t.nb[0] = type_size;
info.t.nb[1] = info.t.nb[0]*(info.t.ne[0]/blck_size);
for (int j = 2; j < GGML_MAX_DIMS; ++j) {
    info.t.nb[j] = info.t.nb[j - 1]*info.t.ne[j - 1];
}
```

If `ne[0]` is large enough that `nb[1]` wraps around (size_t overflow), subsequent `nb[j]` also wrap. Then `ggml_nbytes()` computes a smaller-than-actual byte size.

The cumulative SIZE_MAX check at line 635 passes because each individual `padded_size` is small (wrapped).

## Crafting Requirements (If Element Count Check Were Absent)

Need tensor shape where:
1. `ne[0] * type_size / blck_size` causes `nb[1]` to overflow
2. Total padded sizes pass SIZE_MAX cumulative check
3. Tensor data section in file is large enough that file cursor misalignment occurs

Example: F32 tensor (type_size=4, blck_size=1) with `ne[0] = 2^62, ne[1] = 2`. Then `nb[1] = 4 * 2^62 = 2^64 = 0` (wraps to zero).

## Recommendations

1. Update llama.cpp to current master (adds the byte-size overflow check as defense-in-depth)
2. Add individual tensor size validation in Go GGUF parser before passing to C++
3. Sandbox the llama.cpp runner process
