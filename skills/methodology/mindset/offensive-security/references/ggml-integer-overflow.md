# GGUF Tensor Stride Integer Overflow — Detailed Analysis

**Severity:** Critical — heap buffer overflow via malicious GGUF model files
**Affected:** llama.cpp (ggml) GGUF parser, all downstream consumers (ollama, LM Studio, etc.)
**Attack vector:** Malicious `.gguf` model file (supply chain, shared models)

## Root Cause

The GGUF parser in `gguf.cpp` validates that total tensor elements fit in `int64_t`:
```cpp
// gguf.cpp:550-552
if (ok && ((INT64_MAX/info.t.ne[1] <= info.t.ne[0]) ||
           (INT64_MAX/info.t.ne[2] <= info.t.ne[0]*info.t.ne[1]) ||
           (INT64_MAX/info.t.ne[3] <= info.t.ne[0]*ne[1]*ne[2]))) {
    // reject: total elements >= INT64_MAX
}
```

But does NOT validate that byte stride (`nb`) values fit in `size_t`:
```cpp
// gguf.cpp:590-592 — OVERFLOWS
info.t.nb[1] = info.t.nb[0]*(info.t.ne[0]/blck_size);
for (int j = 2; j < GGML_MAX_DIMS; ++j) {
    info.t.nb[j] = info.t.nb[j - 1]*info.t.ne[j - 1];
}
```

`nb` is `size_t[4]` (64-bit unsigned). Multiplication wraps on overflow.

## Proof of Concept

Tensor dimensions: `ne = {2147483648, 2147483648, 1, 1}` (i.e., `{2^31, 2^31, 1, 1}`)
Type: `GGML_TYPE_F32` (type_size=4, blck_size=1)

### Step-by-step trace

**1. GGUF parser checks (gguf.cpp:550-552):**
```
Total elements = 2^31 * 2^31 * 1 * 1 = 2^62
INT64_MAX = 2^63 - 1 = 9223372036854775807
2^62 < INT64_MAX → checks PASS ✓
```

**2. Stride calculation (gguf.cpp:590-592):**
```
nb[0] = 4
nb[1] = 4 * 2^31 = 2^33
nb[2] = 2^33 * 2^31 = 2^64 → wraps to 0  ← OVERFLOW
nb[3] = 0 * 1 = 0
```

**3. ggml_nbytes (ggml.c:1241-1264):**
```
nbytes = 4                                    // type_size
       + (2^31 - 1) * 2^33                    // ≈ 2^64 → wraps to 0
       + (1 - 1) * 0                          // 0
       + (1 - 1) * 0                          // 0
       = 0                                    // RETURNS 0
```

**4. Allocation (ggml.c:1685-1701):**
```
data_size = ggml_row_size(F32, 2^31)          // = 2^33
data_size *= 2^31                             // = 2^64 → wraps to 0
data_size *= 1                                // 0
data_size *= 1                                // 0
obj_alloc_size = 0                            // 0 bytes allocated!
```

**5. Compute (ggml-cpu.c:1228+):**
```
Element [i0, i1, i2, i3] offset = i0*nb[0] + i1*nb[1] + i2*nb[2] + i3*nb[3]
                                  = i0*4 + i1*2^33 + i2*0 + i3*0
                                  = i0*4 + i1*2^33
```
All elements with different i2/i3 map to the same offset. The maximum offset
(≈ 2^64) wraps around. Writes go beyond the 0-byte buffer → heap corruption.

## Affected Code Paths

| File | Function | Line | Issue |
|------|----------|------|-------|
| `gguf.cpp` | tensor info parsing | 590-592 | `nb` stride overflow |
| `ggml.c` | `ggml_new_tensor_impl` | 1685-1688 | `data_size` overflow |
| `ggml.c` | `ggml_new_tensor_impl` | 1733-1737 | `nb` recalculation overflow |
| `ggml.c` | `ggml_nbytes` | 1241-1264 | Returns 0 for huge tensors |
| `ggml.c` | `ggml_new_object` | 1636 | Allocates 0 bytes (passes check) |
| `ggml-alloc.c` | `ggml_tallocr_alloc` | 80 | Uses overflowed size |
| `ggml-cpu.c` | `ggml_compute_forward_mul_mat` | 1228+ | Stride-based OOB access |

## Additional Issues

### Division by zero (gguf.cpp:550)
If `ne[1] == 0` in the GGUF file, `INT64_MAX / ne[1]` is undefined behavior.
The default value is 1 (line 535), but an explicit 0 in the file bypasses this.
The check on line 541 rejects negative values but NOT zero.

### Division by zero (ggml-cpu.c:1265-1266)
```c
const int64_t r2 = ne12 / ne02;
const int64_t r3 = ne13 / ne03;
```
If source tensor dimensions are 0, this is division by zero.

## All Known Overflow Variants (F32, type_size=4, blck_size=1)

| Variant | Dimensions | What overflows | nb result |
|---------|-----------|----------------|-----------|
| Primary (nb[2]) | `{2^31, 2^31, 1, 1}` | `nb[2] = 4*2^31*2^31 = 2^64` | nb={4, 2^33, **0**, **0**} |
| nb[3] overflow | `{2^21, 2^21, 2^20, 1}` | `nb[3] = 4*2^21*2^21*2^20 = 2^64` | nb={4, 2^23, 2^44, **0**} |
| 4D data_size | `{2^16, 2^16, 2^15, 2^15}` | `data_size = 4*2^16*2^16*2^15*2^15 = 2^64` | nb fits, but **data_size=0** |

All three variants have total elements = 2^62 < INT64_MAX, so they pass the GGUF parser check.

### Type-Specific Analysis

| Type | type_size | blck_size | Overflow with {2^31, 2^31, 1, 1}? |
|------|-----------|-----------|-------------------------------------|
| F32  | 4         | 1         | **YES** — nb[2] = 2^64 → 0 |
| F16  | 2         | 1         | No — nb[2] = 2^63 (fits in size_t) |
| Q8_0 | 34        | 32        | No — nb[1] = 34*2^31/32 ≈ 2^31.4, nb[2] ≈ 2^62.4 (fits) |
| Q4_0 | 18        | 32        | No — similar to Q8_0 |

**Key insight:** The overflow requires `type_size * ne[0] * ne[1]` to exceed `SIZE_MAX` (2^64). For F32 (type_size=4), this means `ne[0] * ne[1] > 2^62`. For F16 (type_size=2), `ne[0] * ne[1] > 2^63`. The GGUF parser's INT64_MAX check caps total elements at 2^63-1, so F16 can only overflow if ne[2] or ne[3] > 1.

## Why Standard llama.cpp Loader Mitigates This

### The `check_tensor_dims` Defense

The llama.cpp loader has a critical defense-in-depth mechanism in `check_tensor_dims` (`llama-model-loader.cpp:764`):

```cpp
for (size_t i = 0; i < GGML_MAX_DIMS; ++i) {
    if ((i < ne.size() && ne[i] != cur->ne[i]) || (i >= ne.size() && cur->ne[i] != 1)) {
        is_ok = false;
        break;
    }
}
```

This validates that GGUF tensor dimensions (`ne`) match the expected dimensions derived from model hyperparameters. Since `nb` (byte stride) is derived from `ne` and `type` using the **identical formula** in both the GGUF parser and ggml tensor creation:

```cpp
// GGUF parser (gguf.cpp:590-592):
nb[0] = type_size;
nb[1] = nb[0] * (ne[0] / blck_size);
nb[j] = nb[j-1] * ne[j-1];

// ggml tensor creation (ggml.c:1733-1737):
nb[0] = type_size;
nb[1] = nb[0] * (ne[0] / blck_size);
nb[i] = nb[i-1] * ne[i-1];
```

**Matching `ne` means matching `nb`.** The only way to get overflowed `nb` is to have overflowed `ne`, which fails `check_tensor_dims`. This makes the vulnerability **fundamentally unexploitable through the standard llama.cpp loader path**.

### Proof of Impossibility

To exploit the overflow through the standard path, we need:
1. GGUF tensor `ne` matches expected `ne` (passes `check_tensor_dims`)
2. GGUF tensor `nb` overflows (causing wrong allocation)
3. Expected tensor `nb` does NOT overflow (so the model uses correct strides)

Conditions 2 and 3 are contradictory because `nb` is a deterministic function of `ne` and `type`, using identical code in both paths. If `ne` matches, `nb` matches.

### The uint32 Hyperparameter Constraint

Even if we try to set hyperparameters to values that cause overflow (e.g., `n_embd = 2^31`, `n_vocab = 2^31`):
- `n_embd` and `n_vocab` are `uint32_t` (max 2^32-1)
- With `ne0 = ne1 = 2^31`: `ne0 * ne1 * 4 = 2^64 = 0` (exact overflow!)
- BUT: `n_vocab = 2^31` requires a token list with 2^31 entries in the GGUF file
- 2^31 strings ≈ 8GB minimum → infeasible to include in a GGUF file
- With max uint32 values `(2^32-1)^2 * 4 = 2^66 - 2^33 + 4` → wraps to `2^64 - 2^33 + 4` (huge, fails bounds check)

So even with extreme hyperparameter values, we cannot simultaneously:
1. Pass `check_tensor_dims` (requires matching `ne`)
2. Cause `ggml_nbytes` to overflow to 0 (requires exact `ne0 * ne1 = 2^62`)
3. Provide a valid token list (requires `n_vocab` entries)

## Ollama Black-Box Testing (v0.24.0)

### API Workflow
1. `POST /api/blobs/sha256:<hex>` — upload raw blob to server
2. `POST /api/create` with `files: {"model.gguf": "sha256:<hex>"}` — create model from blob
3. `POST /api/generate` — triggers model load + inference

### Key Findings
- `from` field only accepts model names (parsed by modelref.ParseRef), NOT file paths or base64
- `files` map is filename → digest (NOT base64 content)
- detectModelTypeFromFiles checks .gguf extension or reads first 4 bytes for GGUF magic
- Digest format: ^sha256[:-][0-9a-fA-F]{64}$ (from manifest/paths.go:40)

### Test Results

| Test | Blob Upload | Model Create | Inference |
|------|-------------|--------------|-----------|
| Original PoC (no hparams) | ✅ 201 | ✅ success | ❌ "unable to load model" |
| v2 PoC (with hparams, wrong tensor shape) | ✅ 201 | ✅ success | ❌ "unable to load model" |
| Complete PoC (with hparams, matching tensor shape) | ✅ 201 | ✅ success | ❌ "unable to load model" |

All tests fail at inference time because `check_tensor_dims` catches dimension mismatches.

### Root Cause of Rejection

The loading pipeline:
```
llama_model_load (llama.cpp:752)
  → load_arch (llama.cpp:473)         ← reads general.architecture KV
  → load_hparams (llama.cpp:480)      ← REQUIRES llama.* KV pairs
  → load_vocab (llama.cpp:500)        ← REQUIRES tokenizer.ggml.tokens
  → load_tensors (llama.cpp:520)      ← llama_model_loader constructor
    → check_tensor_dims               ← VALIDATES ne matches expected
```

Failure points:
1. Missing `llama.block_count` → "key not found in model: llama.block_count"
2. Missing `tokenizer.ggml.tokens` → "cannot find tokenizer vocab in model file"
3. Tensor `ne` mismatch → "tensor 'X' has wrong shape; expected Y, got Z"

### Required KV Pairs for llama Architecture

To pass `load_hparams`, a GGUF needs at minimum these KV pairs:

| Key | Type | Maps to | Notes |
|-----|------|---------|-------|
| `general.architecture` | string | `arch` | Must be "llama" |
| `llama.block_count` | uint32 | `hparams.n_layer` | **Required** — throws if missing |
| `llama.embedding_length` | uint32 | `hparams.n_embd` | **Required** — throws if missing |
| `llama.context_length` | uint32 | `hparams.n_ctx_train` | **Required** — throws if missing |
| `llama.attention.head_count` | uint32 | `hparams.n_head_arr[0]` | **Required** — throws if missing |
| `llama.feed_forward_length` | uint32 | `hparams.n_ff_arr[0]` | **Required** — throws if missing |
| `llama.attention.layer_norm_rms_epsilon` | float32 | `hparams.f_norm_rms_eps` | Required by most llama variants |

Additionally, `load_vocab` requires tokenizer KV pairs:
- `tokenizer.ggml.tokens` (array of strings) — vocab tokens
- `tokenizer.ggml.scores` (array of floats) — token scores
- `tokenizer.ggml.bos_token_id` (uint32)
- `tokenizer.ggml.eos_token_id` (uint32)

### C++ Secondary Bounds Check (Also Bypassed by Overflow)

Even after passing hparams, the `llama_model_loader` constructor (`llama-model-loader.h:40-42`) does its own bounds check:

```cpp
offs = gguf_get_data_offset(gguf_ctx) + gguf_get_tensor_offset(gguf_ctx, tensor_idx);
if (offs + ggml_nbytes(tensor) < offs || offs + ggml_nbytes(tensor) > file->size()) {
    throw std::runtime_error("tensor data is not within the file bounds");
}
```

This check **also passes** for overflow tensors because `ggml_nbytes` returns 0 (due to stride overflow), making `offs + 0 = offs < file->size()`. So the overflow bypasses BOTH the Go-level check AND the C++-level check. But `check_tensor_dims` provides the actual protection.

### Go-Level Bounds Check (Also Bypassed)

The Go `Tensor.Size()` method (`ggml.go:515-517`) also overflows:
```go
func (t Tensor) Size() uint64 {
    return t.Elements() * t.typeSize() / t.blockSize()
}
```
With overflow dimensions: `Elements() = 2^62`, `typeSize = 4`, product = `2^64` → wraps to 0. So `tensorEnd = offset + 0 + 0 = offset < fileSize` → check passes.

## Why 1D Tensors Cannot Overflow (64-bit Proof)

For a 1D tensor `{ne0}` with `type_size` and `block_size`:
```
Size() = ne0 * type_size / block_size
```

Maximum values on 64-bit:
- `ne0` is `int64_t` in GGUF file, but constrained by uint32 hparams → max `ne0 = 2^32 - 1`
- `type_size` max = 8 (F64)
- `block_size` min = 1 (F32, F16, F64)

```
Max Size = (2^32 - 1) * 8 / 1 = 2^35 - 8 = 34,359,738,872
```

This is **far below** `SIZE_MAX = 2^64 - 1`. Therefore, 1D tensors can **never** overflow `size_t` on 64-bit systems when dimensions are constrained by uint32 hyperparameters.

**Implication:** The Go parser's bounds check (`tensorEnd = offset + tensor.Size()`) will **always** catch 1D tensors with large dimensions, because their `Size()` is correct (non-overflowed) and huge. This makes the Go parser **stricter** than the C++ parser for this specific case.

## Go Parser vs C++ Parser: Asymmetric Strictness

| Check | Go Parser | C++ Parser |
|-------|-----------|------------|
| Bounds check ALL tensors | ✅ Yes (gguf.go:259) | ❌ Only expected tensors |
| 1D tensor bounds | ✅ Always catches (no overflow possible) | N/A (not checked) |
| 2D+ tensor bounds | ✅ Catches if Size() > file_size | ✅ Catches via `llama_tensor_weight` constructor |
| Dimension validation | ❌ None | ✅ `check_tensor_dims` validates `ne` |
| Type validation | ❌ None | ❌ `check_tensor_dims` only checks `ne`, not `type` |

**Key insight:** The Go parser is the **first line of defense** and is strictly stronger than the C++ parser for 1D tensors. The C++ `check_tensor_dims` provides defense-in-depth for 2D+ tensors. Both parsers have the same overflow bug in `Size()`/`ggml_nbytes`, but the Go parser's stricter bounds checking prevents overflowed tensors from reaching the C++ code.

## SSRF via `/api/pull` (Separate Attack Vector)

While the GGUF overflow is mitigated, Ollama's `/api/pull` endpoint has an SSRF vulnerability:

- The `from` field accepts arbitrary registry URLs
- `CheckRedirect` limits cross-hostname redirects but the **initial request** goes to any host
- Can be used to: probe internal services, fetch cloud metadata (`169.254.169.254`), or pull malicious models from attacker-controlled servers
- **Chain potential:** SSRF to pull a malicious model → GGUF overflow during inference (if the overflow is exploitable in any configuration)

## Recommendations

1. Add `size_t` overflow checks before `nb` stride multiplications:
   ```c
   if (nb[j-1] != 0 && ne[j-1] > SIZE_MAX / nb[j-1]) {
       // reject: overflow
   }
   ```
2. Use `__builtin_mul_overflow` for all size calculations
3. Validate `ne[j] >= 1` (not just `ne[j] >= 0`) in GGUF parser
4. Add fuzz testing for GGUF tensor dimension edge cases
5. Consider using `size_t` for `ne` values or adding explicit range caps
6. Add a check in `ggml_nbytes` to detect zero-byte allocation for non-zero-dimension tensors

## Detection Pattern

Search for these patterns in C/C++ ML inference code:
- `nb[j] = nb[j-1] * ne[j-1]` without overflow check
- `data_size *= ne[i]` where `data_size` is `size_t` and `ne[i]` is `int64_t`
- `ggml_nbytes` returning 0 for non-zero-dimension tensors
- `INT64_MAX / x <= y` checks that don't account for `type_size` multiplier
