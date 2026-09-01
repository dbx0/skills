# GGUF Tensor Dimension Conventions (GGML)

**Date:** 2026-05-20
**Context:** Building malicious GGUF files for Ollama security research

## GGML Dimension Convention

GGML uses `ne = [fastest_dim, ..., slowest_dim]` — the **opposite** of NumPy/C row-major convention.

For a 2D weight matrix with shape `[rows, cols]`:
- **GGML:** `ne = [cols, rows]` (fastest = columns)
- **NumPy:** `shape = (rows, cols)` (slowest = columns)
- Data is stored **row-major** in both cases

## Correct Tensor Dimensions for Llama Architecture

| Tensor | Logical Shape | GGML `ne` | Notes |
|--------|--------------|-----------|-------|
| `token_embd.weight` | `[n_vocab, n_embd]` | `[n_embd, n_vocab]` | Embedding lookup |
| `output.weight` | `[n_vocab, n_embd]` | `[n_embd, n_vocab]` | Output projection |
| `output_norm.weight` | `[n_embd]` | `[n_embd]` | Layer norm |
| `blk.N.attn_q.weight` | `[n_embd, n_embd]` | `[n_embd, n_embd]` | Attention Q |
| `blk.N.attn_k.weight` | `[n_embd, n_embd]` | `[n_embd, n_embd]` | Attention K |
| `blk.N.attn_v.weight` | `[n_embd, n_embd]` | `[n_embd, n_embd]` | Attention V |
| `blk.N.attn_output.weight` | `[n_embd, n_embd]` | `[n_embd, n_embd]` | Attention output |
| `blk.N.attn_norm.weight` | `[n_embd]` | `[n_embd]` | Layer norm |
| `blk.N.ffn_gate.weight` | `[n_ff, n_embd]` | `[n_embd, n_ff]` | FFN gate |
| `blk.N.ffn_up.weight` | `[n_ff, n_embd]` | `[n_embd, n_ff]` | FFN up |
| `blk.N.ffn_down.weight` | `[n_embd, n_ff]` | `[n_ff, n_embd]` | FFN down (transposed!) |
| `blk.N.ffn_norm.weight` | `[n_embd]` | `[n_embd]` | Layer norm |

## Common Mistakes

1. **Reversing dims:** Using `[n_vocab, n_embd]` instead of `[n_embd, n_vocab]` for embedding/output weights. The GGUF parses but inference fails with "unable to load model".

2. **Wrong ffn_down:** `ffn_down` is `[n_embd, n_ff]` logically but GGML stores it as `[n_ff, n_embd]`. This is because it's the transpose of the logical weight.

3. **Missing tokenizer metadata:** The C++ loader requires ALL of:
   - `tokenizer.ggml.tokens` (string array)
   - `tokenizer.ggml.token_type` (uint32 array)
   - `tokenizer.ggml.scores` (float32 array)
   - `tokenizer.ggml.merges` (string array, can be empty)
   - `tokenizer.ggml.bos_token_id` (uint32)
   - `tokenizer.ggml.eos_token_id` (uint32)
   - `llama.vocab_size` (uint32)

4. **Missing architecture KV pairs:** Required: `general.architecture`, `llama.context_length`, `llama.embedding_length`, `llama.block_count`, `llama.feed_forward_length`, `llama.attention.head_count`, `llama.attention.head_count_kv`, `llama.attention.layer_norm_rms_epsilon`, `llama.rope.freq_base`, `tokenizer.ggml.model`, `general.file_type`.

5. **Vocab off-by-one:** `n_vocab` must equal the actual number of vocabulary entries. For 256 byte tokens + `<unk>` + `<s>` + `</s>` + target = 260 entries. The output weight matrix needs `n_vocab` rows (0 to n_vocab-1), so if target is at index 259, `n_vocab` must be 260.

6. **GPT2 space encoding:** Use `Ġ` (U+0120) for spaces in GPT2 tokenizer output strings, not regular spaces. The tokenizer expects this encoding.

## Tensor Info Section Format

Each tensor entry in the GGUF tensor info section:
```
[name_length: uint64][name: bytes]
[n_dims: uint32][ne: int64 * n_dims]  # ne as int64, NOT uint64!
[type: uint32]  # GGML type ID (0 = F32)
[offset: uint64]  # byte offset into data section
```

**Critical:** `ne` values are signed `int64`, not `uint64`. Using `'<q'` (signed) not `'<Q'` (unsigned) in struct.pack.

## Data Section Alignment

Each tensor's data must be padded to 32-byte alignment (default GGUF alignment). The padding goes AFTER each tensor's data, not before.
