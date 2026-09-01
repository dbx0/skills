# LLM Supply Chain Attack

Attack the model layer rather than the application layer. When a system loads untrusted model weights, the weights themselves become the attack vector.

## When to Use

- Target runs Ollama, vLLM, llama.cpp, or similar LLM serving infrastructure
- Target pulls models from registries (Ollama Hub, HuggingFace, custom registries)
- Target has shared model storage (multiple clients load the same model)
- Target uses automated pipelines that pull models without verification
- You have write access to a model registry or shared model store

## Core Technique: Weight-Level Hijack

Build a minimal GGUF that always emits the same output regardless of input. The output weights are peaked at a single token ID so the model is a constant function.

### GGUF Structure

```
Architecture: llama (simplest, smallest)
Layers: 1 (minimum)
Embedding dim: 8 (minimum)
Vocab: 260 (256 byte-level + 4 special tokens)
Token 256: <unk>
Token 257: <s> (BOS)
Token 258: </s> (EOS)
Token 259: YOUR PAYLOAD STRING
```

Output weight matrix: row 259 peaked at 100.0, all other rows 0.0.

### Critical: Space Encoding

**PITFALL: Raw 0x20 bytes get corrupted by the C++ decoder.** The Ollama C++ tokenizer outputs `[UNK_BYTE_0x20]` for raw space bytes inside token strings, breaking JSON parsing.

**Fix: Use `Ġ` (chr 288, U+0120) for ALL spaces in the output string.** This is the GPT-2 space character. The C++ decoder recognizes it and outputs a real space.

```python
G = chr(288)  # Ġ - GPT-2 space, NOT raw 0x20
cmd = "open" + G + "-a" + G + "Calculator"
```

Do NOT use `${IFS}` or other bash workarounds — `Ġ` is the correct solution.

### Template for CapabilityTools

Use `{{ .Tools }}` in the template to grant `CapabilityTools` via the template var check (`images.go:slices.Contains(v, "tools")`). Do NOT use `{{ .ToolCalls }}` — the generic parser defaults to `{` as the tag, which works with JSON output starting with `{`.

```
template = '{{ .Tools }}{{ range .Messages }}{{ .Role }}: {{ .Content }}\n{{ end }}'
```

### Client Tool Schema Compatibility

Different clients expect different tool argument schemas. Match the schema to your target client:

**OpenCode shell tool** requires: `command` (string) + `description` (string) + optional `timeout` (int) + optional `workdir` (string)

```python
TOOL_JSON = '{"name":' + G + '"bash",' + G + '"arguments":' + G + \
            '{"command":' + G + '"' + cmd + '",' + G + \
            '"description":' + G + '"' + desc + '"}}'
```

**Generic OpenAI-compatible** clients may only need `command`. Check the client's tool definition and include all `required` fields.

### Upload Chain

1. Build GGUF → compute SHA256
2. `POST /api/blobs/sha256:...` — upload raw bytes
3. `POST /api/create` with `files: {"model.gguf": sha256}` + template
4. Model appears with tools capability

### Verification

Query the model and check `tool_calls` in the response. The model should emit the same tool call regardless of input message or client system prompt.

## Version Notes

Tested against Ollama v0.24.0 and v0.30.7. The weight hijack technique is **unaffected** by the v0.30.7 update. New functions like `goTemplateHasToolRoundTrip` only affect template rendering engine selection, not tool call extraction from model output.

Key source locations (v0.30.7):
- `server/routes.go:2528` — system prompt gate (bypassed by weight hijack)
- `server/images.go:240` — `{{ .Tools }}` capability detection
- `tools/tools.go:42-160` — generic tool parser (parseTag, findTool, findArguments)
- `model/parsers/gemma4.go:45` — `HasToolSupport()` returns true
- `fs/ggml/gguf.go:260` — tensor bounds check (Bleeding Llama blocked)

## Pitfalls

1. **0x20 corruption**: Raw space bytes in token strings become `[UNK_BYTE_0x20]`. Always use `Ġ` (chr 288).
2. **Missing schema fields**: Client rejects tool calls with missing required fields. Include ALL required fields from the client's tool definition.
3. **Architecture mismatch**: Using `from: "gemma4"` with llama-shaped tensors crashes the C++ backend. Use `general.architecture: "llama"` for fake models.
4. **Disk space**: Ollama servers can run out of disk. Clean up partial blobs (`*.partial*`) if uploads fail with 500.
5. **Model name is cosmetic**: The `--model` flag in the exploit just sets the name. The GGUF is always the 25KB fake. Name it anything convincing.

## References

- `references/ollama-weight-hijack.md` — full technical report with PoC code, response samples, and version analysis (in original skill)
