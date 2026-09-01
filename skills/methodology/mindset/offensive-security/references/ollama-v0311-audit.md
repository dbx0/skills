# Ollama v0.31.1 Vulnerability Audit

Date: June 2026
Source: Full source code audit against tag v0.31.1, diffed from v0.30.7

## Key Architecture Changes from v0.30.7

1. **Complete Go module restructuring** — `model/` split into `model/input/`, `model/models/`, `model/parsers/`, `model/renderers/`
2. **New `fs/gguf/` GGUF parser** — rewritten with bufferedReader + lazy loading
3. **`detectChatTemplate` moved** from `images.go` to `model.go` — now calls `template.Named(s)` which levenshtein-matches against known template names (threshold < 100), then adds the matched KNOWN Go template as a layer
4. **New `PreferChatTemplate` field** — when both Go TEMPLATE and GGUF chat_template exist, determines precedence based on capability comparison
5. **Llama.cpp version `b9840`** (up from `b3847` in v0.30.7)

## Vulnerability Status

| Report | Vector | Status |
|--------|--------|--------|
| REPORT-01 | Weight hijack (text output) | ⚠️ Code path still exists in Go. Blocked at runtime by llama.cpp vocabulary validation (b3847+) |
| REPORT-05 | Integer overflow DoS | ⚠️ Still vulnerable — `fs/gguf/gguf.go` `readString()` does `make([]byte, uint64)` |
| REPORT-07 | SSRF via redirect | ⚠️ HTTP redirect handling unchanged |
| REPORT-12 | System prompt injection | ⚠️ System prompt gate check still present |
| REPORT-16 | Weight hijack + tool call RCE | ⚠️ Code path exists. Same runtime blocker as REPORT-01 |
| REPORT-17 | GGUF chat template capability injection | ✅ **STILL VULNERABLE** — `chatTemplateHasToolSupport` identical |
| REPORT-18 | `readModelListGGUF` integer confusion | 🔶 **Partially fixed** — rewritten, but `int64(count*size)` at model_list_cache.go:730 is sus |
| REPORT-19 | Dual rendering pipeline | ✅ Same architecture, two separate prompt rendering paths |
| REPORT-20 | Multi-path capability detection | ✅ Expanded to 5 independent paths (was 4) |

## Key Files in v0.31.1

- `server/images.go` — Model struct (HasChatTemplate, HasGoTemplate, PreferChatTemplate, Template)
- `server/images.go:108` — `Capabilities()` → `capabilitiesForTemplate()`
- `server/images.go:117` — `capabilitiesForTemplate()` — chains 6 capability checks
- `server/images.go:139` — `ggufCapabilities()` — reads `tokenizer.chat_template` from GGUF → `chatTemplateCapabilities()`
- `server/images.go:194` — `chatTemplateHasToolSupport()` — `strings.Contains(chatTemplate, "tools") || strings.Contains(chatTemplate, "tool_call")` — **unchanged**
- `server/images.go:287` — `shouldPreferChatTemplate()` — decides GGUF vs Go template precedence
- `server/images.go:341` — `templateSelectionCapabilities()` — evaluates all template sources independently
- `server/images.go:641` — `GetModel()` — sets HasChatTemplate from GGUF KV at line 691
- `server/routes.go:1618` — `selectedModelTemplate()` — returns GGUF chat_template if HasChatTemplate + native chat mode
- `server/routes.go:2381` — `chatModeForModel()` — determines native vs rendered chat mode
- `server/routes.go:2396` — `usesOllamaRenderedChat()` — checks Renderer/Parser/Harmony/GoTemplate
- `server/routes.go:2400` — `shouldUseGoTemplate()` — checks HasGoTemplate, PreferChatTemplate, env
- `server/model.go:93` — `detectChatTemplate()` — uses `template.Named(s)` with levenshtein matching
- `server/model_list_cache.go:489` — `readModelListGGUF()` — rewritten custom GGUF header parser
- `server/create.go:374` — `convertModelFromFiles()` — GGUF upload flow, calls `detectChatTemplate` at line 435
- `llm/llama_server.go` — subprocess wrapper for llama-server binary, version b9840
- `tools/tools.go` — generic tool parser with `{` tag default — **unchanged**
- `template/template.go:72` — `Named(s)` — levenshtein matching against known templates

## Critical New Finding: llama.cpp Vocabulary Validation

The weight hijack (REPORT-01/16) is **blocked at runtime** by llama.cpp's stricter vocabulary validation introduced in v0.30.7 (llama.cpp b3847) and still present in v0.31.1 (b9840). The error:

```
llama_model_load: error loading model: error loading model vocabulary: 
basic_string::substr: __pos (which is 3) > this->size() (which is 1)
```

Our hand-crafted GGUF with 260 single-byte tokens and no BPE merge rules fails validation. The new llama-server requires:
- 1:1 mapping between token IDs and token strings (no duplicates)
- Proper BPE merge rules for GPT-2 tokenizer type
- Valid UTF-8 token strings (no raw `\x00` bytes)

**Mitigation**: The weight hijack still works on Ollama v0.24.0 and earlier (old llama.cpp backend). For v0.30.7+, the GGUF must have a valid vocabulary — either from a real model's tokenizer or a properly constructed BPE vocabulary.

## REPORT-17 Still Valid

`chatTemplateHasToolSupport` at `server/images.go:194-196` is **identical** to v0.30.7:

```go
func chatTemplateHasToolSupport(chatTemplate string) bool {
    return strings.Contains(chatTemplate, "tools") || strings.Contains(chatTemplate, "tool_call")
}
```

Called from `ggufCapabilities` (images.go:139) which reads `f.KeyValue("tokenizer.chat_template").String()` directly from the GGUF file on disk. A model with `tokenizer.chat_template = "{{ .Tools }}"` in its GGUF KV gets `CapabilityTools` with **no Modelfile needed**.

## New in v0.31.1: chatTemplateHasToolRoundTrip

`server/images.go:198-213` — additional validation for tool call round-trip support:

```go
func chatTemplateHasToolRoundTrip(chatTemplate string) bool {
    toolCalls := strings.Contains(chatTemplate, "tool_calls") || strings.Contains(chatTemplate, "assistant_tool_call")
    return toolCalls && (strings.Contains(chatTemplate, "tool_response") ||
        strings.Contains(chatTemplate, "tool_results") ||
        strings.Contains(chatTemplate, "role'] == 'tool'") || ...)
}
```

This is used by `shouldPreferChatTemplate()` to decide whether the GGUF chat template or Go template should take precedence. It doesn't affect capability detection — only template selection priority.

## New in v0.31.1: PreferChatTemplate Logic

When both a Go TEMPLATE layer and a GGUF `tokenizer.chat_template` exist, `shouldPreferChatTemplate()` at `images.go:287` decides precedence:

1. If GGUF chat template has MORE capabilities than Go template → prefer GGUF template (unless Go template handles tool round-trip and GGUF doesn't)
2. If both have tools but differ in capability count → no preference (Go template wins)
3. If both have tools and same capabilities → prefer GGUF if it handles tool round-trip but Go doesn't

This means a GGUF with `tokenizer.chat_template` containing `"tools"` can **override** the Go template for template rendering, not just capability detection.

---

## New Attack Surface in v0.31.1

### NOVEL-01: model_list_cache Go string OOM
**File:** `server/model_list_cache.go:743`
```go
bts := make([]byte, length)  // length = uint64 from GGUF file, no bounds check
```
**Vector:** `readModelListGGUFString` reads a `uint64` string length from the GGUF header with no upper bound. Setting length to `2^62` causes a 4-exabyte allocation → OOM kills the Ollama process.
**Severity:** DoS (medium). Triggered by any malicious GGUF blob on disk when model list cache refreshes.

### NOVEL-02: fs/gguf core parser string OOM
**File:** `fs/gguf/gguf.go:195`
```go
f.bts = make([]byte, n)  // n = uint64 from GGUF file
```
**Vector:** Same pattern in the NEW core GGUF parser. Every model load path reads KV strings with `readString()`.
**Severity:** DoS (medium). Three separate unbounded allocations across 3 parsers.

### NOVEL-03: skipModelListGGUFArray uint64 overflow
**File:** `server/model_list_cache.go:730`
```go
return discardModelListGGUFBytes(r, int64(count*size))
```
**Vector:** `count` and `size` are `uint64`. If `count*size` overflows (e.g., count=2^62, size=8), wraps around. Cast to `int64` can be negative → `discardModelListGGUFBytes` checks `n <= 0` and returns early → parser skips fewer bytes than needed → desynchronized GGUF parsing.
**Severity:** Crash/corruption (low-medium).

### NOVEL-04: Cloud Proxy SSRF via OLLAMA_CLOUD_BASE_URL
**File:** `server/cloud_proxy.go:415-421`
```go
if runMode == gin.ReleaseMode && !loopback {
    return "", "", false, fmt.Errorf("non-loopback cloud override...")
}
```
**Vector:** In dev/debug mode, the env var allows HTTPS proxy to any host. If attacker controls this env, all cloud requests route to their server.
**Severity:** SSRF (low — needs env control).

### NOVEL-05: Anthropic image base64 bomb
**File:** `anthropic/anthropic.go:990`
```go
decoded, err := base64.StdEncoding.DecodeString(source.Data)
```
**Vector:** No size limit on base64 image data in the new Anthropic API bridge (1267-line protocol converter).
**Severity:** OOM (low — authenticated endpoint).

### NOVEL-06: Request body no size limit in cloud proxy
**File:** `server/cloud_proxy.go:294`
```go
body, err := io.ReadAll(r.Body)
```
**Vector:** Reads entire request body without limit in cloud proxy middleware.
**Severity:** OOM (low — already capped by HTTP server).

---

## New Code Audit: Anthropic API Bridge

**File:** `anthropic/anthropic.go` (1267 lines)

A full Anthropic Messages API compatibility layer that converts between Anthropic's API format and Ollama's internal format. Key functions:
- `FromMessagesRequest()` — converts Anthropic `MessagesRequest` to `api.ChatRequest`
- `ToMessagesResponse()` — converts `api.ChatResponse` to Anthropic `MessagesResponse`
- `convertMessage()` — handles message role/content conversion (text, image, tool_use, tool_result, thinking)
- `convertTool()` — passes through tool definitions, maps Anthropic built-in `web_search` to Ollama's

**Security notes:**
- Tool definitions passed through without validation beyond JSON schema parsing
- Image data decoded from base64 with no size limit (NOVEL-05)
- No server-side tool execution — all tool calls are returned to the client

## New Code Audit: Cloud Proxy Infrastructure

**File:** `server/cloud_proxy.go` (568 lines)

Proxies requests to ollama.com for cloud-enabled features:
- `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings` with `:cloud` model suffix
- `/api/experimental/web_search`, `/api/experimental/web_fetch`
- `/v1/messages` (Anthropic API) for cloud models

**Security architecture:**
- Requests signed with `auth.Sign(ctx, challenge)` before proxying
- `OLLAMA_CLOUD_BASE_URL` env var allows override (loopback-only in release mode, any HTTPS in debug)
- `resolveCloudProxyBaseURL()` validates the override URL (rejects userinfo, path, query, fragment)
- `copyProxyRequestHeaders()` strips hop-by-hop headers
- `maxDecompressedBodySize` = 20MB for zstd-decompressed bodies

## New API Endpoints in v0.31.1

| Endpoint | Handler | Purpose |
|----------|---------|---------|
| `POST /api/experimental/web_search` | `WebSearchExperimentalHandler` | Proxied to ollama.com |
| `POST /api/experimental/web_fetch` | `WebFetchExperimentalHandler` | Proxied to ollama.com |
| `GET /api/experimental/model-recommendations` | `ModelRecommendationsExperimentalHandler` | Returns default model recommendations |
| `POST /v1/responses` | OpenAI Responses API | Aliased to ChatHandler |
| `POST /v1/messages` | Anthropic Messages API | Aliased to ChatHandler via AnthropicMessagesMiddleware |
| `POST /v1/images/generations` | Image generation | Aliased to GenerateHandler |
| `POST /v1/images/edits` | Image editing | Aliased to GenerateHandler |

All experimental endpoints require cloud authentication and proxy through ollama.com.

## detectChatTemplate Refactored (Potential Mitigation)

**File:** `server/model.go:93-125`

**v0.30.7 behavior:** Levenshtein matched `tokenizer.chat_template` against known templates and injected the MATCHED KNOWN template's Go template content directly.

**v0.31.1 behavior:** Calls `template.Named(s)` → levenshtein match against known template registry → returns KNOWN template → adds as `application/vnd.ollama.image.template` layer.

**Impact on REPORT-17:** The raw `tokenizer.chat_template` string is no longer directly injected as the Go template for rendering. BUT capability detection (`chatTemplateHasToolSupport`) still reads the raw GGUF KV independently — `CapabilityTools` is granted from the raw string at load time, regardless of which template is selected for rendering.

## Tool call round-trip detection

**File:** `server/images.go:198-213`

New function `chatTemplateHasToolRoundTrip(chatTemplate)` checks if the template handles the complete tool call cycle:
- `tool_calls` or `assistant_tool_call` markers
- `tool_response`, `tool_results`, tool role patterns, or `ipython`

Used by `shouldPreferChatTemplate()` to decide template precedence — **not** a security control.

## OOM Vectors Summary

Three separate GGUF parsers with unbounded string allocation:

| Parser | File | Line | Severity |
|--------|------|------|----------|
| `fs/ggml/ggml.go` (old) | Old parser `readString` wrapper | ~361 | DoS via malicious GGUF string length |
| `fs/gguf/gguf.go` (new) | `readString()` — `make([]byte, n)` | 195 | DoS via malicious GGUF string length |
| `server/model_list_cache.go` | `readModelListGGUFString()` — `make([]byte, length)` | 743 | DoS via malicious GGUF string length (model list cache scan)