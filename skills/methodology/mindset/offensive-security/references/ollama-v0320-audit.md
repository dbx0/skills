# Ollama v0.31.2 / v0.32.0-rc0 Security Audit

**Date:** July 2025
**Scope:** Full source code audit of Ollama v0.31.2 (tag v0.31.2) and v0.32.0-rc0
**LLAMA_CPP_VERSION:** b9888 (v0.31.2) → b9888 (v0.32.0-rc0)

---

## Executive Summary

### What Changed (v0.31.1 → v0.32.0-rc0)

| Component | v0.31.1 | v0.32.0-rc0 | Security Impact |
|-----------|---------|-------------|-----------------|
| LLAMA_CPP_VERSION | b9840 | b9888 | 48 commits of llama.cpp updates |
| Agent TUI | Not present | **NEW: `ollama agent` command** | **Client-side RCE via `--yolo`** |
| Web UI | Basic | Redesigned | New attack surface |
| GGUF Parser | Same | Same | No fixes for known DoS |
| Chat Template | Same | Same | REPORT-17 still works |

### Key Finding: NO server-side RCE in Go code

The Ollama Go server remains a thin wrapper. All model execution is in llama.cpp (C++). The new `ollama agent --yolo` command is **client-side only** — runs on the user's machine, not the server.

---

## NEW: ollama agent --yolo (v0.32.0-rc0)

### Feature Overview

```bash
ollama agent --model <name> --yolo
```

Starts an interactive TUI agent that:
- Sends conversation + tools to model
- Auto-executes tool calls from model output
- Supports: `bash`, `read`, `edit`, `web_search`, `web_fetch`

### Security Analysis: `x/cmd/run.go` + `x/tools/`

| Tool | Safety Check | Bypassable? |
|------|--------------|-------------|
| `bash` | `rejectUnsafeShellCommand()` — blocks `rm -rf /`, SSH keys, AWS creds, kubeconfig | **YES** — string-based only |
| `read` | No path traversal check visible | Likely |
| `edit` | No validation visible | Likely |
| `web_search` | Requires auth | N/A |
| `web_fetch` | No SSRF protection visible | Likely |

### `rejectUnsafeShellCommand` Analysis (`x/tools/bash.go`)

```go
func rejectUnsafeShellCommand(cmd string) (bool, string) {
    if hasUnsafeRecursiveDelete(cmd) { ... }
    if readsCredentialPath(cmd) { ... }
    return false, ""
}
```

**Only checks:**
1. `rm -rf` on dangerous paths (`/`, `/etc`, `/home`, `*`)
2. Reading specific credential files (`.ssh/id_*`, `.aws/credentials`, `.kube/config`, `/etc/shadow`)

**Does NOT block:**
- Command substitution: `echo $(cat /etc/shadow)`
- Variable expansion: `cmd=cat; $cmd /etc/shadow`
- Base64: `echo Y2F0IC9ldGMvc2hhZG93 | base64 -d | bash`
- Shell builtins: `read -r line < /etc/shadow`
- Network commands: `curl`, `wget`, `nc`, `ssh`
- Process execution: `bash -c`, `sh -c`
- Privilege escalation: `sudo`

**Approval bypass:** `--yolo` flag skips ALL approval prompts.

### Threat Model

```
User runs: ollama agent --yolo --model evil-model
                │
                ▼
Model outputs tool calls (bash, read, etc.)
                │
                ▼
Agent auto-executes (--yolo) or prompts once then caches
                │
                ▼
Full RCE on user's machine (NOT the server)
```

**Supply chain impact:** Poison a model on Ollama Library / HuggingFace → users run `ollama agent --yolo --model poisoned` → RCE.

---

## llama.cpp b9888: Jinja2 Chat Template Engine Audit

### Component: `common/jinja/` (C++ implementation)

**Architecture:**
- Custom Jinja2 interpreter in C++ (~10 files, ~3000 lines)
- Parser (`parser.cpp`), Lexer (`lexer.cpp`), Runtime (`runtime.cpp`), Values (`value.cpp`)
- Executes `tokenizer.chat_template` from GGUF metadata

### Builtin Functions/filters — COMPLETE LIST

| Category | Functions | Risk |
|----------|-----------|------|
| Global | `raise_exception`, `namespace`, `strftime_now`, `range`, `tojson` | DoS via `range(1e9)` |
| String | `upper`, `lower`, `strip`, `replace`, `split`, `slice`, `indent`, `title`, `capitalize`, `length`, `startswith`, `endswith`, `int`, `float`, `string`, `default`, `safe`, `tojson` | DoS via `replace("", "x")` infinite loop |
| Array | `first`, `last`, `length`, `slice`, `selectattr`, `rejectattr`, `map`, `select`, `reject`, `list`, `sort`, `reverse`, `min`, `max`, `unique`, `join`, `append`, `pop` | DoS via large arrays |
| Object | `get`, `keys`, `values`, `items`, `tojson`, `string`, `length`, `dictsort`, `join` | Low |
| Tests | `boolean`, `callable`, `odd`, `even`, `divisibleby`, `string`, `integer`, `float`, `number`, `iterable`, `sequence`, `mapping`, `lower`, `upper`, `none`, `defined`, `undefined`, `eq`, `equalto`, `ge`, `gt`, `le`, `lt`, `ne`, `in`, `test`, `sameas`, `escaped`, `filter` | Low |

### NO Dangerous Builtins

| Missing (Good) | Why It Matters |
|----------------|----------------|
| `include`, `import`, `extends`, `block` | No template inheritance/inclusion |
| `eval`, `exec`, `compile` | No code execution |
| `read_file`, `write_file`, `shell` | No filesystem access |
| `http`, `fetch`, `request` | No network access |
| `__class__`, `__bases__`, `__subclasses__`, `__globals__` | No Python-style reflection (C++ types) |

### DoS Vectors Found

| Vector | File | Line | Impact |
|--------|------|------|--------|
| `range(0, 1_000_000_000)` | `value.cpp:382` | Allocates 8GB array | OOM |
| `split("")` | `value.cpp:667` | Splits every char | OOM/CPU |
| `replace("", "x")` | `value.cpp:722` | **Infinite loop** (find("") returns 0) | CPU hang |
| `indent(1_000_000_000)` | `value.cpp:835` | 1GB string | OOM |
| `selectattr`/`map` on 1M items | `value.cpp:912` | Iterates entire array | CPU |
| `sort` on 1M items | `value.cpp:1071` | O(n log n) on huge array | CPU |
| `tojson` on self-ref object | `value.cpp:235` | Stack overflow | Crash |

### Verdict: No RCE, Only DoS

The engine is **properly sandboxed**. No filesystem, network, or code execution primitives exist. The worst an attacker can do is crash the server process via resource exhaustion.

---

## GGUF Parser: Known DoS Vectors (Unfixed in v0.32.0)

| Vector | File | Line | Trigger |
|--------|------|------|---------|
| String length OOM | `fs/gguf/gguf.go:195` | `make([]byte, n)` | 1GB chat_template |
| Array count OOM | `fs/gguf/gguf.go` | `make([]T, n)` | 1B element array |
| Model list cache OOM | `server/model_list_cache.go:743` | `make([]byte, length)` | Malicious GGUF on disk |
| Integer overflow | `server/model_list_cache.go:730` | `int64(count*size)` | Parser desync |

All three parsers (ggml legacy, gguf new, model_list_cache) have the same pattern.

---

## REPORT-17: GGUF Chat Template Capability Injection (STILL WORKS)

### Mechanism

```go
// server/images.go:194
func chatTemplateHasToolSupport(chatTemplate string) bool {
    return strings.Contains(chatTemplate, "tools") || strings.Contains(chatTemplate, "tool_call")
}
```

### Exploit

```python
# Embed in GGUF tokenizer.chat_template KV
malicious = """
{% if tools %}
  {{ tools | tojson }}
{% endif %}
User: {{ messages[-1].content }}
"""

# Creates model with CapabilityTools → client executes tool calls
```

**Status:** Works on ALL versions v0.30.7+. Capability detection reads raw KV independently of template selection logic.

---

## REPORT-16: Weight Hijack (BROKEN by llama.cpp b9840+)

### Root Cause

llama.cpp vocabulary validation (introduced b3847, still in b9888):

```cpp
// llama.cpp vocab validation
basic_string::substr: __pos (which is 3) > this->size() (which is 1)
```

Our hand-crafted GGUF with 260 single-byte tokens fails validation. Requires valid BPE vocabulary with 1:1 token mapping.

### Workaround

Use a **real model's tokenizer** (copy `tokenizer.ggml.tokens`, `tokenizer.ggml.merges`, `tokenizer.ggml.model` from a real GGUF) and only modify the output weight matrix for the target token.

---

## Files Created in This Audit

| File | Purpose |
|------|---------|
| `/home/bx0/ollama_vulns/llama_fuzz_harness.cpp` | libFuzzer harness for GGUF parser + Jinja2 renderer |
| `/home/bx0/ollama_vulns/build_fuzz.sh` | Build script with ASAN/UBSAN |
| `/home/bx0/ollama_vulns/gguf_fuzz.py` | Python mutation fuzzer (11 exploit types) |
| `/home/bx0/ollama_vulns/gguf_exploits.py` | Exploit payload generator |
| `/home/bx0/ollama_vulns/JINJA_AUDIT.md` | Complete Jinja2 engine audit |
| `/home/bx0/ollama_vulns/GGUF_AUDIT.md` | GGUF parser DoS audit |
| `/home/bx0/ollama_vulns/RESEARCH_SUMMARY.md` | Executive summary |

---

## Fuzzing Quickstart

```bash
cd /home/bx0/ollama_vulns
./build_fuzz.sh
python3 gguf_exploits.py -o /tmp/corpus
./llama_fuzz /tmp/corpus -max_len=100000 -jobs=8 -timeout=60
```

---

## Recommendations

### For Ollama Maintainers

1. **Add Jinja2 resource limits** — `MAX_RANGE=10000`, `MAX_STRING=1MB`, `MAX_RECURSION=100`
2. **Add `--agent-timeout`** — prevent infinite agent loops
3. **Audit `--yolo` safety** — the string-based blocklist is trivially bypassable
4. **Fix GGUF parser OOM** — cap string/array allocations at 16MB
5. **Add model load timeout** — prevent hangs on massive models

### For Bug Bounty Hunters

| Target | Vector | Difficulty |
|--------|--------|------------|
| llama.cpp tensor kernels | Malicious weights → OOB in GEMM | Hard (requires GPU/CPU backend knowledge) |
| llama.cpp GGUF parser | String/array length → OOM | Easy (known unfixed) |
| Ollama Agent TUI | `--yolo` + malicious model → client RCE | **Trivial** — new in v0.32.0 |
| Supply chain | Poison model on registry → client RCE via tool calls | **Trivial** (REPORT-17) |

### Best ROI: Supply Chain + Agent TUI

```
1. Publish model with tokenizer.chat_template containing "tools"
2. Model outputs tool calls for bash/read/edit
3. Victim runs: ollama agent --yolo --model poisoned
4. RCE on victim's machine
```

---

## Related References

- `references/ollama-v0311-audit.md` — v0.31.1 deep dive
- `references/ggml-integer-overflow.md` — llama.cpp tensor stride overflow
- `references/ollama-supply-chain-rce.md` — supply chain attack patterns
- `references/ollama-weight-level-toolcall.md` — REPORT-16 details