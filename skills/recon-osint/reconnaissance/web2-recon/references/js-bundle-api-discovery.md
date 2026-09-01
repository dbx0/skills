# JS Bundle API Discovery — Reverse Engineering Frontend Source for Hidden Endpoints

> **Context:** Found in payment gateway bug bounty engagement (June 2026).  
> The SPA at `app.example-pay.tld` (Vite/React) bundled all routes, API calls, and component logic into a single 2.8MB JS file. Manual analysis revealed internal API endpoints, download flow logic, and server-communication patterns that URL crawlers and SecretFinder/LinkFinder missed.

## When to Use This Technique

- Target is a Single-Page Application (React, Vue, Angular, Svelte)
- Traditional crawlers (katana, waybackurls, gau) returned limited API surface
- You suspect hidden `/internal/*` endpoints or purchase-verification logic
- You want to understand the **exact client-server data flow** for a feature (e.g., file download, payment, 2FA)

## Step-by-Step

### 1. Find the JS Bundle

```bash
# From the SPA HTML: look for the main JS bundle
curl -s "https://app.target.com/" | grep -oP 'src="[^"]*\.js[^"]*"' | sed 's/src="//;s/"//'

# Common patterns:
# /assets/index-XXXXXXXX.js  (Vite)
# /_next/static/chunks/pages/...js  (Next.js)
# /static/js/main.XXXXXXXX.chunk.js  (CRA)
# /__nuxt/...js  (Nuxt)
```

### 2. Download with Metadata

```bash
curl -s -o bundle.js -w "%{size_download}" "https://app.target.com/assets/index-XXXXXXXX.js"
# Check size — 2-3MB is normal for large SPAs
```

### 3. Keyword Search for API Endpoints

Search for internal API patterns, HTTP client calls, and route definitions:

```bash
# Internal API endpoints
grep -oP '/internal/[a-zA-Z0-9/_-]+' bundle.js | sort -u

# All API routes
grep -oP '/[vV][0-9]/[a-zA-Z0-9/_-]+' bundle.js | sort -u

# Framework-specific patterns:
# Elysia/Bun: look for route handler names
# React: look for useEffect with API calls
# Axios: grep for ".get(", ".post(", ".put("
# tRPC: grep for "query(" or "mutation("
```

### 4. Search for Feature Keywords

Focus on features that might have hidden endpoints:

```bash
# Download/file features
grep -oP '.{0,50}download.{0,100}' bundle.js | head -20
grep -oP '.{0,50}downloadUrl.{0,100}' bundle.js | head -10

# Purchase/billing flows
grep -oP '.{0,50}purchase.{0,100}' bundle.js | head -10
grep -oP '.{0,50}billingId.{0,100}' bundle.js | head -10

# Auth/security
grep -oP '.{0,50}2fa.{0,100}' bundle.js | head -10
grep -oP '.{0,50}verifyCode.{0,100}' bundle.js | head -10

# Payment
grep -oP '.{0,50}paymentIntent.{0,100}' bundle.js | head -10
grep -oP '.{0,50}pix.{0,100}' bundle.js | head -10

# Generic endpoints
grep -oP '"/(?:api|v1|v2|internal|app)/[^"]*"' bundle.js | sort -u
```

### 5. Extract Full Context

Once you find a keyword match, extract the surrounding context to understand the data flow:

```bash
# Python helper for context extraction
python3 << 'EOF'
with open('bundle.js') as f:
    js = f.read()

seen = set()
for keyword in ['downloadUrl', 'handleDownload', 'internal.product', '/internal/']:
    idx = 0
    while True:
        idx = js.find(keyword, idx)
        if idx == -1: break
        # Avoid showing the same region twice
        region = js[max(0,idx-200):idx+400]
        h = hash(region[:100])
        if h not in seen:
            seen.add(h)
            print(f"=== {keyword} @ {idx} ===")
            print(region)
            print()
        idx += 1
EOF
```

### 6. Reconstruct API Calls from Minified Code

Modern bundlers mangle function names. Look for patterns:

```javascript
// Axios calls look like:
Te.internal.product.download.get({query:{billingId:e}})
// Means: GET /internal/product/download?billingId={value}

// tRPC calls look like:
api.billing.create.useMutation()
// Means: POST /api/billing/create

// Plain fetch:
fetch("/internal/cloudflare/" + a + "/" + b)
// Means: fetches /internal/cloudflare/{param1}/{param2}
```

### 7. Map Component Logic → API Endpoints

```javascript
// React component pattern:
function Dlt(t, e) {  // Dlt = Download component
  const [n, r] = useState(null)  // n = downloadUrl
  const [i, s] = useState(false) // i = isLoading
  
  // On mount, fetch the download URL
  useEffect(() => {
    if (t) {
      s(true)
      Te.internal.product.download.get({query:{billingId:e}})
        .then(u => {
          s(false)
          if (u.data && Ws(u.data))
            r(u.data.data.url)  // url = the file download URL
        })
    }
  }, [t, e])
  
  return { downloadUrl: n, isLoadingDownload: i, ... }
}
```

From this, you learn:
- **Endpoint:** `GET /internal/product/download?billingId={id}`
- **Returns:** `{data: {url: "https://..."}}`
- **Condition:** Only fetches when billingId exists (`if (t)`)
- **Error handling:** None shown (no catch block)

### 8. Also Check for:

- **Route definitions:** `path: "/pay/:id"` — reveals SPA routing structure
- **Component props:** `hasFile`, `hasRepurchase`, `hasChurn` — data shape hints
- **State management:** `sessionStorage.getItem("up-sell:accepted:...")` — client-side state
- **Timing logic:** `setTimeout(() => window.location.href = successUrl, 5000)` — redirects
- **Payment methods:** `method === "PIX"`, `paymentIntent?.method` — supported payment types

## Firebase-Specific JS Bundle Patterns

When the target uses Firebase (common with React/Vite SPAs on Firebase Hosting), JS bundles contain high-value recon data beyond standard API endpoints.

### Detecting Firebase

```bash
# In HTML
grep -i firebase index.html

# In JS bundles
grep -iE '(firebase|firestore|cloudfunctions|firebaseapp)' bundle.js | head -20

# Firebase config object (look for apiKey, projectId, etc.)
grep -oP 'apiKey:\s*"[^"]*"' bundle.js | head -5
grep -oP 'projectId:\s*"[^"]*"' bundle.js | head -5
grep -oP 'authDomain:\s*"[^"]*"' bundle.js | head -5
```

### Extracting Cloud Function Names

Firebase callable functions are invoked via `httpsCallable(functionName)`. In minified code, look for:

```bash
# Pattern 1: direct string literals passed to httpsCallable
grep -oP 'httpsCallable\s*\(\s*["\x27][^"\x27]+["\x27]' bundle.js | sort -u

# Pattern 2: variable assignment then call (common in minified code)
# Look for z("functionName") or similar patterns
grep -oP 'z\s*\(\s*["\x27][a-zA-Z][a-zA-Z0-9]+["\x27]' bundle.js | sort -u

# Pattern 3: string literals near "functions" or "callable"
grep -oP '["\x27][a-zA-Z][a-zA-Z0-9]+["\x27]\s*\)' bundle.js | grep -iE '(admin|list|get|create|update|delete|ban|user|affiliate|store|submit)' | sort -u

# Pattern 4: cloudfunctions.net URL references
grep -oP 'cloudfunctions\.net/[^"\x27\s]+' bundle.js | sort -u
```

### Extracting Firebase Config

```bash
# Full config object (minified)
grep -oP '\{[^}]*apiKey[^}]*\}' bundle.js | head -5

# Individual fields
grep -oP '(apiKey|projectId|authDomain|storageBucket|messagingSenderId|appId|measurementId)\s*:\s*"[^"]*"' bundle.js | sort -u
```

### Extracting Admin Panel Routes

Admin panels bundled in the same SPA (code-split) reveal internal route structure:

```bash
# Look for route path definitions
grep -oP 'path:\s*["\x27][^"\x27]+["\x27]' bundle.js | sort -u

# Look for admin-specific strings
grep -iE '(dashboard|overview|directory|moderation|analytics|ops|command.center)' bundle.js | head -20

# Admin panel title/branding
grep -oP 'fitness app Ops|Command Center|Admin Panel' bundle.js | head -5
```

### Extracting Deep Link / Universal Link Config

```bash
# Apple App Site Association
curl -s "https://target.com/.well-known/apple-app-site-association" | python3 -m json.tool

# Android Asset Links
curl -s "https://target.com/.well-known/assetlinks.json" | python3 -m json.tool

# These reveal: app ID, deep link paths (e.g., /user/*, /post-details*, /clubs/*)
```

### Probing Discovered Cloud Functions

Once you have function names, test them unauthenticated:

```bash
# Base URL pattern
BASE="https://us-central1-{projectId}.cloudfunctions.net"

# Test each function
for func in functionName1 functionName2; do
    echo "=== $func ==="
    curl -s -X POST "$BASE/$func" \
      -H "Content-Type: application/json" \
      -H "Origin: https://target.com" \
      -d '{}' 2>&1
done

# Response interpretation:
# {"error":{"message":"Bad Request","status":"INVALID_ARGUMENT"}} → function exists, needs auth/args
# {"error":{"message":"UNAUTHENTICATED"}} → function exists, needs Firebase Auth
# 404 → function not deployed
# {"error":"custom_error_message"} → function exists and processes input (interesting!)
```

### Testing Firebase Services Directly

```bash
# Firestore (will return 403 if properly secured)
curl -s "https://firestore.googleapis.com/v1/projects/{projectId}/databases/(default)/documents"

# Realtime Database (will return 404 if not enabled)
curl -s "https://{projectId}-default-rtdb.firebaseio.com/.json"

# Storage (will return 401 if properly secured)
curl -s "https://storage.googleapis.com/storage/v1/b/{storageBucket}/o"

# Auth signup (test if anonymous signup is allowed)
curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={apiKey}" \
  -H "Content-Type: application/json" \
  -d '{"returnSecureToken":true}'
```

### Real-World Example: fitness app (2026-06-11)

From `fitness-app.com.br` JS bundles:
- Firebase project: `pumpgym-93f15`
- Cloud functions found: `storeInstallFingerprint`, `submitPublicAffiliateApplication`, `adminListUsers`, `adminListAffiliates`, `adminBanUser`, `adminUnbanUser`, `adminToggleAffiliate`, `adminRefreshOpsSnapshot`, `getRevenueCatMetrics`
- Admin panel: "fitness app Ops — Command Center" with 22 routes (overview, users, affiliates, directory, creators, clubs, community, posts, etc.)
- `storeInstallFingerprint` was publicly callable and returned different errors for invalid format vs valid-but-not-found (boolean oracle for affiliate code enumeration)
- `submitPublicAffiliateApplication` had client-side-only origin validation and honeypot
- Firestore/Storage properly secured (403/401 for unauthenticated)
- API key in bundle was truncated (`AIzaSy...sMBc`) — assembled at runtime

## Better Auth Framework — JS Bundle Patterns

When the target uses Better Auth (common in Next.js/React apps), JS bundles contain specific patterns that reveal the auth architecture.

### Detecting Better Auth

```bash
# In JS bundles
grep -i 'better-auth' bundle.js | head -10
grep -i 'better-auth/client' bundle.js | head -5
grep -i '__Secure-better-auth' bundle.js | head -5

# Look for the client initialization
grep -oP 'baseURL:\s*["\x60]https?://[^"\x60]+["\x60]' bundle.js | head -5
```

### Session Token Format

Better Auth session tokens are **NOT JWTs**. They are two dot-separated parts:
```
E4QQtsaw6vXYHQarYAYctpNP5sGAy8cs.tqU8k5Dpl0VcN23tlg1H7seExbEpbkj40Nr+BxSVsS8=
^______________________________^ ^_____________________________________________^
        token ID                              hashed secret
```

The cookie name is always: `__Secure-better-auth.session_token`

### Extracting API Base URL

```bash
# The baseURL tells you where the API lives
grep -oP 'baseURL:\s*["\x60]https?://[^"\x60]+["\x60]' bundle.js | sort -u

# Often the API is on a subdomain:
# baseURL: "https://api.target.com"
# baseURL: "https://api.target.bsky.app"
```

### Standard Better Auth Endpoints

Once you know the base URL, test these:
```
POST /api/auth/sign-in/social     — Returns {url: "https://accounts.google.com/..."}
POST /api/auth/sign-in/email      — Usually disabled for OAuth-only apps
GET  /api/auth/get-session        — Returns {user: null, session: null} without cookie
POST /api/auth/update-user        — Requires cookie + Origin header (403 without Origin)
POST /api/auth/change-email       — Usually disabled for OAuth-only
POST /api/auth/change-password    — Returns "CREDENTIAL_ACCOUNT_NOT_FOUND" for OAuth users
POST /api/auth/delete-user        — Requires cookie + Origin header
POST /api/auth/revoke-sessions    — Requires cookie + Origin header
POST /api/auth/sign-out           — Requires cookie + Origin header
GET  /api/auth/callback/google    — Redirects to Google OAuth
```

### Key Testing Notes

- **Origin header required**: Better Auth checks Origin for state-changing POST endpoints. Without it: `{"message":"Missing or null Origin","code":"MISSING_OR_NULL_ORIGIN"}` (HTTP 403). Always include `Origin: https://target.com`.
- **CORS is strict**: The API only returns `access-control-allow-origin` for whitelisted origins. Other origins get 204 without CORS headers. This is correct behavior.
- **Session capture**: After Google OAuth login, capture the cookie from browser DevTools → Network → any authenticated request → Cookie header.
- **Use with curl**: `curl -H "Cookie: __Secure-better-auth.session_token=<token>" -H "Origin: https://target.com" https://api.target.com/api/v1/endpoint`

### Real-World Example: speedrun platform (2026-06-11)

From `admin.example-speedrun.tld` JS bundles:
- baseURL: `https://api.example-speedrun.tld`
- Auth: Google OAuth only (email/password disabled)
- Cookie: `__Secure-better-auth.session_token` (two-part dot-separated)
- API endpoints: `/api/v1/events` (public), `/api/v1/runs` (auth), `/api/v1/volunteers` (auth)
- Role system: `RUNNER`, `ADMIN` (seen in session response)
- CSRF: Origin header required for POST endpoints (verified: 403 without it)
- CORS: Whitelist-restricted to `www.example-speedrun.tld` and `admin.example-speedrun.tld`

## Output

Create a structured notes file:

```markdown
# JS Bundle Recon — target.com

## Better Auth Config
- Base URL: https://api.target.com
- Auth: Google OAuth only
- Cookie: __Secure-better-auth.session_token

## API Endpoints
| Endpoint | Auth | Notes |
|----------|------|-------|
| /api/v1/events | None | Public |
| /api/v1/runs | Cookie | Returns empty for new users |

## Findings
- No IDOR on user endpoints
- CSRF protection active (Origin header required)
- CORS properly whitelist-restricted
```

## Why This Works Better Than Automated Tools

| Tool | What It Misses | This Technique Catches |
|------|---------------|------------------------|
| SecretFinder | API call patterns, data flow | Full request/response shapes |
| LinkFinder | Dynamic routes, conditional calls | Business logic + state machines |
| katana/crawler | JavaScript-generated routes | Client-only routes (SPA) |
| gau/waybackurls | Recent deployments | Current live version endpoints |

## Example: payment gateway Results

Searching the 2.8MB bundle for `download` revealed:
- `downloadUrl` (3 occurrences) — component state variable
- `handleDownloadClick` — click handler function
- `hasFile` — product property flag
- `internal.product.download.get` — the actual API call
- `billingId` — query parameter name
- `Arquivo para download` — Portuguese UI text for download section

This led to discovering `GET /internal/product/download?billingId={id}` — an internal endpoint not present in any URL list, sitemap, or API documentation.
