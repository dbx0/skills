# Next.js SPA Recon Patterns

> **Context:** Discovered during example-realestate.tld pentest (June 2026). Next.js SPAs have specific patterns for JS bundle structure, auth flows, and API routing that differ from standard React/Vite apps.

## Detecting Next.js

- HTML: `/_next/static/` paths, `data-dpl-id` (Vercel), `__NEXT_DATA__` hydration
- Headers: `Server: Vercel`
- JS bundles: `/_next/static/chunks/pages/...js` (page components)

## JS Bundle Analysis for Next.js

Next.js bundles are split into chunks. Download the largest ones for secrets/endpoints.

```bash
# Extract bundle URLs from HTML
curl -s "https://app.target.com" | grep -oE 'src="[^"]*\.js[^"]*"' | sed 's/src="//;s/"//'

# Download key chunks
curl -s "https://app.target.com/_next/static/chunks/main-XXXX.js" -o main.js

# Search for secrets/endpoints
grep -oP '"https?://[a-zA-Z0-9._/-]+"' main.js | sort -u  # API base URLs
grep -oP '"/api/[^"]*"' main.js | sort -u                   # API paths
grep -oP '[0-9]+-[a-zA-Z0-9]+\.apps\.googleusercontent\.com' main.js  # Google OAuth
grep -oP 'data-api-key="[^"]*"' main.js                     # Tracking keys
grep -oP 'NEXT_PUBLIC_[A-Z_]+' main.js | sort -u            # Env vars
```

## NextAuth Detection & Auth Patterns

Detect: `grep -i 'nextauth' *.js`

Standard endpoints: `/api/auth/providers`, `/api/auth/csrf`, `/api/auth/signin`, `/api/auth/callback/<provider>`, `/api/auth/session`

Cookie: `next-auth.session-token` or `__Secure-next-auth.session-token`

Note: Next.js API routes that don't match return the 404 HTML page, not JSON. This is normal.

## Browser Form Submission Pitfall

> **CRITICAL**: Next.js/React SPA forms often don't submit via `browser_click` on the submit button or `browser_press Enter`. React synthetic events may not trigger from programmatic interactions.

### Workarounds (try in order):

1. **JS submit via browser console**: `document.querySelector('form').requestSubmit()`
2. **JS click via console**: `document.querySelector('button[type="submit"]').click()`
3. **Direct API call**: Get CSRF token from `/api/auth/csrf`, then POST to callback endpoint
4. **React synthetic event injection**: Use `nativeInputValueSetter` + `dispatchEvent` for each field
5. **Last resort**: Ask user to manually log in and provide session cookie

## Separated Auth Pattern (IMPORTANT)

When `/api/auth/*` returns 404 on the frontend app but a separate `api.` subdomain exists, the real auth endpoint is on the API subdomain.

**Real-world example:** `app.example-realestate.tld/api/auth/*` → 404, but `api.example-realestate.tld/api/v1/login` → 200

**How to find the real auth endpoint:**
1. Search JS bundles for the API subdomain: `grep -oP 'api\.[a-z]+\.[a-z]+' *.js`
2. Look for login/auth function calls in the largest chunks
3. Try common patterns: `POST https://api.target.com/api/v1/login`, `/api/v1/auth/login`, `/api/auth/login`

## Token Handling — CRITICAL

> **Tokens with special characters (`*`, `$`, `!`, spaces) break shell commands and Python f-strings.**

**NEVER do this:**
```bash
# WRONG — shell expands $* as glob
TOKEN=*** -H "Authorization: Bearer ***  # * expands to filenames!

# WRONG — Python interprets * as multiplication
TOKEN=*** = ["curl", "-H", "Bearer " + TOKEN]  # SyntaxError
```

**ALWAYS use file-based token reading:**
```bash
TOKEN=*** /tmp/token.txt)
curl -H "Authorization: Bearer *** "$URL"
```

```python
with open("/tmp/token.txt") as f:
    token = f.read().strip()
subprocess.run(["curl", "-H", "Authorization: Bearer *** + token, url])
```

See `references/api-security-testing.md` for complete API testing patterns including open redirect, mass assignment, CORS, and token bypass techniques.

- `data-dpl-id` in HTML = deployment ID
- `NEXT_PUBLIC_*` env vars exposed in JS bundles
- Headers: `Server: Vercel`, `X-Vercel-Cache`, `X-Vercel-Id`

## RSC (React Server Components) Payload Analysis

Next.js App Router serializes server component data into `__next_f.push()` script tags in the HTML source. These RSC payloads contain the **full user object** including id, email, name, role, subscription status — exposed to anyone who can view the HTML.

**What to look for:**
```html
<script>self.__next_f.push([1,"...user\":{\"id\":\"...\",\"email\":\"user@x.com\",\"name\":\"...\",\"role\":\"member\",\"isPremium\":false}..."])

```

**Checklist:**
- Search HTML for `"user":{` or `\"user\":` — reveals authenticated user objects
- Check for `isPremium`, `role`, `onboardingCompleted`, `subscription` fields
- Even 401/redirected pages may leak user data in RSC before the auth guard runs
- Vercel caches RSC responses — if a page has `cache-control: private`, RSC data may be cached for the wrong user

**Extraction command:**
```bash
curl -s "https://target.com/" | grep -oP '__next_f\.push\(\[1,"[^"]*"\)' | head -5
# Or for the full user object:
curl -s "https://target.com/" | grep -oP '"user":\{[^}]*\}'
```

## Server Actions (Form Without `action` Attribute)

Next.js Server Actions don't use standard form `action` URLs. Instead:

**Detection:**
- Form element has NO `action` attribute
- Uses `Next-Action` header on POST to the same page URL
- The action handler is defined in a JS chunk with `"use server"` directive

**Limitations (can't easily call from curl):**
```bash
# A standard form POST won't trigger the server action
curl -X POST "https://target.com/entrar" -d 'email=test@test.com'
# → Returns the full page HTML (not the action result)

# The real call requires the Next-Action header + serialized action args
# These are minified and not easily reversed
```

**Implications:** Server actions can't be easily tested from curl/CLI. You need browser tools or to reverse-engineer the JS bundle to find the server action ID.

## Turbopack Detection

Next.js App Router apps compiled with Turbopack include a `turbopack-*.js` chunk in the HTML:
```html
<script src="/_next/static/chunks/turbopack-5cbadf49c15f58bd.js"></script>
```

This distinguishes Turbopack builds from Webpack builds (which don't have this chunk).

## Passwordless / Magic Link Auth

Next.js apps frequently use magic-link authentication (no password):
- Login page description: `"Entre com seu email. Sem senha."` (Portuguese: "Login with email. No password.")
- Email OTP/magic link flow is typically a Server Action (no visible API endpoint)
- Supabase: `shouldCreateUser: false` means only existing users can login
- Common providers: Supabase Auth, Clerk, Auth0, custom

**To find the auth provider:**
```bash
# Check JS bundles for auth client
grep -oP 'supabase|clerk|next-auth|nextauth|@auth0' *.js | sort -u
grep -oP 'NEXT_PUBLIC_SUPABASE_URL|NEXT_PUBLIC_CLERK' *.js | sort -u
```

**Key implication:** Passwordless auth means no credential stuffing, but rate-limit testing on the magic link endpoint could reveal user enumeration or email bombing vectors.

## PostHog Analytics in JS Bundles

PostHog (self-hosted or cloud) injects internal API path patterns into client JS:
```javascript
"/api/web_experiments/?token="
"/flags/?v=2"
"/api/early_access_features/?token="
"/array/"
"/config.js"
```

Look for the PostHog cookie: `ph_phc_*_posthog` in the session cookies.

## Cloudflare Email Protection on Next.js Pages

Next.js pages behind Cloudflare with email addresses get auto-injected email protection:
```html
<a href="/cdn-cgi/l/email-protection" class="__cf_email__" data-cfemail="...">[email protected]</a>
<script data-cfasync="false" src="/cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js"></script>
```

The real email is `data-cfemail` XOR-encoded. This is NOT a vulnerability — it's Cloudflare's anti-spam feature. But it means the app has email addresses in its HTML (users' emails).

## Vercel Deployment ID in Every Request

Every Next.js/Vercel request includes `x-deployment-id` and `x-vercel-id`:
```
x-deployment-id: dpl_2oQKvuUYq9MAd5jKpxvfnoKqT24g
x-vercel-id: fra1::iad1::g4rjs-1783188299841-e0ae1cb92167
```

The deployment ID (`dpl_...`) is stable across all requests for that deployment. Use it to fingerprint the current version. The deploy alias is in the URL path: `dpl=dpl_XXX`.

## HTTP Method Probing for API Discovery

Next.js API routes respond differently to different HTTP methods. Use this to map the real API surface:

```bash
# Test each discovered path with all HTTP methods
for path in /api/posts /api/profile /api/subscribe /api/auth/logout /api/posts/6a494...; do
  for method in GET POST PUT PATCH DELETE; do
    code=$(curl -s -o /dev/null -w "%{http_code}" -X $method "https://target.com${path}")
    [ "$code" != "404" ] && echo "$method $path → $code"
  done
done
```

**Response code interpretation:**

| Code | Meaning |
|---|---|
| `404` | Endpoint doesn't exist (or catches all unmatched routes) |
| `405` | **Method Not Allowed** — endpoint EXISTS but needs a different method |
| `401` | **Unauthorized** — endpoint EXISTS, requires authentication, properly protected |
| `403` | **Forbidden** — endpoint EXISTS, authenticated but not authorized |
| `307` | **Redirect** — endpoint exists, redirects to login (often auth middleware) |
| `200` | **OK** — endpoint EXISTS and accepts this method (may return empty body) |
| `000` | Connection timeout / DNS failure |

**Key insight:** `405` is the most valuable signal — it confirms the endpoint exists and tells you it accepts a different HTTP method. If POST returns 405, try GET, PUT, PATCH, or DELETE.

**Real-world example (example-social.tld):**
- `POST /api/subscribe` → 405 with GET, 401 with POST (needs auth + POST = exists)
- `GET /api/posts` → 200 (authenticated) / 401 (not authenticated)
- `POST /api/posts` → 200 (creates post), 401 (not authenticated)
- `DELETE /api/posts/[id]` → 401 (authenticated) → then 200 with body `{"error":"Apenas admins podem remover posts"}` (endpoint exists, properly auth'd)
- `GET /api/posts/[id]/comments` → 405 (endpoint exists but needs POST)
- `PATCH /api/profile` → accepts extra fields (mass assignment test vector)
- `GET /api/posts/random-uuid` → 401 (not 404 — catches all with `/api/posts/:path` handler)

**Mass assignment probe on PATCH endpoints:**
```bash
# After confirming PATCH /api/profile works, test extra fields
curl -s -X PATCH "https://target.com/api/profile" \
  -H 'Content-Type: application/json' \
  -d '{"name":"user","role":"admin","isPremium":true,"balance":99999}'
# Returns {"ok":true} even if server doesn't apply the field
# Verify by checking RSC payload or re-fetching profile
```

## Real-World: example-social.tld (July 2026)

- Next.js App Router + Turbopack on Vercel
- JWT HS256 sessions (`app_session` cookie, 30d expiry)
- Passwordless login (OTP via email)
- payment gateway for payments
- Cloudflare R2 for image storage
- PostHog analytics
- API endpoints: `GET/POST /api/posts`, `DELETE /api/posts/[id]` (admin-only), `POST /api/subscribe`, `POST /api/auth/logout`
- No source maps exposed (403)
- No CORS headers (secure)
- No rate limiting detected on `/api/posts` (30 rapid requests all 200)
- RSC payload leaks full user object: id, email, name, role, isPremium
- 21 public articles, 45 members in private club

## Real-World: example-realestate.tld (June 2026)

- Next.js on Vercel + NextAuth (Google OAuth + credentials)
- `api.example-realestate.tld` backend behind Cloudflare
- Secrets: Google OAuth Client ID, Facebook Pixel ID, HiMetrica API key in JS bundles
- Browser login didn't work via click/Enter - needs JS execution or direct API call
- API endpoint from JS: `https://api.example-realestate.tld/api/v1/ref/`
