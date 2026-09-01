# Next.js Auth Separation Pattern

## Pattern: Next.js Frontend with Separate API Backend

Modern Next.js applications often split auth between the frontend app (Vercel) and a separate API backend. This creates a recon puzzle where `/api/auth/*` routes on the frontend return 404.

## Detection Signals

1. **Next.js app** detected via `/_next/static/` paths and `data-dpl-id` attribute on `<html>`
2. **Auth page loads** with email/password form (standard NextAuth UI)
3. **All `/api/auth/*` routes return 404** on the frontend domain
4. **Form submission doesn't work** via curl or browser automation (React synthetic events issue)
5. **Separate API subdomain** exists (e.g., `api.target.com.br`)

## How to Find the Real Auth Endpoint

```bash
# 1. Download the login page HTML
curl -s "https://app.target.com/auth/sign-in" > login.html

# 2. Extract JS chunk URLs
grep -o 'src="/_next/static/chunks/[^"]*\.js[^"]*"' login.html

# 3. Download the main JS chunks and search for login API patterns
strings *.js | grep -oE '"(/api/v[^"]*login[^"]*)"' | sort -u
strings *.js | grep -oE '"(https?://api\.[^"]*)"' | sort -u
grep -oP '.{0,200}callApi.{0,200}' bundle.js | head -5
```

## Common Patterns

### Pattern A: Auth on API subdomain (most common)
- Frontend: `app.target.com` (Vercel, Next.js)
- API: `api.target.com` (Cloudflare, custom backend)
- Auth: `POST https://api.target.com/api/v1/login`
- Next.js `/api/auth/*` routes return 404

### Pattern B: NextAuth on same domain
- Auth: `POST https://app.target.com/api/auth/callback/credentials`
- Standard `/api/auth/*` paths exist

### Pattern C: Auth in Next.js Server Actions
- Form submits to `/auth/sign-in` (POST)
- No explicit API endpoint in JS bundle
- Use browser DevTools Network tab to capture actual requests

## Real-World Examples

### real-estate SaaS (2026-06)
- Frontend: `app.example-realestate.tld` (Vercel, Next.js)
- API: `api.example-realestate.tld` (Cloudflare, Symfony/PHP)
- Auth: `POST https://api.example-realestate.tld/api/v1/login`
- JS bundle has `callApi` function routing to API subdomain
- `/api/auth/*` on frontend all return 404
- Token stored as `auth_token` in localStorage and cookie
- Response includes `token` (full) and `read_only_token`

## Pitfalls

1. **Browser form submission doesn't work** with `browser_click` — React synthetic events don't trigger via accessibility tree. Use `fetch()` in browser console or call API directly.

2. **NextAuth CSRF endpoint returns 404** when auth is on separate subdomain. Don't assume NextAuth is broken.

3. **Token-based auth**: When API uses Bearer tokens, flow is: `POST /api/v1/login` → store token → use `Authorization: Bearer *** header.

4. **Rate limiting** kicks in after ~5-10 rapid requests. Space out testing.
