# Next.js 14+ Server Action Security Testing

## Architecture Overview

Modern Next.js apps (v14+) use **React Server Components (RSC)** for rendering and **Server Actions (SA)** for form submissions/mutations. Different from traditional REST API apps:

- **No REST API routes** on the app subdomain — all mutations go through Server Actions
- **Server Actions** are POST requests to the current page URL with a `Next-Action: <action_id>` header
- **Internal API calls** are made server-side through SAs, not client-side via fetch
- **Auth** is typically cookie-based (HttpOnly)

## Detection Signals

1. **JS bundles** contain `createServerReference` calls with 40+ hex char action IDs
2. **Network requests** show POST to current page URL with `Next-Action` header
3. **No `/api/*` routes** on the app subdomain (all return 404)
4. **RSC navigation** — client-side nav fetches `?_rsc=<token>` URLs

## Finding Server Action IDs from JS Bundles

```bash
curl -s "https://app.target.com" | grep -o 'src="[^"]*\.js[^"]*"' | head -5
curl -s "https://app.target.com/assets/index-HASH.js" -o bundle.js
grep -oP '"[a-f0-9]{40,}"' bundle.js | sort -u
```

## Intercepting Server Actions via Browser

```javascript
// Set up BEFORE each navigation — interceptor is lost on page reload
window.__saCalls = [];
const orig = window.fetch;
window.fetch = async function() {
  const url = typeof arguments[0] === 'string' ? arguments[0] : (arguments[0]?.url || '');
  const body = arguments[1]?.body;
  const headers = arguments[1]?.headers;
  if (headers) {
    const h = new Headers(headers);
    const sa = h.get('Next-Action') || h.get('next-action');
    if (sa && body) {
      try {
        const parsed = JSON.parse(body.toString());
        window.__saCalls.push({action: sa, url, body: parsed});
      } catch(e) {}
    }
  }
  return orig.apply(this, arguments);
};
```

**Workflow:** Navigate → Set interceptor → Trigger action → Read `window.__saCalls` → Repeat.

## SA Body Format

Server Actions proxy to internal API endpoints:

```json
["/v1/endpoint", {"method": "POST", "body": {"field": "value"}, "headers": "undefined"}]
```

The first array element is the internal API path, the second is the request config.

## Real-World Example (real-estate SaaS engagement)

**SA IDs found:**
- `7c0ae52f81f2d729e47ae331e7478b184b5e5b01ae` — `serverLoginWithCredentials`
- `0098079a5889f4c60f8c88bc4682608ded998723d4` — `validateUserToken`
- `608f68b25f7c1a25115aa29b70254ed3710e233012` — Shared proxy SA

**Internal endpoints via SA:**
- `/v1/pendingDeposits` (GET)
- `/v1/copa-dos-cortes/status` (GET)
- `/v1/updatePassword` (POST)

## Pitfalls

1. **Interceptor lost on every navigation** — re-set after each `browser_navigate`
2. **React auto-escapes all output** — basic XSS in input fields won't work
3. **No `/api/*` routes** on app subdomain — don't waste time fuzzing them
4. **Session expires** — re-login via form when redirected to `/auth/sign-in`
