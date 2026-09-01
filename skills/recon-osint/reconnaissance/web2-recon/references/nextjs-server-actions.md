# Next.js 14+ SPA Recon Notes

## Server Actions Architecture

Modern Next.js apps (14+) often use **Server Actions** instead of traditional REST APIs. Key indicators:

- No `/api/*` routes return valid responses (all 404)
- Form submissions don't trigger visible network requests
- Data is embedded in server-rendered HTML (RSC payloads)
- Client-side navigation uses `?_rsc=<hash>` query parameters

### How to Identify Server Actions

1. **Check for `/api/*` routes** — if all return 404, the app likely uses Server Actions
2. **Look for `createServerReference` in JS bundles** — this is how Next.js registers Server Actions:
   ```
   createServerReference("<action_id>", callServer, void 0, findSourceMapURL, "<function_name>")
   ```
3. **Extract action IDs** — 40+ hex char strings associated with `createServerReference`
4. **Map function names** — the last parameter is the server function name (e.g., `serverLoginWithCredentials`, `validateUserToken`)

### Discovering Internal API Endpoints via Server Actions

Server Actions often proxy to internal API endpoints. To discover them:

1. **Override `window.fetch` in browser console BEFORE any navigation:**
   ```javascript
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
           if (Array.isArray(parsed) && parsed[0]) {
             window.__saCalls.push({action: sa, path: parsed[0], method: parsed[1]?.method || 'GET'});
           }
         } catch(e) {}
       }
     }
     return orig.apply(this, arguments);
   };
   ```

2. **Navigate the app and perform actions** (change password, update settings, etc.)

3. **Collect captured calls:** `JSON.stringify(window.__saCalls);`

**Important:** The interceptor is lost on page navigation. Re-inject after each navigation.

### Real-World Example: real-estate SaaS (2026)

Server Actions discovered:
| Action ID | Function | Internal API Called |
|-----------|----------|---------------------|
| `7c0ae52f81f2d729e47ae331e7478b184b5e5b01ae` | `serverLoginWithCredentials` | External API login |
| `0098079a5889f4c60f8c88bc4682608ded998723d4` | `validateUserToken` | Token validation |
| `608f68b25f7c1a25115aa29b70254ed3710e233012` | Shared proxy SA | `/v1/pendingDeposits`, `/v1/copa-dos-cortes/status`, `/v1/updatePassword` |

The shared proxy SA is particularly interesting - it routes to different internal API endpoints based on the request body, acting as a generic API proxy.

### RSC (React Server Component) Data Loading

- Navigation requests use `?_rsc=<hash>` query parameter
- Response is HTML with embedded data (not JSON)
- Use browser's Performance API to capture RSC requests
- RSC responses contain the full page HTML — data is server-rendered

### Common Pitfalls

- **Don't assume REST APIs exist** — always check if the app uses Server Actions
- **Don't look for `/api/*` routes** — they may not exist in modern Next.js apps
- **Form submissions may not be visible in network tab** — use JS interceptors
- **CSRF tokens may not be in HTML** — they can be in cookies or handled server-side

---

## Token Handling with Special Characters

Auth tokens containing `*`, `?`, or other shell-special characters will break shell commands and Python f-strings.

### Solutions

1. **Read from file** (preferred): `TOKEN=$(cat /path/to/token.file)`
2. **Base64 encode/decode** when passing through shell/Python
3. **Write Python scripts to files** instead of using inline code with tokens

---

## Open Redirect Testing

Always test these parameter names on login/sign-in pages:

```
url, redirect, redirect_uri, callback, next, return, returnTo,
goto, dest, destination, continue, forward, redirect_url,
return_url, return_to, continue_to, target, to, uri, path
```

Use `curl -s -o /dev/null -w "%{url_effective}" -L` to detect redirects to external domains.

---

## Open Redirect Testing (NextAuth.js)

NextAuth.js sign-in pages commonly accept multiple redirect parameters. Always test:

```
url, redirect, redirect_uri, callback, next, return, returnTo,
goto, dest, destination, continue, forward
```

**Detection:**
```bash
for param in url redirect redirect_uri callback next return returnTo goto dest destination continue forward; do
    final=$(curl -s -o /dev/null -w "%{url_effective}" -L "https://app.target.com/auth/sign-in?${param}=https://evil.com")
    echo "$param -> $final"
done
```

**Real-world finding:** NextAuth `/auth/sign-in` accepted 12 redirect parameters (confirmed on real-estate SaaS, 2026).

---

## Mass Assignment on Login

Test with extra fields: `is_admin: true`, `role: "admin"`, `plan: "premium"`, `balance: 99999`, `webhook_url: "https://attacker.com"`.

- `is_admin: true`
- `role: "admin"`
- `plan: "premium"`
- `balance: 99999`
- `blocked: 0`
- `webhook_url: "https://attacker.com"`

Check if login succeeds and if fields appear in the response user object.
