# XSS Testing on React / Next.js SPAs

## Key Insight: React Auto-Escapes Everything

React (and by extension Next.js) automatically HTML-escapes ALL output rendered via JSX expressions (`{variable}`) and props like `value`, `defaultValue`, etc. This means:

```jsx
// If userInput = '<img src=x onerror=alert(1)>'
<input value={userInput} />
// Renders as: value="&lt;img src=x onerror=alert(1)&gt;" — SAFE
```

**Basic XSS payloads will NOT work in React apps.** This includes:
- `<script>alert(1)</script>` in text fields
- `<img src=x onerror=alert(1)>` in text fields
- `"><img src=x onerror=alert(1)>` to break out of attributes
- `javascript:` URLs in text fields

## What to Test Anyway

Even though React auto-escapes, you should still test because:

1. **`dangerouslySetInnerHTML`** — React's escape hatch. Search JS bundles for this string.
2. **Third-party components** — Some component libraries may bypass escaping.
3. **Server-side rendering** — If the server renders user input directly into HTML (not via React), it may be vulnerable.
4. **Rich text editors** — If the app has a WYSIWYG editor, it may allow HTML injection.
5. **Markdown rendering** — If user content is rendered as markdown, XSS via `[click](javascript:...)` or inline HTML may work.
6. **URL parameters** — Check if URL params are reflected without encoding (DOM-based XSS).

## Testing Methodology for React SPAs

### 1. Test all user-controllable input fields
- Profile fields (name, nickname, bio, etc.)
- Search inputs
- URL inputs (video URLs, webhook URLs)
- File upload names
- Any free-text field

### 2. For each field, inject:
```
<img src=x onerror=alert(1)>
"><img src=x onerror=alert(1)>
<script>alert(1)</script>
javascript:alert(1)
<svg onload=alert(1)>
${7*7}  (template injection)
```

### 3. Submit the form and check:
- Is the payload reflected in the DOM as HTML or encoded?
- Is the payload visible in the accessibility tree (snapshot) as encoded or raw?
- Are there any error messages that reflect the input without encoding?

### 4. Check the actual DOM HTML:
```javascript
// In browser console
document.body.innerHTML.includes('<img src=x onerror=alert(1)>')
// If false, React encoded it. If true, investigate further.
```

### 5. Search JS bundles for dangerous patterns:
```bash
grep -l 'dangerouslySetInnerHTML' bundle.js
grep -l 'innerHTML' bundle.js
grep -l 'eval(' bundle.js
grep -l 'document.write' bundle.js
```

## Browser Automation Pitfall: React Login Modals

**Problem**: React login modals rendered via portals often don't appear in the browser accessibility tree (snapshot), even though `document.querySelectorAll('input')` finds them in the DOM.

**Symptoms**:
- `browser_snapshot` shows the page without the modal
- `browser_type` and `browser_click` can't interact with modal elements (not in a11y tree)
- `browser_console` with `document.querySelectorAll('input')` DOES find the email/password fields

**Workaround**:
1. Use `browser_console` to inject values via React fiber approach:
   ```javascript
   const el = document.querySelector('input[type="email"]');
   const key = Object.keys(el).find(k => k.startsWith('__reactFiber'));
   let node = el[key];
   for (let i = 0; i < 15; i++) {
     if (node?.memoizedProps?.onChange) {
       node.memoizedProps.onChange({target: {value: 'user@email.com'}});
       break;
     }
     node = node?.return;
   }
   ```
2. Then click the submit button via JS: `document.querySelector('button[type="submit"]').click()`
3. If login still fails, the Cognito auth may require the actual password — DOM manipulation won't help

**Working login flow (example-auto.tld 2026-06)**:
1. Click ENTRAR button to open login modal (modal is invisible in a11y snapshot but present in DOM)
2. Use React fiber onChange to fill email/password fields (native value setter + dispatchEvent for controlled inputs)
3. Click the second "Entrar" button (first is the header button, second is the modal button)
4. Wait for page reload — check for "SAIR" (logout) button to confirm login
5. Once logged in, use browser XHR to get presigned upload URLs, then curl to upload files

**Important**: The `/api/upload/thumbnail-url` endpoint requires authentication. The `/api/auth/login` endpoint returns HTTP 401 with `{"error":"E-mail ou senha inválidos.","code":"NotAuthorizedException"}` for wrong credentials. Do NOT use `9rt1wo47` as the password — that's the VPS sudo password, not the site password.

## Authenticated File Upload Testing (example-auto.tld 2026-06)

For SVG XSS PoC uploads on authenticated platforms:

1. **Login via browser automation** (React Cognito login, see above)
2. **Get presigned URL via browser XHR** (since endpoint requires auth cookie):
   ```javascript
   const res = await fetch('/api/upload/thumbnail-url', {
     method: 'POST',
     headers: {'Content-Type': 'application/json'},
     body: JSON.stringify({'contentType': 'image/svg+xml', 'extension': '.svg'})
   });
   const data = await res.json();
   // data.putUrl = presigned S3 upload URL
   // data.publicUrl = public CDN URL for the uploaded file
   ```
3. **Upload file via curl** using the presigned URL:
   ```bash
   curl -s -X PUT "<putUrl>" -H "Content-Type: image/svg+xml" --data-binary @/tmp/payload.svg -w "%{http_code}"
   ```
4. **Update profile/reference** with the public URL:
   ```javascript
   await fetch('/api/me/profile', {
     method: 'PUT',
     headers: {'Content-Type': 'application/json'},
     body: JSON.stringify({'avatarUrl': data.publicUrl})
   });
   ```

## Session Management Pitfall

**Next.js apps with Server Actions often have very short browser sessions.** When testing authenticated XSS:

1. **Session expires quickly** — typically after a few page navigations
2. **Re-login via UI each time** — the auth_token cookie is HttpOnly, can't inject via curl
3. **Plan your test sequence** — know exactly which fields to test before navigating
4. **Multi-step flows are hard to test** — flows requiring validated input before reaching the title field may be impossible before session expires
5. **File upload XSS** — Upload an SVG with embedded JavaScript (`<script>alert(1)</script>` inside SVG XML). The filename or metadata may be reflected without sanitization even if the content is safe

## Real-World Example (real-estate SaaS engagement)

**Tested fields:** Name, Nickname, CPF/CNPJ, Phone, Webhook URL, Video URL, Profile name with embedded `<img>` tag

**Video upload flow:** Create-project requires valid YouTube/Drive URL first (server-side validation). XSS payloads in URL field rejected. Project title field was in a multi-step flow that couldn't be reached due to session expiration during navigation.

**Payloads tested:**
- `<img src=x onerror=alert(1)>` — encoded by React
- `"><img src=x onerror=alert(1)>` — encoded by React
- `<script>alert(1)</script>` — encoded by React
- `javascript:alert(document.cookie)` — stored but encoded in value attr

**Results:** All payloads properly HTML-encoded by React. Values stored in DB but rendered safely. No `dangerouslySetInnerHTML` found in JS bundles.

**Session issues:** Browser session expired 6+ times during testing. Each re-login required full UI flow. Multi-step flows like project creation couldn't be completed before timeout.

**Conclusion:** Not vulnerable to XSS via tested fields. React's built-in escaping is effective. Video/title flow and file upload metadata not fully tested due to session constraints.

## ⚠️ CRITICAL: Verify Rendering Before Reporting XSS Severity

**Never report XSS as HIGH/CRITICAL based solely on API response showing raw HTML storage.** Always verify actual browser rendering:

1. **Check the accessibility tree** — if you see `StaticText "<script>alert(1)</script>"`, React escaped it
2. **Search JS bundles** for `dangerouslySetInnerHTML` — zero uses = React handles all rendering safely
3. **Open the page in browser** and inspect the actual DOM — encoded entities mean safe rendering
4. **Downgrade to INFO** if only issue is missing server-side sanitization with proper client-side escaping

**Real example (example-auto.tld 2026-06):** API stored `<script>alert(1)</script>` in comments and bio fields. Initially reported as HIGH. Browser snapshot showed `StaticText "<script>alert(1)</script>"` — React escaped it. Downgraded to INFO (defense-in-depth gap).

## When to Dig Deeper

If basic XSS doesn't work, check for:
- **Stored XSS via file uploads** — Upload SVG with embedded JavaScript (`.svg` files with `<script>` tags). Check if filename/metadata is reflected without sanitization.
- **DOM-based XSS via URL fragments** — `#<img src=x onerror=alert(1)>`
- **PostMessage XSS** — Check origin validation on `window.postMessage`
- **WebSocket XSS** — Check if WS messages rendered as HTML
- **Error messages** — Check if server errors reflect user input without encoding
- **Rich text / markdown fields** — Any field that explicitly renders user HTML
