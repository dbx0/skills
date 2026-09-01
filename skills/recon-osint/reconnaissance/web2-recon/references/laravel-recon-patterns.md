# Laravel Recon Patterns

## Laravel Sanctum (SPA Auth)

Sanctum provides a CSRF cookie endpoint for SPA authentication:

```bash
curl -v 'https://target.com/sanctum/csrf-cookie'
# HTTP/2 204
# set-cookie: XSRF-TOKEN=eyJpdi... (encrypted CSRF token)
# set-cookie: gosorcio-session=eyJpdi... (session cookie)
```

**What this tells you:**
- Laravel Sanctum is active → SPA auth exists
- The `XSRF-TOKEN` cookie can be used for subsequent API calls
- The app uses Laravel backend (confirms fingerprint from headers)

**Detection:** `204 No Content` on `/sanctum/csrf-cookie` = Sanctum installed.

## Laravel Horizon (Queue Dashboard)

Horizon is a queue monitoring dashboard with its own auth:

```bash
for path in /horizon /horizon/dashboard /horizon/jobs /horizon/queues /horizon/failed /horizon/stats /horizon/monitoring /horizon/supervisors /horizon/telescope /horizon/api /horizon/api/jobs /horizon/api/stats; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com${path}")
  echo "${path} → ${code}"
done
```

**Response meanings:**
- **404** → Horizon NOT installed (route not registered)
- **403** → Horizon IS installed but access restricted (styled "Forbidden" page with Laravel UI framework CSS). The forbidden page uses Tailwind CSS + Laravel's standard error page template
- **200** → Horizon is accessible (if behind auth gate, the login page shows)
- **302** → Redirect to login page

**Detection:** 403 with styled Laravel error page = Horizon installed.

## Livewire Recon

Laravel Livewire components expose a `wire:snapshot` in the HTML:

```html
<div wire:snapshot="{&quot;data&quot;:{&quot;email&quot;:&quot;&quot;,&quot;password&quot;:&quot;&quot;},&quot;memo&quot;:{&quot;id&quot;:&quot;aQe0a6q5P...&quot;,&quot;name&quot;:&quot;auth.login-form&quot;,&quot;path&quot;:&quot;login&quot;,&quot;method&quot;:&quot;GET&quot;,&quot;locale&quot;:&quot;en&quot;}}"
```

**What the snapshot reveals:**
- Component name (e.g., `auth.login-form`)
- Current route path
- Method (GET/POST)
- Locale
- Component data structure (field names, even if empty!)

**Livewire endpoint:** `/livewire/message/{component-name}` — but may return 404 for unauthenticated users.

**Detection:** `wire:snapshot` attribute in HTML = Livewire component running.

## Laravel Standard Endpoints

| Path | Expected Behavior |
|------|------------------|
| `/sanctum/csrf-cookie` | 204 → Sanctum auth active |
| `/horizon` | 403 → Horizon installed |
| `/telescope` | 403 → Telescope (debug) installed |
| `/nova` | 403/200 → Nova admin installed |
| `/nova-api` | 403 → Nova API |
| `/api/login` | 405/401 → API auth endpoint |
| `/logout` | 405 → Requires POST (Laravel default) |
| `/forgot-password` | 200 → Password reset enabled |
| `/admin` | 302/200 → Admin panel |

## CSRF Token Format

Laravel CSRF tokens follow specific patterns:

| Framework | Field Name | Format | Sample |
|-----------|-----------|--------|--------|
| Laravel | `_token` | 40-char hex | `iCJ0TxGUKelQDwcJIqWW4ipCudLT5X...` |
| Node.js (AdonisJS) | `_csrf` | 64-char hex | `e0041961ff60c13198a2b0c446fcd9724b30bdf418543a98d219252a105cc67c` |
| Django | `csrfmiddlewaretoken` | Base64 | `z4Px...` |

**Pitfall:** If the file extension is `.php` but the CSRF field is `_csrf` (Node.js format), the app is likely PHP wrapper around Node.js, or a reverse proxy mapping `.php` files to Node.js app routes.

## Real-world Example (insurance-group engagement (phase 2))

**Target:** gosorcio.com.br

```
/sanctum/csrf-cookie → 204 (Sanctum installed)
/horizon → 403 (Horizon installed, protected)
/logout → 405 (POST only — Laravel standard)
/api/login → 405 (POST) / 401 (invalid creds)
/forgot-password → 200 (password reset page)
/admin → redirects to /login
```

Livewire component snapshot found on login page:
```
name: "auth.login-form"
fields: email, password
```