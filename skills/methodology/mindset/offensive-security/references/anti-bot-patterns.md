# Anti-Bot Patterns & Fallbacks

## The Mercado Livre Pattern (JS SPA + API Bot Detection)

**What ML does:**
- Serves a thin HTML shell (~8KB) with no embedded product data
- All content loads via internal API calls (SPA architecture)
- `/api.mercadolibre.com/sites/MLB/search` returns 403 for non-browser clients
- Browser navigation shows "Hubo un error accediendo a esta pagina"
- Blocks: direct API calls (any UA), browser automation, even with valid cookies

**What was tried (all failed):**
| Attempt | Result |
|---------|--------|
| `browser_navigate` to listing URL | Error page (bot detection) |
| `browser_navigate` to base URL | Same error page |
| `curl` with Chrome UA → API search | 403 Forbidden |
| `curl` with iPhone UA → API search | 403 Forbidden |
| Cookie jar + CSRF token → API search | 403 (cookies accepted but API still blocked) |
| Mobile API endpoints | 403 |
| Alternative sites (Buscape, Zoom) | 404 / JS-only |

**Lesson:** Two failed attempts (browser + API) is enough to confirm anti-bot wall. Don't retry more variations — escalate to user.

## General Anti-Bot Recognition Heuristics

| Signal | Meaning | Action |
|--------|---------|--------|
| < 10KB HTML shell, no data | JS SPA, data via API | Try API directly |
| API returns 403 immediately | Bot detection on API | Don't retry — blocked |
| Browser shows error page | Fingerprinting / WAF | Don't retry — blocked |
| 403 after getting cookies | Session-based detection | Don't retry — blocked |
| Works in user curl but not ours | IP-based rate limiting | Ask user to run or provide proxy |

## Escalation Protocol

1. **Confirm the wall** (max 2 different approaches)
2. **Tell the user** what's happening and why
3. **Offer alternatives:**
   - Screenshot from their browser → `vision_analyze` can read it
   - Copy-paste the page content → parse directly
   - Residential proxy → route requests through it
   - `browser_console` on an already-loaded page (for data extraction, not initial load)
4. **Don't silently keep retrying** — wasted context, same result

## Sites Known to Be Difficult

| Site | Anti-Bot Method | Notes |
|------|----------------|-------|
| Mercado Livre (BR) | JS SPA + API 403 + browser fingerprinting | ML's detection is among the strongest |
| Google Shopping | JS rendering + rate limiting | Returns empty HTML for automated requests |
| Amazon | Captcha + bot detection | Requires residential proxy or user interaction |
| Instagram/Facebook | Login required + rate limiting | API is effectively closed |

## Clean Data Extraction (When You Do Get In)

When browser access works, prefer extracting structured data over scraping rendered HTML:

```
// In browser_console:
// 1. Look for JSON-LD
document.querySelectorAll('script[type="application/ld+json"]')
// 2. Look for data islands
document.querySelectorAll('[data-*]')
// 3. Look for initial state
window.__INITIAL_STATE__ || window.__PRELOADED_STATE__
```
