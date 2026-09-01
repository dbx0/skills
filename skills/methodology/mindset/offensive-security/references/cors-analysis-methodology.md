# CORS Analysis Methodology — Quick Reference

## Browser Enforcement Matrix

| ACAO | ACAC | Browser blocks JS read? | Exploitable? |
|------|------|------------------------|--------------|
| `*` | `true` | **YES** — invalid combo per Fetch spec | Only non-browser clients |
| `*` | `false` | No (but no credentials) | Headers readable if no auth needed |
| `https://evil.com` | `true` | **NO** | Full data theft |
| `null` | `true` | **NO** | Sandboxed iframes |
| Missing | — | Yes by default | Not a CORS issue |

## Key Insight

`ACAO: *` + `ACAC: true` is the **most common false positive** in CORS testing. Modern browsers explicitly block this combination. The server should not set ACAO to wildcard when ACAC is true.

## When It IS Exploitable

1. ACAO reflects arbitrary Origin header
2. ACAO: null (sandboxed iframe)
3. ACAO with subdomain takeover
4. Non-browser clients (curl, SSRF, mobile Webhooks)
5. ACAE: * exposes all response headers

## Severity Guidelines

| Scenario | Severity |
|----------|----------|
| ACAO reflects Origin + ACAC: true | HIGH |
| ACAO: * + ACAC: true | MEDIUM |
| ACAE: * without auth | LOW |
| Missing Vary: Origin | LOW |
| Whitelist (specific origins only) | **NOT A VULN** — Proper config |

## Whitelist CORS Pattern (Proper Configuration)

Some APIs implement a CORS whitelist: they check the `Origin` header against an allowlist and only return `access-control-allow-origin` for trusted origins. For non-whitelisted origins, the header is omitted entirely (no CORS headers = browser blocks the response by default).

**How to detect:** Send OPTIONS with various Origin headers:
- Trusted origin (e.g., `https://www.target.com`) → Response includes `access-control-allow-origin: https://www.target.com`
- Untrusted origin (e.g., `https://evil.com`) → Response omits `access-control-allow-origin` entirely
- This is **correct behavior** — not a vulnerability.

**Real-world example (speedrun-platform engagement):** `api.example-speedrun.tld` returns `access-control-allow-origin` only for `www.example-speedrun.tld` and `admin.example-speedrun.tld`. All other origins get no CORS headers. This is a properly configured whitelist.

## PoC Guidance

If the CORS misconfig is blocked by browsers, do NOT build a PoC that claims data theft. Show the misconfiguration headers and explain defense-in-depth risk instead.
