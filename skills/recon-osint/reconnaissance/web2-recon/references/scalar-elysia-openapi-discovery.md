# Scalar & Elysia OpenAPI Discovery — Recon Notes

**Pattern verified**: 2026-06-02 against `api.example-pay.tld` (payment gateway, Elysia/Bun on Cloudflare)

## The Pattern

When probing `/openapi` returns HTML instead of JSON, you're likely looking at a **Scalar API reference** page (common with ElysiaJS, Hono, and other modern Bun/TypeScript frameworks).

The Scalar HTML embeds the actual spec URL in a `data-configuration` attribute:

```html
<script id="api-reference"
  data-configuration='{"url":"openapi/json","version":"latest","cdn":"...","_integration":"elysiajs"}'
></script>
```

The value of the `url` field is the JSON spec endpoint. Common values:
- `/openapi/json` (most common for Elysia)
- `/spec`
- `/docs/json`
- `/swagger/v1/swagger.json`

## Quick Detection & Extraction

```bash
# Fetch the OpenAPI HTML and extract the spec URL
curl -s "https://target.com/openapi" 2>/dev/null \
  | grep -oP "data-configuration='([^']*)'" \
  | grep -oP '"url":"[^"]*"' \
  | cut -d'"' -f4

# Then fetch the actual spec:
curl -s "https://target.com/openapi/json" | python3 -m json.tool | head -100
```

## Elysia-Specific Paths to Try

```
/openapi            → HTML doc page (Scalar UI)
/openapi/json       → Raw OpenAPI JSON spec
/documentation      → Usually 404 or redirects to /openapi
/docs               → Usually 404
/spec               → Sometimes works
```

## What to Look For in the Spec

Once you have the spec JSON, extract high-value targets:

```python
import json
with open('spec.json') as f:
    spec = json.load(f)
for path, methods in spec.get('paths', {}).items():
    for method in methods:
        if method in ('get','post','put','patch','delete'):
            print(f'{method.upper():6s} {path}')
```

**Auto-flag as P0 if spec contains:**
- `/internal/*` routes (internal billing, admin, tokenization)
- `/admin/*` routes
- `/debug/*` or `/test/*` routes
- Catch-all routes (`/*`) with mutation methods (POST/PUT/DELETE)
- `/file/{name}` or similar path-parameter routes without auth (path traversal)
- Refund, payout, or withdrawal endpoints (financial impact)
- Webhook resilience/custom-header endpoints (SSRF)

## Real-World Hit: payment gateway

- `/openapi` → 200, HTML (Scalar UI titled "Elysia Documentation")
- `/openapi/json` → 200, 185KB OpenAPI 3.0.3, **253 endpoints fully documented**
- Exposed `/internal/charge/create`, `/internal/charge/simulate`, `/internal/boleto/create`, `/internal/cloudflare-worker/tokenizer/*`
- Exposed `/file/{name}` GET with no auth requirements
- V1 and V2 API both alive with different auth models
- All on `api.example-pay.tld` behind Cloudflare, no CDN auth wall

## Why This Matters

The single highest-leverage recon finding is a **publicly accessible OpenAPI spec**. It gives you:
1. Complete endpoint map (every route, method, parameter name + type)
2. Auth model understanding (which endpoints require auth vs. public)
3. Business logic reconstruction (data models, enums, validation rules)
4. Hidden endpoints (`/internal/*`, `/admin/*`, deprecated versions)
5. Parameter-level detail for injection testing (types, formats, enums)

A spec with 250+ endpoints turns a blind recon into a targeted attack plan in minutes.
