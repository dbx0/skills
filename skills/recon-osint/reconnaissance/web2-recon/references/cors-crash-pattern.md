# CORS Crash Pattern — Server Returns 500 on Cross-Origin Requests

## Pattern
Some Node.js/Express APIs with CORS middleware crash (return 500) when receiving requests from non-whitelisted origins, instead of properly returning a CORS error.

## Detection
```bash
# Preflight from evil origin
curl -sv -X OPTIONS "https://target.com/api/endpoint" \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" -D - -o /dev/null

# POST from evil origin
curl -s -X POST "https://target.com/api/endpoint" \
  -H "Content-Type: application/json" \
  -H "Origin: https://evil.com" -d '{}'
```

**Indicators:**
- OPTIONS from evil origin → 500 (should be 204)
- POST from evil origin → 500 (should be 401/403)
- Same from whitelisted origin → works normally

## Real Example (crypto-trading SaaS engagement)
`app.example-trading.tld` — ALL cross-origin requests to `/api/*` return 500.

## Impact
- DoS potential (trigger repeated server errors)
- Error responses may leak stack traces
- NOT a bypass — server is crashing, not allowing access
