# Payment Gateway Withdrawal & Financial Flow Testing

Techniques for testing withdrawal, payout, and financial flows in payment gateways. These require working session tokens and understanding the 2FA verification flow.

## 1. Reconnaissance Phase

### 1.1 — Discover Withdrawal Endpoints

Look in the JS bundle for withdrawal-related API calls:

```bash
grep -oP '.{0,100}withdraw.{0,100}' /tmp/bundle.js | grep -i 'post\|get\|create\|make\|list' | head -10
```

Common endpoint patterns found in payment gateways:

| Endpoint | Purpose |
|----------|---------|
| `POST /app/withdrawals/create` | Create a withdrawal |
| `GET /app/withdrawals/list` | Withdrawal history |
| `GET /app/analytics/withdraw-metrics` | Balance and limits info |
| `POST /app/exports/withdrawals` | Export withdrawal records |
| `POST /app/withdrawals/request` | Alternative creation endpoint |

### 1.2 — Extract Withdrawal Form Schema from JS

The JS bundle reveals the exact input fields:

```bash
# Find withdrawal creation mutation
grep -oP '.{0,300}withdrawals.create.post.{0,300}' /tmp/bundle.js
```

The mutation call typically looks like:

```javascript
// PIX withdrawal
Q.mutate({amount: xt, token: Ze, pixKeyType: b, pixKey: E})

// TED withdrawal
Q.mutate({amount: xt, token: Ze, method: "TED", bankCode: A, ownerName: k, agency: T, account: Y, accountDigit: q, bankAccountType: W})
```

### 1.3 — Pix Key Types

Found in the bundle as an enum map:

```javascript
const wmt = {
  CNPJ: "CNPJ",
  CPF: "CPF", 
  EMAIL: "E-mail",
  PHONE: "Telefone",
  RANDOM: "Aleatória"
}
```

### 1.4 — Minimum Amount Constant

Check for a minimum withdrawal amount constant:

```javascript
const O2 = 300  // 300 cents = R$3.00 minimum
```

### 1.5 — Fee Constants

Some gateways charge a fixed fee per withdrawal:

```javascript
const Cmt = 80    // withdrawal fee in cents (e.g., R$0.80)
const XZ = 500    // TED fixed fee in cents (e.g., R$5.00)
```

## 2 — Pre-Withdrawal Checks

### 2.1 — Check 2FA Status

Most financial flows require 2FA. Check status first:

```bash
curl -s "https://api.target.com/app/2fa/status" \
  -H "Authorization: Bearer <SESSION_TOKEN>" | jq
```

Response: `{"success": true, "data": {"enabled": true/false}}`

If 2FA is NOT enabled, the withdrawal may require setup first (Google Authenticator QR code → verify → enabled). The setup flow requires user interaction.

### 2.2 — Check Withdraw Metrics

```bash
curl -s "https://api.target.com/app/analytics/withdraw-metrics" \
  -H "Authorization: Bearer <SESSION_TOKEN>"
```

Key fields:
- `available` — total available balance (in cents)
- `dailyWithdrawLimitCents` — daily limit (e.g., 500000 = R$5,000)
- `withdrawnTodayCents` — already withdrawn today
- `remainingTodayCents` — remaining withdrawal capacity today
- `blocked` — blocked funds (e.g., pending settlement)
- `antecipationProcessing` — funds in anticipation processing

### 2.3 — Check Balance

```bash
curl -s "https://api.target.com/app/analytics/balance" \
  -H "Authorization: Bearer <SESSION_TOKEN>"
```

Key fields: `available`, `blocked`, `pending`

### 2.4 — Check Account Flags

Retrieve account info to check withdrawal capability:

```bash
# From localStorage/cookie after login
# Look for "WITHDRAW" flag in the account.flags array
```

Flags commonly seen: `API`, `WITHDRAW`, `CELLPHONE_VERIFIED`, `MULTISTORE`, `TED_OUT` (if TED withdrawals enabled)

## 3 — 2FA Verification Token Flow

The withdrawal create endpoint requires a **temporary 2FA verification token**, NOT the raw authenticator code.

### 3.1 — Get 6-digit Code from Authenticator App

Ask the user to open their authenticator app (Google Authenticator, Authy, etc.) and provide the 6-digit code.

### 3.2 — Exchange Code for Verification Token

```bash
curl -s -X POST "https://api.target.com/app/2fa/verify-code" \
  -H "Authorization: Bearer <SESSION_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"code": "123456"}'
```

Response: `{"success": true, "data": {"token": "VERIFICATION_TOKEN"}}`

The returned `token` is a **temporary verification token** (different from the session token) that authorizes the withdrawal. It is valid for a short window (typically a few minutes).

### 3.3 — Create Withdrawal with Verification Token

```bash
curl -s -X POST "https://api.target.com/app/withdrawals/create" \
  -H "Authorization: Bearer <SESSION_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 500000,
    "pixKeyType": "EMAIL",
    "pixKey": "user@email.com",
    "token": "VERIFICATION_TOKEN"
  }'
```

### 3.4 — Common Error Responses

| Error | Meaning | Fix |
|-------|---------|-----|
| `Expected property 'token' to be string but found: undefined` | Token field missing | Complete 2FA verify-code step first |
| `Expected number to be greater or equal to 300` | Below minimum | Increase amount to 300+ cents (R$3.00+) |
| `Limite de saque diário` | Daily limit reached | Wait for reset at midnight (Brasilia time) or use smaller amount |
| `Saldo insuficiente` | Insufficient balance | Withdraw less than available |
| `Valor maior que o saldo disponível` | Amount exceeds balance | Reduce withdrawal amount |

### 3.5 — Note on 2FA Setup for First-Time Users

If 2FA has never been configured on the account, the withdrawal flow triggers a setup process:

1. `POST /app/2fa/setup` — generates QR code image URL + secret key
2. User scans QR code with authenticator app
3. `POST /app/2fa/verify-setup` with 6-digit code from app to confirm
4. 2FA is now enabled — repeat from step 3.2 for actual withdrawal

If the API returns `"Saque indisponível"` (withdrawal unavailable) the gateway may block withdrawals in dev/sandbox mode entirely.

## 4 — Withdrawal Limits Analysis

### 4.1 — Daily Limit Calculation

```javascript
// JS bundle shows the daily limit bar component
// Retrieved from withdraw-metrics endpoint:
// dailyWithdrawLimitCents = 500000 (R$5,000.00)
// withdrawnTodayCents = 0
// remainingTodayCents = 500000
```

### 4.2 — Withdrawal Fee Handling

```javascript
// For PIX: amount = requested amount (no fee mentioned)
// For TED: amount = requested amount + XZ (R$5.00 TED fee)
// Fee is typically added to the withdrawal, not subtracted from payout
```

## 5 — Session Token Sources

### 5.1 — Auth-Storage Cookie

When the user provides their auth-storage cookie from browser localStorage, decode it:

```bash
# The cookie is URL-encoded JSON
echo "%7B%22state%22%3A...%7D" | python3 -c "import sys, urllib.parse, json; print(json.dumps(urllib.parse.parse_qs(sys.stdin.read().strip()), indent=2))"
```

Better decoding:
```bash
python3 -c "
import urllib.parse, json
raw = open('/dev/stdin').read().strip()
decoded = urllib.parse.unquote(raw)
parsed = json.loads(decoded)
token = parsed.get('state', {}).get('token', 'NOT_FOUND')
print(f'Token: {token}')
"
```

The auth-storage JSON typically contains:
- `state.token` — the session token (Bearer auth)
- `state.account.role` — user role (ADMIN, MANAGER, etc.)
- `state.account.flags` — array of feature flags
- `state.account.email`, `state.account.id`, `state.account.name`
- `state.account.taxId` — CPF/CNPJ
- `state.account.cellphone`

Common flags to check: `WITHDRAW`, `API`, `CELLPHONE_VERIFIED`, `MULTISTORE`, `TED_OUT`, `SUBSCRIPTION`, `ANTICIPATION`, `PDV`

### 5.2 — Token Validation

Check if the token is still valid by calling an authenticated endpoint:

```bash
curl -s "https://api.target.com/app/api-keys/list" \
  -H "Authorization: Bearer <TOKEN>" | jq '.success'
```

## 6 — Payment Event Simulation

To trigger notification/email event flows (like `payment.received`), simulate a charge payment:

```bash
# First, create a charge with test data
CHARGE=$(curl -s -X POST "https://dash.target.com/internal/charge/create" \
  -H "Content-Type: application/json" \
  -d '{"paymentMethod": "PIX", "billingId": "bill_TEST_ID", "coupons": [], "customer": {"name": "<img src=x onerror=alert(1)>", "cellphone": "...", "email": "...", "taxId": "..."}, "device": {"kind": "browser", "os": "macOS", "name": "Chrome", "ip": "127.0.0.1", "utmParams": {}}}')

# Extract charge ID
CHARGE_ID=$(echo "$CHARGE" | jq -r '.data.charge.id')

# Simulate payment
curl -s -X POST "https://dash.target.com/internal/charge/simulate?id=$CHARGE_ID"

# Verify status is now PAID
curl -s "https://api.target.com/app/payment-intents/list" \
  -H "Authorization: Bearer <TOKEN>" | jq '.data.data[] | select(.id=="$CHARGE_ID") | .status'
```

After simulation, any plugin (like Resend email notifications) wired to `payment.received` event will fire with the injected customer data.

## 7 — Pitfalls

- **2FA code expiry**: 6-digit authenticator codes rotate every 30 seconds. If the user provides a code, use it immediately.
- **Verification token one-time-use**: The token from `/verify-code` can only be used once. If the withdrawal call fails, a new 2FA code + verification token is needed.
- **Daily limit resets at midnight (Brasilia time = UTC-3)**: The limit is daily, not per-24h-window.
- **Sandbox withdrawal blocked**: Many gateways show "Saque indisponível" in dev/sandbox mode. This is expected and should be documented as a limitation.
- **Session token type matters**: The session token from login (hex string) only works on `/app/` endpoints. V1/V2 API endpoints may require a different API key format.
- **Auth-storage cookie might be stale**: If the user's session expired while they were getting the cookie, the token is invalid. Get a fresh token.