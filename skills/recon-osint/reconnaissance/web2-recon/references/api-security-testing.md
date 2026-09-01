# API Security Testing Patterns

> **Context:** Discovered during example-realestate.tld pentest (June 2026). Patterns for testing API authentication, authorization, and input validation.

## Token Handling — CRITICAL

Tokens with special characters (`*`, `$`, `!`, spaces) break shell commands and Python f-strings.

**NEVER assign tokens to shell variables or Python strings directly:**
```bash
TOKEN=*** WRONG — shell expands * as glob
```

**ALWAYS use file-based token reading:**
```bash
TOKEN=*** /tmp/token.txt)
curl -H "Authorization: Bearer *** "$URL"
```

```python
with open("/tmp/token.txt") as f:
    token = f.read().strip()
cmd = ["curl", "-H", "Authorization: Bearer " + token, url]
```

**Best practice:** Write a reusable shell script for API testing with a `TOKEN=$(cat file)` pattern. Shell scripts handle special chars in files correctly; Python string interpolation and f-strings do not.

## Open Redirect Testing on Login Pages

Login pages are the #1 place to find open redirects. Always test ALL of these parameters:

```
url, redirect, redirect_uri, callback, next, return, returnTo, goto, dest, destination, continue, forward
```

```bash
LOGIN_URL="https://app.target.com/auth/sign-in"
for param in url redirect redirect_uri callback next return returnTo goto dest destination continue forward; do
    final=$(curl -s -m 5 -o /dev/null -w "%{url_effective}" -L "${LOGIN_URL}?${param}=https://evil.com")
    if echo "$final" | grep -q "evil.com"; then
        echo "[OPEN REDIRECT] $param"
    fi
done
```

**Real-world:** example-realestate.tld had 12 vulnerable parameters on `/auth/sign-in`.

## Mass Assignment on Login Endpoints

Login endpoints often accept extra fields beyond email/password. Test with all user object fields:

```bash
# Get baseline user fields from login response
# Then test each field as extra parameter
for field in balance plan blocked is_phone_confirmed role is_admin webhook_url; do
    resp=$(curl -s -X POST "$BASE/api/v1/login" \
        -d "{\"email\":\"x\",\"password\":\"y\",\"$field\":\"test\"}")
    if echo "$resp" | grep -q "success\|token"; then echo "[ACCEPTED] $field"; fi
done
```

**Real-world:** example-realestate.tld accepted `is_admin`, `role`, `plan`, `balance`, `blocked`, `webhook_url` etc. on login.

## Read-Only Token Bypass

Some APIs return both full and read-only tokens. The read-only token may bypass plan/auth checks:

```bash
# Compare full vs read-only token on all endpoints
for path in /api/v1/user /api/v1/projects /api/v1/renders; do
    full=$(curl -s -o /dev/null -w "%{http_code}" -H "Bearer $FULL" "$BASE$path")
    ro=$(curl -s -o /dev/null -w "%{http_code}" -H "Bearer $RO" "$BASE$path")
    [ "$full" != "$ro" ] && echo "[BYPASS] $path: full=$full ro=$ro"
done
```

**Real-world:** example-realestate.tld read-only token bypassed plan check (403→200) but hit secondary auth check.

## CORS Testing

```bash
for origin in "https://evil.com" "null" "https://attacker.target.com"; do
    curl -s -i -H "Origin: $origin" -H "Authorization: Bearer $TOKEN" -X OPTIONS "$BASE/api/v1/user" | grep -i "access-control"
done
```

Look for: `Access-Control-Allow-Origin: *` (HIGH), reflected origin (CRITICAL), `Allow-Credentials: true` + wildcard (CRITICAL).

## Information Disclosure in Error Messages

Always inspect error responses for: phone numbers, internal usernames, stack traces, DB errors, internal IPs, framework versions, business logic details.

**Real-world (example-realestate.tld):**
```json
{"error": "...chame o Antonio para validar...+55 (16) 9 9772-1718...", "code": "CALL_ANTONIO"}
```
Revealed: internal phone, staff name, business logic, error code format.
