# Nextcloud Live Testing Notes

Confirmed on Nextcloud 30.0.5 (Docker `nextcloud:30.0.5`) deployed at `http://192.168.0.15:8080`.

## Auth Flow (for curl-based testing)

Nextcloud login requires a CSRF token from the login page. The flow:

```bash
# Step 1: Get login page + extract requesttoken
LOGIN_PAGE=$(curl -s -c /tmp/nc.txt -b /tmp/nc.txt http://HOST/login)
TOKEN=$(echo "$LOGIN_PAGE" | grep -oP 'data-requesttoken="[^"]*"' | sed 's/data-requesttoken="//;s/"//')

# Step 2: POST login (follow redirects, keep cookies)
curl -s -c /tmp/nc.txt -b /tmp/nc.txt -L -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "user=admin&password=PASS&requesttoken=$TOKEN" \
  http://HOST/login

# Step 3: Verify via OCS API
curl -s -c /tmp/nc.txt -b /tmp/nc.txt \
  -H "OCS-APIRequest: true" \
  http://HOST/ocs/v1.php/cloud/users/admin
```

## Confirmed Unauthenticated Findings

### 1. status.php Info Disclosure
- `GET /status.php` — returns version, installed status, maintenance mode, product name
- CORS: `Access-Control-Allow-Origin: *`

### 2. OCS Capabilities Leak
- `GET /ocs/v1.php/cloud/capabilities` with `OCS-APIRequest: true` — returns version, bruteforce delay (800ms), theming config
- No auth required

### 3. CSRF Bypass via OCS-APIRequest Header
- Any POST to `/ocs/v1.php/...` with `OCS-APIRequest: true` skips CSRF validation
- Confirmed: requests are processed (not rejected with 403 CSRF error)

### 4. Public Theming Endpoints
- `GET /apps/theming/favicon/core` — HTTP 200
- `GET /apps/theming/icon/core` — HTTP 200

## Findings NOT Present in This Install

- **user_ldap not enabled** — `/renewpassword/{user}` returns 404
- **No federated sharing configured**
- **No files created yet** — admin storage empty

## Version Differences (30.0.5 vs 35.0.0 dev)

- `#[PublicPage]` attributes in 35.0.0 may not exist in 30.0.5
- `OCS-APIRequest` CSRF bypass exists in both versions
- `status.php` info disclosure exists in both versions

## Test Credentials
- URL: `http://192.168.0.15:8080`
- Admin: `admin` / `admin1234`
