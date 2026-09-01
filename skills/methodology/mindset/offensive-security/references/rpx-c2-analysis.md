# RPX Malware C2 Panel Analysis

## Target
- **URL:** `http://orfjnrn.com:3000` (also `http://94.26.3.90:3000`)
- **Type:** Malware Command & Control dashboard
- **Language:** Portuguese (Brazilian)
- **UI:** Vanilla SPA styled as Telegram dark theme

## Source Code Extraction

The entire client-side code was available at `/app.js` (1170 lines, 48KB):
```bash
curl -s http://orfjnrn.com:3000/app.js -o rpx_app.js
```

## Architecture

### Auth Mechanism
- JWT stored in localStorage as `dnsmgr_jwt`
- Sent as `Authorization: Bearer ***` header
- Login endpoint: `POST /api/auth/login` with `{username, password}`
- JWT secret: **unknown** (different from nsx_dashboard on port 7000)

### API Endpoints (from client code)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/auth/login` | POST | Authentication |
| `/api/me` | GET | Current user info |
| `/api/clients` | GET | List all agents |
| `/api/clients/clear-chat` | POST | Clear agent chat |
| `/api/clients/remove` | POST | Remove agent |
| `/api/clients/display-name` | PATCH | Rename agent |
| `/api/clients/dashboard-group` | PATCH | Assign group |
| `/api/clients/beacon-config` | PATCH | Configure beacon |
| `/api/command-limits` | GET | Get command size limits |
| `/api/dashboard-groups` | GET/POST/DELETE | Group management |
| `/api/messages` | POST | Send command to agent |

### Agent Command Protocol
The C2 uses a simple text-based protocol:

**Commands (dashboard → agent):**
- `dl|<url>|<path>[|exec]` — Download file to agent, optionally execute after
- `tc|<host>[|<port>]` — TCP reachability probe from agent

**Responses (agent → dashboard):**
- `sc tcp ok ...` — TCP probe succeeded
- `sc download ok` — Download completed
- `fl <reason>` — Operation failed (various sub-types)

### Agent Details
- Binary name: `client.exe` (Windows)
- Default download path: `C:\DNSManager\downloads\`
- Beacon interval: 60 seconds (configurable per agent)
- Supports direct IP override for beacon (`beaconDirectIp`)
- Group management with priority levels (1-5)
- Display names for operators to identify victims

### DNS C2 Channel
- **Port 53** open on the C2 server
- Custom DNS server returning `err-DOT-unknown.orfjnrn.com.` for unknown subdomains
- SOA record with dynamic timestamp-based serial
- Agents likely beacon via DNS subdomain queries with encoded data
- Token name `dns_shell_token` (original) confirms DNS-based C2

## Infrastructure

| Port | Service | Auth |
|------|---------|------|
| 3000 | RPX C2 Panel | JWT Bearer |
| 7000 | nsx_dashboard | JWT Cookie |
| 53 | DNS C2 Listener | None (DNS) |
| 22 | SSH | Password only |

## Findings

### No Path Traversal on Port 3000
Unlike port 7000, the RPX panel does NOT have the Express static path traversal vulnerability. All non-existent paths return the SPA HTML shell (same MD5 hash).

### No Unauthenticated Endpoints
All API endpoints return 401 without valid JWT. The login endpoint returns generic "Usuário ou senha inválidos" for wrong creds (no username enumeration).

### CORS Wide Open
`Access-Control-Allow-Origin: *` on all responses — any website can make authenticated requests to this panel.

### Known Users (from nsx_dashboard, may not apply)
- `admin` (admin role)
- `shadydev` (user role) — likely the operator
- `atividade061` (user role)

## Attacker Identifiers
- **Email:** `shadytds777@outlook.com` (from main.js cookies on port 7000)
- **Usernames:** `shadydev`, `atividade061`
- **Server:** `94.26.3.90`

## Access Attempts (All Failed)
- Brute force with common passwords: no success
- JWT forgery with nsx_dashboard secret: rejected (different secret)
- Path traversal on port 3000: not vulnerable (separate app)
- MongoDB direct connection: connection refused (binary protocol, auth required)
- SSH: password auth required, no credentials
- No unauthenticated endpoints found
- SPA catch-all returns 200 with same HTML for all non-existent paths

## Recommendations for Further Access
1. **JWT brute force** — try common/weak JWT secrets against the RPX panel
2. **JWT none-alg attack** — test if the RPX panel's JWT library accepts `alg: "none"`
3. **SSH brute force** — port 22 is open, password auth enabled
4. **DNS C2 analysis** — reverse engineer the beacon protocol from client code + DNS behavior
5. **Agent binary search** — look for `client.exe` on malware sample repositories (VirusTotal, MalwareBazaar) using RPX panel name and DNS domain as indicators
