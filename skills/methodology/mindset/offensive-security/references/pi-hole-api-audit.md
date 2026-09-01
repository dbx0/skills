# Pi-hole API Security Audit Findings

Audit date: 2026-05-29
Repos: pi-hole/pi-hole (v6.x), pi-hole/web, pi-hole/FTL

## Architecture Summary

Pi-hole v6 uses a built-in C webserver (civetweb) in FTL with embedded Lua templates for the frontend. All API routes are in src/api/api.c. Auth is session-based (128-bit SID, CSRF cookies with HttpOnly+SameSite=Lax).

## Authentication Bypass (High Impact — by design)

Empty password = no auth at all. When webserver.api.pwhash is empty string, check_client_auth() returns API_AUTH_EMPTYPASS for ALL requests. Every endpoint is accessible without credentials. This is by design for "trusted local network" but any internet-facing Pi-hole with no password is fully compromised.

## Unauthenticated Endpoints (always accessible)

- GET /api/auth — SID, CSRF status, TOTP enabled
- GET /api/docs — Full OpenAPI specs for ALL endpoints
- GET /api/info/login — DNS status, HTTPS port
- GET /api/info/client — Full request headers (reflection)

With no password: ALL authenticated endpoints open (DNS control, config read/write, history exfil, gravity trigger, teleporter import, client/domain/group/list management).

## dnsmasq Config Injection via misc.dnsmasq_lines (Medium-High)

PATCH /api/config with {"misc":{"dnsmasq_lines":["dhcp-script=/tmp/evil.sh"]}}

Validator only checks for newlines — does NOT validate content. Single-line dnsmasq directives pass. Written directly to config file with fputs(). Config tested via fork+exec dnsmasq --test before applying.

dhcp-script RCE requires: DHCP enabled + file write to plant script. dnsmasq typically runs as unprivileged user.

## Password Visible in /proc (Medium)

SetWebPassword() passes plaintext password on command line to pihole-FTL --config. Any local user can read /proc/PID/cmdline to extract it.

## Weak Default Password (Low-Medium)

8-char from 64-char alphabet = ~48 bits entropy. Also stored in plaintext in install log.

## SHA1 Checksum Verification (Low)

FTL binary verified with SHA1 instead of SHA256. Both binary and checksum from same HTTPS origin.

## Defensive Observations

1. 128-bit random SIDs, CSRF tokens, HttpOnly cookies
2. All API config changes go through type checking + per-field validators
3. write_dnsmasq_config() runs dnsmasq --test before installing any config
4. Gravity parseList uses sqlite3_bind_text() (no SQLi)
5. No popen/system/exec in FTL C API handlers

## Hunt Targets

- Shodan: http.title:"Pi-hole" or http.html:"pi.hole"
- Ports: 80, 443
- GET /api/info/login returns 200 with data = auth likely disabled
- GET /api/docs always accessible, reveals full API surface
